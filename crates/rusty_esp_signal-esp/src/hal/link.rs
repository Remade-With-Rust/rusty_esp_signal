//! The mID-authenticated link over ESP-NOW datagrams.
//!
//! ESP-NOW carries connectionless 2.4 GHz frames of up to 250 bytes to a peer
//! MAC with no association — exactly the shape the core's [`link`] protocol
//! wants. This backend drives the core over it:
//!
//! - [`EspNowLink::handshake_initiator`] / [`EspNowLink::handshake_responder`]
//!   run the three-message Noise-KK handshake ([`Handshake`]) by sending each
//!   message as one ESP-NOW datagram and awaiting the reply, yielding a
//!   [`Session`].
//! - [`EspNowLink::send`] seals a payload with the session and transmits it;
//!   [`EspNowLink::recv`] receives a datagram and opens it, returning the
//!   plaintext (or the reason it was refused, already counted in the session).
//!
//! The session does the cryptography; this backend does the radio. It never
//! sees a key. A firmware constructs it from the ESP-NOW sender/receiver
//! halves and the peer MAC, runs a handshake, then pumps `send`/`recv`.
//!
//! ## Framing
//!
//! One core frame per ESP-NOW datagram. The core's `MAX_FRAME` is 250, the
//! ESP-NOW payload limit, so a full session frame fits exactly and no
//! fragmentation is needed. Handshake messages (84 / 100 / 18 bytes) fit with
//! room to spare.

use esp_radio::esp_now::{BROADCAST_ADDRESS, EspNowReceiver, EspNowSender};
use rusty_esp_signal_core::esp_core::error::Result;
use rusty_esp_signal_core::esp_core::{Error, Micros, Rng};
use rusty_esp_signal_core::link::{DEFAULT_LIFETIME, Handshake, MAX_FRAME, Session};
use rusty_esp_signal_core::mid::did::Did;
use rusty_esp_signal_core::mid::key::DeviceKey;

/// The ESP-NOW broadcast address, for discovery before a peer MAC is known.
#[must_use]
pub const fn broadcast() -> [u8; 6] {
    BROADCAST_ADDRESS
}

/// An authenticated ESP-NOW link to one peer.
///
/// Owns the ESP-NOW sender and receiver halves and the peer's MAC address.
/// Hold a [`Session`] alongside it once a handshake completes.
/// No lifetime parameter: `esp-radio` 1.0.0-beta.1 dropped it from
/// `EspNowSender` and `EspNowReceiver`, and carrying one here would claim a
/// borrow this type does not hold. The halves are owned outright.
pub struct EspNowLink {
    sender: EspNowSender,
    receiver: EspNowReceiver,
    peer: [u8; 6],
    rx_buf: [u8; MAX_FRAME],
}

impl EspNowLink {
    /// Build a link over the ESP-NOW halves, addressed to `peer`. The peer
    /// must already be added to the ESP-NOW peer table (unicast) or be the
    /// broadcast address (discovery).
    #[must_use]
    pub fn new(sender: EspNowSender, receiver: EspNowReceiver, peer: [u8; 6]) -> Self {
        Self {
            sender,
            receiver,
            peer,
            rx_buf: [0u8; MAX_FRAME],
        }
    }

    /// The peer MAC this link is addressed to.
    #[must_use]
    pub const fn peer(&self) -> [u8; 6] {
        self.peer
    }

    /// Point the link at a new peer MAC (after discovery names one).
    pub fn set_peer(&mut self, peer: [u8; 6]) {
        self.peer = peer;
    }

    /// Run the handshake as the **initiator**: send `Hello`, await `Accept`,
    /// send `Confirm`, return the [`Session`]. `allow` decides whether the
    /// responder's DID is acceptable; `now` timestamps the session and
    /// `DEFAULT_LIFETIME` bounds it.
    ///
    /// Errors: `Timeout`-shaped conditions surface as the underlying radio
    /// error mapped to [`Error::Hardware`]; a refused or malformed `Accept`
    /// is [`Error::Denied`] / [`Error::Crypto`] from the core.
    pub async fn handshake_initiator(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
    ) -> Result<Session> {
        let (hs, hello) = Handshake::initiate(me, rng)?;
        self.send_raw(&hello).await?;
        let accept = self.recv_raw().await?;
        let (session, confirm) = hs.finish(me, accept, allow, now, DEFAULT_LIFETIME)?;
        self.send_raw(&confirm).await?;
        Ok(session)
    }

    /// Run the handshake as the **responder**: await `Hello`, send `Accept`,
    /// await `Confirm`, return the [`Session`]. `allow` decides whether the
    /// initiator's DID is acceptable (the owner pin, the adoption roster).
    pub async fn handshake_responder(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
    ) -> Result<Session> {
        let hello = self.recv_raw().await?;
        let (pending, accept) = Handshake::respond(me, rng, hello, allow, now, DEFAULT_LIFETIME)?;
        self.send_raw(&accept).await?;
        let confirm = self.recv_raw().await?;
        pending.confirm(confirm)
    }

    /// Seal `payload` with `session` and transmit it as one ESP-NOW datagram.
    pub async fn send(&mut self, session: &mut Session, payload: &[u8]) -> Result<()> {
        let mut frame = [0u8; MAX_FRAME];
        let n = session.seal(payload, &mut frame)?;
        self.send_raw(&frame[..n]).await
    }

    /// Receive one ESP-NOW datagram and open it with `session`, returning the
    /// plaintext length written into `out`. A refused frame (bad tag, replay,
    /// wrong session) returns the core error and is counted in the session's
    /// counters; the caller usually logs and keeps going.
    pub async fn recv<'o>(&mut self, session: &mut Session, out: &'o mut [u8]) -> Result<&'o [u8]> {
        let frame = self.recv_raw().await?;
        let plain = session.open(frame)?;
        if out.len() < plain.len() {
            return Err(Error::BufferTooSmall {
                needed: plain.len(),
            });
        }
        out[..plain.len()].copy_from_slice(plain);
        Ok(&out[..plain.len()])
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.sender
            .send_async(&self.peer, bytes)
            .await
            .map_err(|_| Error::Hardware)
    }

    /// Await one datagram and return a borrow of its payload in `self.rx_buf`.
    async fn recv_raw(&mut self) -> Result<&[u8]> {
        let data = self.receiver.receive_async().await;
        let payload = data.data();
        let n = payload.len().min(MAX_FRAME);
        self.rx_buf[..n].copy_from_slice(&payload[..n]);
        Ok(&self.rx_buf[..n])
    }
}

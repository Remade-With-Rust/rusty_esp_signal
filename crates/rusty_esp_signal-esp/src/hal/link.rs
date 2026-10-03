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
use rusty_esp_signal_core::link::{
    DEFAULT_LIFETIME, FrameBuf, Handshake, MAX_FRAME, Session, Sha256Blocks, SoftSha,
};
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
    rx_buf: FrameBuf,
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
            rx_buf: FrameBuf::new(),
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
        self.send_with(&mut SoftSha, session, payload).await
    }

    /// [`Self::send`] with the frame's HMAC blocks on `engine` --
    /// `hal::sha::EspSha` for the chip's SHA unit (feature `sha-accel`).
    /// The same frame as `send`.
    pub async fn send_with(
        &mut self,
        engine: &mut impl Sha256Blocks,
        session: &mut Session,
        payload: &[u8],
    ) -> Result<()> {
        let mut buf = FrameBuf::new();
        let frame = &mut buf.0;
        let n = session.seal_with(engine, payload, frame)?;
        self.send_raw(&frame[..n]).await
    }

    /// Receive one ESP-NOW datagram and open it with `session`, returning the
    /// plaintext length written into `out`. A refused frame (bad tag, replay,
    /// wrong session) returns the core error and is counted in the session's
    /// counters; the caller usually logs and keeps going.
    pub async fn recv<'o>(&mut self, session: &mut Session, out: &'o mut [u8]) -> Result<&'o [u8]> {
        self.recv_with(&mut SoftSha, session, out).await
    }

    /// [`Self::recv`] with the frame's HMAC blocks on `engine`. The same
    /// verdicts as `recv`.
    pub async fn recv_with<'o>(
        &mut self,
        engine: &mut impl Sha256Blocks,
        session: &mut Session,
        out: &'o mut [u8],
    ) -> Result<&'o [u8]> {
        let frame = self.recv_raw().await?;
        let plain = session.open_with(engine, frame)?;
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

    /// Await one datagram and return a borrow of its payload in `self.rx_buf.0`.
    async fn recv_raw(&mut self) -> Result<&[u8]> {
        let data = self.receiver.receive_async().await;
        let payload = data.data();
        let n = payload.len().min(MAX_FRAME);
        self.rx_buf.0[..n].copy_from_slice(&payload[..n]);
        Ok(&self.rx_buf.0[..n])
    }
}

/// The mID-authenticated link over UDP datagrams on the network the node
/// already has (`hal::netstack`): the bridge is a process on the LAN with
/// [`UdpRadio`] on its side, and no second radio is needed on the bench
/// (killing-C plan, X9). One core frame per datagram, as over ESP-NOW; the
/// `MAX_FRAME` of 250 bytes holds. The node initiates: it knows the
/// bridge's address and DID, and the bridge answers the DIDs on its roster.
///
/// [`UdpRadio`]: https://docs.rs/rusty_esp_iroh-bridge
#[cfg(feature = "embassy-net")]
pub struct UdpLink<'a> {
    socket: embassy_net::udp::UdpSocket<'a>,
    peer: embassy_net::IpEndpoint,
    rx_buf: FrameBuf,
    /// The SHA unit, when the firmware gave the link one ([`Self::with_sha`]).
    #[cfg(feature = "sha-accel")]
    sha: Option<crate::hal::sha::EspSha<'a>>,
}

#[cfg(feature = "embassy-net")]
impl<'a> UdpLink<'a> {
    /// Over `socket` (bound by the caller) to the bridge at `peer`.
    #[must_use]
    pub fn new(socket: embassy_net::udp::UdpSocket<'a>, peer: embassy_net::IpEndpoint) -> Self {
        UdpLink {
            socket,
            peer,
            rx_buf: FrameBuf::new(),
            #[cfg(feature = "sha-accel")]
            sha: None,
        }
    }

    /// Seal and open every frame of this link on the chip's SHA unit:
    /// [`Self::send`] and [`Self::recv`] then go through it (round 2, R3:
    /// 651 us -> 66 us a sealed-and-opened frame on an S3 at 80 MHz, the
    /// same frames).
    #[cfg(feature = "sha-accel")]
    #[must_use]
    pub fn with_sha(mut self, sha: crate::hal::sha::EspSha<'a>) -> Self {
        self.sha = Some(sha);
        self
    }

    /// The bridge's endpoint.
    #[must_use]
    pub const fn peer(&self) -> embassy_net::IpEndpoint {
        self.peer
    }

    /// Run the handshake as the **initiator**: send `Hello`, await `Accept`
    /// within `patience`, send `Confirm`, return the [`Session`]. `allow`
    /// decides whether the responder's DID is acceptable (the bridge's).
    pub async fn handshake_initiator(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
        patience: embassy_time::Duration,
    ) -> Result<Session> {
        // Nothing that arrived before this hello can be its accept: a late
        // accept for the attempt before (the bridge answered after the
        // patience ran out) would otherwise be read as this one, fail the
        // transcript check, and every attempt after it would read the one
        // before -- seen on the XIAO after a hard reset (X9, run 3).
        self.drain().await;
        let (hs, hello) = Handshake::initiate(me, rng)?;
        self.send_raw(&hello).await?;
        let accept = self.recv_raw(patience).await?;
        let (session, confirm) = hs.finish(me, accept, allow, now, DEFAULT_LIFETIME)?;
        self.send_raw(&confirm).await?;
        Ok(session)
    }

    /// Drop every datagram already queued on the socket.
    async fn drain(&mut self) {
        while embassy_time::with_timeout(
            embassy_time::Duration::from_millis(1),
            self.socket.recv_from(&mut self.rx_buf.0),
        )
        .await
        .is_ok()
        {}
    }

    /// Seal `payload` with `session` and send it as one datagram.
    pub async fn send(&mut self, session: &mut Session, payload: &[u8]) -> Result<()> {
        #[cfg(feature = "sha-accel")]
        if let Some(mut sha) = self.sha.take() {
            let sent = self.send_with(&mut sha, session, payload).await;
            self.sha = Some(sha);
            return sent;
        }
        self.send_with(&mut SoftSha, session, payload).await
    }

    /// [`Self::send`] with the frame's HMAC blocks on `engine` --
    /// `hal::sha::EspSha` for the chip's SHA unit (feature `sha-accel`).
    /// The same frame as `send`.
    pub async fn send_with(
        &mut self,
        engine: &mut impl Sha256Blocks,
        session: &mut Session,
        payload: &[u8],
    ) -> Result<()> {
        let mut buf = FrameBuf::new();
        let frame = &mut buf.0;
        let n = session.seal_with(engine, payload, frame)?;
        self.send_raw(&frame[..n]).await
    }

    /// Receive one datagram from the bridge within `patience` and open it
    /// with `session`, the plaintext copied into `out`. `Timeout` when
    /// nothing came; a refused frame returns the core's error and is
    /// counted in the session.
    pub async fn recv<'o>(
        &mut self,
        session: &mut Session,
        out: &'o mut [u8],
        patience: embassy_time::Duration,
    ) -> Result<&'o [u8]> {
        #[cfg(feature = "sha-accel")]
        if let Some(mut sha) = self.sha.take() {
            let got = self.recv_with(&mut sha, session, out, patience).await;
            self.sha = Some(sha);
            return got;
        }
        self.recv_with(&mut SoftSha, session, out, patience).await
    }

    /// [`Self::recv`] with the frame's HMAC blocks on `engine`. The same
    /// verdicts as `recv`.
    pub async fn recv_with<'o>(
        &mut self,
        engine: &mut impl Sha256Blocks,
        session: &mut Session,
        out: &'o mut [u8],
        patience: embassy_time::Duration,
    ) -> Result<&'o [u8]> {
        let frame = self.recv_raw(patience).await?;
        let plain = session.open_with(engine, frame)?;
        if out.len() < plain.len() {
            return Err(Error::BufferTooSmall {
                needed: plain.len(),
            });
        }
        out[..plain.len()].copy_from_slice(plain);
        Ok(&out[..plain.len()])
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.socket
            .send_to(bytes, self.peer)
            .await
            .map_err(|_| Error::Hardware)
    }

    /// One datagram from the bridge's endpoint (others are dropped),
    /// within `patience`.
    async fn recv_raw(&mut self, patience: embassy_time::Duration) -> Result<&[u8]> {
        let deadline = embassy_time::Instant::now() + patience;
        loop {
            let left = deadline.saturating_duration_since(embassy_time::Instant::now());
            if left.as_ticks() == 0 {
                return Err(Error::Timeout);
            }
            match embassy_time::with_timeout(left, self.socket.recv_from(&mut self.rx_buf.0)).await
            {
                Err(_) => return Err(Error::Timeout),
                Ok(Err(_)) => return Err(Error::Hardware),
                Ok(Ok((n, meta))) => {
                    if meta.endpoint == self.peer {
                        let n = n.min(MAX_FRAME);
                        return Ok(&self.rx_buf.0[..n]);
                    }
                }
            }
        }
    }
}

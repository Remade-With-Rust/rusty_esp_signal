//! The mID-authenticated link on raw frames, on the open lower MAC (the
//! umbrella's experiments plan, row E4). **Not Wi-Fi certified.**
//!
//! The link wants one datagram of up to 250 bytes to a MAC address with no
//! association: on the blob that is ESP-NOW, a vendor action frame
//! `libespnow` builds. Here the frame is ours (`espnow_frame`, laid out by
//! hand from Espressif's published layout and read back by `ieee80211` on
//! the host), sent and received through FoA's lower MAC, so the link rides
//! the same bytes with no Espressif code above the PHY, and a node on the
//! open MAC and a node on the blob link to each other.
//!
//! [`RawLink`] has the shape of `rusty_esp_signal-esp`'s `UdpLink`, so a
//! firmware's link task takes either: [`RawLink::handshake_initiator`],
//! [`RawLink::send`], [`RawLink::recv`]. Under it:
//!
//! - **Transmit**: at 1 Mbit/s, ESP-NOW's rate. To a known peer the frame is
//!   acknowledged and the radio retries it; an unacknowledged frame is the
//!   send's error, as the blob reports it. To broadcast it goes once.
//! - **Receive**: the interface's filter is ESP-NOW's addresses in hardware:
//!   the receiver address ours (or broadcast), the BSSID field broadcast, so
//!   beacons and other networks' data never arrive. [`rx_task`] drains the
//!   interface into a queue of [`INBOX`] datagrams (a bridge's window of 16)
//!   and hands the radio its buffer back at once: a link task writing flash
//!   holds none of the radio's receive buffers.
//! - **The peer**: broadcast until a handshake names an address, which the
//!   link then keeps ([`RawLink::learn_peer`]).
//!
//! The session does the cryptography; this does the radio. It never sees a
//! key. ESP-NOW's own encryption is not used: every frame above the
//! handshake is sealed by the session.

use core::sync::atomic::{AtomicU32, Ordering};

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use embassy_time::{Duration, Instant, with_timeout};
use esp_hal::rng::Rng as HardwareRng;
use foa::esp_wifi_hal::ll::EdcaAccessCategory;
use foa::esp_wifi_hal::prelude::{RxFilterBank, TxMacParameters, TxPlcpParameters};
use foa::esp_wifi_hal::rates::{HrDsssRate, TxPhyRate};
use foa::{FoARunner, RetryBehaviour, RxEndpoint, TxEndpoint, VirtualInterface};
use rusty_esp_signal_core::esp_core::error::Result;
use rusty_esp_signal_core::esp_core::{Error, Micros, Rng};
use rusty_esp_signal_core::link::{
    DEFAULT_LIFETIME, FrameBuf, Handshake, MAX_FRAME, Session, Sha256Blocks, SoftSha,
};
use rusty_esp_signal_core::mid::did::Did;
use rusty_esp_signal_core::mid::key::DeviceKey;
use static_cell::StaticCell;

/// The broadcast address: every ESP-NOW radio in range, for discovery
/// before a peer's address is known.
pub const BROADCAST: [u8; 6] = espnow_frame::BROADCAST;

/// Datagrams the receive queue holds: a bridge's window of 16 chunks.
pub const INBOX: usize = 16;

/// How often the radio tries a frame to a known peer before the send fails.
const RETRIES: u8 = 7;

static SENT: AtomicU32 = AtomicU32::new(0);
static UNACKED: AtomicU32 = AtomicU32::new(0);
static HEARD: AtomicU32 = AtomicU32::new(0);
static TAKEN: AtomicU32 = AtomicU32::new(0);
static INBOX_DROPPED: AtomicU32 = AtomicU32::new(0);
static FOREIGN: AtomicU32 = AtomicU32::new(0);
static DUPLICATES: AtomicU32 = AtomicU32::new(0);

/// One received ESP-NOW datagram, copied out of the radio's buffer.
#[derive(Clone, Copy)]
struct Datagram {
    from: [u8; 6],
    len: u8,
    bytes: [u8; MAX_FRAME],
}

type Inbox = Channel<NoopRawMutex, Datagram, INBOX>;

/// The link's receive side, for [`rx_task`]: the interface drained into the
/// queue the link reads.
pub struct RawRunner {
    rx: RxEndpoint<'static, 'static>,
    me: [u8; 6],
    inbox: Sender<'static, NoopRawMutex, Datagram, INBOX>,
}

/// An authenticated link to one peer over raw ESP-NOW frames. Hold a
/// [`Session`] alongside it once a handshake completes. `E` is where the
/// frames' HMAC blocks run: [`SoftSha`], or the chip's SHA unit through
/// [`RawLink::with_engine`].
pub struct RawLink<E: Sha256Blocks = SoftSha> {
    tx: &'static TxEndpoint<'static>,
    inbox: Receiver<'static, NoopRawMutex, Datagram, INBOX>,
    me: [u8; 6],
    peer: [u8; 6],
    /// Whether `peer` was learned at a handshake (and may be forgotten at a
    /// failed one) rather than named by the firmware.
    learned: bool,
    learn: bool,
    last_from: [u8; 6],
    rx_buf: FrameBuf,
    engine: E,
}

/// What [`raw_link`] gives a firmware: the link, and the two runners to
/// spawn ([`mac_task`], [`rx_task`]) before a handshake is tried.
pub struct OpenRawLink {
    /// The link, addressed to the peer [`raw_link`] was given.
    pub link: RawLink,
    /// The receive side, for [`rx_task`].
    pub rx: RawRunner,
    /// FoA's lower-MAC runner, for [`mac_task`].
    pub mac: FoARunner<'static>,
    /// This radio's address: the chip's base MAC, as ESP-NOW uses the
    /// station's on the blob.
    pub address: [u8; 6],
}

/// The open MAC brought up for raw frames alone: no station, no access
/// point, no IP. Once per firmware (the MAC's resources are static).
/// `channel` is the 2.4 GHz channel both ends are on (the blob's ESP-NOW
/// uses its station's, 1 unless set); `peer` is the other end's address or
/// [`BROADCAST`].
pub fn raw_link(
    wifi: esp_hal::peripherals::WIFI<'static>,
    channel: u8,
    peer: [u8; 6],
) -> OpenRawLink {
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    let ([vif, ..], mac) = foa::init(crate::FOA.take(), wifi);
    let (link, rx) = attach(VIF.init(vif), channel, peer);
    let address = link.me;
    OpenRawLink {
        link,
        rx,
        mac,
        address,
    }
}

/// A raw link on one of the radio's virtual interfaces (the access point
/// takes another): the channel locked, the hardware filter set to ESP-NOW's
/// addresses, the receive queue made. Once per firmware.
pub fn attach(
    vif: &'static mut VirtualInterface<'static>,
    channel: u8,
    peer: [u8; 6],
) -> (RawLink, RawRunner) {
    let (control, rx, tx) = vif.split();
    let base = esp_hal::efuse::base_mac_address();
    let mut me = [0u8; 6];
    me.copy_from_slice(base.as_bytes());
    let _ = control.lock_channel(channel);
    // frames to this address or to broadcast, whose address 3 is broadcast:
    // ESP-NOW's, and little else on the channel
    control.set_filter(RxFilterBank::ReceiverAddress, me);
    control.set_filter(RxFilterBank::Bssid, BROADCAST);
    control.set_filter_bssid_check(true);

    static INBOX_CELL: StaticCell<Inbox> = StaticCell::new();
    let inbox: &'static Inbox = INBOX_CELL.init(Channel::new());
    let tx: &'static TxEndpoint<'static> = tx;
    (
        RawLink {
            tx,
            inbox: inbox.receiver(),
            me,
            peer,
            learned: false,
            learn: true,
            last_from: BROADCAST,
            rx_buf: FrameBuf::new(),
            engine: SoftSha,
        },
        RawRunner {
            rx,
            me,
            inbox: inbox.sender(),
        },
    )
}

/// FoA's lower-MAC runner, for the life of the firmware.
#[embassy_executor::task]
pub async fn mac_task(mut runner: FoARunner<'static>) {
    runner.run().await
}

/// The link's receive side, for the life of the firmware: every frame the
/// interface passes is read as ESP-NOW; one for this radio is copied into
/// the queue (dropped, and counted, when the queue is full) and the radio's
/// buffer goes back before the next. A retransmission of a frame already
/// taken (its acknowledgement was lost on the way back) is dropped here, as
/// any 802.11 receiver drops it: the session above would refuse it as a
/// replay, and count one.
#[embassy_executor::task]
pub async fn rx_task(mut runner: RawRunner) -> ! {
    let mut seen = espnow_frame::Duplicates::new();
    loop {
        let received = runner.rx.receive().await;
        HEARD.fetch_add(1, Ordering::Relaxed);
        if seen.is_duplicate(received.mpdu_buffer()) {
            DUPLICATES.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let datagram = espnow_frame::parse(received.mpdu_buffer()).and_then(|frame| {
            if frame.to != runner.me && frame.to != BROADCAST {
                return None;
            }
            let len = frame.body.len().min(MAX_FRAME);
            let mut bytes = [0u8; MAX_FRAME];
            bytes[..len].copy_from_slice(&frame.body[..len]);
            Some(Datagram {
                from: frame.from,
                len: len as u8,
                bytes,
            })
        });
        drop(received);
        if let Some(datagram) = datagram {
            if runner.inbox.try_send(datagram).is_ok() {
                TAKEN.fetch_add(1, Ordering::Relaxed);
            } else {
                INBOX_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn one_mbit() -> TxPlcpParameters {
    TxPlcpParameters {
        rate: TxPhyRate::HrDsss(HrDsssRate::new(0, false).expect("1 Mbit/s, long preamble")),
        ..Default::default()
    }
}

impl<E: Sha256Blocks> RawLink<E> {
    /// The frames' HMAC blocks on `engine` from here on: the chip's SHA
    /// unit (`rusty_esp_signal-esp`'s `hal::sha::EspSha`) seals and opens
    /// the same frames in a tenth of the time.
    #[must_use]
    pub fn with_engine<F: Sha256Blocks>(self, engine: F) -> RawLink<F> {
        RawLink {
            tx: self.tx,
            inbox: self.inbox,
            me: self.me,
            peer: self.peer,
            learned: self.learned,
            learn: self.learn,
            last_from: self.last_from,
            rx_buf: self.rx_buf,
            engine,
        }
    }

    /// This radio's address.
    #[must_use]
    pub const fn address(&self) -> [u8; 6] {
        self.me
    }

    /// The address frames go to.
    #[must_use]
    pub const fn peer(&self) -> [u8; 6] {
        self.peer
    }

    /// Point the link at `peer` ([`BROADCAST`] to discover again).
    pub fn set_peer(&mut self, peer: [u8; 6]) {
        self.peer = peer;
        self.learned = false;
    }

    /// Whether a handshake's peer address is kept (the default): frames
    /// then go to it alone, acknowledged and retried, and frames from
    /// anyone else are dropped. A learned address is forgotten when a later
    /// handshake with it fails -- the peer's radio may have been replaced
    /// -- and the next hello is a broadcast again; an address the firmware
    /// named is never forgotten. Off, the link stays on broadcast, as a
    /// blob's link built on the broadcast address does.
    pub fn learn_peer(&mut self, learn: bool) {
        self.learn = learn;
    }

    /// Run the handshake as the **initiator**: send `Hello`, await `Accept`
    /// within `patience`, send `Confirm`, return the [`Session`]. `allow`
    /// decides whether the responder's DID is acceptable.
    pub async fn handshake_initiator(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
        patience: Duration,
    ) -> Result<Session> {
        let session = self.initiate(me, rng, allow, now, patience).await;
        if session.is_err() && self.learned {
            // the address learned last time did not answer (or answered
            // wrong): discover again
            self.peer = BROADCAST;
            self.learned = false;
        }
        session
    }

    async fn initiate(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
        patience: Duration,
    ) -> Result<Session> {
        // nothing queued before this hello can be its accept (X9, run 3)
        self.drain();
        let (hs, hello) = Handshake::initiate(me, rng)?;
        self.send_raw(&hello).await?;
        let n = self.recv_raw(patience).await?;
        let (session, confirm) =
            hs.finish(me, &self.rx_buf.0[..n], allow, now, DEFAULT_LIFETIME)?;
        // the accept verified: its sender is the peer
        if self.learn && self.peer == BROADCAST {
            self.peer = self.last_from;
            self.learned = true;
        }
        self.send_raw(&confirm).await?;
        Ok(session)
    }

    /// Run the handshake as the **responder**: await `Hello` within
    /// `patience`, send `Accept`, await `Confirm`, return the [`Session`].
    /// `allow` decides whether the initiator's DID is acceptable.
    pub async fn handshake_responder(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
        patience: Duration,
    ) -> Result<Session> {
        let session = self.respond(me, rng, allow, now, patience).await;
        if session.is_err() && self.learned {
            self.peer = BROADCAST;
            self.learned = false;
        }
        session
    }

    async fn respond(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
        patience: Duration,
    ) -> Result<Session> {
        let n = self.recv_raw(patience).await?;
        let (pending, accept) =
            Handshake::respond(me, rng, &self.rx_buf.0[..n], allow, now, DEFAULT_LIFETIME)?;
        if self.learn && self.peer == BROADCAST {
            self.peer = self.last_from;
            self.learned = true;
        }
        self.send_raw(&accept).await?;
        let n = self.recv_raw(patience).await?;
        pending.confirm(&self.rx_buf.0[..n])
    }

    /// Seal `payload` with `session` and send it as one frame.
    pub async fn send(&mut self, session: &mut Session, payload: &[u8]) -> Result<()> {
        // sealed straight into the frame's body: sealed into a zeroed
        // buffer and copied in after, the datagram went to an odd offset a
        // byte at a time (2026-10-07)
        let mut buf = self.tx.alloc_tx_buf().await;
        let window = espnow_frame::OVERHEAD..buf.len().min(espnow_frame::MAX_FRAME);
        let body = buf.get_mut(window).ok_or(Error::BufferTooSmall {
            needed: espnow_frame::MAX_FRAME,
        })?;
        let n = session.seal_with(&mut self.engine, payload, body)?;
        let random = HardwareRng::new().random().to_le_bytes();
        let total = espnow_frame::write_header(&mut buf[..], &self.peer, &self.me, random, n)
            .ok_or(Error::BufferTooSmall { needed: n })?;
        self.transmit_frame(buf, total).await
    }

    /// Send `bytes` as one ESP-NOW datagram outside any session, to the
    /// peer (broadcast until one is known): a probe, a numbered beacon for
    /// counting loss. Nothing sent here is authenticated; the link's own
    /// frames go through [`RawLink::send`].
    pub async fn send_unsealed(&mut self, bytes: &[u8]) -> Result<()> {
        self.send_raw(bytes).await
    }

    /// Receive one frame from the peer within `patience` and open it with
    /// `session`, the plaintext copied into `out`. `Timeout` when nothing
    /// came; a refused frame returns the core's error and is counted in the
    /// session.
    pub async fn recv<'o>(
        &mut self,
        session: &mut Session,
        out: &'o mut [u8],
        patience: Duration,
    ) -> Result<&'o [u8]> {
        let n = self.recv_raw(patience).await?;
        let plain = session.open_with(&mut self.engine, &self.rx_buf.0[..n])?;
        if out.len() < plain.len() {
            return Err(Error::BufferTooSmall {
                needed: plain.len(),
            });
        }
        out[..plain.len()].copy_from_slice(plain);
        Ok(&out[..plain.len()])
    }

    /// Drop every datagram already queued.
    fn drain(&mut self) {
        while self.inbox.try_receive().is_ok() {}
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> Result<()> {
        let mut buf = self.tx.alloc_tx_buf().await;
        let random = HardwareRng::new().random().to_le_bytes();
        let n = espnow_frame::write(&mut buf[..], &self.peer, &self.me, random, bytes).ok_or(
            Error::BufferTooSmall {
                needed: bytes.len(),
            },
        )?;
        self.transmit_frame(buf, n).await
    }

    /// A laid-out frame of `n` octets in `buf` on the air: acknowledged
    /// and retried to the peer, once to broadcast; counted.
    async fn transmit_frame(&mut self, buf: foa::TxBuffer<'static>, n: usize) -> Result<()> {
        let unicast = self.peer != BROADCAST;
        let done = self
            .tx
            .transmit_edca(
                EdcaAccessCategory::default(),
                buf,
                n,
                one_mbit(),
                TxMacParameters {
                    wait_for_ack: unicast,
                    override_seq_num: true,
                    ..Default::default()
                },
                if unicast {
                    RetryBehaviour::RetryUntil(RETRIES)
                } else {
                    RetryBehaviour::Drop
                },
            )
            .wait_for_completion()
            .await;
        SENT.fetch_add(1, Ordering::Relaxed);
        if matches!(done, Some(d) if d.result.is_ok()) {
            Ok(())
        } else {
            UNACKED.fetch_add(1, Ordering::Relaxed);
            Err(Error::Hardware)
        }
    }

    /// One datagram from the peer (anyone, while the peer is broadcast)
    /// into `rx_buf` within `patience`: its length.
    async fn recv_raw(&mut self, patience: Duration) -> Result<usize> {
        let deadline = Instant::now() + patience;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.as_ticks() == 0 {
                return Err(Error::Timeout);
            }
            let Ok(datagram) = with_timeout(left, self.inbox.receive()).await else {
                return Err(Error::Timeout);
            };
            if self.peer != BROADCAST && datagram.from != self.peer {
                FOREIGN.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let n = usize::from(datagram.len);
            self.rx_buf.0[..n].copy_from_slice(&datagram.bytes[..n]);
            self.last_from = datagram.from;
            return Ok(n);
        }
    }
}

/// The raw link's counters since boot, for a firmware's watch line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Frames sent.
    pub sent: u32,
    /// Sends that failed: a frame to a known peer never acknowledged.
    pub unacked: u32,
    /// Frames the interface's filter passed.
    pub heard: u32,
    /// ESP-NOW datagrams for this radio put in the queue.
    pub taken: u32,
    /// Datagrams dropped for a full queue.
    pub inbox_dropped: u32,
    /// Datagrams from another address than the peer's, dropped.
    pub foreign: u32,
    /// Retransmissions of a frame already taken, dropped.
    pub duplicates: u32,
}

/// The counters now.
#[must_use]
pub fn stats() -> Stats {
    let r = |a: &AtomicU32| a.load(Ordering::Relaxed);
    Stats {
        sent: r(&SENT),
        unacked: r(&UNACKED),
        heard: r(&HEARD),
        taken: r(&TAKEN),
        inbox_dropped: r(&INBOX_DROPPED),
        foreign: r(&FOREIGN),
        duplicates: r(&DUPLICATES),
    }
}

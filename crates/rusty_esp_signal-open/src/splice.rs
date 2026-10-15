//! A splice between a radio's network device and the IP stack above it
//! (a NAT relay, for one):
//! every frame the radio receives is shown to the firmware's `decide` once,
//! and goes to the stack as it came, out of this radio again, across to the
//! other side's splice, or nowhere. The stack's own frames go out
//! untouched, and so do the frames the other side sends across.
//!
//! The decision is the firmware's (its forwarding policy); this
//! module only moves frames, and never blocks on a full queue: a frame the
//! stack, or the other side, has no room for is dropped and counted, so
//! one side's backlog never stalls the other's traffic, or the device's own.
//! Not Wi-Fi certified.

use core::future::poll_fn;
use core::sync::atomic::{AtomicU32, Ordering};
use core::task::Poll;

use embassy_futures::select::{Either3, select3};
use embassy_net_driver::{Driver, HardwareAddress, LinkState, RxToken, TxToken};
use embassy_net_driver_channel as ch;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;

use crate::turn::{First, Turns};

/// The longest frame a splice carries, Ethernet header included (the open
/// MAC's station and access point both).
pub const MTU: usize = 1514;

/// One frame in a [`Crossing`].
pub struct Frame {
    /// Its length.
    pub len: usize,
    /// Its bytes (the first `len`).
    pub buf: [u8; MTU],
}

impl Frame {
    /// An empty frame.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            len: 0,
            buf: [0; MTU],
        }
    }
}

impl Default for Frame {
    fn default() -> Self {
        Self::new()
    }
}

/// Frames on their way from one side's splice to the other's: `N` at most,
/// a full one drops.
pub type Crossing<const N: usize> = Channel<CriticalSectionRawMutex, Frame, N>;

/// Where a frame goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// To this radio's IP stack, as it came.
    Stack,
    /// Out of this radio again.
    Here,
    /// Across, to the other side's radio.
    Across,
    /// Nowhere.
    Drop,
}

/// What `decide` says of a frame, and of the extra frame it wrote, if any:
/// its route (`Here` or `Across`) and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The frame's route.
    pub frame: Route,
    /// One more frame, written to the buffer `decide` was given.
    pub extra: Option<(Route, usize)>,
}

/// What a splice has done since it started.
#[derive(Debug, Default)]
pub struct SpliceStats {
    /// Frames received from the radio.
    pub received: AtomicU32,
    /// Frames sent on the radio (for the stack, for the other side, here).
    pub sent: AtomicU32,
    /// Bytes sent on the radio.
    pub sent_bytes: AtomicU32,
    /// Frames the other side sent across that this radio sent.
    pub across_in: AtomicU32,
    /// Bytes of those.
    pub across_in_bytes: AtomicU32,
    /// Frames for the stack it had no room for.
    pub stack_full: AtomicU32,
    /// Frames for the other side its crossing had no room for.
    pub across_full: AtomicU32,
}

impl SpliceStats {
    /// Nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            received: AtomicU32::new(0),
            sent: AtomicU32::new(0),
            sent_bytes: AtomicU32::new(0),
            across_in: AtomicU32::new(0),
            across_in_bytes: AtomicU32::new(0),
            stack_full: AtomicU32::new(0),
            across_full: AtomicU32::new(0),
        }
    }
}

fn bump(c: &AtomicU32, by: u32) {
    c.fetch_add(by, Ordering::Relaxed);
}

/// A radio's device on one end, the stack's on the other: run it with
/// [`Splice::run`] for the life of the firmware.
pub struct Splice {
    radio: ch::Device<'static, MTU>,
    state: ch::StateRunner<'static>,
    up: ch::RxRunner<'static, MTU>,
    down: ch::TxRunner<'static, MTU>,
}

/// Put a splice between `radio` and the stack: the device the stack is
/// built on (`embassy_net::new`), at `mac`, and the splice to run. `state`
/// holds the stack's side: `RX` frames waiting for the stack, `TX` frames
/// from it.
pub fn splice<const RX: usize, const TX: usize>(
    radio: ch::Device<'static, MTU>,
    state: &'static mut ch::State<MTU, RX, TX>,
    mac: [u8; 6],
) -> (ch::Device<'static, MTU>, Splice) {
    let (runner, device) = ch::new(state, HardwareAddress::Ethernet(mac));
    let (state, up, down) = runner.split();
    state.set_link_state(LinkState::Down);
    (
        device,
        Splice {
            radio,
            state,
            up,
            down,
        },
    )
}

/// Send `bytes` on the radio, waiting for room.
async fn transmit(radio: &mut ch::Device<'static, MTU>, bytes: &[u8]) {
    poll_fn(|cx| match radio.transmit(cx) {
        Some(token) => {
            token.consume(bytes.len(), |b| b.copy_from_slice(bytes));
            Poll::Ready(())
        }
        None => Poll::Pending,
    })
    .await;
}

impl Splice {
    /// Move frames for the life of the firmware. While `relay_behind` is
    /// set (a shedding policy's relayed-traffic-behind), the stack's own
    /// frame goes before a relayed one whenever both wait ([`crate::turn`]);
    /// otherwise they take turns. `decide` is shown every
    /// frame the radio receives, with a buffer for one more frame (an ARP
    /// request, an ICMP error); `stack_sent` is shown every frame the stack
    /// sends, before it goes (a NAT follows the device's own
    /// connections by them); `across` takes frames for the other side's
    /// splice, `from_across` brings this side the other's. `stats` counts.
    pub async fn run<const A: usize, const B: usize>(
        self,
        mut decide: impl FnMut(&mut [u8], &mut [u8]) -> Verdict,
        mut stack_sent: impl FnMut(&[u8]),
        relay_behind: &'static core::sync::atomic::AtomicBool,
        across: &'static Crossing<A>,
        from_across: &'static Crossing<B>,
        stats: &'static SpliceStats,
    ) -> ! {
        let Splice {
            mut radio,
            state,
            mut up,
            mut down,
        } = self;
        let mut frame = Frame::new();
        let mut extra = Frame::new();
        let mut link = LinkState::Down;
        enum Radio {
            Frame,
            Link(LinkState),
        }
        enum Event<'a> {
            Radio(Radio),
            Stack(&'a mut [u8]),
            Across(Frame),
        }
        let mut turns = Turns::new();
        loop {
            let radio_ready = poll_fn(|cx| {
                let now = radio.link_state(cx);
                if now != link {
                    return Poll::Ready(Radio::Link(now));
                }
                if radio.receive(cx).is_some() {
                    Poll::Ready(Radio::Frame)
                } else {
                    Poll::Pending
                }
            });
            // when the stack's frame and a relayed one both wait, the turn
            // decides (L2): the stack's first while relaying is put behind
            let event = match turns.first(relay_behind.load(Ordering::Relaxed)) {
                First::Stack => {
                    match select3(radio_ready, down.tx_buf(), from_across.receive()).await {
                        Either3::First(r) => Event::Radio(r),
                        Either3::Second(b) => Event::Stack(b),
                        Either3::Third(f) => Event::Across(f),
                    }
                }
                First::Across => {
                    match select3(radio_ready, from_across.receive(), down.tx_buf()).await {
                        Either3::First(r) => Event::Radio(r),
                        Either3::Second(f) => Event::Across(f),
                        Either3::Third(b) => Event::Stack(b),
                    }
                }
            };
            match event {
                Event::Radio(Radio::Link(now)) => {
                    link = now;
                    state.set_link_state(now);
                }
                Event::Radio(Radio::Frame) => {
                    let len = poll_fn(|cx| match radio.receive(cx) {
                        Some((rx, _)) => Poll::Ready(rx.consume(|b| {
                            let n = b.len().min(MTU);
                            frame.buf[..n].copy_from_slice(&b[..n]);
                            n
                        })),
                        None => Poll::Pending,
                    })
                    .await;
                    bump(&stats.received, 1);
                    let verdict = decide(&mut frame.buf[..len], &mut extra.buf);
                    match verdict.frame {
                        Route::Stack => match up.try_rx_buf() {
                            Some(b) if b.len() >= len => {
                                b[..len].copy_from_slice(&frame.buf[..len]);
                                up.rx_done(len);
                            }
                            _ => bump(&stats.stack_full, 1),
                        },
                        Route::Here => {
                            transmit(&mut radio, &frame.buf[..len]).await;
                            bump(&stats.sent, 1);
                            bump(&stats.sent_bytes, len as u32);
                        }
                        Route::Across => {
                            frame.len = len;
                            let crossing = core::mem::replace(&mut frame, Frame::new());
                            if across.try_send(crossing).is_err() {
                                bump(&stats.across_full, 1);
                            }
                        }
                        Route::Drop => {}
                    }
                    match verdict.extra {
                        Some((Route::Here, n)) if n <= MTU => {
                            transmit(&mut radio, &extra.buf[..n]).await;
                            bump(&stats.sent, 1);
                            bump(&stats.sent_bytes, n as u32);
                        }
                        Some((Route::Across, n)) if n <= MTU => {
                            extra.len = n;
                            let crossing = core::mem::replace(&mut extra, Frame::new());
                            if across.try_send(crossing).is_err() {
                                bump(&stats.across_full, 1);
                            }
                        }
                        _ => {}
                    }
                }
                Event::Stack(bytes) => {
                    turns.served(First::Stack);
                    let n = bytes.len();
                    stack_sent(bytes);
                    transmit(&mut radio, bytes).await;
                    down.tx_done();
                    bump(&stats.sent, 1);
                    bump(&stats.sent_bytes, n as u32);
                }
                Event::Across(f) => {
                    turns.served(First::Across);
                    let n = f.len.min(MTU);
                    transmit(&mut radio, &f.buf[..n]).await;
                    bump(&stats.sent, 1);
                    bump(&stats.sent_bytes, n as u32);
                    bump(&stats.across_in, 1);
                    bump(&stats.across_in_bytes, n as u32);
                }
            }
        }
    }
}

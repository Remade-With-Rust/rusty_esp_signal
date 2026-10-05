#![no_std]
#![no_main]
//! **S1 over raw frames** (the experiments plan's E4): `c6-s1-link`'s kill
//! test from an ESP32-S3 on the open lower MAC. The link's datagrams are
//! ESP-NOW frames laid out by hand (`espnow_frame`) and sent through FoA,
//! with no `libespnow` and no Wi-Fi blob above the PHY; the other half is
//! `c6-s1-link` on the blob (a C6, an ESP32, another S3), unmodified, so
//! the blob's ESP-NOW is the independent implementation ours is checked
//! against. **Not Wi-Fi certified.**
//!
//! One source, two images, as there: the default `role-initiator` drives,
//! `--no-default-features --features role-responder` echoes. The lines are
//! S1's (`S1 ...`, one `RESULT:`), so a run reads beside the blob's.
//!
//! # What S1 asserts
//!
//! > 1,000 frames each way over an mID-authenticated link; loss,
//! > replay-rejected and bad-tag counters recorded; a third unadopted
//! > identity cannot join.
//!
//! # What this adds
//!
//! - `tx=`: after the handshake the link keeps the peer's address and sends
//!   to it alone, acknowledged and retried by the radio (E4's D-E4d).
//!   `JANUS_S1_BROADCAST=1` at build time keeps it on broadcast, as the
//!   blob's S1 is, for a like-for-like run.
//! - `S1 raw ...`: the raw link's counters (frames sent, sends never
//!   acknowledged, frames the filter passed, datagrams queued, dropped,
//!   from strangers) and the heap in use.
//! - The channel is `JANUS_LINK_CHANNEL` at build time, 1 by default: the
//!   blob's ESP-NOW rides its station's channel, which is 1 unless set.

extern crate alloc;

use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::time::Instant;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use rusty_esp_core::Micros;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_signal_esp::hal::rng::EspTrng;
use rusty_esp_signal_open::raw_link::{self, BROADCAST, RawLink};

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(all(feature = "role-initiator", feature = "role-responder"))]
compile_error!("pick exactly one role: role-initiator OR role-responder");
#[cfg(not(any(feature = "role-initiator", feature = "role-responder")))]
compile_error!("pick exactly one role: role-initiator OR role-responder");

/// Frames each way. The S1 row says 1,000.
const FRAMES: u32 = 1_000;
/// How long one receive may take before it is counted as loss.
const RX_TIMEOUT: Duration = Duration::from_millis(500);
/// How long a handshake's reply may take.
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Payload size, as S1's.
const PAYLOAD: usize = 64;
/// The channel both ends are on.
const CHANNEL: u8 = match option_env!("JANUS_LINK_CHANNEL") {
    Some(s) => parse_channel(s),
    None => 1,
};
/// Stay on broadcast after the handshake, as the blob's S1 does.
const KEEP_BROADCAST: bool = option_env!("JANUS_S1_BROADCAST").is_some();

const fn parse_channel(s: &str) -> u8 {
    let b = s.as_bytes();
    let mut n = 0u8;
    let mut i = 0;
    while i < b.len() {
        assert!(
            b[i].is_ascii_digit(),
            "JANUS_LINK_CHANNEL is a channel number"
        );
        n = n * 10 + (b[i] - b'0');
        i += 1;
    }
    assert!(n >= 1 && n <= 13, "JANUS_LINK_CHANNEL is 1 to 13");
    n
}

fn now() -> Micros {
    Micros(Instant::now().duration_since_epoch().as_micros())
}

fn raw_line() {
    let r = raw_link::stats();
    println!(
        "S1 raw sent={} unacked={} heard={} taken={} inbox_dropped={} foreign={} duplicates={} heap_used={}",
        r.sent,
        r.unacked,
        r.heard,
        r.taken,
        r.inbox_dropped,
        r.foreign,
        r.duplicates,
        esp_alloc::HEAP.used()
    );
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 64 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    // the USB-JTAG console reattaches after a reset: lines printed in the
    // first second are lost to a monitor that just reset the board (E3's
    // C16, run 1)
    Timer::after(Duration::from_millis(1500)).await;

    let role = if cfg!(feature = "role-initiator") {
        "initiator"
    } else {
        "responder"
    };
    println!("== JANUS S1 open-link ==");
    println!(
        "S1 role={role} frames={FRAMES} payload={PAYLOAD} stack=open-mac channel={CHANNEL} (NOT Wi-Fi certified)"
    );

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = Trng::try_new().expect("TRNG entropy source enabled");
    let mut rng = EspTrng::new(trng);

    let me = DeviceKey::generate(&mut rng, "janus-xiao-open").expect("device key");
    let mut did_buf = [0u8; 64];
    if let Ok(s) = me.did().write(&mut did_buf) {
        println!("S1 did={s}");
    }

    let heap_before = esp_alloc::HEAP.used();
    let raw = raw_link::raw_link(peripherals.WIFI, CHANNEL, BROADCAST);
    spawner.spawn(raw_link::mac_task(raw.mac).expect("mac task"));
    spawner.spawn(raw_link::rx_task(raw.rx).expect("rx task"));
    let mut link = raw.link;
    link.learn_peer(!KEEP_BROADCAST);
    println!(
        "S1 address={:02x?} radio_heap={} tx={}",
        raw.address,
        esp_alloc::HEAP.used() - heap_before,
        if KEEP_BROADCAST {
            "broadcast"
        } else {
            "unicast once the peer is known"
        }
    );

    #[cfg(feature = "role-responder")]
    responder(&mut link, &me, &mut rng).await;
    #[cfg(feature = "role-initiator")]
    initiator(&mut link, &me, &mut rng).await;

    loop {
        Timer::after(Duration::from_secs(60)).await;
    }
}

// ------------------------------------------------------------- responder --

/// Accept one peer, echo its frames, then refuse anyone else.
#[cfg(feature = "role-responder")]
async fn responder(link: &mut RawLink, me: &DeviceKey, rng: &mut EspTrng) {
    println!("S1 waiting for peer");

    let mut adopted = [0u8; 64];
    let mut adopted_len = 0usize;

    // a hello may be a long time coming: wait for it a minute at a time
    let mut session = loop {
        match link
            .handshake_responder(
                me,
                rng,
                |peer| {
                    if let Ok(s) = peer.write(&mut adopted) {
                        adopted_len = s.len();
                    }
                    true
                },
                now(),
                Duration::from_secs(60),
            )
            .await
        {
            Ok(s) => break s,
            Err(rusty_esp_core::Error::Timeout) => link.set_peer(BROADCAST),
            Err(e) => {
                println!("S1 handshake_failed={e:?}");
                println!("RESULT: FAIL -- no session");
                return;
            }
        }
    };
    let peer_did = core::str::from_utf8(&adopted[..adopted_len]).unwrap_or("?");
    println!(
        "S1 session={} peer={peer_did} peer_address={:02x?}",
        session.id(),
        link.peer()
    );

    let mut buf = [0u8; 256];
    let mut echoed = 0u32;
    let mut timeouts = 0u32;
    while echoed < FRAMES && timeouts < 20 {
        match link.recv(&mut session, &mut buf, RX_TIMEOUT).await {
            Ok(plain) => {
                let n = plain.len();
                if link.send(&mut session, &buf[..n]).await.is_ok() {
                    echoed += 1;
                }
                timeouts = 0;
            }
            Err(rusty_esp_core::Error::Timeout) => timeouts += 1,
            // a refused frame is already counted inside the session
            Err(_) => {}
        }
    }

    let c = session.counters();
    println!(
        "S1 role=responder echoed={echoed} want={FRAMES} received={} sent={}",
        c.received, c.sent
    );
    println!(
        "S1 bad_tag={} replayed={} foreign={}",
        c.bad_tag, c.replayed, c.foreign
    );
    raw_line();

    // the unadopted-identity arm: anyone but the DID above is refused
    println!("S1 now refusing any DID but the adopted one");
    link.set_peer(BROADCAST);
    let refused = !matches!(
        link.handshake_responder(
            me,
            rng,
            |peer| {
                let mut other = [0u8; 64];
                match peer.write(&mut other) {
                    Ok(s) => s.as_bytes() == &adopted[..adopted_len],
                    Err(_) => false,
                }
            },
            now(),
            JOIN_TIMEOUT,
        )
        .await,
        Ok(_)
    );
    println!(
        "S1 reject_unadopted={}",
        if refused { "REFUSED" } else { "ADMITTED" }
    );

    if echoed >= FRAMES && refused && c.bad_tag == 0 {
        println!("RESULT: PASS -- {echoed} frames echoed, unadopted identity refused");
    } else {
        println!("RESULT: FAIL");
    }
}

// ------------------------------------------------------------- initiator --

/// Drive the frames, then try to join again under an identity nobody adopted.
#[cfg(feature = "role-initiator")]
async fn initiator(link: &mut RawLink, me: &DeviceKey, rng: &mut EspTrng) {
    println!("S1 handshaking");
    // a hello on broadcast has no acknowledgement: a lost one is sent again
    let mut attempts = 0u32;
    let mut session = loop {
        attempts += 1;
        match link
            .handshake_initiator(me, rng, |_peer| true, now(), JOIN_TIMEOUT)
            .await
        {
            Ok(s) => break s,
            Err(e) if attempts < 12 => {
                println!("S1 handshake attempt {attempts}: {e:?}; again");
                link.set_peer(BROADCAST);
            }
            Err(e) => {
                println!("S1 handshake_failed={e:?}");
                raw_line();
                println!("RESULT: FAIL -- no session");
                return;
            }
        }
    };
    println!(
        "S1 session={} attempts={attempts} peer_address={:02x?}",
        session.id(),
        link.peer()
    );

    let payload = [0xA5u8; PAYLOAD];
    let mut buf = [0u8; 256];
    let mut sent = 0u32;
    let mut ok = 0u32;
    let mut lost = 0u32;

    let started = Instant::now();
    for i in 0..FRAMES {
        let mut p = payload;
        p[0..4].copy_from_slice(&i.to_le_bytes());
        if link.send(&mut session, &p).await.is_err() {
            lost += 1;
            continue;
        }
        sent += 1;
        match link.recv(&mut session, &mut buf, RX_TIMEOUT).await {
            Ok(echo) => {
                if echo.len() == PAYLOAD && echo[0..4] == i.to_le_bytes() {
                    ok += 1;
                } else {
                    println!("S1 mismatch at {i}");
                }
            }
            Err(rusty_esp_core::Error::Timeout) => lost += 1,
            Err(_) => {} // refused: the session counted it
        }
    }
    let elapsed_ms = started.elapsed().as_millis();

    let c = session.counters();
    println!("S1 role=initiator frames_sent={sent} frames_ok={ok} lost={lost}");
    println!(
        "S1 bad_tag={} replayed={} foreign={} session_sent={} session_received={}",
        c.bad_tag, c.replayed, c.foreign, c.sent, c.received
    );
    println!("S1 elapsed_ms={elapsed_ms}");
    raw_line();

    // a DID the responder has never seen: same radio, same distance, only
    // the identity differs
    Timer::after(Duration::from_millis(200)).await;
    println!("S1 attempting join as an unadopted identity");
    let rogue = match DeviceKey::generate(rng, "janus-xiao-rogue") {
        Ok(k) => k,
        Err(_) => {
            println!("RESULT: FAIL -- could not mint the rogue key");
            return;
        }
    };
    let mut rdid = [0u8; 64];
    if let Ok(s) = rogue.did().write(&mut rdid) {
        println!("S1 rogue_did={s}");
    }
    link.set_peer(BROADCAST);
    let admitted = link
        .handshake_initiator(&rogue, rng, |_peer| true, now(), JOIN_TIMEOUT)
        .await
        .is_ok();
    println!(
        "S1 reject_unadopted={}",
        if admitted { "ADMITTED" } else { "REFUSED" }
    );

    if ok >= FRAMES && !admitted && c.bad_tag == 0 {
        println!(
            "RESULT: PASS -- {ok}/{FRAMES} round-trips, lost={lost}, bad_tag=0, unadopted identity refused"
        );
    } else {
        println!(
            "RESULT: FAIL -- ok={ok} lost={lost} bad_tag={} admitted={admitted}",
            c.bad_tag
        );
    }
}

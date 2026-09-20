#![no_std]
#![no_main]
//! **S1** — the C6 ↔ C6 authenticated ESP-NOW link, as a self-driving kill
//! test.
//!
//! One source, two images. `--features role-initiator` drives; the default
//! `role-responder` echoes. Building the same code twice with one feature
//! different is what makes the two halves comparable, and is why the runbook
//! hands a colleague two `.bin` files instead of a toolchain.
//!
//! # What S1 asserts
//!
//! > 1,000 frames each way over an mID-authenticated ESP-NOW link; loss,
//! > replay-rejected and bad-tag counters recorded; a third unadopted
//! > identity cannot join.
//!
//! # The third identity does not need a third board
//!
//! The row is written as "a third unadopted C6 cannot join", which reads as
//! three boards. It is not: what has to be refused is an unadopted
//! **identity**, not a particular piece of silicon. So after the frame run
//! the initiator mints a second `DeviceKey` — a DID the responder has never
//! seen — and tries to hand-shake again. The responder's `allow` closure
//! pins the first DID it accepted and refuses anything else.
//!
//! That is the stronger test, not a weaker substitute: same radio, same
//! antenna, same distance, same RF conditions. Only the identity differs, so
//! a refusal cannot be explained away by range or interference.
//!
//! # Every wait is bounded
//!
//! `EspNowLink::recv` awaits a datagram and a lost frame would otherwise
//! hang the run forever, which on a colleague's bench is indistinguishable
//! from a crash. Every receive here is wrapped in a timeout, and a timeout
//! is **counted as loss** rather than being fatal — a run that loses frames
//! still produces numbers, and numbers are what S1 is for.
//!
//! # Reading the output
//!
//! Both roles print `S1 ...` lines and finish with one `RESULT:` line. The
//! counters come from the session itself (`Session::counters`), not from
//! this firmware's own tallies, so `bad_tag` and `replayed` are the core's
//! judgement rather than a restatement of it.

use embassy_time::{Duration, Timer, with_timeout};
use esp_backtrace as _;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::time::Instant;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use rusty_esp_core::Micros;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_signal_esp::hal::link::EspNowLink;
use rusty_esp_signal_esp::hal::rng::EspTrng;

esp_bootloader_esp_idf::esp_app_desc!();

#[cfg(all(feature = "role-initiator", feature = "role-responder"))]
compile_error!("pick exactly one role: role-initiator OR role-responder");
#[cfg(not(any(feature = "role-initiator", feature = "role-responder")))]
compile_error!("pick exactly one role: role-initiator OR role-responder");

/// Frames each way. The S1 row says 1,000.
const FRAMES: u32 = 1_000;
/// How long one receive may take before it is counted as loss.
const RX_TIMEOUT: Duration = Duration::from_millis(500);
/// How long the unadopted join may hang before it counts as refused-by-silence.
const JOIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Payload size. Small enough to leave ESP-NOW's 250-byte budget room for the
/// sealed frame's header and tag.
const PAYLOAD: usize = 64;

fn now() -> Micros {
    Micros(Instant::now().duration_since_epoch().as_micros())
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    // The ESP32 (the CAM board) has far less contiguous DRAM than the C6 or
    // the S3, and `heap_allocator!` reserves statically -- at 96 KB it eats
    // the main stack and the link fails with "Main stack is smaller than
    // 8192 bytes", which reads like a stack setting and is really a heap
    // one. The harness needs nowhere near 96 KB.
    #[cfg(feature = "chip-esp32")]
    esp_alloc::heap_allocator!(size: 32 * 1024);
    #[cfg(not(feature = "chip-esp32"))]
    esp_alloc::heap_allocator!(size: 96 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    let role = if cfg!(feature = "role-initiator") {
        "initiator"
    } else {
        "responder"
    };
    println!("== JANUS S1 c6-link ==");
    println!("S1 role={role} frames={FRAMES} payload={PAYLOAD}");

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = Trng::try_new().expect("TRNG entropy source enabled");
    let mut rng = EspTrng::new(trng);

    let me = DeviceKey::generate(&mut rng, "janus-c6").expect("device key");
    let mut did_buf = [0u8; 64];
    if let Ok(s) = me.did().write(&mut did_buf) {
        println!("S1 did={s}");
    }

    let mut wifi = esp_radio::wifi::WifiController::new(
        peripherals.WIFI,
        esp_radio::wifi::ControllerConfig::default(),
    )
    .expect("wifi controller");
    wifi.set_config(&esp_radio::wifi::Config::Station(
        esp_radio::wifi::sta::StationConfig::default(),
    ))
    .expect("station config");

    let esp_now = wifi.esp_now();
    let (_manager, sender, receiver) = esp_now.split();
    let mut link = EspNowLink::new(
        sender,
        receiver,
        rusty_esp_signal_esp::hal::link::broadcast(),
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
async fn responder(link: &mut EspNowLink, me: &DeviceKey, rng: &mut EspTrng) {
    println!("S1 waiting for peer");

    // The first DID to hand-shake is the adopted one. Recorded here, and
    // nothing else is admitted afterwards.
    let mut adopted = [0u8; 64];
    let mut adopted_len = 0usize;

    let mut session = match link
        .handshake_responder(me, rng, |peer| {
            if let Ok(s) = peer.write(&mut adopted) {
                adopted_len = s.len();
            }
            true
        }, now())
        .await
    {
        Ok(s) => s,
        Err(e) => {
            println!("S1 handshake_failed={e:?}");
            println!("RESULT: FAIL -- no session");
            return;
        }
    };
    let peer_did = core::str::from_utf8(&adopted[..adopted_len]).unwrap_or("?");
    println!("S1 session={} peer={peer_did}", session.id());

    // Echo until the initiator has had its FRAMES, or until the link goes
    // quiet for long enough that waiting further cannot change the numbers.
    let mut buf = [0u8; 256];
    let mut echoed = 0u32;
    let mut timeouts = 0u32;
    while echoed < FRAMES && timeouts < 20 {
        match with_timeout(RX_TIMEOUT, link.recv(&mut session, &mut buf)).await {
            Ok(Ok(plain)) => {
                let n = plain.len();
                if link.send(&mut session, &buf[..n]).await.is_ok() {
                    echoed += 1;
                }
                timeouts = 0;
            }
            // A refused frame is already counted inside the session; the
            // point of S1 is that it is counted, not that it never happens.
            Ok(Err(_)) => {}
            Err(_) => timeouts += 1,
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

    // The unadopted-identity arm: anyone but the DID above is refused.
    println!("S1 now refusing any DID but the adopted one");
    let refused = match with_timeout(
        JOIN_TIMEOUT,
        link.handshake_responder(me, rng, |peer| {
            let mut other = [0u8; 64];
            match peer.write(&mut other) {
                Ok(s) => s.as_bytes() == &adopted[..adopted_len],
                Err(_) => false,
            }
        }, now()),
    )
    .await
    {
        Ok(Ok(_)) => false,      // a session with an unadopted DID: a failure
        Ok(Err(_)) => true,      // refused outright
        Err(_) => true,          // nothing completed: also not joined
    };
    println!(
        "S1 reject_unadopted={}",
        if refused { "REFUSED" } else { "ADMITTED" }
    );

    let ok = echoed >= FRAMES && refused && c.bad_tag == 0;
    if ok {
        println!("RESULT: PASS -- {echoed} frames echoed, unadopted identity refused");
    } else {
        println!("RESULT: FAIL");
    }
}

// ------------------------------------------------------------- initiator --

/// Drive the frames, then try to join again under an identity nobody adopted.
#[cfg(feature = "role-initiator")]
async fn initiator(link: &mut EspNowLink, me: &DeviceKey, rng: &mut EspTrng) {
    println!("S1 handshaking");
    let mut session = match link.handshake_initiator(me, rng, |_peer| true, now()).await {
        Ok(s) => s,
        Err(e) => {
            println!("S1 handshake_failed={e:?}");
            println!("RESULT: FAIL -- no session");
            return;
        }
    };
    println!("S1 session={}", session.id());

    let payload = [0xA5u8; PAYLOAD];
    let mut buf = [0u8; 256];
    let mut sent = 0u32;
    let mut ok = 0u32;
    let mut lost = 0u32;

    let started = Instant::now();
    for i in 0..FRAMES {
        // The sequence number goes in the payload as well as the sealed
        // header, so a mismatch shows up as a wrong echo rather than only as
        // a counter.
        let mut p = payload;
        p[0..4].copy_from_slice(&i.to_le_bytes());
        if link.send(&mut session, &p).await.is_err() {
            lost += 1;
            continue;
        }
        sent += 1;
        match with_timeout(RX_TIMEOUT, link.recv(&mut session, &mut buf)).await {
            Ok(Ok(echo)) => {
                if echo.len() == PAYLOAD && echo[0..4] == i.to_le_bytes() {
                    ok += 1;
                } else {
                    // Arrived, opened, wrong content: not loss, and worth
                    // separating from it.
                    println!("S1 mismatch at {i}");
                }
            }
            Ok(Err(_)) => {} // refused: the session counted it
            Err(_) => lost += 1,
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

    // A DID the responder has never seen. Same radio, same antenna, same
    // distance -- only the identity differs, so a refusal cannot be put down
    // to range or interference.
    Timer::after(Duration::from_millis(200)).await;
    println!("S1 attempting join as an unadopted identity");
    let rogue = match DeviceKey::generate(rng, "janus-c6-rogue") {
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
    let admitted = matches!(
        with_timeout(
            JOIN_TIMEOUT,
            link.handshake_initiator(&rogue, rng, |_peer| true, now())
        )
        .await,
        Ok(Ok(_))
    );
    println!(
        "S1 reject_unadopted={}",
        if admitted { "ADMITTED" } else { "REFUSED" }
    );

    let pass = ok >= FRAMES && !admitted && c.bad_tag == 0;
    if pass {
        println!(
            "RESULT: PASS -- {ok}/{FRAMES} round-trips, lost={lost}, \
             bad_tag=0, unadopted identity refused"
        );
    } else {
        println!("RESULT: FAIL -- ok={ok} lost={lost} bad_tag={} admitted={admitted}", c.bad_tag);
    }
}

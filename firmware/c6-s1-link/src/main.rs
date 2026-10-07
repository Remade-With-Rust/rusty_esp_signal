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

extern crate alloc;

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

/// `JANUS_MAC_SNAPSHOT` (E5's P2 method): the MAC's registers as the radio
/// stack left them.
#[allow(dead_code)]
#[path = "../../common/mac_snapshot.rs"]
mod mac_snapshot;

/// The run's `RESULT:` line, kept to be said again: a reader that joins after
/// the run (the C6-DevKitC's bridge loses what is printed while the port is
/// closed or after its reset lines move, 2026-10-07) still hears it.
static VERDICT: critical_section::Mutex<core::cell::RefCell<Option<alloc::string::String>>> =
    critical_section::Mutex::new(core::cell::RefCell::new(None));

macro_rules! verdict {
    ($($arg:tt)*) => {{
        let line = alloc::format!($($arg)*);
        println!("{}", line);
        critical_section::with(|cs| *VERDICT.borrow_ref_mut(cs) = Some(line));
    }};
}

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

/// `JANUS_BEACON=count,gap_us,length` at build time: instead of S1, send
/// that many numbered broadcasts (one way, no session) for a receiver to
/// count -- `JB`, a tag octet for the stack, a 32-bit sequence number,
/// filler. The same frames from both stacks, at the same pace.
fn beacon_plan() -> Option<(u32, u64, usize)> {
    let mut parts = option_env!("JANUS_BEACON")?.split(',');
    let count = parts.next()?.trim().parse().ok()?;
    let gap_us = parts.next()?.trim().parse().ok()?;
    let length: usize = parts.next()?.trim().parse().ok()?;
    Some((count, gap_us, length.clamp(7, 250)))
}

async fn beacon(
    sender: &mut esp_radio::esp_now::EspNowSender,
    count: u32,
    gap_us: u64,
    length: usize,
) {
    println!("S1 beacon stack=blob count={count} gap_us={gap_us} len={length}");
    // let the receiver's capture start (and a USB console reattach)
    Timer::after(Duration::from_secs(3)).await;
    let mut frame = [0xA5u8; 250];
    frame[..3].copy_from_slice(b"JBB");
    let started = embassy_time::Instant::now();
    let mut failed = 0u32;
    for sequence in 0..count {
        Timer::at(started + Duration::from_micros(u64::from(sequence) * gap_us)).await;
        frame[3..7].copy_from_slice(&sequence.to_be_bytes());
        if sender
            .send_async(&esp_radio::esp_now::BROADCAST_ADDRESS, &frame[..length])
            .await
            .is_err()
        {
            failed += 1;
        }
    }
    println!(
        "S1 beacon elapsed_ms={} sent={count} failed={failed}",
        started.elapsed().as_millis()
    );
    println!("RESULT: beacons done sent={count} failed={failed}");
}

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
    // The radio's own allocations (some 53 KB at start on esp-radio) do not
    // fit in those 32 KB: the ESP32 also gets the DRAM its ROM loader used,
    // free once the application runs and otherwise unused (`dram2_seg`).
    #[cfg(feature = "chip-esp32")]
    {
        esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 98_768);
        esp_alloc::heap_allocator!(size: 32 * 1024);
    }
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
    #[allow(unused_mut)]
    let (_manager, mut sender, receiver) = esp_now.split();
    if mac_snapshot::ON {
        // the blob's MAC, started in station mode with ESP-NOW on
        Timer::after(Duration::from_millis(500)).await;
        #[cfg(feature = "chip-esp32s3")]
        mac_snapshot::window(
            "blob",
            mac_snapshot::S3_BASE,
            mac_snapshot::S3_LEN,
            mac_snapshot::S3_SKIP,
        );
        #[cfg(feature = "chip-esp32c6")]
        let taken = mac_snapshot::take(&mac_snapshot::C6_REGISTERS);
        #[cfg(feature = "chip-esp32c6")]
        mac_snapshot::print("blob", &mac_snapshot::C6_REGISTERS, &taken);
        // a heartbeat: a capture that goes quiet tells a reset (a new boot
        // banner) from a stalled line (beats resuming); the C6's reading
        // again every 15 s for a reader that joined after boot
        let mut beat = 0u32;
        loop {
            Timer::after(Duration::from_secs(1)).await;
            beat += 1;
            println!("MACSNAP alive {beat}");
            #[cfg(feature = "chip-esp32c6")]
            if beat % 15 == 0 {
                mac_snapshot::print("blob", &mac_snapshot::C6_REGISTERS, &taken);
            }
        }
    }
    if let Some((count, gap_us, length)) = beacon_plan() {
        beacon(&mut sender, count, gap_us, length).await;
        loop {
            Timer::after(Duration::from_secs(60)).await;
        }
    }
    let mut link = EspNowLink::new(
        sender,
        receiver,
        rusty_esp_signal_esp::hal::link::broadcast(),
    );

    #[cfg(feature = "role-responder")]
    responder(&mut link, &me, &mut rng).await;
    #[cfg(feature = "role-initiator")]
    initiator(&mut link, &me, &mut rng).await;

    // A bench knob: built with JANUS_S1_REARM_S, the firmware restarts that
    // many seconds after its verdict, so a responder on a board with no
    // reset line (the ESP32-CAM's base) takes the next pair with no hand
    // on it. The link's code is the same either way.
    let rearm = option_env!("JANUS_S1_REARM_S").and_then(|s| s.parse::<u64>().ok());
    if let Some(after) = rearm {
        println!("S1 restarting in {after} s (JANUS_S1_REARM_S)");
    }
    // the verdict again every 2 s for a reader that joins late (VERDICT)
    let finished = embassy_time::Instant::now();
    loop {
        Timer::after(Duration::from_secs(2)).await;
        if let Some(line) = critical_section::with(|cs| VERDICT.borrow_ref(cs).clone()) {
            println!("{line} (again)");
        }
        if rearm.is_some_and(|after| finished.elapsed().as_secs() >= after) {
            esp_hal::system::software_reset();
        }
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

    // A failed handshake starts over rather than ending the run: a stranger's
    // ESP-NOW frame on the channel failed S1 "no session" (InvalidFormat)
    // before its initiator had spoken, and the initiator now sends its hello
    // again when unanswered (2026-10-07). Bounded, so a channel full of
    // strangers still ends in a verdict.
    let mut foreign = 0u32;
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
            )
            .await
        {
            Ok(s) => break s,
            // a stranger's frame, or the initiator's retried hello arriving
            // where this side waited for its confirm: start over, bounded
            Err(e) if foreign < 50 => {
                foreign += 1;
                println!("S1 handshake attempt {foreign} failed={e:?}; waiting again");
            }
            Err(e) => {
                println!("S1 handshake_failed={e:?}");
                verdict!("RESULT: FAIL -- no session");
                return;
            }
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
        ),
    )
    .await
    {
        Ok(Ok(_)) => false, // a session with an unadopted DID: a failure
        Ok(Err(_)) => true, // refused outright
        Err(_) => true,     // nothing completed: also not joined
    };
    println!(
        "S1 reject_unadopted={}",
        if refused { "REFUSED" } else { "ADMITTED" }
    );

    let ok = echoed >= FRAMES && refused && c.bad_tag == 0;
    if ok {
        verdict!(
            "RESULT: PASS -- {echoed} frames echoed, unadopted identity refused; peer {peer_did}"
        );
    } else {
        // the counts and the peer in the verdict itself: it is said again
        // for a reader that joined late, and the lines before it are lost
        verdict!(
            "RESULT: FAIL -- echoed={echoed}/{FRAMES} refused={refused} bad_tag={}; peer {peer_did}",
            c.bad_tag
        );
    }
}

// ------------------------------------------------------------- initiator --

/// Drive the frames, then try to join again under an identity nobody adopted.
#[cfg(feature = "role-initiator")]
async fn initiator(link: &mut EspNowLink, me: &DeviceKey, rng: &mut EspTrng) {
    println!("S1 handshaking");
    // One hello, then a wait with no end: a responder still bringing its
    // radio up missed it and the run hung "handshaking" (2026-10-07, C6 to
    // C6). A hello again every JOIN_TIMEOUT, ten times at most.
    let mut session = None;
    for attempt in 1..=10u32 {
        match with_timeout(
            JOIN_TIMEOUT,
            link.handshake_initiator(me, rng, |_peer| true, now()),
        )
        .await
        {
            Ok(Ok(s)) => {
                session = Some(s);
                break;
            }
            Ok(Err(e)) => println!("S1 handshake attempt {attempt} failed={e:?}"),
            Err(_) => println!("S1 handshake attempt {attempt}: no answer"),
        }
    }
    let Some(mut session) = session else {
        verdict!("RESULT: FAIL -- no session");
        return;
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
            verdict!("RESULT: FAIL -- could not mint the rogue key");
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
        verdict!(
            "RESULT: PASS -- {ok}/{FRAMES} round-trips, lost={lost}, \
             bad_tag=0, unadopted identity refused"
        );
    } else {
        verdict!(
            "RESULT: FAIL -- ok={ok} lost={lost} bad_tag={} admitted={admitted}",
            c.bad_tag
        );
    }
}

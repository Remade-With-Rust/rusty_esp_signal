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
#[path = "../../common/raw_tx.rs"]
mod raw_tx;

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

/// The descriptor and frame our own arming uses, in DRAM where the MAC's
/// DMA can reach them (E5's P4 bisection).
static mut OUR_DESC: esp_hal::dma::DmaDescriptor = esp_hal::dma::DmaDescriptor::EMPTY;
static mut OUR_BUF: [u8; 256] = [0; 256];

/// The window `JANUS_TX_WINDOW` watches while a frame is in the air, as a
/// bare hex address without the `0x` (`JANUS_TX_WINDOW=600a4000`). 256
/// words, so a 1 KB window a run.
fn window_base() -> u32 {
    let Some(text) = option_env!("JANUS_TX_WINDOW") else {
        return 0x600a_4c00;
    };
    let mut value = 0u32;
    let mut any = false;
    for b in text.trim().as_bytes() {
        let digit = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => continue,
        };
        value = value.wrapping_mul(16).wrapping_add(digit as u32);
        any = true;
    }
    if any { value } else { 0x600a_4c00 }
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
    // the last sequence the blob sends, which is the one a relaunch repeats
    let count_hint = count.saturating_sub(1);
    for sequence in 0..count {
        Timer::at(started + Duration::from_micros(u64::from(sequence) * gap_us)).await;
        frame[3..7].copy_from_slice(&sequence.to_be_bytes());
        // E5's P4: what the blob writes into a transmit slot, sampled right
        // after the first few launches
        // E5's P4: a different length each time, so the register that tracks
        // it can be told from the rest
        let this_length = if mac_snapshot::TX_WATCH {
            [60usize, 100, 150, 200, 250][(sequence as usize) % 5].min(length)
        } else {
            length
        };
        if mac_snapshot::TX_WATCH && sequence < 10 {
            mac_snapshot::tx_watch("before");
        }
        // E5's P4: the slot sampled WHILE the frame goes out. P4 assumed
        // bits 30 and 31 of `plcp0` are "valid" and "enable" from the S3's
        // register map and never saw them set -- a send returns with them
        // already cleared. A frame is about a millisecond of air, so
        // sampling concurrently catches whatever the blob really sets.
        let sampled = if mac_snapshot::TX_WATCH && sequence < 10 {
            let slot = raw_tx::SLOT_BASE + raw_tx::BLOB_SLOT * raw_tx::SLOT_STRIDE;
            let send = sender.send_async(&esp_radio::esp_now::BROADCAST_ADDRESS, &frame[..this_length]);
            // `JANUS_TX_WINDOW=0xADDRESS` widens the aperture from the slot
            // to a window, to find the write that launches a frame
            let sample = async {
                match option_env!("JANUS_TX_WINDOW") {
                    Some(_) => raw_tx::sample_window_while(window_base(), raw_tx::WINDOW_WORDS).await,
                    None => raw_tx::sample_while(slot).await,
                }
            };
            match embassy_futures::select::select(send, sample).await {
                embassy_futures::select::Either::First(r) => (r.is_err(), true),
                embassy_futures::select::Either::Second(()) => (false, true),
            }
        } else {
            (
                sender
                    .send_async(&esp_radio::esp_now::BROADCAST_ADDRESS, &frame[..this_length])
                    .await
                    .is_err(),
                false,
            )
        };
        if sampled.1 {
            if option_env!("JANUS_TX_WINDOW").is_some() {
                raw_tx::report_window(this_length as u32, raw_tx::WINDOW_WORDS);
            } else {
                raw_tx::report_samples(this_length as u32);
            }
        }
        if sampled.0 {
            failed += 1;
        }
        if mac_snapshot::TX_WATCH && sequence < 10 {
            println!("TXWATCH len={this_length}");
            mac_snapshot::tx_watch("after");
            // the frame on the air is the payload plus ESP-NOW's 39 octets
            // of headers, and the radio appends a 4-octet FCS
            let n = this_length as u32;
            mac_snapshot::find_value("len", &[n, n + 39, n + 43, n + 4]);
            // the MPDU on the air is the payload plus ESP-NOW's headers; the
            // probe adds the FCS's four, so it is testing n + 43
            mac_snapshot::plcp_probe("blob", n + 39);
            mac_snapshot::plcp_watch("blob", n);
            mac_snapshot::txq_state("blob");
            // E5's P4: the blob's own descriptor against a frame whose
            // length we chose, so the descriptor's field order is read off
            // the hardware instead of assumed from esp-hal's layout
            raw_tx::watch_blob_descriptor(
                raw_tx::SLOT_BASE + raw_tx::BLOB_SLOT * raw_tx::SLOT_STRIDE,
                this_length as u32 + 39,
            );
            if sequence == 0 && option_env!("JANUS_TX_DUMP").is_some() {
                // the whole MAC block, after ONE frame of the blob's has
                // gone out: the reference state for P4's comparison
                mac_snapshot::dump_range("blob", 0x600a_4000, 2048);
                // twice, as our own side is dumped twice: a dump of 800
                // lines at 115200 can drop a burst of them, and a dropped
                // line is indistinguishable from a register reading zero
                mac_snapshot::dump_range("blobagain", 0x600a_4000, 2048);
                // and the modem subsystem BEYOND the MAC: the clocks, the
                // PHY and the analog I2C master all live out here, and the
                // MAC's own block is now proven not to hold the answer
                mac_snapshot::dump_range("blobwide", 0x600a_6000, 10240);
                mac_snapshot::dump_range("blobwideagain", 0x600a_6000, 10240);
                // the modem region BELOW the MAC, the last uncovered window
                mac_snapshot::dump_range("bloblow", 0x600a_0000, 4096);
                mac_snapshot::dump_range("bloblowagain", 0x600a_0000, 4096);
            }
        }
    }
    // E5's P4, the bisection: OUR OWN slot arming (firmware/common/raw_tx.rs,
    // the very same code c6-open-rx runs) on the MAC that esp-radio has just
    // brought up and transmitted through. If a frame radiates HERE and not
    // under our own bring-up, the arming sequence is right and the whole of
    // the missing step is in bring-up. The blob's own slot is used, after its
    // beacons are finished, so nothing is racing us for it.
    // `JANUS_OURTX=count`.
    // E5's P4, the tightest test: ONE write, bits 30-31 added to whatever
    // `plcp0` already holds, on the blob's own descriptor still carrying its
    // last beacon. A duplicate of that beacon's sequence number in the
    // relay's log is the frame. `JANUS_RELAUNCH=count`.
    if let Some(plan) = option_env!("JANUS_RELAUNCH") {
        let count: u32 = plan.trim().parse().unwrap_or(20);
        let slot = raw_tx::SLOT_BASE + raw_tx::BLOB_SLOT * raw_tx::SLOT_STRIDE;
        println!(
            "RELAUNCH begin count={count} last_beacon_sequence={} (NOT Wi-Fi certified)",
            count_hint
        );
        for i in 0..count {
            let (plcp0, err, cmp) = raw_tx::relaunch(slot);
            if i < 6 {
                println!("RELAUNCH {i} plcp0_after={plcp0:08x} err={err:08x} cmp={cmp:08x}");
            }
            Timer::after(Duration::from_millis(50)).await;
        }
        println!("RELAUNCH done count={count}");
    }

    if let Some(plan) = option_env!("JANUS_OURTX") {
        let count: u32 = plan.trim().parse().unwrap_or(8);
        let slot = raw_tx::SLOT_BASE + raw_tx::BLOB_SLOT * raw_tx::SLOT_STRIDE;
        let mut me = [0u8; 6];
        me.copy_from_slice(esp_hal::efuse::base_mac_address().as_bytes());
        let (mut took, mut complete) = (0u32, 0u32);
        println!("RAWTX begin on=blob-brought-up-mac count={count} (NOT Wi-Fi certified)");
        // the blob's own descriptor, read before we overwrite the slot, and
        // then armed AS IT STANDS: it still holds a frame the blob sent
        let blob_descriptor = raw_tx::describe_blob_descriptor(slot);
        // the poll loop calibrated against embassy's clock, so `polls` below
        // reads as a time: a 107-octet frame is about a millisecond of air
        // at 1 Mbit/s, so a slot handed back in a few microseconds cannot
        // have transmitted anything whatever the status registers say
        let per_us = raw_tx::polls_per_us(
            || embassy_time::Instant::now().as_micros(),
            200_000,
        );
        println!("RAWTX calibration polls_per_us={per_us}");
        for sequence in 0..4u32 {
            let verdict = raw_tx::arm_foreign_descriptor(slot, blob_descriptor, 50_000);
            if sequence < 2 {
                raw_tx::report("blobdesc-armed", slot, 0, &verdict);
            }
            Timer::after(Duration::from_millis(20)).await;
        }
        for sequence in 0..count {
            // tag `R`: ours, on a MAC the blob initialised. The relay
            // reports the tag, so this can never be read as a blob frame
            // (`B`) or as one from our own bring-up (`O`).
            let mut body = [0xa5u8; 64];
            body[..3].copy_from_slice(b"JBR");
            body[3..7].copy_from_slice(&sequence.to_be_bytes());
            // SAFETY: single-threaded here; the hardware owns the descriptor
            // only until the enable bit clears, which `arm` waits for
            let (desc, buf) = unsafe { (&mut *(&raw mut OUR_DESC), &mut *(&raw mut OUR_BUF)) };
            let Some(n) =
                espnow_frame::write(buf, &espnow_frame::BROADCAST, &me, [0, 0, 0, 0], &body)
            else {
                continue;
            };
            if option_env!("JANUS_TX_INPLACE").is_some() {
                // the frame into the descriptor the slot already points at
                let (descriptor, buffer) = raw_tx::arm_in_place(slot, &buf[..n]);
                Timer::after(Duration::from_millis(5)).await;
                if sequence < 4 {
                    raw_tx::report_in_place("inplace", descriptor, buffer, n);
                }
            } else if option_env!("JANUS_TX_DOORBELL").is_some() {
                // plcp0 holds the descriptor, config starts the frame
                raw_tx::arm_by_config(slot, desc, buf, n, sequence % 4);
                if sequence < 4 {
                    raw_tx::report_after("doorbell", slot, n);
                }
            } else {
                let verdict = raw_tx::arm(slot, desc, buf, n, 50_000);
                if verdict.dma_read_the_frame() {
                    took += 1;
                }
                if verdict.complete & 0xffff != 0 {
                    complete += 1;
                }
                if sequence < 4 {
                    raw_tx::report("blobmac", slot, n, &verdict);
                }
            }
            Timer::after(Duration::from_millis(20)).await;
        }
        println!("RAWTX RESULT on=blob-brought-up-mac of={count} dma_took_frame={took} tx_complete={complete}");
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
        // E5's P4: the MAC as the blob leaves it once it HAS transmitted, to
        // diff against ours after our own transmit
        #[cfg(feature = "chip-esp32c6")]
        if mac_snapshot::TX_WATCH {
            let after = mac_snapshot::take(&mac_snapshot::C6_REGISTERS);
            loop {
                mac_snapshot::print("blobtx", &mac_snapshot::C6_REGISTERS, &after);
                Timer::after(Duration::from_secs(15)).await;
            }
        }
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

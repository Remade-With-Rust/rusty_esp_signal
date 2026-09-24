#![no_std]
#![no_main]
//! Janus **J4** firmware, Track B (`no_std` / esp-hal), ESP32-C6: a mesh node
//! that ingests every Wi-Fi/UART signal type into `rusty_esp_signal-core`.
//!
//! What runs: the node brings up Wi-Fi as a station, takes the ESP-NOW halves,
//! and runs the mID-authenticated link ([`EspNowLink`]) as the responder,
//! answering the handshake of ONE peer -- the DID in `JANUS_LINK_PEER` at
//! build time, the bridge's -- and then echoing sealed frames. Without it,
//! every hello is refused and the boot line says so.
//! The device key comes from the hardware TRNG through the core's `Rng` seam.
//!
//! What is compiled in and ready but not driven without a full room and peers:
//! the CSI presence path ([`csi::csi_frame`] + a `PresenceDetector`), the
//! LD2410 UART reader ([`Ld2410Uart`]), and the Wi-Fi station policy
//! ([`station::run_station`]). Each is referenced below so the backend
//! compiles for this chip; the on-radio kill tests wait for hardware (the
//! package ledger's S1–S6).
//!
//! Track B compiles on the stable RISC-V toolchain; no espup needed for the
//! C6. Build: `cargo build --release` in this directory.

extern crate alloc;

use esp_backtrace as _;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::time::Instant;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use rusty_esp_core::Micros;
use rusty_esp_mid_core::did::Did;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_signal_core::radar::csi::{Config as CsiConfig, PresenceDetector};
use rusty_esp_signal_core::wifi::{PolicyConfig, StationPolicy};
use rusty_esp_signal_esp::hal::csi::{csi_frame, recommended_layout};
use rusty_esp_signal_esp::hal::ld2410::Ld2410Uart;
use rusty_esp_signal_esp::hal::link::EspNowLink;
use rusty_esp_signal_esp::hal::rng::EspTrng;
use rusty_esp_signal_esp::hal::station::run_station;

esp_bootloader_esp_idf::esp_app_desc!();

/// A monotonic microsecond clock read from esp-hal's system timer.
fn now() -> Micros {
    Micros(Instant::now().duration_since_epoch().as_micros())
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    esp_alloc::heap_allocator!(size: 96 * 1024);

    // The RTOS the radio driver needs.
    // esp-rtos 0.4 takes the FROM_CPU interrupt peripheral directly; 0.3 went
    // through `SoftwareInterruptControl::new(peripherals.SW_INTERRUPT)`.
    // This is the seam Kairos's port plugs into -- `rusty_rtos_port-xtensa`
    // runs its context switch in exactly this software interrupt so
    // `xtensa-lx-rt`'s exception entry spills the register windows.
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // The hardware true-RNG behind the core's Rng seam. The TrngSource owns
    // RNG + ADC1 and must outlive every Trng handle, so it stays in scope.
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = Trng::try_new().expect("TRNG entropy source enabled");
    let mut rng = EspTrng::new(trng);

    // The device identity: a P-256 did:mata generated once from the TRNG. On a
    // shipping build this is loaded from encrypted NVS (rusty_esp_mid-esp); here
    // it is generated each boot until the NVS backend lands for Track B.
    let me = DeviceKey::generate(&mut rng, "janus-c6").expect("device key");
    let did = me.did();
    let mut did_buf = [0u8; 64];
    if let Ok(s) = did.write(&mut did_buf) {
        println!("DID {s}");
    }

    // Wi-Fi up as a station, then the ESP-NOW halves.
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

    // The authenticated ESP-NOW link. Start addressed to broadcast for
    // discovery; a real deployment learns the peer MAC from the first frame.
    let mut link = EspNowLink::new(
        sender,
        receiver,
        rusty_esp_signal_esp::hal::link::broadcast(),
    );

    // The one peer this node answers: the bridge's DID, given at build time
    // (`JANUS_LINK_PEER=did:mata:…`; the bridge prints its own at start).
    // Track B has no NVS backend yet, so there is no provisioning record to
    // read it from, and the build carries it until there is. With none, every
    // hello is refused: a node that would answer anyone is not one an owner
    // adopted, and the roster's whole point is that it is the owner's.
    let peer: Option<Did> = option_env!("JANUS_LINK_PEER").and_then(|s| Did::parse(s).ok());
    match peer {
        Some(_) => {
            println!("c6-mesh-node up; answering the peer named by JANUS_LINK_PEER over ESP-NOW")
        }
        None => println!(
            "c6-mesh-node up; JANUS_LINK_PEER unset or not a did:mata: every handshake will be refused"
        ),
    }

    match link
        .handshake_responder(&me, &mut rng, |did| peer.as_ref() == Some(did), now())
        .await
    {
        Ok(mut session) => {
            println!(
                "session {} established with an authenticated peer",
                session.id()
            );
            let mut buf = [0u8; 256];
            loop {
                match link.recv(&mut session, &mut buf).await {
                    Ok(plain) => {
                        let n = plain.len();
                        // Echo the authenticated payload straight back.
                        if link.send(&mut session, &buf[..n]).await.is_err() {
                            println!("send failed");
                        }
                    }
                    Err(_) => {
                        // A refused frame is counted in the session; keep going.
                    }
                }
            }
        }
        Err(_) => {
            println!("handshake refused; the other radios are compiled in below");
            radios_compiled_in().await;
            loop {
                embassy_time::Timer::after(embassy_time::Duration::from_secs(60)).await;
            }
        }
    }
}

/// Reference the CSI, LD2410 and station backends so they compile for this
/// chip. `radios_compiled_in` names each concrete helper; a named async fn
/// monomorphises when referenced, which a throwaway closure would not do
/// cleanly across the controller borrow. The on-radio kill tests (ledger
/// S1-S6) drive these for real.
async fn radios_compiled_in() {
    let _ = install_csi;
    let _ = drive_station;
    let _ = read_ld2410;
    // Also instantiate the pure detector so its monomorphisation is checked.
    let _detector = PresenceDetector::<50>::new(CsiConfig::default());
    let _layout = recommended_layout();
}

/// One CSI measurement into the fixed-point presence detector's input.
fn install_csi(info: &esp_radio::wifi::csi::WifiCsiInfo<'_>) {
    let frame = csi_frame(info, Micros(0));
    let _ = frame.features(&recommended_layout());
}

/// The Wi-Fi station policy over a real controller, until it asks to provision.
async fn drive_station(
    controller: &mut esp_radio::wifi::WifiController<'_>,
) -> rusty_esp_signal_core::wifi::Phase {
    let mut policy = StationPolicy::new(PolicyConfig::DEFAULT);
    run_station(controller, &mut policy, now).await
}

/// The LD2410 reader over an async UART receiver.
async fn read_ld2410(rx: esp_hal::uart::UartRx<'static, esp_hal::Async>) {
    let mut ld = Ld2410Uart::new(rx);
    let _ = ld.next_report().await;
    let _ = ld.stats();
}

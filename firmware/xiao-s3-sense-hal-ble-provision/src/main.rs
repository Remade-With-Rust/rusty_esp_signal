//! Janus S3 on Track B: the XIAO ESP32-S3 Sense provisioned over BLE, with
//! no ESP-IDF and no Bluedroid under it.
//!
//! This is `xiao-s3-sense-idf-ble-provision` rebuilt on esp-hal, and
//! `c6-ble-provision`'s stack with the join the C6 firmware could not do:
//! the core's GATT table served by `trouble-host` over esp-radio's BLE
//! controller, the setup session carried to the core's [`Provisioner`], the
//! join by esp-radio's station, the phase back to the phone as a `status`
//! notification. Where the ESP-IDF twin ran Bluedroid's host, FreeRTOS and
//! lwIP in C, this runs `trouble-host`, esp-rtos and `smoltcp` in Rust, and
//! the C left is Espressif's radio blob.
//!
//! The provisioning service carries the encrypted setup session (SPAKE2+,
//! the Janus umbrella's `docs/setup-protocol.md`, 11.1): the phone reads
//! `discover`, subscribes to `setup` and writes the session's messages to
//! it; each answer is stored in `setup` and its header notified. The
//! network arrives sealed in the session's Settings and is written to the
//! owner's settings before the join. `credentials` (a plaintext TLV) and
//! the public `scan` are retired.
//!
//! A device takes a session only once a setup code's verifier (`setup.v`)
//! is in its settings, which the portal (espino) writes at flash time;
//! without one, Discover offers no code and every Start is `NoVerifier`.
//!
//! The settings are the `janus` namespace of the `nvs` partition; the
//! device key lives in the `identity` partition (in `nvs` when the table
//! has none), minted there on the first boot and loaded on every other.
//!
//! Two boots, the way the Track A sketch lives:
//!
//! 1. **Provisioning.** The setup window is open: no stored network, or a
//!    power-on (which opens it for ten minutes on a provisioned device too).
//!    Advertise as `janus-s3` with the provisioning service, carry the
//!    session, join with the phone still connected (the S3's one modem
//!    shared by both radios, `coex`), notify `Connected` and restart. A
//!    window that closes with nobody connected also restarts, when a
//!    network is stored.
//! 2. **Station.** A stored network and a closed window (the software reset
//!    out of provisioning, or any reset but a power-on): Bluetooth is never
//!    initialised, the station joins through `hal::netstack` with DHCP and
//!    prints its address and the join time, then a line every ten seconds.
//!
//! Lines are prefixed `BLE` so a monitor can parse them. The passphrase is
//! never printed: the session's `Debug` redacts it.

#![no_std]
#![no_main]

extern crate alloc;


use core::cell::RefCell;

use embassy_futures::join::join;
use embassy_net::StackResources;
use embassy_time::{Duration, Timer, with_timeout};
use esp_backtrace as _;
use esp_hal::rng::{Rng, Trng, TrngSource};
use esp_hal::rtc_cntl::SocResetReason;
use esp_hal::system::{reset_reason, software_reset};
use esp_hal::time::Instant;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::ble::controller::BleConnector;
use esp_radio::wifi::{ControllerConfig, Interface, WifiController};
use esp_storage::FlashStorage;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_mid_esp::hal::EspHalRng;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::provision::{Env, Provisioner};
use rusty_esp_signal_core::setup::Reset;
use rusty_esp_signal_core::wifi::{Action, Credentials, Event, PolicyConfig, StationPolicy};
use rusty_esp_signal_esp::ble::{JanusServer, Served, accept, assert_uuids, setup_address};
use rusty_esp_signal_esp::hal::netstack::{self, SOCKETS};
use static_cell::StaticCell;
use rusty_esp_mid_esp::hal::{SharedFlash, Store, open_shared};
use trouble_host::prelude::*;

/// The namespace the settings and the identity live in, on every track.
const NAMESPACE: &str = "janus";
/// The owner's partition: what the portal writes at flash time (the network,
/// the name, the setup code's verifier), and what the session writes.
const SETTINGS_PARTITION: &str = "nvs";
/// The identity's own partition, which a re-provision never rewrites; a
/// table without one keeps the identity in `nvs`, and a re-provision then
/// re-mints the DID.
const IDENTITY_PARTITION: &str = "identity";

esp_bootloader_esp_idf::esp_app_desc!();

/// The advertised name: the IDF twin's, so the page finds either.
const NAME: &str = "janus-s3";
/// This board, in the key store's terms; the DID depends on the key alone.
const DEVICE_ID: &str = "janus";
/// How long one join may take before the phone is told it failed.
const JOIN_TIMEOUT: Duration = Duration::from_secs(20);
/// How long the `Connected` notification gets to leave before the link is
/// dropped for the restart.
const NOTIFY_GRACE: Duration = Duration::from_millis(700);
/// How long the disconnect gets to leave before the reset. Without it the
/// phone learns of the restart from its supervision timeout, ten seconds on.
const DISCONNECT_GRACE: Duration = Duration::from_millis(300);

/// The HCI transport: esp-radio's BLE controller behind bt-hci's external
/// controller, with room for 20 in-flight commands.
type Controller = ExternalController<BleConnector<'static>, 20>;
/// One connection, no L2CAP channels, one advertising set.
type Resources = HostResources<Controller, DefaultPacketPool, 1, 0, 1>;
static RESOURCES: StaticCell<Resources> = StaticCell::new();
/// The IP stack's sockets and buffers, for the station boot.
static NET: StaticCell<StackResources<SOCKETS>> = StaticCell::new();

/// A monotonic microsecond clock read from esp-hal's system timer.
fn now() -> Micros {
    Micros(Instant::now().duration_since_epoch().as_micros())
}

/// The radio's station configuration for `creds`, or why the radio would
/// refuse it.
fn station_config(creds: &Credentials) -> Result<esp_radio::wifi::Config, &'static str> {
    let ssid = core::str::from_utf8(creds.ssid()).map_err(|_| "ssid is not UTF-8")?;
    let psk = core::str::from_utf8(creds.psk()).map_err(|_| "passphrase is not UTF-8")?;
    netstack::station_config(ssid, psk).map_err(|_| "credentials the radio refuses")
}

/// One join, timed: the milliseconds to the association, or why not.
async fn join_once(
    wifi: &mut WifiController<'static>,
    creds: &Credentials,
) -> Result<u64, &'static str> {
    wifi.set_config(&station_config(creds)?)
        .map_err(|_| "station config refused")?;
    let started = Instant::now();
    match with_timeout(JOIN_TIMEOUT, wifi.connect_async()).await {
        Ok(Ok(_)) => Ok(started.elapsed().as_millis()),
        Ok(Err(_)) => Err("the join failed"),
        Err(_) => Err("no association within the timeout"),
    }
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 160 * 1024);

    // The RTOS the radio driver needs: a timer for its scheduler and the
    // software interrupt its context switch runs in.
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    // The radio's and the host's own log lines, at the level ESP_LOG names.
    #[cfg(feature = "diag")]
    esp_println::logger::init_logger_from_env();

    let boot = Instant::now();
    // Only a power-on opens the setup window on a provisioned device; the
    // software reset out of provisioning does not (protocol section 9).
    let reset = match reset_reason() {
        Some(SocResetReason::ChipPowerOn) => Reset::PowerOn,
        _ => Reset::Other,
    };

    // The settings and the identity, from flash.
    let storage: SharedFlash = RefCell::new(FlashStorage::new(peripherals.FLASH));
    let settings = RefCell::new(
        open_shared(&storage, SETTINGS_PARTITION, NAMESPACE)
            .expect("nvs partition readable")
            .expect("an nvs partition in the table"),
    );
    let own_identity = match open_shared(&storage, IDENTITY_PARTITION, NAMESPACE) {
        Ok(Some(kv)) => Some(RefCell::new(kv)),
        other => {
            println!(
                "BLE no usable identity partition ({:?}): the device key shares the owner's nvs and a re-provision re-mints the DID",
                other.err()
            );
            None
        }
    };
    let mut identity = Store(own_identity.as_ref().unwrap_or(&settings));

    // The device key, from the chip's true generator: minted once, loaded on
    // every boot after.
    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let mut rng = EspHalRng(Trng::try_new().expect("TRNG entropy source enabled"));
    let key = DeviceKey::load_or_generate(&mut identity, &mut rng, DEVICE_ID).expect("device key");
    let devpub = *key.did().pubkey();
    let did = key.did();

    // The core's session: the setup session, the network, the station
    // policy and the scan list, in one object.
    let env = Env {
        settings: Store(&settings),
        identity,
        rng,
        signer: key,
    };
    let mut provisioner: Provisioner<_> =
        Provisioner::new(StationPolicy::default(), devpub, reset, now(), env)
            .expect("setup session");
    let booted = provisioner.boot(now());

    if booted.action == Action::Connect && !provisioner.advertising(now()) {
        // ---- the station boot: no Bluetooth, the network from the settings.
        println!("== JANUS BLE xiao-s3 track=B mode=station reset={reset:?} ==");
        println!("BLE device {did}");
        let creds = provisioner
            .credentials()
            .cloned()
            .expect("a stored network");
        // The session is not served this boot.
        drop(provisioner);
        let mut controller =
            WifiController::new(peripherals.WIFI, ControllerConfig::default()).expect("wifi");
        controller
            .set_config(&station_config(&creds).expect("stored credentials"))
            .expect("station config");
        // Never the passphrase: `Credentials` redacts it.
        println!("BLE station ssid_len={} joining", creds.ssid().len());
        drop(creds);
        let rng = Rng::new();
        let seed = (u64::from(rng.random()) << 32) | u64::from(rng.random());
        let (stack, runner) =
            netstack::stack(Interface::station(), NET.init(StackResources::new()), seed);
        spawner.spawn(netstack::net_task(runner).expect("net task"));
        spawner.spawn(
            netstack::station_task(controller, PolicyConfig::DEFAULT, now).expect("station task"),
        );
        stack.wait_link_up().await;
        let join_ms = boot.elapsed().as_millis();
        stack.wait_config_up().await;
        let dhcp_ms = boot.elapsed().as_millis();
        let ip = stack.config_v4().expect("ipv4 lease").address.address();
        println!("BLE mode=station ip={ip} join_ms={join_ms} dhcp_ms={dhcp_ms}");
        loop {
            Timer::after(Duration::from_secs(10)).await;
            let up = boot.elapsed().as_secs();
            let link = if stack.is_link_up() { "up" } else { "down" };
            println!("BLE station up_s={up} link={link} ip={ip}");
        }
    }

    // ---- the provisioning boot: BLE up, the station idle until a session
    // applies a network.
    println!("== JANUS BLE xiao-s3 track=B mode=provision reset={reset:?} ==");
    println!("BLE device {did}");
    assert_uuids().expect("GATT UUIDs match the core table");

    let connector =
        BleConnector::new(peripherals.BT, esp_radio::ble::Config::default()).expect("ble");
    let controller: Controller = ExternalController::new(connector);
    // a new random static address each boot, not the public one (see
    // setup_address: a central's per-address state outlives a lost session)
    let mut own = [0u8; 6];
    Trng::try_new().expect("TRNG entropy source enabled").read(&mut own);
    let stack = trouble_host::new(controller, RESOURCES.init(Resources::new()))
        .set_random_address(setup_address(own))
        .build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();
    let server = JanusServer::new_default(NAME).expect("gatt server");

    // The station, built once and kept: a failed join must not spend the
    // modem, so every attempt reconfigures this one controller.
    let mut wifi =
        WifiController::new(peripherals.WIFI, ControllerConfig::default()).expect("wifi");

    println!(
        "BLE advertising name={NAME} boot_ms={}",
        boot.elapsed().as_millis()
    );

    let _ = join(runner.run(), async {
        let mut closed = false;
        loop {
            let session = match accept(&mut peripheral, &server, NAME, &provisioner, now()).await {
                Ok(Some(session)) => session,
                Ok(None) => {
                    if provisioner.credentials().is_some() {
                        // The window a power-on opened is over and a network
                        // is stored: the station boot takes it from here.
                        println!("BLE window closed; restarting into station mode");
                        Timer::after(Duration::from_millis(50)).await;
                        software_reset();
                    }
                    // Unprovisioned and closed: the lockout, until a power-on.
                    if !closed {
                        println!("BLE window closed; not advertising");
                        closed = true;
                    }
                    provisioner.tick(now());
                    Timer::after(Duration::from_secs(1)).await;
                    continue;
                }
                Err(e) => {
                    println!("BLE error {e:?}; re-advertising");
                    Timer::after(Duration::from_secs(1)).await;
                    continue;
                }
            };
            closed = false;
            println!("BLE peer connected at_ms={}", boot.elapsed().as_millis());
            loop {
                let action = match session.serve(&server, &mut provisioner, now).await {
                    Ok(Served::Provisioned(action)) => action,
                    // the backend has closed the carrier session
                    Ok(Served::Disconnected) => {
                        println!("BLE peer disconnected");
                        break;
                    }
                    Err(_) => {
                        println!("BLE error on the connection");
                        provisioner.carrier_closed();
                        break;
                    }
                };
                println!("BLE provisioned: {:?} -> {:?}", provisioner, action);
                if action != Action::Connect {
                    continue;
                }
                let Some(creds) = provisioner.credentials().cloned() else {
                    continue;
                };
                // The join with the phone still on the line, its reads and
                // writes answered meanwhile; `None` means it left.
                let Some(joined) = session.attend(join_once(&mut wifi, &creds)).await else {
                    println!("BLE peer left during the join");
                    provisioner.carrier_closed();
                    break;
                };
                match joined {
                    Ok(join_ms) => {
                        println!("BLE joined join_ms={join_ms}");
                        let _ = session
                            .report(&server, &mut provisioner, Event::Connected, now())
                            .await;
                        Timer::after(NOTIFY_GRACE).await;
                        // Hang up first, so the phone sees the link end now
                        // rather than at its supervision timeout.
                        drop(session);
                        provisioner.carrier_closed();
                        Timer::after(DISCONNECT_GRACE).await;
                        // The network is in the settings already: the session
                        // wrote it before it answered.
                        println!("BLE restarting into station mode");
                        Timer::after(Duration::from_millis(50)).await;
                        software_reset();
                    }
                    Err(why) => {
                        println!("BLE join failed: {why}");
                        // The policy backs off. A new session with a
                        // corrected network is the retry while the window is
                        // open, and the peer stays connected for it.
                        let _ = session
                            .report(&server, &mut provisioner, Event::Disconnected, now())
                            .await;
                    }
                }
            }
        }
    })
    .await;
}

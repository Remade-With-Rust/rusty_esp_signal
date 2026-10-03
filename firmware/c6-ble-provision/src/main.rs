#![no_std]
#![no_main]
//! Janus **J4** firmware, Track B, ESP32-C6: BLE provisioning over the setup
//! session.
//!
//! Serves the core's GATT table (provisioning, manifest, telemetry) over
//! `trouble-host` on esp-radio's BLE controller. The provisioning service
//! carries the encrypted setup session (SPAKE2+, the Janus umbrella's
//! `docs/setup-protocol.md`, 11.1): a phone reads `discover`, subscribes to
//! `setup`, and writes the session's messages to it; the backend hands each
//! one to the core's `Provisioner`, stores the answer and notifies its
//! header. The settings a session applies (the network among them) are
//! sealed on the air and land in the owner's settings, where the next boot
//! finds them. `credentials` (a plaintext TLV) and the public `scan` are
//! retired.
//!
//! A device takes a session only once a setup code's verifier (`setup.v`)
//! is in its settings, which the portal (espino) writes at flash time;
//! without one, Discover offers no code and every Start is `NoVerifier`.
//!
//! The settings are the `janus` namespace of the `nvs` partition; the
//! device key lives in the `identity` partition (in `nvs` when the table
//! has none), minted there on the first boot and loaded on every other.
//! The service is advertised only while the setup window is open: until a
//! network is stored, and for ten minutes after a power-on once one is.
//!
//! This chip has no Wi-Fi stack here, so the policy's `Connect` is printed
//! rather than executed and the scan list stays empty. The kill test
//! (package ledger S3) is a phone provisioning from a Web Bluetooth page
//! with no app-store app; that needs hardware. This builds.

extern crate alloc;


use core::cell::RefCell;

use embassy_futures::join::join;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::rtc_cntl::SocResetReason;
use esp_hal::system::reset_reason;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_storage::FlashStorage;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_mid_esp::hal::EspHalRng;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::provision::{Env, Provisioner};
use rusty_esp_signal_core::setup::Reset;
use rusty_esp_signal_core::wifi::StationPolicy;
use rusty_esp_signal_esp::ble::{JanusServer, Served, assert_uuids, serve};
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

/// The advertised name.
const NAME: &str = "janus";
/// This board, in the key store's terms; the DID depends on the key alone.
const DEVICE_ID: &str = "janus";

/// The HCI transport: esp-radio's BLE controller behind bt-hci's external
/// controller, with room for 20 in-flight commands.
type Controller = ExternalController<esp_radio::ble::controller::BleConnector<'static>, 20>;
/// One connection, no L2CAP channels, one advertising set.
type Resources = HostResources<Controller, DefaultPacketPool, 1, 0, 1>;
static RESOURCES: StaticCell<Resources> = StaticCell::new();

/// A monotonic microsecond clock: the one the setup window and the
/// policy's backoff run on.
fn now() -> Micros {
    Micros(embassy_time::Instant::now().as_micros())
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    esp_alloc::heap_allocator!(size: 96 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    // esp-rtos 0.4 takes the FROM_CPU interrupt peripheral directly.
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // The literal UUIDs in the backend still match the core's table.
    assert_uuids().expect("GATT UUIDs match the core table");

    // Only a power-on opens the setup window on a provisioned device; a
    // software or watchdog reset does not (protocol section 9).
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
                "no usable identity partition ({:?}): the device key shares the owner's nvs and a re-provision re-mints the DID",
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
    println!("device {}", key.did());

    let connector = esp_radio::ble::controller::BleConnector::new(
        peripherals.BT,
        esp_radio::ble::Config::default(),
    )
    .expect("ble controller");
    let controller: Controller = ExternalController::new(connector);

    let resources = RESOURCES.init(Resources::new());
    let stack = trouble_host::new(controller, resources).build();
    let mut runner = stack.runner();
    let mut peripheral = stack.peripheral();

    let server = JanusServer::new_default(NAME).expect("gatt server");

    // The core's session: the setup session, the network, the station
    // policy and the scan list, in one object. This firmware has no Wi-Fi
    // stack, so the policy's `Connect` is printed rather than executed and
    // the scan list stays empty.
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
    println!("boot reset={:?} -> {:?}", reset, booted.action);

    let _ = join(runner.run(), async {
        let mut closed = false;
        loop {
            match serve(&mut peripheral, &server, NAME, &mut provisioner, now).await {
                Ok(Some(served)) => {
                    closed = false;
                    match served {
                        Served::Provisioned(action) => {
                            // Never the passphrase: the session's Debug
                            // redacts it.
                            println!("provisioned: {:?} -> {:?}", provisioner, action);
                        }
                        Served::Disconnected => println!("peer disconnected"),
                    }
                    // `serve` drops the connection either way: the carrier
                    // session is over (a no-op after a disconnect).
                    provisioner.carrier_closed();
                }
                Ok(None) => {
                    if !closed {
                        println!("setup window closed; not advertising");
                        closed = true;
                    }
                    provisioner.tick(now());
                    Timer::after(Duration::from_secs(1)).await;
                }
                Err(_) => {
                    // the connection, if there was one, is gone with the error
                    provisioner.carrier_closed();
                    println!("ble error; re-advertising");
                }
            }
        }
    })
    .await;
}

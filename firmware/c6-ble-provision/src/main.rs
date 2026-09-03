#![no_std]
#![no_main]
//! Janus **J4** firmware, Track B, ESP32-C6: BLE Wi-Fi provisioning.
//!
//! Serves the core's GATT table (provisioning, manifest, telemetry) over
//! `trouble-host` on esp-radio's BLE controller. A phone writes the Wi-Fi
//! credential TLV to the provisioning characteristic; the backend decodes it
//! with the core's `Credentials` (which redacts in `Debug` and zeroises on
//! drop) and hands it back here.
//!
//! The kill test (package ledger S3) is a phone provisioning from a Web
//! Bluetooth page with no app-store app; that needs hardware. This builds.

extern crate alloc;

use embassy_futures::join::join;
use esp_backtrace as _;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::provision::Provisioner;
use rusty_esp_signal_core::wifi::StationPolicy;
use rusty_esp_signal_esp::ble::{JanusServer, Served, assert_uuids, serve};
use static_cell::StaticCell;
use trouble_host::prelude::*;

esp_bootloader_esp_idf::esp_app_desc!();

/// One connection, no L2CAP channels, one advertising set.
type Resources = HostResources<DefaultPacketPool, 1, 0, 1>;
static RESOURCES: StaticCell<Resources> = StaticCell::new();

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    esp_alloc::heap_allocator!(size: 96 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw = esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw.software_interrupt0);

    // The literal UUIDs in the backend still match the core's table.
    assert_uuids().expect("GATT UUIDs match the core table");

    let connector = esp_radio::ble::controller::BleConnector::new(
        peripherals.BT,
        esp_radio::ble::Config::default(),
    )
    .expect("ble controller");
    let controller: ExternalController<_, 20> = ExternalController::new(connector);

    let resources = RESOURCES.init(Resources::new());
    let stack = trouble_host::new(controller, resources);
    let Host {
        mut peripheral,
        mut runner,
        ..
    } = stack.build();

    let server = JanusServer::new_default("janus").expect("gatt server");

    println!("c6-ble-provision advertising as 'janus'");
    // The core's session: the credentials, the station policy and the scan
    // list, in one object. This firmware has no Wi-Fi stack, so the policy's
    // `Connect` is printed rather than executed and the scan list stays empty.
    let mut provisioner: Provisioner = Provisioner::new(StationPolicy::default());
    let now = || Micros(embassy_time::Instant::now().as_micros());

    let _ = join(runner.run(), async {
        loop {
            match serve(&mut peripheral, &server, "janus", &mut provisioner, now).await {
                Ok(Served::Provisioned(action)) => {
                    // Never the passphrase: the session's Debug redacts it.
                    println!("provisioned: {:?} -> {:?}", provisioner, action);
                }
                Ok(Served::Disconnected) => println!("peer disconnected"),
                Err(_) => println!("ble error; re-advertising"),
            }
        }
    })
    .await;
}

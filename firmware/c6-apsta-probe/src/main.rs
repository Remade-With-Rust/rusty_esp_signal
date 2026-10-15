#![no_std]
#![no_main]
//! **Both roles on one radio, on the vendor's stack**: an ESP32-C6 that joins
//! the network named at build time (`JANUS_WIFI_SSID`, `JANUS_WIFI_PASS`) and
//! at the same time hosts one of its own (`JANUS_AP_SSID`, `JANUS_AP_PASS`),
//! both WPA2, with a DHCP server on the hosted side. Neither passphrase is
//! ever printed.
//!
//! **Why.** The open MAC can transmit encrypted data frames on the radio's
//! FIRST virtual interface only, whatever the role: an access point hosted
//! beside a station cannot protect its frames, and a station hosted beside an
//! access point cannot either -- the chip reports them sent and the peer
//! receives nothing it can use. That blocks any firmware meant to be both
//! at once. `esp_radio::wifi::Config::AccessPointStation` is the vendor's own
//! answer to the same question, and this firmware asks whether it works:
//! nothing here forwards, so what it tests is only the radio.
//!
//! **What it proves, if a client leases.** Encrypted data flows both ways on
//! two interfaces of one radio, so a relay between two networks can be one
//! chip.
//!
//! Lines, said again and again so a reader that joins late still hears them:
//! `APSTA boot`, `APSTA station ...` (its own lease from the upstream
//! network), `APSTA hosting ...` and `APSTA watch up_s=... stations=...`.
//! Not Wi-Fi certified.

extern crate alloc;

use core::net::Ipv4Addr;

use embassy_net::{Ipv4Cidr, StackResources};
use embassy_time::{Duration, Instant, Timer};
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::wifi::{ControllerConfig, Interface, WifiController};
use rusty_esp_core::Micros;
use rusty_esp_signal_core::wifi::PolicyConfig;
use rusty_esp_signal_esp::hal::netstack;
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

/// The network this joins (the bench router).
const SSID: &str = env!("JANUS_WIFI_SSID");
const PASS: &str = env!("JANUS_WIFI_PASS");
/// The network this hosts.
const AP_SSID: &str = env!("JANUS_AP_SSID");
const AP_PASS: &str = env!("JANUS_AP_PASS");
/// The hosted network. A different /24 from the bench router's, so nothing a
/// client sends to its own network is confused with the upstream one.
const AP_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 63, 200, 1);
const MAX_STATIONS: u16 = 8;

static STA_NET: StaticCell<StackResources<4>> = StaticCell::new();
static AP_NET: StaticCell<StackResources<4>> = StaticCell::new();

fn now() -> Micros {
    Micros(Instant::now().as_micros())
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    esp_alloc::heap_allocator!(size: 96 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    let boot = Instant::now();
    println!(
        "APSTA boot: station and access point on one radio, esp-radio, both WPA2 \
         (not Wi-Fi certified)"
    );

    let mut controller =
        WifiController::new(peripherals.WIFI, ControllerConfig::default()).expect("wifi");
    // both roles in one configuration: the radio starts both
    controller
        .set_config(
            &netstack::access_point_station_config(SSID, PASS, AP_SSID, AP_PASS, MAX_STATIONS)
                .expect("credentials"),
        )
        .expect("the radio takes both roles");
    // the C6 is quiet at esp-radio's default 5 dBm on this bench
    match controller.set_max_tx_power(64) {
        Ok(()) => println!("APSTA tx_qdbm=64"),
        Err(e) => println!("APSTA tx_qdbm refused {e:?}"),
    }

    let rng = Rng::new();
    let seed = (u64::from(rng.random()) << 32) | u64::from(rng.random());

    // the station's stack takes a lease from the upstream network
    let (sta_stack, sta_runner) = netstack::stack(
        Interface::station(),
        STA_NET.init(StackResources::new()),
        seed,
    );
    // the hosted network's stack sits at a fixed address, its gateway
    let ap_cidr = Ipv4Cidr::new(AP_ADDRESS, 24);
    let (ap_stack, ap_runner) = netstack::hosted_stack(
        Interface::access_point(),
        ap_cidr,
        AP_NET.init(StackResources::new()),
        seed ^ 0xa95a,
    );

    spawner.spawn(netstack::net_task(sta_runner).expect("station net task"));
    spawner.spawn(netstack::net_task(ap_runner).expect("access point net task"));
    spawner.spawn(netstack::dhcp_server_task(ap_stack, ap_cidr).expect("dhcp server"));
    spawner.spawn(
        netstack::station_task(controller, PolicyConfig::DEFAULT, now).expect("station task"),
    );

    println!("APSTA hosting {AP_SSID} (wpa2) at {AP_ADDRESS}/24, dhcp from .50");

    let mut said_lease = false;
    loop {
        let up = boot.elapsed().as_secs();
        if !said_lease {
            if let Some(config) = sta_stack.config_v4() {
                println!(
                    "APSTA station up_s={up} ip={} gateway={:?} lease_ms={}",
                    config.address,
                    config.gateway,
                    boot.elapsed().as_millis()
                );
                said_lease = true;
            }
        }
        println!(
            "APSTA watch up_s={up} station_link={} station_lease={} ap_link={}",
            sta_stack.is_link_up(),
            sta_stack.config_v4().is_some(),
            ap_stack.is_link_up()
        );
        Timer::after(Duration::from_secs(5)).await;
    }
}

#![no_std]
#![no_main]
//! E3's four stations: an ESP32-C6 **station on esp-radio** that joins the
//! network named at build time (`JANUS_WIFI_SSID`, `JANUS_WIFI_PASS` -- the
//! passphrase is never printed), takes a lease, and fetches `GET /` from the
//! access point (the lease's gateway) every second. Three of them beside the
//! laptop are the four stations the open-MAC access point has to carry.
//!
//! Lines: `STA boot`, `STA joined ip=... gateway=... join_ms=...`, then
//! `STA stats up_s=... ok=... failed=... last_ms=... max_ms=...` every 5 s --
//! said again and again, so a reader that joins late (the C6 DevKitC's
//! bridge loses what is printed between sessions) still hears it.
//!
//! Build-time switches for the access point's power-save checks (E3):
//! `JANUS_POWER_SAVE` set puts the station in esp-radio's minimum power
//! save (it dozes between DTIM beacons, so the access point must buffer for
//! it); `JANUS_STA_QUIET` set joins and then sends nothing at all, for the
//! access point's inactivity drop (`STA quiet up_s=... link=...` lines).

extern crate alloc;

use embassy_net::tcp::TcpSocket;
use embassy_net::{IpEndpoint, StackResources};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use embedded_io_async::Write as _;
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_radio::wifi::{ControllerConfig, Interface, PowerSaveMode, WifiController};
use rusty_esp_core::Micros;
use rusty_esp_signal_core::wifi::PolicyConfig;
use rusty_esp_signal_esp::hal::netstack;
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &str = env!("JANUS_WIFI_SSID");
const PASS: &str = env!("JANUS_WIFI_PASS");
static NET: StaticCell<StackResources<4>> = StaticCell::new();

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
    println!("STA boot (E3's four stations; esp-radio station, the network from the build)");

    let mut controller =
        WifiController::new(peripherals.WIFI, ControllerConfig::default()).expect("wifi");
    controller
        .set_config(&netstack::station_config(SSID, PASS).expect("credentials"))
        .expect("station config");
    let rng = Rng::new();
    let seed = (u64::from(rng.random()) << 32) | u64::from(rng.random());
    if option_env!("JANUS_POWER_SAVE").is_some() {
        controller
            .set_power_saving(PowerSaveMode::Minimum)
            .expect("power save");
        println!("STA power save: minimum (dozes between DTIM beacons)");
    }
    let (stack, runner) =
        netstack::stack(Interface::station(), NET.init(StackResources::new()), seed);
    spawner.spawn(netstack::net_task(runner).expect("net task"));
    spawner.spawn(
        netstack::station_task(controller, PolicyConfig::DEFAULT, now).expect("station task"),
    );

    stack.wait_config_up().await;
    let config = stack.config_v4().expect("ipv4");
    let gateway = config.gateway.expect("a gateway in the lease");
    let ip = config.address.address();
    let join_ms = boot.elapsed().as_millis();
    println!("STA joined ip={ip} gateway={gateway} join_ms={join_ms}");
    if option_env!("JANUS_STA_QUIET").is_some() {
        // nothing sent from here on: whether the access point keeps us
        loop {
            Timer::after(Duration::from_secs(5)).await;
            println!(
                "STA quiet up_s={} ip={ip} link={}",
                boot.elapsed().as_secs(),
                stack.is_link_up()
            );
        }
    }

    let (mut ok, mut failed, mut last_ms, mut max_ms) = (0u32, 0u32, 0u64, 0u64);
    let mut rx = [0u8; 1024];
    let mut tx = [0u8; 512];
    let mut buf = [0u8; 512];
    let mut said = Instant::now();
    loop {
        let started = Instant::now();
        let fetched = with_timeout(Duration::from_secs(5), async {
            let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
            socket.set_timeout(Some(Duration::from_secs(4)));
            socket
                .connect(IpEndpoint::new(gateway.into(), 80))
                .await
                .map_err(|_| ())?;
            socket
                .write_all(b"GET / HTTP/1.1\r\nHost: ap\r\nConnection: close\r\n\r\n")
                .await
                .map_err(|_| ())?;
            let mut total = 0usize;
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => total += n,
                }
            }
            socket.close();
            if total > 0 { Ok(()) } else { Err(()) }
        })
        .await;
        match fetched {
            Ok(Ok(())) => {
                ok += 1;
                last_ms = started.elapsed().as_millis();
                max_ms = max_ms.max(last_ms);
            }
            _ => failed += 1,
        }
        if said.elapsed().as_secs() >= 5 {
            said = Instant::now();
            println!(
                "STA stats up_s={} ip={ip} ok={ok} failed={failed} last_ms={last_ms} max_ms={max_ms} link={}",
                boot.elapsed().as_secs(),
                stack.is_link_up()
            );
        }
        Timer::after(Duration::from_secs(1)).await;
    }
}

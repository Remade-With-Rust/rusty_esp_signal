//! E1's probe (experiments plan): an ESP32-S3 Wi-Fi station on the open
//! lower MAC. The MAC is `esp-wifi-hal` and the 802.11 station FoA's
//! (`rusty_esp_signal/vendor/open-mac`, pinned and ported to the family's
//! esp-hal 1.2); the PHY is still Espressif's `libphy`, and nothing here
//! sets transmit power, channels or regulatory tables. **Not Wi-Fi
//! certified.** Its first boot is on a sacrificial S3, never the bench XIAO
//! first (the bench rule; the authors' warning).
//!
//! Build with the network in the environment (never in a file):
//! `JANUS_WIFI_SSID=... JANUS_WIFI_PASS=... cargo build --release`. It joins
//! once, takes a DHCP lease, pings the gateway 100 times, then stays up
//! answering pings (embassy-net's automatic echo reply). Without the two
//! variables it brings the MAC up and parks: a build and boot check alone.
//! FoA's own logging stays off: its debug logs can carry key material.
#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_net::icmp::{
    ChecksumCapabilities, IcmpEndpoint, IcmpSocket, Icmpv4Packet, Icmpv4Repr, PacketMetadata,
};
use embassy_net::{Runner as NetRunner, StackResources};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use foa::{FoAResources, FoARunner, VirtualInterface};
use foa_sta::{ConnectionConfig, Credentials, StaNetDevice, StaResources, StaRunner};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: Option<&str> = option_env!("JANUS_WIFI_SSID");
const PASS: Option<&str> = option_env!("JANUS_WIFI_PASS");
const PINGS: u16 = 100;

macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static CELL: StaticCell<$t> = StaticCell::new();
        CELL.init_with(|| $val)
    }};
}

#[embassy_executor::task]
async fn foa_task(mut runner: FoARunner<'static>) {
    runner.run().await
}

#[embassy_executor::task]
async fn sta_task(mut runner: StaRunner<'static, 'static>) {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(mut runner: NetRunner<'static, StaNetDevice<'static>>) -> ! {
    runner.run().await
}

/// `PINGS` echoes to the gateway, one at a time: how many came back, and
/// the round trips' min / mean / max in microseconds.
async fn ping_gateway(stack: embassy_net::Stack<'_>) -> (u16, u64, u64, u64) {
    let Some(gateway) = stack.config_v4().and_then(|c| c.gateway) else {
        return (0, 0, 0, 0);
    };
    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_meta = [PacketMetadata::EMPTY; 1];
    let mut rx_bytes = [0u8; 256];
    let mut tx_bytes = [0u8; 256];
    let mut socket = IcmpSocket::new(stack, &mut rx_meta, &mut rx_bytes, &mut tx_meta, &mut tx_bytes);
    let ident = 0x4a45u16;
    if socket.bind(IcmpEndpoint::Ident(ident)).is_err() {
        return (0, 0, 0, 0);
    }
    let payload = [0x5au8; 56];
    let mut request = [0u8; 64];
    let mut response = [0u8; 128];
    let checksum = ChecksumCapabilities::default();
    let (mut got, mut sum, mut min, mut max) = (0u16, 0u64, u64::MAX, 0u64);
    for seq in 1..=PINGS {
        Icmpv4Repr::EchoRequest { ident, seq_no: seq, data: &payload }
            .emit(&mut Icmpv4Packet::new_unchecked(&mut request[..]), &checksum);
        let sent = Instant::now();
        let reply = with_timeout(Duration::from_secs(1), async {
            if socket.send_to(&request, gateway).await.is_err() {
                return;
            }
            loop {
                let Ok((n, from)) = socket.recv_from(&mut response).await else {
                    continue;
                };
                let packet = Icmpv4Packet::new_unchecked(&response[..n]);
                if let Ok(Icmpv4Repr::EchoReply { ident: i, seq_no, .. }) =
                    Icmpv4Repr::parse(&packet, &checksum)
                    && from == gateway.into()
                    && i == ident
                    && seq_no == seq
                {
                    return;
                }
            }
        })
        .await;
        if reply.is_ok() {
            let us = sent.elapsed().as_micros();
            got += 1;
            sum += us;
            min = min.min(us);
            max = max.max(us);
        }
        Timer::after_millis(100).await;
    }
    (got, sum / u64::from(got.max(1)), if got > 0 { min } else { 0 }, max)
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 64 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    println!("open-sta: boot (E1 probe; the open MAC, NOT Wi-Fi certified)");

    let started = Instant::now();
    let resources = mk_static!(FoAResources, FoAResources::new());
    let ([vif, ..], runner) = foa::init(resources, peripherals.WIFI);
    spawner.spawn(foa_task(runner).expect("foa task"));
    println!("open-sta: mac up init_ms={}", started.elapsed().as_millis());

    let (Some(ssid), Some(pass)) = (SSID, PASS) else {
        println!("open-sta: no network built in (JANUS_WIFI_SSID / JANUS_WIFI_PASS); parked");
        loop {
            Timer::after_secs(60).await;
        }
    };

    let (mut control, runner, device) = foa_sta::new_sta_interface(
        mk_static!(VirtualInterface<'static>, vif),
        mk_static!(StaResources<'static>, StaResources::default()),
    );
    spawner.spawn(sta_task(runner).expect("sta task"));
    let _ = control.randomize_mac_address();
    let (stack, runner) = embassy_net::new(
        device,
        embassy_net::Config::dhcpv4(Default::default()),
        mk_static!(StackResources<4>, StackResources::new()),
        u64::from(Rng::new().random()) << 32 | u64::from(Rng::new().random()),
    );
    spawner.spawn(net_task(runner).expect("net task"));

    let joining = Instant::now();
    let joined = with_timeout(
        Duration::from_secs(25),
        control.connect_by_ssid(
            ssid,
            Some(ConnectionConfig { beacon_timeout: None, ..Default::default() }),
            Some(Credentials::Passphrase(pass)),
        ),
    )
    .await;
    match joined {
        Ok(Ok(_)) => println!("open-sta: joined join_ms={}", joining.elapsed().as_millis()),
        Ok(Err(e)) => {
            println!("open-sta: join failed: {e:?}");
            loop {
                Timer::after_secs(60).await;
            }
        }
        Err(_) => {
            println!("open-sta: join timed out");
            loop {
                Timer::after_secs(60).await;
            }
        }
    }
    if with_timeout(Duration::from_secs(15), stack.wait_config_up()).await.is_err() {
        println!("open-sta: no DHCP lease");
        loop {
            Timer::after_secs(60).await;
        }
    }
    let config = stack.config_v4().expect("ipv4");
    println!(
        "open-sta: address {} dhcp_ms={}",
        config.address,
        joining.elapsed().as_millis()
    );
    let (got, mean, min, max) = ping_gateway(stack).await;
    println!("open-sta: gateway pings {got}/{PINGS} min_us={min} mean_us={mean} max_us={max}");
    loop {
        Timer::after_secs(60).await;
        println!("open-sta: up_s={} linked={}", started.elapsed().as_secs(), stack.is_link_up());
    }
}

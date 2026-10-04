//! E3's P4a (experiments plan): an ESP32-S3 access point on the open lower
//! MAC that a station joins. `janus-e3-open`, an open network on channel 6;
//! the access point at 192.168.4.1 hands out leases (edge-dhcp) and answers
//! pings. The MAC is `esp-wifi-hal` and FoA's lower MAC, the access point's
//! decisions and frames `ap_core`'s, the PHY Espressif's `libphy`. **Not
//! Wi-Fi certified.**
//!
//! One task owns the radio: at each TBTT a beacon (its TIM from the station
//! table); a management frame from a station is answered (probe,
//! authentication, association or re-association, through `ap_core`); a data
//! frame from an associated station goes up to the IP stack as Ethernet, or
//! across to the station it is for; an Ethernet frame from the stack goes
//! out as a from-DS data frame. A station silent for 5 minutes is dropped.
//! The soft-AP TSF starts from the RTC's time since power-up (E3's R1).
#![no_std]
#![no_main]

#[path = "../tsf.rs"]
mod tsf;

use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU32, Ordering};

use ap_core::frames::{self, Bss};
use ap_core::request::{self, Request};
use ap_core::stations::{State, Stations};
use ap_core::{Address, reason, status};
use embassy_executor::Spawner;
use embassy_futures::select::{Either3, select3};
use embassy_net::{Ipv4Cidr, Stack, StackResources, StaticConfigV4};
use embassy_net_driver::{HardwareAddress, LinkState};
use embassy_net_driver_channel as ch;
use embassy_time::{Duration, Instant, Timer};
use esp_backtrace as _;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use foa::esp_wifi_hal::ll::EdcaAccessCategory;
use foa::esp_wifi_hal::prelude::{RxFilterBank, TxMacParameters, TxPlcpParameters};
use foa::esp_wifi_hal::rates::{HrDsssRate, OfdmRate, TxPhyRate};
use foa::{FoAResources, FoARunner, RetryBehaviour, TxEndpoint, VirtualInterface};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &[u8] = b"janus-e3-open";
const CHANNEL: u8 = 6;
const BEACON_INTERVAL_TU: u16 = 100;
const DTIM_PERIOD: u8 = 2;
const MTU: usize = 1514;
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
/// A station heard nothing from for this long is dropped (reason 4).
const INACTIVITY_US: u64 = 300_000_000;
/// 802.2 LLC/SNAP, for an EtherType.
const SNAP: [u8; 6] = [0xaa, 0xaa, 0x03, 0, 0, 0];

static BEACONS: AtomicU32 = AtomicU32::new(0);
static BEACON_FAILURES: AtomicU32 = AtomicU32::new(0);
static MANAGEMENT_REPLIES: AtomicU32 = AtomicU32::new(0);
static MANAGEMENT_UNACKED: AtomicU32 = AtomicU32::new(0);
static UP_FRAMES: AtomicU32 = AtomicU32::new(0);
static DOWN_FRAMES: AtomicU32 = AtomicU32::new(0);
static FORWARDED: AtomicU32 = AtomicU32::new(0);
static TO_DOZING: AtomicU32 = AtomicU32::new(0);
static STRANGERS: AtomicU32 = AtomicU32::new(0);
static DROPPED_FOR_INACTIVITY: AtomicU32 = AtomicU32::new(0);

macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static CELL: StaticCell<$t> = StaticCell::new();
        CELL.init_with(|| $val)
    }};
}

#[embassy_executor::task]
async fn mac_task(mut runner: FoARunner<'static>) {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, ch::Device<'static, MTU>>) -> ! {
    runner.run().await
}

/// The DHCP server the hosted network's stations ask (embassy-net has a
/// client only): edge-dhcp, as rusty_esp_signal-esp's `dhcp_server_task`,
/// without esp-radio under it.
#[embassy_executor::task]
async fn dhcp_task(stack: Stack<'static>) -> ! {
    use core::net::{SocketAddr, SocketAddrV4};
    use edge_dhcp::io::{self, DEFAULT_SERVER_PORT};
    use edge_dhcp::server::{Server, ServerOptions};
    use edge_nal::UdpBind as _;
    use edge_nal_embassy::{Udp, UdpBuffers};

    let now = || Instant::now().as_secs();
    let mut server = Server::<_, 8>::new(now, ADDRESS);
    let mut gateway = [ADDRESS];
    let options = ServerOptions::new(ADDRESS, Some(&mut gateway));
    let buffers = UdpBuffers::<1, 1500, 1500, 2>::new();
    let mut packet = [0u8; 1500];
    loop {
        let udp = Udp::new(stack, &buffers);
        if let Ok(mut socket) = udp
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_SERVER_PORT)))
            .await
        {
            let _ = io::server::run(&mut server, &options, &mut socket, &mut packet).await;
        }
        Timer::after(Duration::from_millis(500)).await;
    }
}

fn plcp(rate: TxPhyRate) -> TxPlcpParameters {
    TxPlcpParameters {
        rate,
        ..Default::default()
    }
}

fn one_mbit() -> TxPhyRate {
    TxPhyRate::HrDsss(HrDsssRate::new(0, false).expect("1 Mbit/s, long preamble"))
}

fn is_group(a: &[u8]) -> bool {
    a.first().is_some_and(|b| b & 1 == 1)
}

/// The radio's side of the access point.
struct AccessPoint {
    tx: &'static mut TxEndpoint<'static>,
    bss: Bss<'static>,
    stations: Stations,
}

impl AccessPoint {
    /// A management frame to a station, sent once with retries; counted.
    async fn reply(&mut self, frame: impl FnOnce(&mut [u8]) -> Option<usize>) {
        let mut buf = self.tx.alloc_tx_buf().await;
        let Some(n) = frame(&mut buf[..]) else {
            return;
        };
        let done = self
            .tx
            .transmit_edca(
                EdcaAccessCategory::default(),
                buf,
                n,
                plcp(one_mbit()),
                TxMacParameters {
                    wait_for_ack: true,
                    override_seq_num: true,
                    ..Default::default()
                },
                RetryBehaviour::RetryUntil(4),
            )
            .wait_for_completion()
            .await;
        MANAGEMENT_REPLIES.fetch_add(1, Ordering::Relaxed);
        if !matches!(done, Some(d) if d.result.is_ok()) {
            MANAGEMENT_UNACKED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A data frame from the access point (from-DS): to `to`, from the
    /// Ethernet source `from`, with this EtherType and payload. Unicast at
    /// 24 Mbit/s with ACKs and retries; group-addressed at 1 Mbit/s once.
    async fn send_data(&mut self, to: Address, from: &[u8], ether_type: [u8; 2], payload: &[u8]) {
        let group = is_group(&to);
        if !group {
            match self.stations.get(&to) {
                Some(s) if s.state == State::Connected => {
                    if s.power_save {
                        // P5 holds these frames for the TIM; until then they
                        // are sent and counted
                        TO_DOZING.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ => return,
            }
        }
        let mut buf = self.tx.alloc_tx_buf().await;
        let n = 24 + 8 + payload.len();
        let Some(frame) = buf.get_mut(..n) else {
            return;
        };
        frame[..4].copy_from_slice(&[0x08, 0x02, 0, 0]);
        frame[4..10].copy_from_slice(&to);
        frame[10..16].copy_from_slice(&self.bss.bssid);
        frame[16..22].copy_from_slice(from);
        frame[22..24].copy_from_slice(&[0, 0]);
        frame[24..30].copy_from_slice(&SNAP);
        frame[30..32].copy_from_slice(&ether_type);
        frame[32..].copy_from_slice(payload);
        let (rate, retry) = if group {
            (one_mbit(), RetryBehaviour::Drop)
        } else {
            (TxPhyRate::Ofdm(OfdmRate::Mbits24), RetryBehaviour::RetryUntil(7))
        };
        let _ = self.tx.transmit_edca(
            EdcaAccessCategory::default(),
            buf,
            n,
            plcp(rate),
            TxMacParameters {
                wait_for_ack: !group,
                override_seq_num: true,
                ..Default::default()
            },
            retry,
        );
        DOWN_FRAMES.fetch_add(1, Ordering::Relaxed);
    }

    /// A frame a station sent, copied out of the receive buffer.
    async fn received(&mut self, f: &[u8], up: &mut ch::RxRunner<'static, MTU>) {
        let (Some(&fc0), Some(&fc1)) = (f.first(), f.get(1)) else {
            return;
        };
        let now = Instant::now().as_micros();
        match (fc0 >> 2) & 0b11 {
            0 => self.management(f, now).await,
            2 => self.data(f, fc0, fc1, now, up).await,
            _ => {}
        }
    }

    async fn management(&mut self, f: &[u8], now: u64) {
        let bss = self.bss;
        match request::parse(f, &bss.bssid) {
            Some(Request::Probe { from, ssid }) if ssid.is_none() || ssid == Some(SSID) => {
                let ts = tsf::access_point();
                self.reply(|out| {
                    let n = frames::probe_response(out, &bss, from)?;
                    out[24..32].copy_from_slice(&ts.to_le_bytes());
                    Some(n)
                })
                .await;
            }
            Some(Request::Authentication { from, algorithm, sequence }) => {
                let status = self.stations.authenticate(from, algorithm, sequence);
                self.stations.heard(&from, now, false);
                println!("open-ap: authentication from {:02x?} status={status}", from);
                self.reply(|out| frames::authentication(out, bss.bssid, from, status)).await;
            }
            Some(Request::Association { from, ssid, rsn_element, reassociation }) => {
                let (status, aid) =
                    match self.stations.associate(from, ssid == Some(SSID), rsn_element, bss.protected) {
                        Ok(aid) => (status::SUCCESS, aid),
                        Err(status) => (status, 0),
                    };
                self.stations.heard(&from, now, false);
                println!(
                    "open-ap: {} from {:02x?} status={status} aid={aid}",
                    if reassociation { "re-association" } else { "association" },
                    from
                );
                self.reply(|out| frames::association_response(out, &bss, from, status, aid, reassociation))
                    .await;
            }
            Some(Request::Deauthentication { from, reason } | Request::Disassociation { from, reason }) => {
                if self.stations.remove(&from).is_some() {
                    println!("open-ap: {:02x?} left reason={reason}", from);
                }
            }
            _ => {}
        }
    }

    async fn data(&mut self, f: &[u8], fc0: u8, fc1: u8, now: u64, up: &mut ch::RxRunner<'static, MTU>) {
        // to the DS, from a station: address 1 the BSSID, 2 the station, 3 the destination
        if fc1 & 0b11 != 0b01 || f.len() < 24 {
            return;
        }
        let (Ok(bssid), Ok(station), Ok(destination)) = (
            <[u8; 6]>::try_from(&f[4..10]),
            <[u8; 6]>::try_from(&f[10..16]),
            <[u8; 6]>::try_from(&f[16..22]),
        ) else {
            return;
        };
        if bssid != self.bss.bssid {
            return;
        }
        let power_save = fc1 & 0x10 != 0;
        let connected = self.stations.get(&station).is_some_and(|s| s.state == State::Connected);
        if !self.stations.heard(&station, now, power_save) || !connected {
            // a class 3 frame from a station not associated (802.11-2020 11.3.3)
            STRANGERS.fetch_add(1, Ordering::Relaxed);
            let b = self.bss.bssid;
            self.reply(|out| frames::deauthentication(out, b, station, reason::CLASS3_FROM_NONASSOC))
                .await;
            return;
        }
        let subtype = fc0 >> 4;
        // Null and QoS Null carry nothing (bit 2 of the subtype); a
        // Protected frame on an open network is not ours to read
        if subtype & 0b0100 != 0 || fc1 & 0x40 != 0 {
            return;
        }
        let header = if subtype & 0b1000 != 0 { 26 } else { 24 };
        let Some(llc) = f.get(header..header + 8) else {
            return;
        };
        if llc[..6] != SNAP {
            return;
        }
        let ether_type = [llc[6], llc[7]];
        let payload = &f[header + 8..];
        UP_FRAMES.fetch_add(1, Ordering::Relaxed);
        let for_us = destination == self.bss.bssid;
        let group = is_group(&destination);
        if for_us || group {
            if let Some(buf) = up.try_rx_buf() {
                let n = 14 + payload.len();
                if let Some(eth) = buf.get_mut(..n) {
                    eth[..6].copy_from_slice(&destination);
                    eth[6..12].copy_from_slice(&station);
                    eth[12..14].copy_from_slice(&ether_type);
                    eth[14..].copy_from_slice(payload);
                    up.rx_done(n);
                }
            }
        }
        if !for_us {
            // to another station, or to all of them: across the access point
            FORWARDED.fetch_add(1, Ordering::Relaxed);
            self.send_data(destination, &station, ether_type, payload).await;
        }
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 96 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    println!("open-ap: boot (E3 P4a; the open MAC, NOT Wi-Fi certified)");
    let started = Instant::now();

    // R1: the soft-AP TSF from the RTC's time since power-up, which a reset
    // or a reflash does not stop
    let rtc = esp_hal::rtc_cntl::Rtc::new(peripherals.RTC_TIMER);
    let rtc_us = rtc.time_since_power_up().as_micros();
    tsf::start_access_point_clock_at(rtc_us);
    println!("open-ap: tsf started at {rtc_us} us (the RTC's time since power-up)");

    static FOA: StaticCell<FoAResources> = StaticCell::new();
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    let ([vif, ..], runner) = foa::init(FOA.init(FoAResources::new()), peripherals.WIFI);
    spawner.spawn(mac_task(runner).expect("mac task"));
    let vif = VIF.init(vif);
    let (control, mut rx, tx) = vif.split();

    let base = esp_hal::efuse::base_mac_address();
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(base.as_bytes());
    bssid[5] = bssid[5].wrapping_add(1);

    if control.lock_channel(CHANNEL).is_err() {
        println!("open-ap: channel {CHANNEL} refused");
    }
    control.set_filter(RxFilterBank::ReceiverAddress, bssid);
    control.set_filter(RxFilterBank::Bssid, bssid);
    control.set_filter_bssid_check(false);

    // the access point's own IP interface, on the BSSID's address
    let state = mk_static!(ch::State<MTU, 8, 8>, ch::State::new());
    let (net_runner, device) = ch::new(state, HardwareAddress::Ethernet(bssid));
    let (state_runner, mut up, mut down) = net_runner.split();
    state_runner.set_link_state(LinkState::Up);
    let config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(ADDRESS, 24),
        gateway: None,
        dns_servers: Default::default(),
    });
    let seed = u64::from(esp_hal::rng::Rng::new().random()) << 32 | u64::from(esp_hal::rng::Rng::new().random());
    let (stack, stack_runner) =
        embassy_net::new(device, config, mk_static!(StackResources<6>, StackResources::new()), seed);
    spawner.spawn(net_task(stack_runner).expect("net task"));
    spawner.spawn(dhcp_task(stack).expect("dhcp task"));

    let mut ap = AccessPoint {
        tx,
        bss: Bss {
            bssid,
            ssid: SSID,
            channel: CHANNEL,
            beacon_interval_tu: BEACON_INTERVAL_TU,
            protected: false,
            ht: false,
        },
        stations: Stations::new(),
    };
    println!(
        "open-ap: hosting ssid=janus-e3-open channel={CHANNEL} bssid={:02x?} address={ADDRESS} init_ms={}",
        bssid,
        started.elapsed().as_millis()
    );

    let interval_us = u64::from(BEACON_INTERVAL_TU) * 1024;
    const LEAD_US: u64 = 40;
    const TO_TIMESTAMP_US: u64 = 192 + 24 * 8;
    let mut beacon_index: u32 = 0;
    let mut frame = [0u8; 1600];
    let mut report = Instant::now();
    loop {
        let now = tsf::access_point();
        let next_tbtt = (now / interval_us + 1) * interval_us;
        let wait = next_tbtt.saturating_sub(now).saturating_sub(LEAD_US);
        match select3(Timer::after(Duration::from_micros(wait)), rx.receive(), down.tx_buf()).await {
            Either3::First(()) => {
                let dtim_count = (beacon_index % u32::from(DTIM_PERIOD)) as u8;
                beacon_index = beacon_index.wrapping_add(1);
                let tim = ap.stations.tim(dtim_count, DTIM_PERIOD, false);
                let mut buf = ap.tx.alloc_tx_buf().await;
                let Some(beacon) = frames::beacon(&mut buf[..], &ap.bss, &tim) else {
                    continue;
                };
                let at = beacon.timestamp_at;
                let sent = ap
                    .tx
                    .transmit_beacon_with_hook(
                        &mut buf[..beacon.len],
                        plcp(one_mbit()),
                        TxMacParameters {
                            override_seq_num: true,
                            ..Default::default()
                        },
                        |f| {
                            let ts = tsf::access_point() + TO_TIMESTAMP_US;
                            f[at..at + 8].copy_from_slice(&ts.to_le_bytes());
                        },
                    )
                    .await;
                if sent.is_ok() {
                    BEACONS.fetch_add(1, Ordering::Relaxed);
                } else {
                    BEACON_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
            }
            Either3::Second(received) => {
                // copied out, so the receive buffer goes back before any reply
                let bytes = received.mpdu_buffer();
                let n = bytes.len().min(frame.len());
                frame[..n].copy_from_slice(&bytes[..n]);
                drop(received);
                ap.received(&frame[..n], &mut up).await;
            }
            Either3::Third(eth) => {
                let n = eth.len();
                if n >= 14 {
                    frame[..n].copy_from_slice(eth);
                }
                down.tx_done();
                if n >= 14 {
                    let to: Address = frame[..6].try_into().unwrap_or([0; 6]);
                    let from: [u8; 6] = frame[6..12].try_into().unwrap_or([0; 6]);
                    let ether_type = [frame[12], frame[13]];
                    let payload = &frame[14..n];
                    ap.send_data(to, &from, ether_type, payload).await;
                }
            }
        }
        if report.elapsed().as_secs() >= 10 {
            report = Instant::now();
            let now_us = Instant::now().as_micros();
            while let Some(gone) = ap.stations.inactive(now_us, INACTIVITY_US) {
                ap.stations.remove(&gone);
                DROPPED_FOR_INACTIVITY.fetch_add(1, Ordering::Relaxed);
                let b = ap.bss.bssid;
                ap.reply(|out| frames::deauthentication(out, b, gone, reason::INACTIVITY)).await;
            }
            println!(
                "open-ap: up_s={} stations={} beacons={} beacon_failures={} replies={} unacked={} up={} down={} forwarded={} to_dozing={} strangers={} inactive_dropped={}",
                started.elapsed().as_secs(),
                ap.stations.iter().count(),
                BEACONS.load(Ordering::Relaxed),
                BEACON_FAILURES.load(Ordering::Relaxed),
                MANAGEMENT_REPLIES.load(Ordering::Relaxed),
                MANAGEMENT_UNACKED.load(Ordering::Relaxed),
                UP_FRAMES.load(Ordering::Relaxed),
                DOWN_FRAMES.load(Ordering::Relaxed),
                FORWARDED.load(Ordering::Relaxed),
                TO_DOZING.load(Ordering::Relaxed),
                STRANGERS.load(Ordering::Relaxed),
                DROPPED_FOR_INACTIVITY.load(Ordering::Relaxed),
            );
        }
    }
}

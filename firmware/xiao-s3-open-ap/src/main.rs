//! E3's P3 probe (experiments plan): an ESP32-S3 access point's beacons on
//! the open lower MAC. The MAC is `esp-wifi-hal` and FoA's lower MAC
//! (`rusty_esp_signal/vendor/open-mac`); the access point's frames are
//! `ap_core`'s; the PHY is still Espressif's `libphy`, and nothing here sets
//! transmit power or regulatory tables. **Not Wi-Fi certified.**
//!
//! An open network, `janus-e3-probe` on channel 6 (the owner's D-E2 for an
//! access point, 2026-10-03), no association: it beacons every 102.4 ms and
//! answers probe requests, and it reports
//! - the S3's TSF: its registers before and after the soft-AP clock is
//!   started the way the blob's `hal_mac_tsf_reset(0)` does, and the count
//!   through each latch bit over 100 ms, so the board names the latch that
//!   reads the access point's clock;
//! - every 5 s: beacons sent and failed, probe requests heard, probe
//!   responses sent and failed, frames received.
//!
//! The board named the soft-AP clock's latch (2026-10-03, the first run:
//! `CTRL` bit 1 counts from the start at 1 us/us; bit 0 is a counter from
//! boot, bit 2 stays 0), and the laptop's scans showed the hardware leaves a
//! beacon's timestamp as the hook writes it. So each beacon is sent at a
//! TBTT, when the soft-AP TSF reaches a multiple of the beacon interval,
//! and carries that TSF: what a station's power save wakes by.
#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU32, Ordering};

use ap_core::frames::{self, Bss, Tim};
use ap_core::request::{self, Request};
use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Instant, Timer};
use esp_backtrace as _;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use foa::esp_wifi_hal::ll::EdcaAccessCategory;
use foa::esp_wifi_hal::prelude::{RxFilterBank, TxMacParameters, TxPlcpParameters};
use foa::esp_wifi_hal::rates::{HrDsssRate, TxPhyRate};
use foa::{FoAResources, FoARunner, RetryBehaviour, VirtualInterface};
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &[u8] = b"janus-e3-probe";
const CHANNEL: u8 = 6;
const BEACON_INTERVAL_TU: u16 = 100;

static BEACONS_OK: AtomicU32 = AtomicU32::new(0);
static BEACONS_FAILED: AtomicU32 = AtomicU32::new(0);
static PROBES_HEARD: AtomicU32 = AtomicU32::new(0);
static PROBE_RESPONSES_OK: AtomicU32 = AtomicU32::new(0);
static PROBE_RESPONSES_FAILED: AtomicU32 = AtomicU32::new(0);
static RX_FRAMES: AtomicU32 = AtomicU32::new(0);

mod tsf;

#[embassy_executor::task]
async fn mac_task(mut runner: FoARunner<'static>) {
    runner.run().await
}

fn one_mbit() -> TxPlcpParameters {
    TxPlcpParameters {
        rate: TxPhyRate::HrDsss(HrDsssRate::new(0, false).expect("1 Mbit/s, long preamble")),
        ..Default::default()
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 64 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    println!("open-ap: boot (E3 P3 probe; the open MAC, NOT Wi-Fi certified)");
    let started = Instant::now();

    static FOA: StaticCell<FoAResources> = StaticCell::new();
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    let ([vif, ..], runner) = foa::init(FOA.init(FoAResources::new()), peripherals.WIFI);
    spawner.spawn(mac_task(runner).expect("mac task"));
    let vif = VIF.init(vif);
    let (control, mut rx, tx) = vif.split();

    let base = esp_hal::efuse::base_mac_address();
    // the access point's own address: the base MAC + 1, Espressif's soft-AP
    // convention, so it is not the station's (the base MAC)
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(base.as_bytes());
    bssid[5] = bssid[5].wrapping_add(1);
    println!("open-ap: mac up init_ms={}", started.elapsed().as_millis());

    // the TSF, before anything is asked of it, then the soft-AP clock
    // started; which latch reads a counter, and how fast
    tsf::dump("at boot");
    tsf::start_access_point_clock();
    tsf::dump("after start");
    println!(
        "open-ap: tsf station_cfg={:08x} access_point_cfg={:08x}",
        tsf::read(tsf::STA_CFG),
        tsf::read(tsf::AP_CFG)
    );
    for bit in [1u32, 2, 4] {
        let (h0, l0) = tsf::latched(bit);
        let t0 = Instant::now();
        Timer::after_millis(100).await;
        let (h1, l1) = tsf::latched(bit);
        let elapsed = t0.elapsed().as_micros();
        let before = (u64::from(h0) << 32) | u64::from(l0);
        let after = (u64::from(h1) << 32) | u64::from(l1);
        println!(
            "open-ap: tsf latch={bit} before={before} after={after} delta={} over_us={elapsed}",
            after.wrapping_sub(before)
        );
    }

    // the access point's receive side: frames to its address and BSSID, and
    // broadcast probe requests (the BSSID check off, as for hosting)
    if control.lock_channel(CHANNEL).is_err() {
        println!("open-ap: channel {CHANNEL} refused");
    }
    control.set_filter(RxFilterBank::ReceiverAddress, bssid);
    control.set_filter(RxFilterBank::Bssid, bssid);
    control.set_filter_bssid_check(false);

    let bss = Bss {
        bssid,
        ssid: SSID,
        channel: CHANNEL,
        beacon_interval_tu: BEACON_INTERVAL_TU,
        protected: false,
        ht: false,
    };
    let interval_us = u64::from(BEACON_INTERVAL_TU) * 1024;
    // how early, in TSF microseconds, the wait ends: the frame's build, about
    // 20 us (with 400 the hook ran 380 us before the TBTT, a steady phase)
    const LEAD_US: u64 = 40;
    // the timestamp is the TSF when its first bit is on the air (802.11-2020
    // 11.1.3.1): at 1 Mbit/s the long DSSS preamble and PLCP header (192 us)
    // and the 24-byte MAC header (192 us) go first
    const TO_TIMESTAMP_US: u64 = 192 + 24 * 8;
    let mut phase_min = u64::MAX;
    let mut phase_max = 0u64;
    let mut report = Instant::now();
    let mut beacon_index: u32 = 0;
    println!(
        "open-ap: beaconing ssid=janus-e3-probe channel={CHANNEL} bssid={:02x?} interval_tu={BEACON_INTERVAL_TU}",
        bssid
    );
    loop {
        let now = tsf::access_point();
        let next_tbtt = (now / interval_us + 1) * interval_us;
        let wait = next_tbtt.saturating_sub(now).saturating_sub(LEAD_US);
        match select(Timer::after(Duration::from_micros(wait)), rx.receive()).await {
            Either::First(()) => {
                let tim = Tim {
                    dtim_count: (beacon_index % 2) as u8,
                    dtim_period: 2,
                    group_buffered: false,
                    buffered_aids: 0,
                };
                beacon_index = beacon_index.wrapping_add(1);
                let mut buf = tx.alloc_tx_buf().await;
                let Some(beacon) = frames::beacon(&mut buf[..], &bss, &tim) else {
                    continue;
                };
                let at = beacon.timestamp_at;
                let result = tx
                    .transmit_beacon_with_hook(
                        &mut buf[..beacon.len],
                        one_mbit(),
                        TxMacParameters {
                            override_seq_num: true,
                            ..Default::default()
                        },
                        |frame| {
                            let now = tsf::access_point();
                            frame[at..at + 8].copy_from_slice(&(now + TO_TIMESTAMP_US).to_le_bytes());
                            // where in the interval this beacon left
                            let phase = now % interval_us;
                            let phase = phase.min(interval_us - phase);
                            phase_min = phase_min.min(phase);
                            phase_max = phase_max.max(phase);
                        },
                    )
                    .await;
                if result.is_ok() {
                    BEACONS_OK.fetch_add(1, Ordering::Relaxed);
                } else {
                    BEACONS_FAILED.fetch_add(1, Ordering::Relaxed);
                }
            }
            Either::Second(frame) => {
                RX_FRAMES.fetch_add(1, Ordering::Relaxed);
                let to = match request::parse(frame.mpdu_buffer(), &bssid) {
                    Some(Request::Probe { from, ssid }) if ssid.is_none() || ssid == Some(SSID) => {
                        PROBES_HEARD.fetch_add(1, Ordering::Relaxed);
                        Some(from)
                    }
                    _ => None,
                };
                drop(frame);
                if let Some(to) = to {
                    let mut buf = tx.alloc_tx_buf().await;
                    if let Some(n) = frames::probe_response(&mut buf[..], &bss, to) {
                        buf[24..32].copy_from_slice(&tsf::access_point().to_le_bytes());
                        let done = tx
                            .transmit_edca(
                                EdcaAccessCategory::default(),
                                buf,
                                n,
                                one_mbit(),
                                TxMacParameters {
                                    wait_for_ack: true,
                                    override_seq_num: true,
                                    ..Default::default()
                                },
                                RetryBehaviour::RetryUntil(3),
                            )
                            .wait_for_completion()
                            .await;
                        match done {
                            Some(d) if d.result.is_ok() => PROBE_RESPONSES_OK.fetch_add(1, Ordering::Relaxed),
                            _ => PROBE_RESPONSES_FAILED.fetch_add(1, Ordering::Relaxed),
                        };
                    }
                }
            }
        }
        if report.elapsed().as_secs() >= 5 {
            report = Instant::now();
            println!(
                "open-ap: up_s={} beacons_ok={} beacons_failed={} probes_heard={} probe_responses_ok={} probe_responses_failed={} rx_frames={} tsf={} tbtt_phase_us={}..{}",
                started.elapsed().as_secs(),
                BEACONS_OK.load(Ordering::Relaxed),
                BEACONS_FAILED.load(Ordering::Relaxed),
                PROBES_HEARD.load(Ordering::Relaxed),
                PROBE_RESPONSES_OK.load(Ordering::Relaxed),
                PROBE_RESPONSES_FAILED.load(Ordering::Relaxed),
                RX_FRAMES.load(Ordering::Relaxed),
                tsf::access_point(),
                phase_min,
                phase_max
            );
            phase_min = u64::MAX;
            phase_max = 0;
        }
    }
}

#![no_std]
#![no_main]
//! **E7's bench: the setup session over the device's own page, on the open
//! MAC, with no Bluetooth.** NOT Wi-Fi certified.
//!
//! The XIAO hosts an open network, `janus-setup`, from the open MAC
//! (`rusty_esp_signal-open::access_point`, `AccessPointConfig::open`; no
//! esp-radio) and answers the setup protocol's section 11.2 on port 80:
//! `GET /setup` is Discover, `POST /setup` one message in and one out, the
//! carrier session named by `X-Setup-Session` (`setup::page`). `GET /` is a
//! line saying so. The settings and the setup code's verifier are in `nvs`
//! (written by `espino provision --setup-code-out`); the device key is
//! loaded from `identity` and **never minted here**: a board with no key is
//! refused at boot. An applied record is stored and reported (its network's
//! name, never its passphrase); this bench joins nothing (E1 joins).
//!
//! Lines: `SETUP boot ...`, `SETUP did ...`, `SETUP hosting ...`,
//! `SETUP request <method> <path> -> <status>`, `SETUP applied network=...`,
//! and a watch line every ten seconds.

extern crate alloc;

use core::cell::RefCell;

use embassy_net::tcp::TcpSocket;
use embassy_net::{Ipv4Address, Ipv4Cidr, Stack, StackResources};
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_backtrace as _;
use esp_hal::rng::{Rng, Trng, TrngSource};
use esp_hal::rtc_cntl::SocResetReason;
use esp_hal::system::reset_reason;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_storage::FlashStorage;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_mid_esp::hal::{EspHalRng, SharedFlash, SharedNvs, open_shared};
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::setup::{Device, MAX_MESSAGE, Page, Reset, Status, label};
use rusty_esp_signal_open::access_point as open_ap;
use rusty_esp_video_core::http::{self, Path, Request};
use rusty_esp_video_core::sink::SliceSink;
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

/// The network: `janus-setup`, open, unless the build names others --
/// `JANUS_AP_SSID`, and `JANUS_AP_PASS` for WPA2 (E3's four stations; the
/// passphrase is the run's, in its environment only, never printed).
const SSID: &str = match option_env!("JANUS_AP_SSID") {
    Some(s) => s,
    None => "janus-setup",
};
const PASS: &str = match option_env!("JANUS_AP_PASS") {
    Some(s) => s,
    None => "",
};
const ADDRESS: Ipv4Cidr = Ipv4Cidr::new(Ipv4Address::new(192, 168, 71, 1), 24);
const NAMESPACE: &str = "janus";
const SETTINGS_PARTITION: &str = "nvs";
const IDENTITY_PARTITION: &str = "identity";
const DEVICE_ID: &str = "janus";
const SOCKETS: usize = 6; // DHCP's UDP and port 80's three
/// A request head, and a message behind it.
const REQUEST_BYTES: usize = http::MAX_REQUEST_BYTES + MAX_MESSAGE;

/// Port 80's listeners.
const SERVERS: usize = 3;

static NET: StaticCell<StackResources<SOCKETS>> = StaticCell::new();
static FLASH: StaticCell<SharedFlash<'static>> = StaticCell::new();
static SHARED: StaticCell<RefCell<Shared>> = StaticCell::new();

/// The setup session's state, shared by port 80's listeners.
struct Shared {
    page: Page,
    device: Device,
    settings: SharedNvs<'static, 'static>,
    identity: SharedNvs<'static, 'static>,
    rng: EspHalRng,
    key: DeviceKey,
}

fn now() -> Micros {
    Micros(Instant::now().as_micros())
}

#[esp_rtos::main]
async fn main(spawner: embassy_executor::Spawner) {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 96 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    // the USB-JTAG console reattaches after a reset (E3's C16, run 1)
    Timer::after(Duration::from_millis(1500)).await;

    let reset = match reset_reason() {
        Some(SocResetReason::ChipPowerOn) => Reset::PowerOn,
        _ => Reset::Other,
    };
    println!("== JANUS SETUP xiao-s3 open-mac page reset={reset:?} (NOT Wi-Fi certified) ==");

    // the settings, the identity, the key: loaded, never minted
    let storage: &'static SharedFlash<'static> =
        FLASH.init(RefCell::new(FlashStorage::new(peripherals.FLASH)));
    let mut settings = open_shared(storage, SETTINGS_PARTITION, NAMESPACE)
        .expect("nvs partition readable")
        .expect("an nvs partition in the table");
    let identity = match open_shared(storage, IDENTITY_PARTITION, NAMESPACE) {
        Ok(Some(kv)) => kv,
        other => panic!(
            "SETUP no identity partition ({:?}): this bench never mints a key",
            other.err()
        ),
    };
    let key = match DeviceKey::load(&identity, DEVICE_ID) {
        Ok(Some(key)) => key,
        other => panic!(
            "SETUP no device key in the identity partition ({:?}): this bench never mints one",
            other.err()
        ),
    };
    println!("SETUP did {}", key.did());

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let rng = EspHalRng(Trng::try_new().expect("TRNG entropy source enabled"));
    let mut device = Device::new(
        label::PAGE,
        *key.did().pubkey(),
        reset,
        now(),
        &mut settings,
    )
    .expect("setup session");
    let window = device.window(now(), &settings);
    println!(
        "SETUP boot window_open={} window_s={} attempts_left={}",
        window.open, window.window_s, window.attempts_left
    );
    // what a Discover costs the device, with no network in the way
    let mut probe = Page::new();
    let mut discover = [0u8; 64];
    for _ in 0..3 {
        let t = Instant::now();
        let a = probe.discover(&mut device, now(), &settings, &mut discover);
        println!(
            "SETUP discover_us={} ok={}",
            t.elapsed().as_micros(),
            a.is_ok()
        );
    }
    let shared: &'static RefCell<Shared> = SHARED.init(RefCell::new(Shared {
        page: Page::new(),
        device,
        settings,
        identity,
        rng,
        key,
    }));

    // the open MAC hosting the setup network: open, no handshake
    let seed_rng = Rng::new();
    let seed = (u64::from(seed_rng.random()) << 32) | u64::from(seed_rng.random());
    let tsf_seed_us = esp_hal::rtc_cntl::Rtc::new(peripherals.RTC_TIMER)
        .time_since_power_up()
        .as_micros();
    let ap = open_ap::hosted_stack(
        peripherals.WIFI,
        open_ap::AccessPointConfig {
            address: ADDRESS,
            // `JANUS_HT=0` at build time: WMM and HT off (E3's round-trip A/B)
            ht: option_env!("JANUS_HT") != Some("0"),
            ..if PASS.is_empty() {
                open_ap::AccessPointConfig::open(SSID, tsf_seed_us)
            } else {
                open_ap::AccessPointConfig::new(SSID, PASS, tsf_seed_us)
            }
        },
        NET.init(StackResources::new()),
        seed,
    );
    let stack = ap.stack;
    spawner.spawn(open_ap::mac_task(ap.mac).expect("mac task"));
    spawner.spawn(open_ap::ap_task(ap.ap).expect("access point task"));
    spawner.spawn(open_ap::net_task(ap.net).expect("net task"));
    spawner.spawn(open_ap::dhcp_server_task(stack, ADDRESS).expect("dhcp server task"));
    spawner.spawn(watch_task().expect("watch task"));
    // several sockets listening: one alone leaves port 80 closed while it
    // finishes a connection, and Windows retries a refused connect about
    // half a second later (E7's bench, runs 2 and 3: Discover 540 ms over
    // the air for 6.5 ms of work)
    for n in 0..SERVERS {
        spawner.spawn(server_task(stack, shared, n).expect("server task"));
    }
    println!(
        "SETUP hosting {SSID} ({}) on the open MAC, page http://192.168.71.1/setup",
        if PASS.is_empty() { "open" } else { "wpa2" }
    );
    loop {
        Timer::after(Duration::from_secs(3600)).await;
    }
}

/// The access point's counters every ten seconds.
#[embassy_executor::task]
async fn watch_task() {
    let started = Instant::now();
    loop {
        Timer::after(Duration::from_secs(10)).await;
        let a = open_ap::stats();
        let (ap_tsf, stamp_tsf) = open_ap::clocks();
        println!(
            "SETUP watch up_s={} stations={} joins={} up={} down={} beacons={} plaintext_dropped={} dozing={} held={} released={} wakes={} ps_polls={} dropped_inactive={} held_dropped={} beacons_late={} tbtts_skipped={} beacon_late_max_us={} stamp_offset_us={} stamp_syncs={} qos_sent={} ht_sent={} data_unacked={} ladder_up={} ladder_down={} strangers={} replays={} handshake_refused={} hs_m2={} hs_m4={} hs_group={} m2_frame={} m2_mic={} m2_keyinfo={} m2_replay={} m2_rsn={} hs_begun={} hs_restarted={} handshake_timeouts={} up_dropped={}",
            started.elapsed().as_secs(),
            a.stations,
            a.joins,
            a.up,
            a.down,
            a.beacons,
            a.plaintext_dropped,
            a.dozing,
            a.held,
            a.released,
            a.wakes,
            a.ps_polls,
            a.dropped_inactive,
            a.held_dropped,
            a.beacons_late,
            a.tbtts_skipped,
            a.beacon_late_max_us,
            stamp_tsf as i64 - ap_tsf as i64,
            a.stamp_syncs,
            a.qos_sent,
            a.ht_sent,
            a.data_unacked,
            a.ladder_up,
            a.ladder_down,
            a.strangers,
            a.replays,
            a.handshake_refused,
            a.handshake_refused_m2,
            a.handshake_refused_m4,
            a.handshake_refused_group,
            a.m2_frame,
            a.m2_mic,
            a.m2_keyinfo,
            a.m2_replay,
            a.m2_rsn,
            a.handshakes_begun,
            a.handshakes_restarted,
            a.handshake_timeouts,
            a.up_dropped
        );
    }
}

#[embassy_executor::task(pool_size = SERVERS)]
async fn server_task(stack: Stack<'static>, shared: &'static RefCell<Shared>, n: usize) -> ! {
    serve(stack, shared, n).await
}

/// Port 80: the setup session's two requests. The state is borrowed only
/// between awaits, so the listeners take turns at it on the one executor.
async fn serve(stack: Stack<'static>, shared: &'static RefCell<Shared>, n: usize) -> ! {
    let mut rx = [0u8; REQUEST_BYTES];
    let mut tx = [0u8; 1024];
    let mut request = [0u8; REQUEST_BYTES];
    let mut answer = [0u8; MAX_MESSAGE];
    let mut response = [0u8; MAX_MESSAGE + 256];
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_timeout(Some(Duration::from_secs(10)));
        if socket.accept(80).await.is_err() {
            continue;
        }
        // the head, then the body its Content-Length names
        let mut len = 0usize;
        let mut want: Option<usize> = None;
        let complete = loop {
            if let Some(w) = want {
                if len >= w {
                    break true;
                }
            }
            if len == request.len() {
                break false;
            }
            match with_timeout(Duration::from_secs(5), socket.read(&mut request[len..])).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break false,
                Ok(Ok(k)) => len += k,
            }
            if want.is_none() && http::head_complete(&request[..len]) {
                let body_at = http::body_offset(&request[..len]).unwrap_or(len);
                let body_len = match http::parse_request(&request[..len], None) {
                    Some(Request::Post {
                        content_length: Some(k),
                        ..
                    }) => k as usize,
                    _ => 0,
                };
                want = Some(body_at + body_len.min(MAX_MESSAGE));
            }
        };
        let parsed = if complete || want.is_some() {
            http::parse_request(&request[..len], None)
        } else {
            None
        };
        let handled_at = Instant::now();
        let mut sink = SliceSink::new(&mut response);
        let mut state = shared.borrow_mut();
        let Shared {
            page,
            device,
            settings,
            identity,
            rng,
            key,
        } = &mut *state;
        let (what, status) = match parsed {
            Some(Request::Get {
                path: Path::Setup, ..
            }) => match page.discover(device, now(), settings, &mut answer) {
                Ok(a) => {
                    let _ = http::write_octets(&mut sink, a.status, &answer[..a.len]);
                    ("GET /setup", a.status)
                }
                Err(_) => {
                    let _ = http::write_status(&mut sink, http::Status::BadRequest);
                    ("GET /setup", 500)
                }
            },
            Some(Request::Post {
                path: Path::Setup,
                content_length,
                setup_session,
                ..
            }) => {
                let body_at = http::body_offset(&request[..len]).unwrap_or(len);
                let body_len = content_length.unwrap_or(0) as usize;
                let body = request.get(body_at..body_at + body_len).unwrap_or(&[]);
                let header = setup_session.as_ref().map_or(&[][..], |s| &s[..]);
                let status_line = Status {
                    phase: 0,
                    scan: &[],
                };
                match page.post(
                    device,
                    header,
                    body,
                    now(),
                    settings,
                    identity,
                    rng,
                    &*key,
                    &status_line,
                    &mut answer,
                ) {
                    Ok(a) => {
                        let _ = http::write_octets(&mut sink, a.status, &answer[..a.len]);
                        if let Some(net) = a.applied.as_ref().and_then(|x| x.network.as_ref()) {
                            println!(
                                "SETUP applied network={} (passphrase {} bytes, not shown)",
                                core::str::from_utf8(net.ssid()).unwrap_or("?"),
                                net.psk().len()
                            );
                        }
                        ("POST /setup", a.status)
                    }
                    Err(_) => {
                        let _ = http::write_status(&mut sink, http::Status::BadRequest);
                        ("POST /setup", 500)
                    }
                }
            }
            Some(Request::Get {
                path: Path::Index, ..
            }) => {
                let _ = http::write_plain(
                    &mut sink,
                    200,
                    "OK",
                    "janus setup: the setup session is at /setup (setup protocol section 11.2)\n",
                );
                ("GET /", 200)
            }
            Some(Request::Get { .. }) => {
                let _ = http::write_status(&mut sink, http::Status::NotFound);
                ("GET other", 404)
            }
            Some(_) => {
                let _ = http::write_status(&mut sink, http::Status::MethodNotAllowed);
                ("other method", 405)
            }
            None => {
                let _ = http::write_status(&mut sink, http::Status::BadRequest);
                ("bad request", 400)
            }
        };
        let in_flight = page.in_flight();
        let attempts_left = device.window(now(), &*settings).attempts_left;
        drop(state);
        let handler_us = handled_at.elapsed().as_micros();
        let bytes = sink.len();
        let mut sent = 0;
        while sent < bytes {
            match socket.write(&response[sent..bytes]).await {
                Ok(0) | Err(_) => break,
                Ok(k) => sent += k,
            }
        }
        let _ = socket.flush().await;
        socket.close();
        Timer::after(Duration::from_millis(20)).await;
        socket.abort();
        println!(
            "SETUP request {what} -> {status} handler_us={handler_us} server={n} in_flight={in_flight} attempts_left={attempts_left}"
        );
    }
}

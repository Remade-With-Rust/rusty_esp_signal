#![no_std]
#![no_main]
//! E5's P2 and P3 on an ESP32-C6: the Wi-Fi MAC brought up **without the
//! vendor's MAC library** (no libpp, no libnet80211), then frames received
//! into a ring of this firmware's own. NOT Wi-Fi certified (D-E2); this
//! firmware never transmits.
//!
//! The method (`docs/plans/e5-c6.md`, P2): no translation of the vendor's
//! code. The clocks come from esp-radio's open code (its `enable_wifi` for
//! the C6), the PHY from esp-phy (the PHY library's own bring-up and
//! calibration, as the S3's open MAC uses it), and the MAC's configuration
//! from what the chip was seen to hold after esp-radio's bring-up
//! ([`replay::MAC_CONFIG`], read back from two boards).
//!
//! Lines on the UART socket:
//! - `E5 boot`, `E5 up ...` once;
//! - `MACSNAP open <address> <value>` and `MACSNAP open done ...`: the
//!   same 243 registers `c6-s1-link`'s snapshot reads after the blob's
//!   bring-up, read after this one (P2's check, `tools/e5-c6.py compare`),
//!   printed again every 15 s for a reader that joined late;
//! - `P3 frame n=... ch=... len=... fc=... flags=...`: the first frames'
//!   lengths and frame-control fields (no addresses: a neighbour's are not
//!   ours to log);
//! - `P3 ch=... frames=... ...` every two seconds.
//!
//! `JANUS_CHANNEL` (build time) picks the channel; unset, it walks 1 to 13,
//! four seconds each, then stays on the busiest.

#[allow(dead_code)] // the S3 window and the build-time switch are c6-s1-link's
#[path = "../../common/mac_snapshot.rs"]
mod mac_snapshot;
mod replay;
mod sniff;

use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_hal::time::{Duration, Instant};
use esp_println::println;

esp_bootloader_esp_idf::esp_app_desc!();

/// The ring: descriptors in the layout every ESP32 DMA list uses (size,
/// length, end of frame and owner in the first word, then the buffer and
/// the next descriptor), as the S3's open MAC builds them.
const BUFFERS: usize = 8;
const BUFFER_SIZE: usize = 1600;

#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct Descriptor {
    flags: u32,
    buffer: *mut u8,
    next: *mut Descriptor,
}

/// What the C6's MAC writes ahead of each frame (first runs, 2026-10-07):
/// the signal strength in byte 0 (dBm, signed), a microsecond timestamp in
/// bytes 12-15, the frame's length in bytes 84-85 (and 86-87 with the FCS),
/// and the 802.11 frame itself from byte 92.
const META_LEN: usize = 92;
const META_RSSI: usize = 0;
const META_FRAME_LEN: usize = 84;
const META_LOCAL_US: usize = 12;

const OWNER_DMA: u32 = 1 << 31;
const EOF: u32 = 1 << 30;

static mut RING: [Descriptor; BUFFERS] = [Descriptor {
    flags: 0,
    buffer: core::ptr::null_mut(),
    next: core::ptr::null_mut(),
}; BUFFERS];
static mut BUFFER: [[u8; BUFFER_SIZE]; BUFFERS] = [[0; BUFFER_SIZE]; BUFFERS];

/// The receive DMA list's registers, where the C6 snapshot shows them
/// (`e5/c6-mac-registers.md`: control, base, next, last), one word below the
/// S3's: control bit 31 enables reception, bit 0 reloads the list.
const RX_CTRL: u32 = 0x600a_4080;
const RX_BASE: u32 = 0x600a_4084;
const RX_NEXT: u32 = 0x600a_4088;
const RX_LAST: u32 = 0x600a_408c;
const RX_ENABLE: u32 = 1 << 31;
const RX_RELOAD: u32 = 1;
/// The other bit esp-radio's bring-up leaves set in the control word.
const RX_CTRL_OBSERVED: u32 = 0x0800_0000;

unsafe extern "C" {
    /// The PHY library's channel tuning (libphy; the S3's open MAC calls it
    /// the same way).
    fn chip_v7_set_chan(channel: u8, bandwidth: u8);
}

fn read(address: u32) -> u32 {
    unsafe { (address as *const u32).read_volatile() }
}

fn write(address: u32, value: u32) {
    unsafe { (address as *mut u32).write_volatile(value) }
}

/// The modem clocks Wi-Fi needs, as esp-radio's `enable_wifi(true)` sets
/// them for the C6 (`radio_clocks/clocks_ll/esp32c6.rs`): while they are
/// gated, the C6 drops every write to the MAC.
fn wifi_clocks_on() {
    let syscon = esp_hal::peripherals::MODEM_SYSCON::regs();
    syscon.clk_conf1().modify(|_, w| {
        w.clk_wifi_apb_en().set_bit();
        w.clk_wifimac_en().set_bit();
        w.clk_fe_apb_en().set_bit();
        w.clk_fe_cal_160m_en().set_bit();
        w.clk_fe_160m_en().set_bit();
        w.clk_fe_80m_en().set_bit();
        w.clk_wifibb_160x1_en().set_bit();
        w.clk_wifibb_80x1_en().set_bit();
        w.clk_wifibb_40x1_en().set_bit();
        w.clk_wifibb_80x_en().set_bit();
        w.clk_wifibb_40x_en().set_bit();
        w.clk_wifibb_80m_en().set_bit();
        w.clk_wifibb_44m_en().set_bit();
        w.clk_wifibb_40m_en().set_bit();
        w.clk_wifibb_22m_en().set_bit()
    });
    esp_hal::peripherals::MODEM_LPCON::regs()
        .clk_conf()
        .modify(|_, w| {
            w.clk_wifipwr_en().set_bit();
            w.clk_coex_en().set_bit()
        });
}

/// Every descriptor back to the hardware, chained in order and the last back
/// to the first: a list the hardware never runs off (a list that ended
/// stopped reception for good, and the S3's reload did not restart it,
/// 2026-10-07); returns the first.
fn arm_ring() -> *mut Descriptor {
    unsafe {
        let ring = &raw mut RING;
        let buffers = &raw mut BUFFER;
        for i in 0..BUFFERS {
            let next = &raw mut (*ring)[(i + 1) % BUFFERS];
            (*ring)[i] = Descriptor {
                flags: OWNER_DMA | BUFFER_SIZE as u32,
                buffer: (&raw mut (*buffers)[i]) as *mut u8,
                next,
            };
        }
        &raw mut (*ring)[0]
    }
}

/// The ring installed and reception on.
fn start_rx() {
    let first = arm_ring();
    write(RX_CTRL, read(RX_CTRL) & !RX_ENABLE);
    write(RX_BASE, first as u32);
    write(RX_CTRL, read(RX_CTRL) | RX_RELOAD);
    let started = Instant::now();
    while read(RX_CTRL) & RX_RELOAD != 0 && started.elapsed() < Duration::from_millis(100) {}
    write(RX_CTRL, read(RX_CTRL) | RX_ENABLE | RX_CTRL_OBSERVED);
}

/// Frames counted by their frame-control field.
#[derive(Default)]
struct Kinds {
    management: u32,
    control: u32,
    data: u32,
    other: u32,
    beacons: u32,
    beacons_broadcast: u32,
    rssi_sum: i32,
}

fn tune(channel: u8) {
    unsafe { chip_v7_set_chan(channel, 0) };
}

#[esp_hal::main]
fn main() -> ! {
    // 160 MHz, as esp-radio assumes for the C6's radio
    let _peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 32 * 1024);
    println!("E5 boot c6-open-rx (no libpp; never transmits)");

    // P2: clocks, the PHY (and Wi-Fi reception in it), the MAC's
    // configuration as observed, a channel, the ring
    wifi_clocks_on();
    esp_phy::enable_phy_with_wifi_rx();
    for (address, value) in replay::MAC_CONFIG {
        write(address, value);
    }
    for address in replay::MAC_CLEARED {
        write(address, 0);
    }
    let fixed: Option<u8> = option_env!("JANUS_CHANNEL").and_then(|c| c.parse().ok());
    let mut channel = fixed.unwrap_or(1);
    tune(channel);
    start_rx();
    let base = read(RX_BASE);
    println!(
        "E5 up channel={channel} rx_ctrl=0x{:08x} rx_base=0x{base:08x} ring=0x{:08x} config={}",
        read(RX_CTRL),
        (&raw const RING) as u32,
        replay::MAC_CONFIG.len()
    );
    let taken = mac_snapshot::take(&mac_snapshot::C6_REGISTERS);
    mac_snapshot::print("open", &mac_snapshot::C6_REGISTERS, &taken);

    // P3: poll the ring
    let mut frames = 0u32;
    let mut kinds = Kinds::default();
    let mut on_channel = 0u32;
    let mut best = (channel, 0u32);
    let mut index = 0usize;
    let mut beat = 0u32;
    let mut last_beat = Instant::now();
    let mut dwell = Instant::now();
    let mut walking = fixed.is_none();
    // one frame's raw start every ten seconds, for a reader that joined late
    let mut dump = false;
    let sniff_ssid = option_env!("JANUS_SNIFF_SSID").map(str::as_bytes);
    let mut sniffer = sniff::Sniffer::default();
    loop {
        // the C6's MAC leaves the owner bit set: a descriptor it has filled
        // shows a length and the end of a frame (first run, 2026-10-07)
        let flags = unsafe { (*(&raw const RING))[index].flags };
        if flags & EOF != 0 || (flags >> 12) & 0xfff != 0 {
            let length = (flags >> 12) & 0xfff;
            frames += 1;
            on_channel += 1;
            {
                let buffer = unsafe { &(*(&raw const BUFFER))[index] };
                let frame_len =
                    u16::from_le_bytes([buffer[META_FRAME_LEN], buffer[META_FRAME_LEN + 1]])
                        as usize;
                let fc = buffer[META_LEN];
                match (fc >> 2) & 3 {
                    0 => kinds.management += 1,
                    1 => kinds.control += 1,
                    2 => kinds.data += 1,
                    _ => kinds.other += 1,
                }
                if fc == 0x80 && frame_len >= 24 && META_LEN + 10 <= BUFFER_SIZE {
                    kinds.beacons += 1;
                    // a beacon's first address is broadcast: the check that
                    // the frame starts where we think it does
                    if buffer[META_LEN + 4..META_LEN + 10] == [0xff; 6] {
                        kinds.beacons_broadcast += 1;
                    }
                    kinds.rssi_sum += i32::from(buffer[META_RSSI] as i8);
                    if let Some(ssid) = sniff_ssid {
                        let end = (META_LEN + frame_len.saturating_sub(4)).min(BUFFER_SIZE);
                        let local_us = u32::from_le_bytes([
                            buffer[META_LOCAL_US],
                            buffer[META_LOCAL_US + 1],
                            buffer[META_LOCAL_US + 2],
                            buffer[META_LOCAL_US + 3],
                        ]);
                        sniffer.beacon(&buffer[META_LEN..end], ssid, local_us);
                    }
                }
            }
            if frames <= 6 || core::mem::take(&mut dump) {
                // the raw start of the buffer, for the receive layout (the
                // capture stays on the bench: it can hold a neighbour's
                // address)
                let buffer = unsafe { &(*(&raw const BUFFER))[index] };
                println!(
                    "P3 frame n={frames} ch={channel} len={length} eof={} flags=0x{flags:08x} raw={:02x?}",
                    flags & EOF != 0,
                    &buffer[..96.min(length as usize)]
                );
            } else if frames <= 40 {
                println!("P3 frame n={frames} ch={channel} len={length}");
            }
            // read: back to the hardware at once
            unsafe { (*(&raw mut RING))[index].flags = OWNER_DMA | BUFFER_SIZE as u32 };
            index = (index + 1) % BUFFERS;
        }
        if last_beat.elapsed() >= Duration::from_secs(2) {
            last_beat = Instant::now();
            beat += 1;
            println!(
                "P3 ch={channel} frames={frames} on_channel={on_channel} rx_ctrl=0x{:08x} next=0x{:08x} last=0x{:08x} first_flags=0x{:08x}",
                read(RX_CTRL),
                read(RX_NEXT),
                read(RX_LAST),
                unsafe { (*(&raw const RING))[0].flags }
            );
            if beat % 5 == 0 {
                dump = sniff_ssid.is_none();
                if sniff_ssid.is_some() {
                    sniffer.report();
                }
                println!(
                    "P3 kinds management={} control={} data={} other={} beacons={} beacons_to_broadcast={} beacon_rssi_avg={}",
                    kinds.management,
                    kinds.control,
                    kinds.data,
                    kinds.other,
                    kinds.beacons,
                    kinds.beacons_broadcast,
                    if kinds.beacons > 0 {
                        kinds.rssi_sum / kinds.beacons as i32
                    } else {
                        0
                    }
                );
            }
            if beat % 8 == 0 {
                mac_snapshot::print("open", &mac_snapshot::C6_REGISTERS, &taken);
            }
        }
        if walking && dwell.elapsed() >= Duration::from_secs(4) {
            if on_channel > best.1 {
                best = (channel, on_channel);
            }
            println!("P3 walk ch={channel} frames={on_channel}");
            if channel < 13 {
                channel += 1;
            } else {
                walking = false;
                channel = best.0;
                println!(
                    "P3 walk done: staying on ch={channel} ({} frames there)",
                    best.1
                );
            }
            tune(channel);
            on_channel = 0;
            dwell = Instant::now();
        }
    }
}

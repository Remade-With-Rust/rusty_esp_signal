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
mod e8;
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
/// E8's tally takes frames to 3,600 bytes: 4,092 is the most a descriptor's
/// 12-bit size field holds, kept a multiple of four.
const E8_TALLY: bool = option_env!("JANUS_E8_TALLY").is_some();
const BUFFER_SIZE: usize = if E8_TALLY { 4092 } else { 1600 };

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

/// P4's one transmit descriptor and its frame, in DRAM at a stable address
/// (the hardware is handed the descriptor's low 20 bits).
static mut TX_DESC: esp_hal::dma::DmaDescriptor = esp_hal::dma::DmaDescriptor {
    flags: esp_hal::dma::DmaDescriptorFlags(0),
    buffer: core::ptr::null_mut(),
    next: core::ptr::null_mut(),
};
static mut TX_BUF: [u8; espnow_frame::MAX_FRAME] = [0; espnow_frame::MAX_FRAME];

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

// ---- E5's P4: transmit -------------------------------------------------
// Every number here was read off the hardware (the blob programming its own
// slots while it transmitted; `mac_snapshot::tx_watch` / `find_value`) or
// agrees with the S3's working port:
//
//   * the slots are at 0x600a4d20, four words each, stride 16; the blob
//     uses slot 4, which is why the P1b map found `mac_tx_set_plcp0` at
//     0x600a4d6c (slot 4 + 0xc);
//   * `config` (+0x8) read 0x020023ff: AIFSN 2, timeout 0x3ff, and the
//     middle bits a random backoff that changed on every send;
//   * `plcp0` (+0xc) read 0x0061e060, whose low 20 bits are a descriptor in
//     RAM (0x4081e060) -- the S3's plcp0 holds the descriptor the same way,
//     with valid at bit 30 and enable at bit 31;
//   * `conf1` (+0x4), the PPDU, stayed 0 for the basic rate;
//   * NO register tracked the frame's length across 60/100/150/200/250-byte
//     frames (`find_value` over the MAC's whole 4 KB), so the length is in
//     the DESCRIPTOR, as it is on the receive side.
/// The transmit slots: base, stride, and the slot the blob itself uses.
const TX_SLOT_BASE: u32 = 0x600a_4d20;
const TX_SLOT_STRIDE: u32 = 0x10;
const TX_SLOT: u32 = 4;
/// Slot words.
const TX_CONF1: u32 = 0x4;
const TX_CONFIG: u32 = 0x8;
const TX_PLCP0: u32 = 0xc;
/// Whether the queues' status is cleared before arming (`JANUS_TX_NOCLEAR`
/// turns it off): the two `_clear` registers are named from the S3's map,
/// and the C6's `0x600a4ca4` reads back `0x40` under the blob, which a
/// write-to-clear register should not. Switchable, so the clearing can be
/// ruled in or out rather than assumed.
const CLEAR_STATUS: bool = option_env!("JANUS_TX_NOCLEAR").is_none();
/// `plcp0`: the descriptor's low 20 bits, then valid and enable.
const TX_DMA_MASK: u32 = 0x000f_ffff;
/// Bits 21 and 22, which the blob sets in `plcp0` and we did not. They are
/// not part of the address: the blob's own `plcp0` reads `0x0061e068`, and
/// an address field wide enough to hold those bits would put the descriptor
/// at offset `0x61e068`, far outside the C6's 512 KB of SRAM. The blob
/// writes the word ONCE and never again -- only `config`'s backoff moves
/// per frame -- so this is its written value, not a status the hardware
/// left behind.
const TX_PLCP0_FLAGS: u32 = 0x0060_0000;
const TX_SLOT_VALID: u32 = 1 << 30;
const TX_SLOT_ENABLED: u32 = 1 << 31;
/// `config` as the blob leaves it: AIFSN 2, timeout 0x3ff (the backoff bits
/// are the hardware's to randomise).
const TX_CONFIG_VALUE: u32 = 0x0200_23ff;
/// The transmit queues' state, four registers as the S3's own map names
/// them. `0x600a4ca8` is NOT a "transmit block" as P4 first read it: it is
/// `tx_error_status`, and this firmware was WRITING to it. The pair of
/// `_clear` registers is what a driver writes; the pair of `_status`
/// registers is what it reads to learn a frame's fate, and
/// `tx_complete_status` answers "did the MAC transmit?" on this board
/// alone, with no second board listening.
const TXQ_ERROR_CLEAR: u32 = 0x600a_4ca4;
const TXQ_ERROR_STATUS: u32 = 0x600a_4ca8;
const TXQ_COMPLETE_CLEAR: u32 = 0x600a_4cac;
const TXQ_COMPLETE_STATUS: u32 = 0x600a_4cb0;

unsafe extern "C" {
    /// The PHY library's channel tuning (libphy; the S3's open MAC calls it
    /// the same way).
    fn chip_v7_set_chan(channel: u8, bandwidth: u8);
    /// The PHY's transmit power control, which the S3's port runs once
    /// every four frames. Never called here.
    ///
    /// Its neighbours in the S3's channel-change sequence,
    /// `disable_wifi_agc` and `enable_wifi_agc`, are NOT in the C6's
    /// libraries at all: declaring them leaves `rust-lld` with two
    /// undefined symbols even with `-lphy` and `-lpp` on the line
    /// (2026-10-08). The gain control cannot be the C6's missing step
    /// under those names.
    fn tx_pwctrl_background(a: u8, b: u8);
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

/// One frame on the air from `buf[..n]`, through slot [`TX_SLOT`]: the
/// descriptor armed as the S3's port arms its own (the length is the frame
/// plus the four octets of FCS the radio appends), the block cleared, the
/// slot marked valid and enabled, then the hardware's enable bit watched
/// until it clears. `Ok(())` when the hardware finished with it, `Err(())`
/// on a timeout.
/// The descriptor's first word as the hardware sees it: size, length, and
/// the flag bits (owner is the top one).
fn desc_word0(desc: &esp_hal::dma::DmaDescriptor) -> u32 {
    // SAFETY: a read of the descriptor's own first word, which is a plain
    // u32 at its start
    unsafe { core::ptr::read_volatile((desc as *const esp_hal::dma::DmaDescriptor).cast::<u32>()) }
}

fn transmit(desc: &mut esp_hal::dma::DmaDescriptor, buf: &mut [u8], n: usize) -> Result<u32, ()> {
    transmit_at(TX_SLOT_BASE + TX_SLOT * TX_SLOT_STRIDE, desc, buf, n)
}

/// As [`transmit`], for a NAMED slot address, so which slot the hardware
/// actually services can be found by trying each of them instead of being
/// inferred from a bit number in an undocumented status register.
fn transmit_at(
    slot: u32,
    desc: &mut esp_hal::dma::DmaDescriptor,
    buf: &mut [u8],
    n: usize,
) -> Result<u32, ()> {
    use esp_hal::dma::Owner;
    // the descriptor: the frame, and room for the FCS
    desc.set_size(n + 4);
    desc.set_length(n + 4);
    desc.set_owner(Owner::Dma);
    desc.set_suc_eof(true);
    desc.buffer = buf.as_mut_ptr();
    desc.next = core::ptr::null_mut();
    // the access parameters the blob uses. It writes `config` and `plcp0`
    // and nothing else per frame: `conf0` and `conf1` stay zero through a
    // whole beacon run, and the words that carry a length and a rate on the
    // S3 are, on the C6, written once at bring-up and never touched again.
    write(slot + TX_CONFIG, TX_CONFIG_VALUE);
    // the previous frame's verdict cleared, so what is read after this one
    // belongs to this one. Only our slot is ever armed, so every bit that
    // comes back is ours and the whole register can be cleared.
    if CLEAR_STATUS {
        write(TXQ_ERROR_CLEAR, !0);
        write(TXQ_COMPLETE_CLEAR, !0);
    }
    let address = (desc as *const esp_hal::dma::DmaDescriptor) as u32;
    write(
        slot + TX_PLCP0,
        (address & TX_DMA_MASK) | TX_PLCP0_FLAGS | TX_SLOT_VALID | TX_SLOT_ENABLED,
    );
    // the hardware clears the enable bit when it is done with the slot
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(50) {
        let plcp0 = read(slot + TX_PLCP0);
        if plcp0 & TX_SLOT_ENABLED == 0 {
            // the hardware is done with the slot; its own verdict on why
            return Ok(read(TXQ_COMPLETE_STATUS) | (read(TXQ_ERROR_STATUS) << 16));
        }
    }
    Err(())
}

fn tune(channel: u8) {
    unsafe {
        chip_v7_set_chan(channel, 0);
        // the S3's order around a channel change (`JANUS_TX_PHY`). Its
        // `set_mac_state` step is left out on purpose: that one clears bits
        // of CTRL at 0x600a4ca0, and CTRL reads zero under both stacks
        // here, so there is nothing for it to do on this chip.
        if PHY_TX {
            tx_pwctrl_background(1, 0);
        }
    }
}

/// Whether the PHY's gain and transmit-power control are started
/// (`JANUS_TX_PHY`).
const PHY_TX: bool = option_env!("JANUS_TX_PHY").is_some();

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

    // P4: frames on the air from our own MAC, in our own ESP-NOW layout, so
    // an independent receiver (the espnow relay on another board) counts
    // them with their signal strength -- the same harness E6's loss test
    // used. `JANUS_TX_SEND=count,gap_us,len`.
    // P4: WHICH slot does the hardware service? Every candidate address in
    // the slot array is armed in turn with the same frame, and the
    // descriptor's owner bit says whether the DMA engine read it. One line
    // a slot; no second board and no bit-layout guess involved.
    if option_env!("JANUS_TX_SWEEP").is_some() {
        let mut me = [0u8; 6];
        me.copy_from_slice(esp_hal::efuse::base_mac_address().as_bytes());
        for (address, value) in replay::TX_COLD {
            write(address, value);
        }
        let mut body = [0xa5u8; 64];
        body[..3].copy_from_slice(b"JBO");
        println!("P4 sweep base=0x600a4d10 stride=0x10 slots=0..12 (NOT Wi-Fi certified)");
        for k in 0..12u32 {
            let slot = 0x600a_4d10 + k * TX_SLOT_STRIDE;
            // SAFETY: single-threaded; the hardware owns the descriptor
            // only until the enable bit clears, which `transmit_at` awaits
            let (desc, buf) = unsafe { (&mut *(&raw mut TX_DESC), &mut *(&raw mut TX_BUF)) };
            let Some(n) =
                espnow_frame::write(buf, &espnow_frame::BROADCAST, &me, [0, 0, 0, 0], &body)
            else {
                continue;
            };
            let verdict = transmit_at(slot, desc, buf, n);
            let word0 = desc_word0(desc);
            match verdict {
                Ok(v) => println!(
                    "P4 slot 0x{slot:08x} k={k} complete={:04x} error={:04x} owner_dma={} eof={}",
                    v & 0xffff,
                    v >> 16,
                    word0 >> 31,
                    (word0 >> 30) & 1
                ),
                Err(()) => println!("P4 slot 0x{slot:08x} k={k} NEVER CLEARED owner_dma={}", word0 >> 31),
            }
        }
        println!("P4 sweep done");
    }

    if let Some(plan) = option_env!("JANUS_TX_SEND") {
        let mut fields = plan.split(',');
        let mut next = |fallback: u32| {
            fields
                .next()
                .and_then(|f| f.parse::<u32>().ok())
                .unwrap_or(fallback)
        };
        let (count, gap_us, body_len) = (next(200), next(20_000), next(64) as usize);
        let mut me = [0u8; 6];
        me.copy_from_slice(esp_hal::efuse::base_mac_address().as_bytes());
        // the transmit path's one-time arming, which the blob does on its
        // own first frame (replay::TX_COLD): without it the slot completes
        // and nothing radiates
        let mut stuck = 0u32;
        for (address, value) in replay::TX_COLD {
            write(address, value);
            // read back: a write that does not stick says this region is
            // not a register block we can configure, and TX_COLD is no
            // explanation for anything
            let got = read(address);
            if got == value {
                stuck += 1;
            } else if stuck + 1 == 0 || address < 0x600a_5030 {
                println!("P4 cold 0x{address:08x} wrote={value:08x} read={got:08x}");
            }
        }
        println!("P4 cold {stuck} of {} writes stuck", replay::TX_COLD.len());
        // the blob's whole observed configuration, in either half of the
        // MAC's block or both (`JANUS_TX_MATCH=low|high|both`)
        if let Some(which) = option_env!("JANUS_TX_MATCH") {
            let mut n = 0u32;
            if which != "high" {
                for (address, value) in replay::TX_MATCH_LOW {
                    write(address, value);
                    n += 1;
                }
            }
            if which != "low" {
                for (address, value) in replay::TX_MATCH_HIGH {
                    write(address, value);
                    n += 1;
                }
            }
            // TX_COLD again: TX_MATCH_HIGH's zeroing covers the same region
            for (address, value) in replay::TX_COLD {
                write(address, value);
            }
            println!("P4 match {which} {n} writes");
        }
        // the baseband settings below the MAC (`JANUS_TX_BB=n`)
        if let Some(n) = option_env!("JANUS_TX_BB") {
            let take: usize = match n.as_bytes() {
                [b] => (b - b'0') as usize,
                _ => replay::TX_BB.len(),
            };
            for (address, value) in replay::TX_BB.iter().take(take) {
                write(*address, *value);
                let got = read(*address);
                println!(
                    "P4 bb 0x{address:08x} wrote={value:08x} read={got:08x}{}",
                    if got == *value { "" } else { "  REFUSED" }
                );
            }
        }
        // the modem settings outside the MAC (`JANUS_TX_MODEM`)
        if option_env!("JANUS_TX_MODEM").is_some() {
            for (address, value) in replay::TX_MODEM {
                write(address, value);
                let got = read(address);
                println!(
                    "P4 modem 0x{address:08x} wrote={value:08x} read={got:08x}{}",
                    if got == value { "" } else { "  REFUSED" }
                );
            }
        }
        // the registers the blob sets and we do not (`JANUS_TX_EXTRA`)
        if option_env!("JANUS_TX_EXTRA").is_some() {
            let mut ok = 0u32;
            for (address, value) in replay::TX_EXTRA {
                write(address, value);
                if read(address) == value {
                    ok += 1;
                } else {
                    println!("P4 extra 0x{address:08x} wrote={value:08x} read={:08x}", read(address));
                }
            }
            println!("P4 extra {ok} of {} writes stuck", replay::TX_EXTRA.len());
        }
        let (mut sent, mut failed) = (0u32, 0u32);
        // the hardware's own verdicts, so the question "did it transmit?"
        // is answered on this board and not by a second one listening
        let (mut completed, mut errored) = (0u32, 0u32);
        let mut verdicts = [0u32; 4];
        println!("P4 transmit count={count} gap_us={gap_us} body={body_len} (NOT Wi-Fi certified)");
        for sequence in 0..count {
            // the body the relay counts. The tag is `O` for OUR MAC, where
            // the blob's generator sends `B`: the relay reports the tag it
            // heard, so a control run on the blob can never be read as a
            // frame of ours.
            let mut body = [0xa5u8; 250];
            body[..3].copy_from_slice(b"JBO");
            body[3..7].copy_from_slice(&sequence.to_be_bytes());
            let body = &body[..body_len.clamp(7, 250)];
            // SAFETY: single-threaded; the hardware owns the descriptor only
            // between arming and the enable bit clearing, which `transmit`
            // waits for
            let (desc, buf) = unsafe { (&mut *(&raw mut TX_DESC), &mut *(&raw mut TX_BUF)) };
            let Some(n) = espnow_frame::write(buf, &espnow_frame::BROADCAST, &me, [0, 0, 0, 0], body)
            else {
                failed += 1;
                continue;
            };
            match transmit(desc, buf, n) {
                Ok(verdict) => {
                    if (sequence as usize) < verdicts.len() {
                        verdicts[sequence as usize] = verdict;
                        // The descriptor's own word, AFTER the attempt. The
                        // DMA engine clears the owner bit when it has read
                        // the buffer, so an owner bit still set means the
                        // engine never touched our frame and the failure is
                        // upstream of the air entirely.
                        // Every nonzero word of the three windows, after
                        // ONE attempt of ours, each read TWICE back to back
                        // (`JANUS_TX_DUMP`). A register block read twice
                        // must read the same both times; where it does not,
                        // the word is a counter and not a setting, and the
                        // reading is no evidence about the blob at all.
                        if sequence == 0 && option_env!("JANUS_TX_DUMP").is_some() {
                            for (tag, again, base, words) in [
                                ("open", "again", 0x600a_4000, 2048),
                                ("openwide", "openwideagain", 0x600a_6000, 10240),
                                ("openlow", "openlowagain", 0x600a_0000, 4096),
                            ] {
                                mac_snapshot::dump_range(tag, base, words);
                                mac_snapshot::dump_range(again, base, words);
                            }
                        }
                        println!(
                            "P4 desc n={sequence} word0=0x{:08x} owner_dma={} len={} at=0x{:08x}",
                            desc_word0(desc),
                            desc_word0(desc) >> 31,
                            (desc_word0(desc) >> 12) & 0xfff,
                            (desc as *const esp_hal::dma::DmaDescriptor) as u32
                        );
                    }
                    if verdict & 0xffff != 0 {
                        completed += 1;
                    }
                    if verdict >> 16 != 0 {
                        errored += 1;
                    }
                    sent += 1;
                }
                Err(()) => failed += 1,
            }
            let until = Instant::now() + Duration::from_micros(u64::from(gap_us));
            while Instant::now() < until {}
        }
        println!(
            "P4 RESULT sent={sent} failed={failed} of {count};              tx_complete={completed} tx_error={errored};              first verdicts (complete|error<<16) {:08x} {:08x} {:08x} {:08x}",
            verdicts[0], verdicts[1], verdicts[2], verdicts[3]
        );
        // the MAC as OUR bring-up leaves it once we have armed and the
        // hardware has finished: the diff against the blob's `blobtx`
        // snapshot holds whatever enable we are missing
        let after = mac_snapshot::take(&mac_snapshot::C6_REGISTERS);
        mac_snapshot::print("ourtx", &mac_snapshot::C6_REGISTERS, &after);
    }

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
    let mut tally = e8::Tally::default();
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
                if E8_TALLY {
                    let end = (META_LEN + frame_len).min(BUFFER_SIZE);
                    tally.frame(&buffer[META_LEN..end], frame_len, buffer[META_RSSI] as i8);
                }
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
            if E8_TALLY {
                // the tally prints its own table
            } else if frames <= 6 || core::mem::take(&mut dump) {
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
            if E8_TALLY && beat % 3 == 0 {
                tally.report();
            }
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

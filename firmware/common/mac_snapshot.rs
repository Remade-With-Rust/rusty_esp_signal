//! `JANUS_MAC_SNAPSHOT` (experiments plan E5, P2's method): the Wi-Fi MAC's
//! registers as this firmware's radio stack left them, read back on the chip
//! and printed. What a bring-up must reproduce is observed on silicon from
//! the outside -- addresses and the values the hardware holds -- not read out
//! of anyone's code; the S3, where an open MAC already works, is the check of
//! the method (the blob's state against the open MAC's).
//!
//! Lines: `MACSNAP <stage> <address> <value>` for every nonzero register, then
//! `MACSNAP <stage> done read=<n> nonzero=<m>`. The S3's key slots are never
//! read, so no snapshot holds key material.

use esp_println::println;

/// The ESP32-S3's MAC (esp32s3-wifi-regs' `WIFI`, 0x6003_3000) up to its
/// power interrupt registers.
pub const S3_BASE: u32 = 0x6003_3000;
pub const S3_LEN: u32 = 0x2200;
/// The S3's key slots (0x1400..0x17e8): skipped.
pub const S3_SKIP: (u32, u32) = (0x6003_4400, 0x6003_47E8);

/// The ESP32-C6's MAC registers the blob uses: the 243 addresses of
/// `docs/plans/e5/c6-mac-registers.md` (generated from it), so nothing
/// outside the map is read.
pub const C6_REGISTERS: [u32; 243] = [
    0x600A4004, 0x600A400C, 0x600A4014, 0x600A4020, 0x600A4028, 0x600A402C, 0x600A4034, 0x600A4038,
    0x600A403C, 0x600A4040, 0x600A4044, 0x600A4048, 0x600A407C, 0x600A4080, 0x600A4084, 0x600A4088,
    0x600A408C, 0x600A4090, 0x600A4094, 0x600A4098, 0x600A409C, 0x600A40A0, 0x600A40E4, 0x600A40F4,
    0x600A40F8, 0x600A40FC, 0x600A4100, 0x600A4104, 0x600A410C, 0x600A4110, 0x600A4114, 0x600A4118,
    0x600A411C, 0x600A4120, 0x600A4124, 0x600A4128, 0x600A412C, 0x600A4130, 0x600A4134, 0x600A413C,
    0x600A4140, 0x600A4144, 0x600A4148, 0x600A414C, 0x600A4150, 0x600A4158, 0x600A415C, 0x600A4160,
    0x600A4164, 0x600A4168, 0x600A416C, 0x600A42B4, 0x600A42B8, 0x600A42BC, 0x600A42C0, 0x600A42C4,
    0x600A42C8, 0x600A42CC, 0x600A42D0, 0x600A42D4, 0x600A42FC, 0x600A4308, 0x600A4394, 0x600A43AC,
    0x600A43B4, 0x600A4400, 0x600A4408, 0x600A440C, 0x600A4410, 0x600A4414, 0x600A4418, 0x600A441C,
    0x600A4420, 0x600A4424, 0x600A4428, 0x600A442C, 0x600A4430, 0x600A4434, 0x600A4438, 0x600A4440,
    0x600A4444, 0x600A444C, 0x600A4450, 0x600A4458, 0x600A4470, 0x600A4474, 0x600A4800, 0x600A4804,
    0x600A4808, 0x600A480C, 0x600A4810, 0x600A4814, 0x600A4C1C, 0x600A4C20, 0x600A4C24, 0x600A4C2C,
    0x600A4C34, 0x600A4C38, 0x600A4C40, 0x600A4C48, 0x600A4C4C, 0x600A4C54, 0x600A4C58, 0x600A4C5C,
    0x600A4C60, 0x600A4C70, 0x600A4C78, 0x600A4C7C, 0x600A4C80, 0x600A4C84, 0x600A4C8C, 0x600A4C90,
    0x600A4C98, 0x600A4C9C, 0x600A4CA4, 0x600A4CA8, 0x600A4CB0, 0x600A4CB8, 0x600A4D64, 0x600A4D68,
    0x600A4D6C, 0x600A4DB4, 0x600A4DB8, 0x600A4DBC, 0x600A4DC0, 0x600A4DC4, 0x600A4DD0, 0x600A4DD4,
    0x600A4DD8, 0x600A4DDC, 0x600A4DE0, 0x600A4DE8, 0x600A4DF0, 0x600A4DF8, 0x600A5330, 0x600A53A4,
    0x600A5418, 0x600A548C, 0x600A6000, 0x600A6004, 0x600A6008, 0x600A7018, 0x600A702C, 0x600A7030,
    0x600A7044, 0x600A705C, 0x600A7068, 0x600A7094, 0x600A70A0, 0x600A7124, 0x600A7128, 0x600A713C,
    0x600A7400, 0x600A7424, 0x600A7428, 0x600A7438, 0x600A7808, 0x600A780C, 0x600A7848, 0x600A7890,
    0x600A78DC, 0x600A78E4, 0x600A790C, 0x600A7980, 0x600A7A28, 0x600A7C00, 0x600A7C30, 0x600A7C6C,
    0x600A7CA8, 0x600A7CD0, 0x600A8004, 0x600A8060, 0x600A9804, 0x600A980C, 0x600A9810, 0x600A9814,
    0x600A981C, 0x600AD000, 0x600AD010, 0x600AD014, 0x600AD018, 0x600AD01C, 0x600AD020, 0x600AD024,
    0x600AD02C, 0x600AD030, 0x600AD038, 0x600AD044, 0x600AD04C, 0x600AD050, 0x600AD054, 0x600AD058,
    0x600AD068, 0x600AD070, 0x600AD094, 0x600AD098, 0x600AD09C, 0x600AD0A0, 0x600AD0A4, 0x600AD0A8,
    0x600AD0B0, 0x600AD0B4, 0x600AF00C, 0x600AF010, 0x600AF014, 0x600AF018, 0x600AF020, 0x600AF818,
    0x600AF81C, 0x600AF820, 0x600AF824, 0x600AF828, 0x600AF82C, 0x600AFC00, 0x600AFC04, 0x600AFC08,
    0x600AFC0C, 0x600AFC10, 0x600AFC14, 0x600AFC18, 0x600AFC1C, 0x600AFC20, 0x600AFC24, 0x600AFC28,
    0x600AFC2C, 0x600AFC30, 0x600AFC34, 0x600AFC38, 0x600AFC3C, 0x600AFC40, 0x600AFC44, 0x600AFC48,
    0x600AFC4C, 0x600AFC50, 0x600AFC54, 0x600AFC58, 0x600AFC5C, 0x600AFC60, 0x600AFC64, 0x600AFC68,
    0x600AFC6C, 0x600AFC70, 0x600AFC74,
];

fn read(address: u32) -> u32 {
    // SAFETY: a 32-bit aligned read of a memory-mapped register in the Wi-Fi
    // MAC's window, after the radio stack has clocked the MAC.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// Every register in `base..base+len` (4-byte steps) but `skip`.
pub fn window(stage: &str, base: u32, len: u32, skip: (u32, u32)) {
    let (mut read_n, mut nonzero) = (0u32, 0u32);
    let mut a = base;
    while a < base + len {
        if !(skip.0..skip.1).contains(&a) {
            let v = read(a);
            read_n += 1;
            if v != 0 {
                nonzero += 1;
                println!("MACSNAP {stage} 0x{a:08x} 0x{v:08x}");
            }
        }
        a += 4;
    }
    println!("MACSNAP {stage} done read={read_n} nonzero={nonzero}");
}

/// The listed registers.
pub fn list(stage: &str, addresses: &[u32]) {
    print(stage, addresses, &take(addresses));
}

/// The listed registers read, all of them before any is printed: interleaved
/// with the prints the reads spread over most of a second beside the radio's
/// driver, and the C6 reset part-way through (2026-10-07).
pub fn take(addresses: &[u32]) -> [u32; 256] {
    let mut values = [0u32; 256];
    for (v, &a) in values.iter_mut().zip(addresses) {
        *v = read(a);
    }
    values
}

/// A reading from [`take`] printed: one `MACSNAP` line per nonzero register,
/// then `done`. Printed again later by a firmware whose serial reader may join
/// after boot (the C6 DevKitC's bridge loses what is printed between
/// sessions), the same reading each time.
pub fn print(stage: &str, addresses: &[u32], values: &[u32; 256]) {
    let n = addresses.len().min(values.len());
    let mut nonzero = 0u32;
    for (&a, &v) in addresses[..n].iter().zip(&values[..n]) {
        if v != 0 {
            nonzero += 1;
            println!("MACSNAP {stage} 0x{a:08x} 0x{v:08x}");
        }
    }
    println!("MACSNAP {stage} done read={n} nonzero={nonzero}");
}

/// E5's P4: the MAC's TRANSMIT slots, watched while the radio stack
/// transmits, so the layout and the encodings are read off the hardware
/// instead of guessed. Base and stride agree with two independent sources:
/// the P1b register map put `mac_tx_set_plcp0` at `0x600a4d6c` and
/// `hal_mac_tx_config_edca` / `hal_mac_tx_config_timeout` at `0x600a4d68`,
/// which is slot 4's `plcp0` (+0xc) and `config` (+0x8) under a base of
/// `0x600a4d20` with a stride of 16 -- the layout the public C6 research
/// documents. Four words a slot: conf0, conf1 (the PPDU, per
/// `hal_mac_tx_set_ppdu`), config (EDCA timeout and backoff), plcp0.
pub const TX_SLOT_BASE: u32 = 0x600a_4d20;
/// Slots watched (the array's length is not documented; six covers it and
/// a word that never moves says so).
pub const TX_SLOTS: usize = 6;
/// The modem-PM transmit block: an armed frame does not launch while this
/// holds (the public research reads `0x00ff1000` here).
pub const TX_BLOCK: u32 = 0x600a_4ca8;

const TX_WORDS: usize = TX_SLOTS * 4 + 1;
static mut TX_PREV: [u32; TX_WORDS] = [0; TX_WORDS];

/// Every transmit-slot word that CHANGED since the last call, printed as
/// `TXWATCH <tag> <address> <slot>.<word> <old> -> <new>`. The first call
/// reports whatever is set, which is the state the stack left at rest.
pub fn tx_watch(tag: &str) {
    const WORDS: [&str; 4] = ["conf0", "conf1", "config", "plcp0"];
    let mut now = [0u32; TX_WORDS];
    for (i, slot) in now.iter_mut().enumerate().take(TX_SLOTS * 4) {
        *slot = read(TX_SLOT_BASE + (i as u32) * 4);
    }
    now[TX_SLOTS * 4] = read(TX_BLOCK);
    // SAFETY: single-threaded, and the watcher is the only user
    let prev = unsafe { *(&raw const TX_PREV) };
    for (i, (&was, &is)) in prev.iter().zip(now.iter()).enumerate() {
        if was == is {
            continue;
        }
        if i == TX_SLOTS * 4 {
            println!("TXWATCH {tag} 0x{TX_BLOCK:08x} txblock {was:08x} -> {is:08x}");
        } else {
            let address = TX_SLOT_BASE + (i as u32) * 4;
            println!(
                "TXWATCH {tag} 0x{address:08x} slot{}.{} {was:08x} -> {is:08x}",
                i / 4,
                WORDS[i % 4]
            );
        }
    }
    unsafe { *(&raw mut TX_PREV) = now };
}

/// A WINDOW of the MAC watched for changes, for finding a register whose
/// value tracks something we vary (E5's P4: the frame's length and its
/// rate are not in the transmit slot, so they are somewhere else).
pub const WATCH_BASE: u32 = 0x600a_4c00;
pub const WATCH_WORDS: usize = 128;
static mut WINDOW_PREV: [u32; WATCH_WORDS] = [0; WATCH_WORDS];

/// Every word of the window that changed since the last call.
pub fn window_watch(tag: &str) {
    let mut now = [0u32; WATCH_WORDS];
    for (i, w) in now.iter_mut().enumerate() {
        *w = read(WATCH_BASE + (i as u32) * 4);
    }
    // SAFETY: single-threaded, and the watcher is the only user
    let prev = unsafe { *(&raw const WINDOW_PREV) };
    for (i, (&was, &is)) in prev.iter().zip(now.iter()).enumerate() {
        if was != is {
            let address = WATCH_BASE + (i as u32) * 4;
            println!("WINWATCH {tag} 0x{address:08x} {was:08x} -> {is:08x}");
        }
    }
    unsafe { *(&raw mut WINDOW_PREV) = now };
}

/// Search the whole MAC window for a value, so "where does the frame's
/// length go?" is answered by the hardware rather than by guessing: after a
/// frame of known length, any register holding that number (whole, or in
/// either half) is printed. A register that matches for EVERY length is
/// the length's; one that matches once is a coincidence.
pub fn find_value(tag: &str, needles: &[u32]) {
    const BASE: u32 = 0x600a_4000;
    // 16 KB. The first pass stopped at 4 KB and so could never have seen the
    // length: on the S3 the word that carries it is 0x11c8 past the block.
    const WORDS: usize = 4096;
    for i in 0..WORDS {
        let address = BASE + (i as u32) * 4;
        let word = read(address);
        let (low, high) = (word & 0xffff, word >> 16);
        for &n in needles {
            // a length is PACKED with the rate beside it, so the low twelve
            // bits count as a match too
            if word == n || low == n || high == n {
                println!("FOUND {tag} need={n} 0x{address:08x} {word:08x}");
            } else if word & 0xfff == n && n != 0 {
                println!("FOUND12 {tag} need={n} 0x{address:08x} {word:08x}");
            }
        }
    }
}

/// E5's P4: the per-slot words a transmit needs that do NOT live in the
/// transmit slot. The S3's open port writes four of them for every frame --
/// `plcp1` (the frame's LENGTH and its rate), `ht_sig`, `plcp2` (the rate the
/// hardware answers at) and `duration` -- and reads a fifth, `pmd`, for the
/// MAC protocol's verdict. There they sit at `0x11c8` and up from the MAC
/// block with a stride of 76 bytes a slot. This reads the same offsets of the
/// C6's block, so what the blob puts there for a frame of KNOWN length is
/// observed rather than assumed: the word whose low twelve bits are that
/// length (plus the four of the FCS) is the C6's `plcp1`.
pub const PLCP_BASE: u32 = 0x600a_51c8;
pub const PLCP_STRIDE: u32 = 76;

/// The per-slot region watched for CHANGES instead of for a guessed value:
/// the blob's frames differ in length by a known amount, so the word that
/// carries the length is the one whose value moves by that amount. This
/// answers both halves at once -- which word, and what else it packs
/// beside the length -- without having to know what ESP-NOW's headers
/// add to a payload.
pub const PLCP_WATCH_BASE: u32 = 0x600a_5000;
pub const PLCP_WATCH_WORDS: usize = 256; // 1 KB: the nine slot entries
static mut PLCP_PREV: [u32; PLCP_WATCH_WORDS] = [0; PLCP_WATCH_WORDS];

pub fn plcp_watch(tag: &str, len: u32) {
    let mut now = [0u32; PLCP_WATCH_WORDS];
    for (i, w) in now.iter_mut().enumerate() {
        *w = read(PLCP_WATCH_BASE + (i as u32) * 4);
    }
    // SAFETY: single-threaded, and the watcher is the only user
    let prev = unsafe { *(&raw const PLCP_PREV) };
    for (i, (&was, &is)) in prev.iter().zip(now.iter()).enumerate() {
        if was != is {
            let address = PLCP_WATCH_BASE + (i as u32) * 4;
            // the low twelve bits are where a length would sit
            let delta = (is & 0xfff) as i32 - (was & 0xfff) as i32;
            println!("PLCPWATCH {tag} len={len} 0x{address:08x} {was:08x} -> {is:08x} d12={delta}");
        }
    }
    unsafe { *(&raw mut PLCP_PREV) = now };
}

/// The five words of every slot, with the length each is tested against.
pub fn plcp_probe(tag: &str, len: u32) {
    const WORDS: [(u32, &str); 5] = [
        (0x00, "plcp1"),
        (0x08, "htsig"),
        (0x1c, "plcp2"),
        (0x20, "duration"),
        (0x28, "pmd"),
    ];
    for slot in 0..TX_SLOTS as u32 {
        for (offset, name) in WORDS {
            let address = PLCP_BASE + slot * PLCP_STRIDE + offset;
            let word = read(address);
            if word == 0 {
                continue;
            }
            // the length as the hardware carries it: the MPDU plus its FCS
            let hit = if word & 0xfff == len + 4 { " <= LEN+4" } else { "" };
            println!("PLCP {tag} len={len} 0x{address:08x} slot{slot}.{name} {word:08x}{hit}");
        }
    }
}

/// EVERY nonzero word of a range, with no address list in the way. P4's
/// first comparison ran against `C6_REGISTERS`, a map of 243 addresses that
/// holds nothing in `0x600a5000`..`0x600a6000` -- so it reported "no
/// register the blob sets that we do not" while being blind to the 54 words
/// of [`crate::replay::TX_COLD`]. A dump with no filter cannot be blind in
/// that way: whatever the blob sets and we do not is in the difference.
pub fn dump_range(tag: &str, base: u32, words: usize) {
    for i in 0..words {
        let address = base + (i as u32) * 4;
        let word = read(address);
        if word != 0 {
            println!("DUMP {tag} 0x{address:08x} {word:08x}");
        }
    }
    println!("DUMP {tag} done words={words}");
}

/// The transmit queues' four state words, as the S3's map names them:
/// `tx_error_clear`, `tx_error_status`, `tx_complete_clear`,
/// `tx_complete_status`. P4 read `0x600a4ca8` as a "transmit block" and
/// wrote to it; it is the error status. Printed for the blob's frames and
/// for ours, the four tell us what SUCCESS looks like on this chip instead
/// of what it looks like on the S3.
pub const TXQ_STATE_BASE: u32 = 0x600a_4ca4;

pub fn txq_state(tag: &str) {
    const WORDS: [&str; 4] = ["err_clear", "err_status", "cmp_clear", "cmp_status"];
    let mut line = [0u32; 4];
    for (i, w) in line.iter_mut().enumerate() {
        *w = read(TXQ_STATE_BASE + (i as u32) * 4);
    }
    println!(
        "TXQ {tag} {}={:08x} {}={:08x} {}={:08x} {}={:08x}",
        WORDS[0], line[0], WORDS[1], line[1], WORDS[2], line[2], WORDS[3], line[3]
    );
}

/// Whether this build watches the transmit slots (`JANUS_TX_WATCH`).
pub const TX_WATCH: bool = option_env!("JANUS_TX_WATCH").is_some();

/// Whether this build takes snapshots (`JANUS_MAC_SNAPSHOT` set at build time).
pub const ON: bool = option_env!("JANUS_MAC_SNAPSHOT").is_some();

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
    let mut nonzero = 0u32;
    for &a in addresses {
        let v = read(a);
        if v != 0 {
            nonzero += 1;
            println!("MACSNAP {stage} 0x{a:08x} 0x{v:08x}");
        }
    }
    println!(
        "MACSNAP {stage} done read={} nonzero={nonzero}",
        addresses.len()
    );
}

/// Whether this build takes snapshots (`JANUS_MAC_SNAPSHOT` set at build time).
pub const ON: bool = option_env!("JANUS_MAC_SNAPSHOT").is_some();

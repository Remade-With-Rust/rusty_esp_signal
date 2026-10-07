//! The S3's TSF registers (OpenSensor's `docs/esp32s3/REVIEW.md`, from the
//! blob's `hal_tsf.o` and `hal_mac.o`; E3's P1), and the soft access point's
//! clock found on the board in P3: the latch `CTRL` bit 1.
// shared by the P3 probe and P4's access point, each using part of it

// The S3's soft-AP TSF registers, found on the bench (E3's P3), are not in
// the PAC: they are read and written volatile here, the one place this crate
// touches memory-mapped hardware on its own. The register map's constants
// are kept whole as the record of what was found.
#![allow(unsafe_code, dead_code)]

pub const BASE: usize = 0x6003_5000;
pub const CTRL: usize = 0x6003_500c;
pub const LOAD_LOW: usize = 0x6003_5010;
pub const LOAD_HIGH: usize = 0x6003_5014;
pub const READ_LOW: usize = 0x6003_5018;
pub const READ_HIGH: usize = 0x6003_501c;
/// The station's TSF: enable bits 31, 28, 27 (`hal_enable_sta_tsf`).
pub const STA_CFG: usize = 0x6003_5028;
/// The soft access point's TSF: enable bits 31, 30
/// (`hal_disable_softap_tsf` clears them).
pub const AP_CFG: usize = 0x6003_5034;

pub fn read(address: usize) -> u32 {
    // SAFETY: an aligned read inside the MAC block, clocked with the radio
    unsafe { (address as *const u32).read_volatile() }
}
pub fn write(address: usize, value: u32) {
    // SAFETY: as `read`; the probe owns the MAC's TSF
    unsafe { (address as *mut u32).write_volatile(value) }
}

/// The TSF through latch `bit` of the control word: (high, low).
pub fn latched(bit: u32) -> (u32, u32) {
    write(CTRL, read(CTRL) | bit);
    let high = read(READ_HIGH);
    let low = read(READ_LOW);
    write(CTRL, read(CTRL) & !bit);
    (high, low)
}

/// The counter the MAC stamps beacons with (latch `CTRL` bit 0, "a counter
/// from boot" in P3) is loaded from the load words by `CTRL` bit 4 (found on
/// the XIAO, 2026-10-07; bit 3 does nothing). Beacons are scheduled by the
/// soft access point's clock but go out with this one's time: left at its
/// boot value it sat 75 ms of phase away, so a dozing station woke for each
/// beacon 75 ms early, and a rebooted access point's beacons still ran
/// backwards whatever the soft-AP clock was loaded with (E3, the C6
/// sniffer).
pub const LOAD_STAMP: u32 = 0x10;

/// The soft access point's TSF (latch `CTRL` bit 1, found on the board).
pub fn access_point() -> u64 {
    let (high, low) = latched(2);
    (u64::from(high) << 32) | u64::from(low)
}

/// Start the soft access point's TSF from 0, as the blob's
/// `hal_mac_tsf_reset(0)` does: enable off, the load words 0, the load
/// bit (`CTRL` bit 5), enable on.
pub fn start_access_point_clock() {
    start_access_point_clock_at(0);
}

/// Start the soft access point's TSF at `start_us` (E3's R1: from a clock
/// that survives a reset, so a rebooted access point's TSF does not run
/// backwards; a client's driver ignored a BSSID whose TSF had restarted).
pub fn start_access_point_clock_at(start_us: u64) {
    write(AP_CFG, read(AP_CFG) & 0x3fff_ffff);
    write(LOAD_LOW, start_us as u32);
    write(LOAD_HIGH, (start_us >> 32) as u32);
    write(CTRL, read(CTRL) | 0x20);
    write(AP_CFG, read(AP_CFG) | 0xc000_0000);
}

/// The counter beacons are stamped with (latch bit 0).
pub fn stamp() -> u64 {
    let (high, low) = latched(1);
    (u64::from(high) << 32) | u64::from(low)
}

/// The stamping clock set to the soft access point's: loaded at the clock's
/// start it did not hold (34,556 s apart a minute later: the MAC's bring-up
/// comes after), loaded once the access point runs it does, to within the
/// reads' 10 us (2026-10-07).
pub fn sync_stamp() {
    let now = access_point();
    write(LOAD_LOW, now as u32);
    write(LOAD_HIGH, (now >> 32) as u32);
    write(CTRL, read(CTRL) | LOAD_STAMP);
    write(CTRL, read(CTRL) & !LOAD_STAMP);
}

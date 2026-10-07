//! The C6 MAC's configuration as the chip held it after esp-radio's own
//! bring-up (station, ESP-NOW on), read back from silicon by
//! `firmware/common/mac_snapshot.rs` (E5, 2026-10-07): addresses and
//! values, observed, and the same on two C6-DevKitC-1 boards. Only the
//! MAC's blocks (0x600A4000-0x600A5FFF and the timer block at
//! 0x600AD000); the PHY's, the I2C master's and the modem clocks'
//! registers are written by esp-phy and esp-hal. Left out:
//!
//! - `0x600a4004`: the station's beacon filter: its low half is the board's own address (two bytes); per board
//! - `0x600a4080`: receive control: enabled last, by this firmware
//! - `0x600a4084`: ring base: this firmware's ring
//! - `0x600a4088`: ring next (the hardware's)
//! - `0x600a408c`: ring last (the hardware's)
//! - `0x600a4090`: ring record (the hardware's)
//! - `0x600a4094`: ring record (the hardware's)
//! - `0x600a43ac`: receive record (the hardware's)
//! - `0x600a43b4`: receive record (the hardware's)
//! - `0x600ad000`: the MAC timer (a counter)

/// (address, value), in ascending address order.
pub const MAC_CONFIG: [(u32, u32); 104] = [
    (0x600a400c, 0x40000000),
    (0x600a4020, 0x1801fe00),
    (0x600a402c, 0x1801fe00),
    (0x600a4038, 0x007fe800),
    (0x600a403c, 0x00800800),
    (0x600a4048, 0x000001f0),
    (0x600a407c, 0x10000000),
    (0x600a4098, 0x08280101),
    (0x600a409c, 0x00000008),
    (0x600a40a0, 0x3a064000),
    (0x600a40e4, 0x0001c385),
    (0x600a40f4, 0x00078600),
    (0x600a40f8, 0x05000000),
    (0x600a40fc, 0x05000000),
    (0x600a410c, 0xa0180820),
    (0x600a4110, 0x000000ff),
    (0x600a4114, 0x81b00000),
    (0x600a4118, 0x000000ff),
    (0x600a411c, 0x00003f7e),
    (0x600a4120, 0x00023006),
    (0x600a4124, 0x00023006),
    (0x600a4128, 0x00023006),
    (0x600a412c, 0x0002301c),
    (0x600a4130, 0x0002301c),
    (0x600a4134, 0x00023011),
    (0x600a413c, 0x00000608),
    (0x600a4140, 0x00000808),
    (0x600a4144, 0x00008e88),
    (0x600a4148, 0x44004300),
    (0x600a414c, 0x43004400),
    (0x600a4150, 0x00000001),
    (0x600a4158, 0x0000ffff),
    (0x600a415c, 0x0000ffff),
    (0x600a4160, 0x0000ffff),
    (0x600a4164, 0xffffffff),
    (0x600a4168, 0xffffffff),
    (0x600a416c, 0x000000ff),
    (0x600a42cc, 0x00000020),
    (0x600a42d0, 0xfefe0646),
    (0x600a42d4, 0x4fe3f8fe),
    (0x600a4308, 0x00000002),
    (0x600a4400, 0xc1cb3754),
    (0x600a4408, 0x00000514),
    (0x600a440c, 0x00010514),
    (0x600a4410, 0x00050514),
    (0x600a4414, 0x000b0511),
    (0x600a4418, 0x000a0512),
    (0x600a441c, 0x00090512),
    (0x600a4420, 0x00900512),
    (0x600a4424, 0x00910512),
    (0x600a4428, 0x00920512),
    (0x600a442c, 0x00920512),
    (0x600a4430, 0x05050505),
    (0x600a4434, 0x05050505),
    (0x600a4438, 0x05050505),
    (0x600a4440, 0x00090a0b),
    (0x600a4444, 0x00050100),
    (0x600a444c, 0x00090a0b),
    (0x600a4450, 0x00050100),
    (0x600a4458, 0x04081020),
    (0x600a4470, 0x00801000),
    (0x600a4474, 0x80000000),
    (0x600a4800, 0x00030000),
    (0x600a4804, 0x00030000),
    (0x600a4c1c, 0xc0000011),
    (0x600a4c20, 0x800000f0),
    (0x600a4c24, 0x000000f0),
    (0x600a4c40, 0x19a879e0),
    (0x600a4c54, 0x1409d800),
    (0x600a4c58, 0x0bd234a0),
    (0x600a4c60, 0xffff2710),
    (0x600a4c70, 0x40800000),
    (0x600a4c78, 0x001d7120),
    (0x600a4c7c, 0x10823c00),
    (0x600a4c80, 0x28010be0),
    (0x600a4c84, 0x0e7c0000),
    (0x600a4c8c, 0xb3c8bf2c),
    (0x600a4c98, 0x00000014),
    (0x600a4c9c, 0x00000003),
    (0x600a4ca4, 0x00000040),
    (0x600a4db8, 0x00040000),
    (0x600a4dbc, 0x00040000),
    (0x600a4dc0, 0x00040000),
    (0x600a4dc4, 0x00040000),
    (0x600a4dd0, 0x000a00a0),
    (0x600a4dd4, 0x000022b6),
    (0x600a4dd8, 0x00000071),
    (0x600a4ddc, 0x00000001),
    (0x600a4de0, 0x0103e950),
    (0x600a5330, 0x00020000),
    (0x600a53a4, 0x00020000),
    (0x600a5418, 0x00020000),
    (0x600a548c, 0x00020000),
    (0x600ad030, 0x0cf10a00),
    (0x600ad038, 0x000001ff),
    (0x600ad044, 0x00000028),
    (0x600ad04c, 0x000001ff),
    (0x600ad050, 0x88080000),
    (0x600ad054, 0x00000064),
    (0x600ad058, 0x08000000),
    (0x600ad068, 0x08000000),
    (0x600ad09c, 0x04040404),
    (0x600ad0a0, 0xffff0000),
    (0x600ad0a4, 0x00000100),
];

/// Registers the blob's bring-up leaves at zero whose power-on value is not
/// zero: read after this firmware's first bring-up, `0x87800000`,
/// `0x87800000` and `0x003fffc0` (P2's comparison, 2026-10-07).
pub const MAC_CLEARED: [u32; 3] = [0x600a_4100, 0x600a_4104, 0x600a_4810];

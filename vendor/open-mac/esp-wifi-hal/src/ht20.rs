//! C3/S3 HT20 encodings checked against `mac_tx_set_plcp1` and `mac_tx_set_htsig`.
//! Keep these independent of MMIO so the encoding boundaries can be tested on a host.

pub(crate) const fn ht_rate(mcs: u8, short_gi: bool) -> u8 {
    assert!(mcs < 8);
    0x10 + mcs + 8 * short_gi as u8
}

pub(crate) const fn ht_sig(mcs: u8, short_gi: bool, length: usize) -> u32 {
    assert!(mcs < 8);
    // Bit 7 is not the short-GI bit on C3/S3. The blob selects 0x87/0x07 in
    // the high byte for rate codes 24..31/16..23 respectively (HT20, no STBC).
    mcs as u32 | ((length as u32 & 0xffff) << 8) | 0x07000000 | ((short_gi as u32) << 31)
}

pub(crate) const fn tx_misc(current: u32, response_rate: u8, interface: usize) -> u32 {
    assert!(interface < 4);
    (current & !((0xff << 6) | (0x3 << 28)))
        | (1 << 5)
        | ((response_rate as u32) << 6)
        | ((interface as u32) << 28)
}

/// PLCP1 for a C3/S3 transmission, as `mac_tx_set_plcp1` of the ESP32-S3
/// blob writes it. LEN 0..11, RATE 12..16, KEY_SLOT_ID 17..21, the HT bit
/// at 25. Bits 30:31 stay clear: the S3 blob never sets them (the S2 blob
/// is the one that puts the interface there). The interface itself is
/// PLCP2 bits 28:29, written by [`tx_misc`], which is where
/// `mac_tx_set_txop_q` puts it.
///
/// A keyed frame on an odd interface also sets bit 29. The blob sets that
/// bit when the descriptor's interface id has its low bit set and the
/// frame carries a key. Interface 0 never does, so its word is unchanged.
pub(crate) const fn tx_plcp1(
    frame_length: u32,
    hardware_rate: u32,
    key_slot: u32,
    ht: bool,
    interface: usize,
    keyed: bool,
) -> u32 {
    assert!(interface < 4);
    let odd_interface = interface & 1 == 1;
    (frame_length & 0xfff)
        | ((hardware_rate & 0x1f) << 12)
        | ((key_slot & 0x1f) << 17)
        | ((ht as u32) << 25)
        | if keyed && odd_interface { 1 << 29 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_and_short_gi_use_disjoint_rate_ranges() {
        for mcs in 0..8 {
            assert_eq!(ht_rate(mcs, false), 16 + mcs);
            assert_eq!(ht_rate(mcs, true), 24 + mcs);
        }
    }

    #[test]
    fn short_gi_only_changes_the_high_sig_bit() {
        assert_eq!(ht_sig(0, false, 1500), 0x0705dc00);
        assert_eq!(ht_sig(7, true, 1500), 0x8705dc07);
        for mcs in 0..8 {
            for length in [0, 24, 1500, 4095, 65535] {
                let long = ht_sig(mcs, false, length);
                let short = ht_sig(mcs, true, length);
                assert_eq!(long ^ short, 1 << 31);
                assert_eq!(short & (1 << 7), 0);
                assert_eq!((short >> 8) & 0xffff, length as u32);
            }
        }
    }

    #[test]
    fn replacing_response_and_interface_preserves_other_slot_bits() {
        let changed = (0xff << 6) | (3 << 28) | (1 << 5);
        for current in [0, u32::MAX, 0x00400020, 0xa5a5a5a5] {
            for interface in 0..4 {
                for rate in [0, 3, 9, 11] {
                    let value = tx_misc(current, rate, interface);
                    assert_eq!(value & !changed, current & !changed);
                    assert_eq!((value >> 6) & 0xff, rate as u32);
                    assert_eq!((value >> 28) & 3, interface as u32);
                    assert_ne!(value & (1 << 5), 0);
                }
            }
        }
    }

    #[test]
    fn plcp1_follows_the_s3_blob() {
        let open = tx_plcp1(1500, 0x1b, 7, true, 1, false);
        assert_eq!(open & 0xfff, 1500);
        assert_eq!((open >> 12) & 0x1f, 0x1b);
        assert_eq!((open >> 17) & 0x1f, 7);
        assert_eq!((open >> 25) & 1, 1);
        // bits 29:31 stay clear on an open frame, and on interface 0 even
        // when a key is used
        assert_eq!(open >> 29, 0);
        assert_eq!(tx_plcp1(1500, 0x1b, 7, true, 0, true) >> 29, 0);
        // a keyed frame on interface 1 sets bit 29 and leaves 30:31 clear
        let keyed = tx_plcp1(1500, 0x1b, 7, true, 1, true);
        assert_eq!(keyed >> 29, 1);
        assert_eq!(keyed & !(1 << 29), open);
        assert_eq!(tx_plcp1(24, 0, 24, false, 2, true) >> 29, 0);
        assert_eq!(tx_plcp1(24, 0, 24, false, 3, true) >> 29, 1);
    }
}

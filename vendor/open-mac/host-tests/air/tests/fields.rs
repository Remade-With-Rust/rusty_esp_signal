//! Fields read from raw bytes laid out by hand from 802.11-2020, not by
//! `ieee80211`'s own serialisers: a test that round-trips through the crate
//! agrees with itself even where the crate is wrong (E2's F13 passed the
//! simulated access point because both sides read the Key RSC big-endian).

use ieee80211::crypto::CryptoHeader;
use ieee80211::crypto::eapol::EapolKeyFrame;
use ieee80211::elements::rsn::IEEE80211AkmType;
use ieee80211::scroll::Pread;

/// An EAPOL-Key frame (from its version byte) with this Key RSC field.
fn key_frame_with_rsc(rsc: [u8; 8]) -> Vec<u8> {
    let mut e = vec![2, 3, 0, 95, 2];
    e.extend_from_slice(&0x13cau16.to_be_bytes()); // key information
    e.extend_from_slice(&16u16.to_be_bytes()); // key length
    e.extend_from_slice(&2u64.to_be_bytes()); // replay counter: big-endian
    e.extend_from_slice(&[0x11; 32]); // nonce
    e.extend_from_slice(&[0; 16]); // IV
    e.extend_from_slice(&rsc); // RSC: the PN's octets, PN0 first
    e.extend_from_slice(&[0; 8]); // reserved
    e.extend_from_slice(&[0; 16]); // MIC
    e.extend_from_slice(&0u16.to_be_bytes()); // key data length
    e
}

#[test]
fn the_key_rsc_is_the_group_packet_number_little_endian() {
    // F13: the access point's group counter at 5 (and at 0x0102_0304_0506)
    let f = key_frame_with_rsc([5, 0, 0, 0, 0, 0, 0, 0]);
    let k = f
        .pread_with::<EapolKeyFrame>(0, IEEE80211AkmType::Psk)
        .unwrap();
    assert_eq!(k.key_rsc, 5);
    assert_eq!(k.key_replay_counter, 2);
    let f = key_frame_with_rsc([6, 5, 4, 3, 2, 1, 0, 0]);
    let k = f
        .pread_with::<EapolKeyFrame>(0, IEEE80211AkmType::Psk)
        .unwrap();
    assert_eq!(k.key_rsc, 0x0102_0304_0506);
}

#[test]
fn the_ccmp_header_key_id_is_its_top_two_bits() {
    // F14: PN0, PN1, reserved, key ID byte (Ext IV bit 5, key ID bits 6-7), PN2..PN5
    for key_id in 0..4u8 {
        let h = [0x34, 0x12, 0, 0x20 | (key_id << 6), 0x78, 0x56, 0, 0];
        let c = h.pread::<CryptoHeader>(0).unwrap();
        assert_eq!(c.key_id(), key_id);
        assert_eq!(c.packet_number(), 0x5678_1234);
    }
}

#[test]
fn a_ccmp_header_out_of_range_is_not_made() {
    // F14: either value out of range refuses
    assert!(CryptoHeader::new(1, 3).is_some());
    assert!(CryptoHeader::new(1, 4).is_none());
    assert!(CryptoHeader::new(CryptoHeader::MAX_PN + 1, 0).is_none());
}

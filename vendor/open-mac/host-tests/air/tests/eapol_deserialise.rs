//! `ieee80211::crypto::deserialize_eapol_data_frame` on frames anyone on
//! the channel can send: during the 4-way handshake the station feeds every
//! EAPOL-typed data frame from the access point's address to it, message 1
//! with no key at all. Whatever the frame says, the answer is an `Err`,
//! never a panic.

use std::panic::{AssertUnwindSafe, catch_unwind};

use ieee80211::crypto::deserialize_eapol_data_frame;
use ieee80211::elements::rsn::IEEE80211AkmType;

/// A data frame from the access point (from-DS), LLC/SNAP for EAPOL, then
/// `eapol` as the EAPOL frame.
fn frame(eapol: &[u8]) -> Vec<u8> {
    let mut f = vec![0x08, 0x02, 0, 0];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // address 1: the station
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // address 2: the access point
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // address 3
    f.extend_from_slice(&[0, 0]); // sequence control
    f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e]);
    f.extend_from_slice(eapol);
    f
}

/// An EAPOL-Key frame's fixed 99 bytes: key information `info`, the key
/// data length field `key_data_len`, then `key_data`.
fn key_frame(info: u16, key_data_len: u16, key_data: &[u8]) -> Vec<u8> {
    let mut e = vec![2, 3];
    let body_len = (95 + key_data.len()) as u16;
    e.extend_from_slice(&body_len.to_be_bytes());
    e.push(2); // descriptor: RSN
    e.extend_from_slice(&info.to_be_bytes());
    e.extend_from_slice(&16u16.to_be_bytes()); // key length
    e.extend_from_slice(&1u64.to_be_bytes()); // replay counter
    e.extend_from_slice(&[0x11; 32]); // nonce
    e.extend_from_slice(&[0; 16 + 8 + 8]); // IV, RSC, reserved
    e.extend_from_slice(&[0; 16]); // MIC
    e.extend_from_slice(&key_data_len.to_be_bytes());
    e.extend_from_slice(key_data);
    e
}

const AES_SHA1: u16 = 2;
const PAIRWISE: u16 = 1 << 3;
const ACK: u16 = 1 << 7;
const MIC: u16 = 1 << 8;
const ENCRYPTED: u16 = 1 << 12;

/// Run the deserialiser as the station does: `keys` false for message 1
/// (no KCK or KEK yet), true for message 3 and the group handshake.
fn outcome(mut f: Vec<u8>, keys: bool) -> Result<bool, String> {
    let kck = [0x42u8; 16];
    let kek = [0x24u8; 16];
    let mut scratch = vec![0u8; 512];
    catch_unwind(AssertUnwindSafe(|| {
        let (kck, kek, scratch): (_, _, &mut [u8]) = if keys {
            (Some(&kck), Some(&kek), scratch.as_mut_slice())
        } else {
            (None, None, &mut [])
        };
        deserialize_eapol_data_frame(kck, kek, &mut f, scratch, IEEE80211AkmType::Psk, false).is_ok()
    }))
    .map_err(|p| {
        p.downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_default()
    })
}

#[test]
fn a_frame_that_ends_inside_the_eapol_header_is_refused() {
    // 3 bytes of EAPOL: the ether type check passes, the key information
    // offset (13 bytes in) is past the end
    for n in 0..13 {
        let e = &key_frame(AES_SHA1 | PAIRWISE | ACK, 0, &[])[..n];
        assert_eq!(outcome(frame(e), false), Ok(false), "EAPOL cut to {n} bytes");
    }
}

#[test]
fn key_data_longer_than_the_frame_is_refused() {
    // no MIC bit, so no MIC check; encrypted key data that claims 0xffff
    // bytes where there are 16
    let e = key_frame(AES_SHA1 | PAIRWISE | ACK | ENCRYPTED, 0xffff, &[0; 16]);
    assert_eq!(outcome(frame(&e), false), Ok(false));
    assert_eq!(outcome(frame(&e), true), Ok(false));
}

#[test]
fn key_data_shorter_than_a_key_wrap_block_is_refused() {
    // with the keys present (message 3, the group handshake) and no MIC bit:
    // 4 bytes of "wrapped" key data, less than the 8-byte integrity block
    for len in 0..8u16 {
        let e = key_frame(AES_SHA1 | PAIRWISE | ACK | ENCRYPTED, len, &vec![0; len as usize]);
        assert_eq!(outcome(frame(&e), true), Ok(false), "key data of {len} bytes");
    }
}

#[test]
fn key_data_not_a_whole_number_of_blocks_is_refused() {
    let e = key_frame(AES_SHA1 | PAIRWISE | ACK | ENCRYPTED, 21, &[0; 21]);
    assert_eq!(outcome(frame(&e), true), Ok(false));
}

#[test]
fn a_wrong_mic_is_refused() {
    let e = key_frame(AES_SHA1 | PAIRWISE | ACK | MIC, 0, &[]);
    assert_eq!(outcome(frame(&e), true), Ok(false));
    // and with no KCK to check it with
    assert_eq!(outcome(frame(&e), false), Ok(false));
}

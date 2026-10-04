//! Data frames as FoA's station reads them (`foa_sta/src/runner.rs`,
//! `handle_data_rx`): `GenericFrame::new`, `parse_to_typed::<DataFrame>`,
//! then `potentially_wrapped_payload`. Anyone in range can send a data frame
//! to the station's address, with the Protected bit set or not, so every
//! length and every flag is the sender's; the answer is `None`, never a
//! panic.

use std::panic::{AssertUnwindSafe, catch_unwind};

use ieee80211::GenericFrame;
use ieee80211::crypto::MicState;
use ieee80211::data_frame::DataFrame;

/// A from-DS data frame to the station; `protected` sets the Protected bit.
fn frame(protected: bool, payload: &[u8]) -> Vec<u8> {
    let flags = 0x02 | if protected { 0x40 } else { 0 };
    let mut f = vec![0x08, flags, 0, 0];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 3]);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}

/// What the station's routing task does with the bytes, up to the payload:
/// Ok(true) a payload came out, Ok(false) refused, Err a panic.
fn read(bytes: &[u8]) -> Result<bool, String> {
    catch_unwind(AssertUnwindSafe(|| {
        let Ok(generic) = GenericFrame::new(bytes, false) else {
            return false;
        };
        let Some(Ok(data_frame)) = generic.parse_to_typed::<DataFrame<'_, &[u8]>>() else {
            return false;
        };
        data_frame
            .potentially_wrapped_payload(Some(MicState::NotPresent))
            .is_some()
    }))
    .map_err(|p| {
        p.downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| p.downcast_ref::<String>().cloned())
            .unwrap_or_default()
    })
}

#[test]
fn a_protected_frame_too_short_for_its_ccmp_header_is_refused() {
    // CCMP's header is 8 bytes; a "protected" payload of 0..7 bytes
    for n in 0..8 {
        assert_eq!(
            read(&frame(true, &vec![0; n])),
            Ok(false),
            "protected payload of {n} bytes"
        );
    }
}

#[test]
fn an_unprotected_frame_of_any_length_reads_without_a_panic() {
    for n in 0..64 {
        assert!(
            read(&frame(false, &vec![0xaa; n])).is_ok(),
            "payload of {n} bytes"
        );
    }
}

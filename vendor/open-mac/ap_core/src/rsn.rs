//! The RSN element a station offers in its association request (802.11-2020
//! 9.4.2.24): what this access point takes, read field by field. It hosts
//! WPA2-PSK with CCMP-128 and no management-frame protection, so a station
//! must select exactly that: one pairwise cipher (CCMP), one AKM (PSK), the
//! group cipher the access point named, and not require PMF.

use crate::status;

const CCMP: [u8; 4] = [0x00, 0x0f, 0xac, 4];
const PSK: [u8; 4] = [0x00, 0x0f, 0xac, 2];
/// RSN Capabilities: Management Frame Protection Required.
const MFPR: u16 = 1 << 6;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// Whether a station's RSN element body (after the ID and length octets)
/// is one this access point takes; `Err` carries the status code the
/// association response answers with.
pub fn check_station(body: &[u8]) -> Result<(), u16> {
    let malformed = status::INVALID_ELEMENT;
    if u16_at(body, 0).ok_or(malformed)? != 1 {
        return Err(status::UNSUPPORTED_RSNE_VERSION);
    }
    // a station's element may stop after the version; then every field
    // takes its default, CCMP and 802.1X, and 802.1X is not PSK
    let group = body.get(2..6).ok_or(status::INVALID_AKMP)?;
    if group != CCMP {
        return Err(status::INVALID_GROUP_CIPHER);
    }
    let pairwise_count = usize::from(u16_at(body, 6).ok_or(malformed)?);
    let pairwise = body.get(8..8 + 4 * pairwise_count).ok_or(malformed)?;
    if pairwise_count != 1 || pairwise != CCMP {
        return Err(status::INVALID_PAIRWISE_CIPHER);
    }
    let at = 8 + 4 * pairwise_count;
    let akm_count = usize::from(u16_at(body, at).ok_or(malformed)?);
    let akms = body.get(at + 2..at + 2 + 4 * akm_count).ok_or(malformed)?;
    if akm_count != 1 || akms != PSK {
        return Err(status::INVALID_AKMP);
    }
    let at = at + 2 + 4 * akm_count;
    if u16_at(body, at).is_some_and(|capabilities| capabilities & MFPR != 0) {
        return Err(status::INVALID_RSNE_CAPABILITIES);
    }
    Ok(())
}

//! Beyond 802.11g (E3's P7): WMM, the QoS the stations of today expect,
//! and HT, 802.11n's rates, which stations take only from an access point
//! that offers WMM. Only what one ESP32-S3 radio can do is advertised: one
//! spatial stream, 20 MHz, MCS 0-7, the short guard interval; no
//! aggregation (there is no block-ack in the MAC, so no A-MPDU is ever
//! agreed) and no 40 MHz. The elements are laid out by hand from
//! 802.11-2020 (9.4.2.55 HT Capabilities, 9.4.2.56 HT Operation) and the
//! Wi-Fi Alliance's WMM specification 1.2 (the parameter and information
//! elements), so the tests read them back with `ieee80211`'s parsers.

use crate::elements::Elements;

/// The Wi-Fi Alliance's OUI and the WMM type, the start of every WMM
/// element's body.
pub const WMM_OUI_TYPE: [u8; 4] = [0x00, 0x50, 0xf2, 0x02];
/// Element ID: vendor specific.
pub const VENDOR_SPECIFIC: u8 = 221;
/// Element ID: HT Capabilities.
pub const HT_CAPABILITIES: u8 = 45;
/// Element ID: HT Operation.
pub const HT_OPERATION: u8 = 61;

/// One access category's record in the WMM parameter element: ACI/AIFSN,
/// ECWmin/ECWmax, the TXOP limit in 32 µs units (little-endian).
const fn ac_record(aci: u8, aifsn: u8, ecw_min: u8, ecw_max: u8, txop: u16) -> [u8; 4] {
    let [lo, hi] = txop.to_le_bytes();
    [
        (aci << 5) | (aifsn & 0xf),
        (ecw_max << 4) | (ecw_min & 0xf),
        lo,
        hi,
    ]
}

/// The WMM parameter element the access point advertises (beacon, probe
/// response, association response), header included: the WMM 1.2 default
/// parameters for stations on an 802.11g/n network (the ones every access
/// point hands out; the hardware's own queues follow 802.11's defaults,
/// which match). QoS Info: parameter set count 0, no U-APSD.
pub const WMM_PARAMETER_ELEMENT: [u8; 26] = {
    let be = ac_record(0, 3, 4, 10, 0);
    let bk = ac_record(1, 7, 4, 10, 0);
    let vi = ac_record(2, 2, 3, 4, 94);
    let vo = ac_record(3, 2, 2, 3, 47);
    [
        VENDOR_SPECIFIC,
        24,
        0x00,
        0x50,
        0xf2,
        0x02, // WMM
        0x01, // parameter element
        0x01, // version
        0x00, // QoS info
        0x00, // reserved
        be[0],
        be[1],
        be[2],
        be[3],
        bk[0],
        bk[1],
        bk[2],
        bk[3],
        vi[0],
        vi[1],
        vi[2],
        vi[3],
        vo[0],
        vo[1],
        vo[2],
        vo[3],
    ]
};

/// The HT Capabilities element, header included (9.4.2.55): 20 MHz only,
/// SM power save disabled, the short guard interval at 20 MHz, no STBC, no
/// LDPC, the 3,839-byte A-MSDU, A-MPDU parameters zero, MCS 0-7 received,
/// the TX MCS set equal to it; no extended capabilities, beamforming or
/// antenna selection.
pub const HT_CAPABILITIES_ELEMENT: [u8; 28] = [
    HT_CAPABILITIES,
    26,
    0x2c, // HT capability info: SM power save disabled (bits 2-3), SGI 20 MHz (bit 5)
    0x00,
    0x00, // A-MPDU parameters
    0xff, // RX MCS 0-7
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00, // RX highest supported data rate: not specified
    0x00,
    0x01, // TX MCS set defined, equal to RX
    0x00,
    0x00,
    0x00,
    0x00, // HT extended capabilities
    0x00,
    0x00, // transmit beamforming capabilities
    0x00,
    0x00,
    0x00,
    0x00, // ASEL capabilities
];

/// The HT Operation element for `channel`, header included (9.4.2.56): no
/// secondary channel, 20 MHz, no RIFS, HT protection mode 0 with
/// non-greenfield HT stations present, no basic MCS set (none required of
/// a station).
#[must_use]
pub const fn ht_operation_element(channel: u8) -> [u8; 24] {
    let mut e = [0u8; 24];
    e[0] = HT_OPERATION;
    e[1] = 22;
    e[2] = channel;
    e[3] = 0x00; // secondary channel offset none, 20 MHz, no RIFS
    e[4] = 0x04; // HT protection 0, non-greenfield HT STAs present
    e
}

/// What a station's association request says about HT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtCapabilities {
    /// It receives the short guard interval at 20 MHz.
    pub short_gi_20: bool,
    /// The MCS indices 0-7 it receives, as a bit mask (bit n: MCS n).
    pub rx_mcs: u8,
}

impl HtCapabilities {
    /// The highest MCS index the station receives, if any.
    #[must_use]
    pub const fn highest_mcs(&self) -> Option<u8> {
        if self.rx_mcs == 0 {
            None
        } else {
            Some(7 - self.rx_mcs.leading_zeros() as u8)
        }
    }
}

/// Whether a station's elements carry a WMM element (information or
/// parameter): it takes QoS data frames.
#[must_use]
pub fn station_is_qos(mut elements: Elements<'_>) -> bool {
    elements.any(|(id, body)| id == VENDOR_SPECIFIC && body.len() >= 6 && body[..4] == WMM_OUI_TYPE)
}

/// The station's HT Capabilities, if its elements carry a whole one.
#[must_use]
pub fn station_ht(elements: Elements<'_>) -> Option<HtCapabilities> {
    let body = elements.first(HT_CAPABILITIES)?;
    if body.len() < 26 {
        return None;
    }
    Some(HtCapabilities {
        short_gi_20: body[0] & 0x20 != 0,
        rx_mcs: body[3],
    })
}

/// The access category of a user priority (802.11-2020 Table 10-1):
/// 0 BE, 1 BK, 2 VI, 3 VO.
#[must_use]
pub const fn access_category(user_priority: u8) -> u8 {
    match user_priority & 7 {
        1 | 2 => 1,
        0 | 3 => 0,
        4 | 5 => 2,
        _ => 3,
    }
}

/// The QoS Control field for a data frame with `user_priority` (its TID),
/// normal acknowledgement, no A-MSDU, nothing queued announced.
#[must_use]
pub const fn qos_control(user_priority: u8) -> [u8; 2] {
    [user_priority & 0x7, 0]
}

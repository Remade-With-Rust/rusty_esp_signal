//! What a station sends the access point, read from the bytes: the
//! management frames that join or leave (802.11-2020 9.3.3). Every byte is
//! the sender's, before any authentication; every read is checked. Data
//! frames (EAPOL among them) are the driver's to route; this reads
//! management frames only.

use crate::elements::{Elements, id};
use crate::{Address, BROADCAST};

/// A management frame from a station, as far as the access point acts on
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// A probe request; `ssid` is `None` for a wildcard (an empty SSID).
    Probe {
        /// The station.
        from: Address,
        /// The network asked for.
        ssid: Option<&'a [u8]>,
    },
    /// An authentication frame.
    Authentication {
        /// The station.
        from: Address,
        /// The algorithm (0: open system).
        algorithm: u16,
        /// The transaction sequence number.
        sequence: u16,
    },
    /// An association or re-association request.
    Association {
        /// The station.
        from: Address,
        /// The network asked for (`None`: no SSID element).
        ssid: Option<&'a [u8]>,
        /// Its RSN element, header included.
        rsn_element: Option<&'a [u8]>,
        /// A re-association request.
        reassociation: bool,
        /// It carried a WMM element: it takes QoS data frames.
        qos: bool,
        /// Its HT Capabilities, if it carried them.
        ht: Option<crate::qos::HtCapabilities>,
    },
    /// A deauthentication.
    Deauthentication {
        /// The station.
        from: Address,
        /// Why.
        reason: u16,
    },
    /// A disassociation.
    Disassociation {
        /// The station.
        from: Address,
        /// Why.
        reason: u16,
    },
}

const HEADER: usize = 24;

fn address(b: &[u8], at: usize) -> Option<Address> {
    b.get(at..at + 6)?.try_into().ok()
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// Read a management frame addressed to the access point `bssid` (a probe
/// request may be broadcast, to any BSSID). `None` for anything else: not
/// management, not ours, protected or carrying an HT Control field (this
/// access point negotiates neither), or too short for its fields.
#[must_use]
pub fn parse<'a>(mpdu: &'a [u8], bssid: &Address) -> Option<Request<'a>> {
    let [fc0, fc1, ..] = *mpdu else {
        return None;
    };
    // protocol 0, type 0 (management)
    if fc0 & 0b1111 != 0 {
        return None;
    }
    // Protected, Order
    if fc1 & (0x40 | 0x80) != 0 {
        return None;
    }
    let subtype = fc0 >> 4;
    let receiver = address(mpdu, 4)?;
    let from = address(mpdu, 10)?;
    let bssid_field = address(mpdu, 16)?;
    let body = mpdu.get(HEADER..)?;
    let to_us = receiver == *bssid && bssid_field == *bssid;
    match subtype {
        4 => {
            if !(to_us
                || (receiver == BROADCAST && (bssid_field == BROADCAST || bssid_field == *bssid)))
            {
                return None;
            }
            let ssid = Elements::new(body).first(id::SSID)?;
            Some(Request::Probe {
                from,
                ssid: (!ssid.is_empty()).then_some(ssid),
            })
        }
        _ if !to_us => None,
        11 => Some(Request::Authentication {
            from,
            algorithm: u16_at(body, 0)?,
            sequence: u16_at(body, 2)?,
        }),
        0 | 2 => {
            // capability information, listen interval, and for a
            // re-association the current access point's address
            let fixed = if subtype == 2 { 10 } else { 4 };
            let elements = Elements::new(body.get(fixed..)?);
            Some(Request::Association {
                from,
                ssid: elements.first(id::SSID),
                rsn_element: elements.first_whole(id::RSN),
                reassociation: subtype == 2,
                qos: crate::qos::station_is_qos(elements),
                ht: crate::qos::station_ht(elements),
            })
        }
        12 => Some(Request::Deauthentication {
            from,
            reason: u16_at(body, 0)?,
        }),
        10 => Some(Request::Disassociation {
            from,
            reason: u16_at(body, 0)?,
        }),
        _ => None,
    }
}

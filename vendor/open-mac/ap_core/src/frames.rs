//! The management frames the access point sends, laid out byte by byte
//! from 802.11-2020 (9.3.3): the MAC header, the fixed fields, the elements
//! in Table 9-34's order. Multi-byte fields are little-endian. The
//! sequence number is left 0: the driver numbers frames as it sends them.
//! Every function writes into `out` and returns the length, or `None` when
//! `out` is too short.

use crate::elements::id;
use crate::{Address, BROADCAST};

/// The network the access point hosts.
#[derive(Clone, Copy, Debug)]
pub struct Bss<'a> {
    /// The access point's address, which is also the BSSID.
    pub bssid: Address,
    /// The network's name, at most 32 bytes.
    pub ssid: &'a [u8],
    /// The 2.4 GHz channel, 1-13.
    pub channel: u8,
    /// The beacon interval in time units of 1,024 us (100: 102.4 ms).
    pub beacon_interval_tu: u16,
    /// WPA2-PSK (the RSN element and the Privacy bit) or open.
    pub protected: bool,
    /// WMM and HT offered (E3's P7): the WMM parameter element, HT
    /// Capabilities and HT Operation in the beacon, probe response and
    /// association response.
    pub ht: bool,
}

/// Rates, in 500 kbit/s units, the high bit marking a basic rate: 1, 2,
/// 5.5 and 11 Mbit/s basic (DSSS/CCK, what every 2.4 GHz station takes),
/// 6, 9, 12, 18 here and 24, 36, 48, 54 in the Extended Supported Rates.
pub const SUPPORTED_RATES: [u8; 8] = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24];
/// The rest of the 802.11g rates.
pub const EXTENDED_RATES: [u8; 4] = [0x30, 0x48, 0x60, 0x6c];

/// Frame control's first byte: protocol 0, type management (0), subtype.
const fn management(subtype: u8) -> u8 {
    subtype << 4
}

struct Writer<'a> {
    out: &'a mut [u8],
    at: usize,
}

impl Writer<'_> {
    fn bytes(&mut self, b: &[u8]) -> Option<()> {
        self.out
            .get_mut(self.at..self.at + b.len())?
            .copy_from_slice(b);
        self.at += b.len();
        Some(())
    }
    fn u16(&mut self, v: u16) -> Option<()> {
        self.bytes(&v.to_le_bytes())
    }
    /// A beacon's or probe response's fixed fields: the timestamp (zero:
    /// the transmit hook writes it), the beacon interval, the capability
    /// information; one room check where three writes were three.
    fn fixed_fields(&mut self, beacon_interval_tu: u16, capabilities: u16) -> Option<()> {
        let out = self.out.get_mut(self.at..self.at + 12)?;
        out[..8].fill(0);
        out[8..10].copy_from_slice(&beacon_interval_tu.to_le_bytes());
        out[10..12].copy_from_slice(&capabilities.to_le_bytes());
        self.at += 12;
        Some(())
    }
    fn element(&mut self, id: u8, body: &[u8]) -> Option<()> {
        let len = u8::try_from(body.len()).ok()?;
        // the whole element's room checked once (two checks before: the
        // header's, then the body's)
        let out = self.out.get_mut(self.at..self.at + 2 + body.len())?;
        out[0] = id;
        out[1] = len;
        out[2..].copy_from_slice(body);
        self.at += 2 + body.len();
        Some(())
    }
    /// HT Capabilities, HT Operation and the WMM parameter element, when
    /// the network offers them (the vendor element last, as 802.11 orders).
    fn ht(&mut self, bss: &Bss<'_>) -> Option<()> {
        if bss.ht {
            use crate::qos::{HT_CAPABILITIES_ELEMENT as CAP, WMM_PARAMETER_ELEMENT as WMM};
            const OP: usize = 24;
            // the three elements' room checked once (three checks before)
            let out = self
                .out
                .get_mut(self.at..self.at + CAP.len() + OP + WMM.len())?;
            out[..CAP.len()].copy_from_slice(&CAP);
            out[CAP.len()..CAP.len() + OP]
                .copy_from_slice(&crate::qos::ht_operation_element(bss.channel));
            out[CAP.len() + OP..].copy_from_slice(&WMM);
            self.at += CAP.len() + OP + WMM.len();
        }
        Some(())
    }
    /// The 24-byte management header: frame control, duration, the
    /// receiver, the transmitter (the access point), the BSSID, sequence.
    fn header(&mut self, subtype: u8, to: Address, bssid: Address) -> Option<()> {
        // one room check, the fields written in place (five checks before)
        let out = self.out.get_mut(self.at..self.at + 24)?;
        out[..4].copy_from_slice(&[management(subtype), 0, 0, 0]);
        out[4..10].copy_from_slice(&to);
        out[10..16].copy_from_slice(&bssid);
        out[16..22].copy_from_slice(&bssid);
        out[22..24].fill(0);
        self.at += 24;
        Some(())
    }
}

/// The Capability Information field: ESS, and Privacy for WPA2.
#[must_use]
pub const fn capabilities(protected: bool) -> u16 {
    1 | if protected { 1 << 4 } else { 0 }
}

/// The access point's RSN element: version 1, CCMP-128 as the group and
/// the one pairwise cipher, PSK the one AKM, no capabilities (no PMF).
pub const RSN_ELEMENT: [u8; 22] = [
    id::RSN,
    20,
    1,
    0,
    0x00,
    0x0f,
    0xac,
    4,
    1,
    0,
    0x00,
    0x0f,
    0xac,
    4,
    1,
    0,
    0x00,
    0x0f,
    0xac,
    2,
    0,
    0,
];

/// The Traffic Indication Map a beacon carries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tim {
    /// Beacons until the next DTIM (0: this one is).
    pub dtim_count: u8,
    /// Beacons between DTIMs.
    pub dtim_period: u8,
    /// Group-addressed frames are buffered (meaningful on a DTIM beacon).
    pub group_buffered: bool,
    /// Bit `n` set: frames are buffered for the station with AID `n`
    /// (1-15; bit 0 is ignored).
    pub buffered_aids: u16,
}

/// Where a beacon's fields are, for the hook that sends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Beacon {
    /// The frame's length.
    pub len: usize,
    /// The 8-byte Timestamp field: the TSF, written as the beacon goes out.
    pub timestamp_at: usize,
    /// The TIM element's first byte (its ID).
    pub tim_at: usize,
}

/// A beacon (9.3.3.2).
#[must_use]
pub fn beacon(out: &mut [u8], bss: &Bss<'_>, tim: &Tim) -> Option<Beacon> {
    let mut w = Writer { out, at: 0 };
    w.header(8, BROADCAST, bss.bssid)?;
    let timestamp_at = w.at;
    w.fixed_fields(bss.beacon_interval_tu, capabilities(bss.protected))?;
    w.element(id::SSID, bss.ssid)?;
    w.element(id::SUPPORTED_RATES, &SUPPORTED_RATES)?;
    w.element(id::DSSS, &[bss.channel])?;
    let tim_at = w.at;
    // the partial virtual bitmap from AID 0, two octets (AIDs 0-15)
    let [low, high] = (tim.buffered_aids & !1).to_le_bytes();
    w.element(
        id::TIM,
        &[
            tim.dtim_count,
            tim.dtim_period,
            u8::from(tim.group_buffered),
            low,
            high,
        ],
    )?;
    w.element(id::ERP, &[0])?;
    w.element(id::EXTENDED_RATES, &EXTENDED_RATES)?;
    if bss.protected {
        w.bytes(&RSN_ELEMENT)?;
    }
    w.ht(bss)?;
    Some(Beacon {
        len: w.at,
        timestamp_at,
        tim_at,
    })
}

/// A beacon from [`beacon`] made the next TBTT's: its TIM rewritten in
/// place (the element always has the same length), every other byte being
/// the same from one beacon to the next while the network is (only the
/// timestamp moves, and the transmit hook writes that). Building the whole
/// beacon every 102.4 ms was the work of a template (2026-10-07).
pub fn set_tim(frame: &mut [u8], tim_at: usize, tim: &Tim) -> Option<()> {
    let [low, high] = (tim.buffered_aids & !1).to_le_bytes();
    frame.get_mut(tim_at + 2..tim_at + 7)?.copy_from_slice(&[
        tim.dtim_count,
        tim.dtim_period,
        u8::from(tim.group_buffered),
        low,
        high,
    ]);
    Some(())
}

/// A frame from this module sent to `to` instead: its receiver address
/// rewritten (a probe response is the same for every station but that).
pub fn set_receiver(frame: &mut [u8], to: Address) -> Option<()> {
    frame.get_mut(4..10)?.copy_from_slice(&to);
    Some(())
}

/// A probe response to `to` (9.3.3.10): a beacon's body without the TIM.
#[must_use]
pub fn probe_response(out: &mut [u8], bss: &Bss<'_>, to: Address) -> Option<usize> {
    let mut w = Writer { out, at: 0 };
    w.header(5, to, bss.bssid)?;
    w.fixed_fields(bss.beacon_interval_tu, capabilities(bss.protected))?;
    w.element(id::SSID, bss.ssid)?;
    w.element(id::SUPPORTED_RATES, &SUPPORTED_RATES)?;
    w.element(id::DSSS, &[bss.channel])?;
    w.element(id::ERP, &[0])?;
    w.element(id::EXTENDED_RATES, &EXTENDED_RATES)?;
    if bss.protected {
        w.bytes(&RSN_ELEMENT)?;
    }
    w.ht(bss)?;
    Some(w.at)
}

/// The second frame of open-system authentication (9.3.3.12).
#[must_use]
pub fn authentication(out: &mut [u8], bssid: Address, to: Address, status: u16) -> Option<usize> {
    let mut w = Writer { out, at: 0 };
    w.header(11, to, bssid)?;
    w.u16(0)?; // open system
    w.u16(2)?; // transaction sequence number
    w.u16(status)?;
    Some(w.at)
}

/// An association response (9.3.3.7), or a re-association response
/// (9.3.3.9, subtype 3: what a station roaming in, or re-associating,
/// expects); `aid` is set only on success, with the two high bits the
/// standard sets in the AID field.
#[must_use]
pub fn association_response(
    out: &mut [u8],
    bss: &Bss<'_>,
    to: Address,
    status: u16,
    aid: u16,
    reassociation: bool,
) -> Option<usize> {
    let mut w = Writer { out, at: 0 };
    w.header(if reassociation { 3 } else { 1 }, to, bss.bssid)?;
    w.u16(capabilities(bss.protected))?;
    w.u16(status)?;
    w.u16(if status == crate::status::SUCCESS {
        aid | 0xc000
    } else {
        0
    })?;
    w.element(id::SUPPORTED_RATES, &SUPPORTED_RATES)?;
    w.element(id::EXTENDED_RATES, &EXTENDED_RATES)?;
    w.ht(bss)?;
    Some(w.at)
}

/// A deauthentication (9.3.3.13).
#[must_use]
pub fn deauthentication(out: &mut [u8], bssid: Address, to: Address, reason: u16) -> Option<usize> {
    let mut w = Writer { out, at: 0 };
    w.header(12, to, bssid)?;
    w.u16(reason)?;
    Some(w.at)
}

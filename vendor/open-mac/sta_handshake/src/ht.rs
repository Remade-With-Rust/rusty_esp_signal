//! The station's side of 802.11n (Janus E8, the family's addition): what
//! it asks for when it associates, what it reads back from the access
//! point's answer, the QoS data frames it sends once it is an HT station,
//! the A-MSDU that carries two packets in one frame, and the block-ack
//! agreement it declines.
//!
//! FoA associated without HT capabilities, so its station sent at most
//! 54 Mbit/s, one packet per channel access. On the XIAO the time an
//! attempt spends beyond its frame's airtime (contention, the ACK, the
//! hotspot's own frames) measured 450-900 µs against 244 µs of air for a
//! 1,500-byte frame at 54 Mbit/s (E1): the rate is not where the time is,
//! the number of channel accesses is. An A-MSDU halves them for a stream
//! of full-size packets, and needs no block-ack: every HT station must
//! take one of up to 3,839 bytes (802.11-2020 9.4.2.55.2).
//!
//! Layouts are from 802.11-2020 (9.2.4.5 QoS Control, 9.3.2.2 A-MSDU,
//! 9.4.2.55 HT Capabilities, 9.6.4 Block Ack Action frames) and the Wi-Fi
//! Alliance's WMM specification 1.2. Not Wi-Fi certified.

/// Element ID: vendor specific.
pub const VENDOR_SPECIFIC: u8 = 221;
/// Element ID: HT Capabilities.
pub const HT_CAPABILITIES: u8 = 45;
/// The Wi-Fi Alliance's OUI and the WMM type.
pub const WMM_OUI_TYPE: [u8; 4] = [0x00, 0x50, 0xf2, 0x02];

/// The WMM Information element a station puts in its association request,
/// header included: version 1, QoS Info 0 (no U-APSD).
pub const WMM_INFORMATION_ELEMENT: [u8; 9] =
    [VENDOR_SPECIFIC, 7, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00];

/// The HT Capabilities element the station asks with, header included:
/// what one ESP32-S3 radio does. 20 MHz only, SM power save disabled, the
/// short guard interval at 20 MHz received, no STBC or LDPC, the
/// 3,839-byte A-MSDU, A-MPDU parameters zero (it agrees to no block-ack,
/// so it is never sent one), MCS 0-7 received, the TX MCS set equal to it.
/// The same bytes as `ap_core::qos::HT_CAPABILITIES_ELEMENT`.
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

/// What the association left the station with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Link {
    /// The access point takes QoS data frames (it answered with WMM).
    pub qos: bool,
    /// The HT rates the station may send at, if the association is HT.
    pub ht: Option<HtLink>,
}

/// An HT association, as the station may use it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HtLink {
    /// The access point receives the short guard interval at 20 MHz.
    pub short_gi: bool,
    /// The MCS indices 0-7 it receives (bit n: MCS n).
    pub mcs: u8,
}

impl HtLink {
    /// The highest MCS index the access point receives.
    #[must_use]
    pub const fn highest_mcs(&self) -> Option<u8> {
        if self.mcs == 0 {
            None
        } else {
            Some(7 - self.mcs.leading_zeros() as u8)
        }
    }
}

/// The elements of a frame body, as (ID, body) pairs. Stops at the first
/// element that runs past the end (a trailing FCS, a truncated frame).
pub fn elements(mut bytes: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    core::iter::from_fn(move || {
        let (&id, rest) = bytes.split_first()?;
        let (&len, rest) = rest.split_first()?;
        let body = rest.get(..usize::from(len))?;
        bytes = &rest[usize::from(len)..];
        Some((id, body))
    })
}

/// The link an association response's elements grant. HT only together
/// with WMM: an HT station is a QoS station (802.11-2020 10.2.1), and HT
/// rates go in QoS data frames.
#[must_use]
pub fn negotiated(response_elements: &[u8]) -> Link {
    let mut qos = false;
    let mut ht = None;
    for (id, body) in elements(response_elements) {
        match id {
            // the WMM parameter element (subtype 1); an information element
            // (subtype 0) in a response is still WMM
            VENDOR_SPECIFIC if body.len() >= 6 && body[..4] == WMM_OUI_TYPE => qos = true,
            HT_CAPABILITIES if body.len() >= 26 && ht.is_none() => {
                ht = Some(HtLink {
                    short_gi: body[0] & 0x20 != 0,
                    mcs: body[3],
                });
            }
            _ => {}
        }
    }
    Link {
        qos,
        ht: if qos { ht.filter(|h| h.mcs != 0) } else { None },
    }
}

/// The offset of an association response's elements in its MPDU: the
/// 24-byte management header, then capabilities, status and AID.
pub const ASSOCIATION_RESPONSE_ELEMENTS: usize = 24 + 6;

/// HT-mixed preamble at 20 MHz, one stream: L-STF, L-LTF, L-SIG, HT-SIG,
/// HT-STF and one HT-LTF.
const HT_PREAMBLE_US: u32 = 8 + 8 + 4 + 8 + 4 + 4;
/// Data bits per OFDM symbol, MCS 0-7, 20 MHz, one stream.
const HT_DBPS: [u32; 8] = [26, 52, 78, 104, 156, 208, 234, 260];

/// The airtime of an MPDU of `bytes` at HT `mcs` (0-7, 20 MHz, HT-mixed),
/// µs: the 16 service bits, the frame and the 6 tail bits in 4 µs symbols,
/// or 3.6 µs ones with the short guard interval rounded up to the 4 µs
/// boundary (802.11-2020 19.4.3).
#[must_use]
pub const fn ht_airtime_us(mcs: u8, short_gi: bool, bytes: u32) -> u32 {
    let dbps = HT_DBPS[(mcs & 7) as usize];
    let symbols = (16 + 8 * bytes + 6).div_ceil(dbps);
    let data = if short_gi {
        // 3.6 µs a symbol, the whole rounded up to 4 µs
        4 * (9 * symbols).div_ceil(10)
    } else {
        4 * symbols
    };
    HT_PREAMBLE_US + data
}

/// The QoS data MAC header's length: 24 bytes, then QoS Control.
pub const QOS_HEADER: usize = 26;
/// CCMP's header before the body, its MIC after it.
pub const CCMP_HEADER: usize = 8;
pub const CCMP_MIC: usize = 8;
/// The largest A-MSDU an HT station must take (802.11-2020 9.4.2.55.2).
pub const MAX_AMSDU: usize = 3839;
/// One A-MSDU subframe's header: DA, SA, Length.
pub const SUBFRAME_HEADER: usize = 14;
/// RFC 1042's LLC/SNAP header without the ether type.
const SNAP: [u8; 6] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00];

/// The bytes an Ethernet II frame takes inside an A-MSDU: the subframe
/// header, the LLC/SNAP header and ether type, the payload.
#[must_use]
pub const fn subframe_len(ethernet_len: usize) -> usize {
    SUBFRAME_HEADER + SNAP.len() + ethernet_len.saturating_sub(12)
}

/// Whether Ethernet II frames of these lengths fit one A-MSDU, padding
/// included.
#[must_use]
pub fn amsdu_fits(ethernet_lens: &[usize]) -> bool {
    let mut total: usize = 0;
    for (i, len) in ethernet_lens.iter().enumerate() {
        if *len < 14 {
            return false;
        }
        if i > 0 {
            total = total.next_multiple_of(4);
        }
        total += subframe_len(*len);
    }
    total <= MAX_AMSDU
}

/// Why a QoS data frame could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The buffer is too small for it.
    TooLong,
    /// An Ethernet frame shorter than its own header.
    Runt,
    /// No packet to send.
    Empty,
}

/// A QoS data frame from the station to its access point being laid out
/// in a TX buffer, one Ethernet II frame at a time: TID 0 (best effort),
/// normal acknowledgement. Each packet is written as an A-MSDU subframe;
/// [`finish`](Self::finish) makes a frame of one packet a plain MSDU
/// again (the subframe header taken out, Address 3 the destination), so
/// the caller can take a second packet only if one is already waiting
/// and never holds the first back for it. With `ccmp` = (packet number,
/// key ID) the frame is laid out for the MAC's CCMP engine: the Protected
/// bit, the CCMP header, and 8 zero bytes for the MIC, as `ieee80211`'s
/// `crypto_wrap` lays them. The sequence number is left 0 for the driver
/// to assign, the duration 0 as FoA's other data frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QosData {
    /// Where the body (the A-MSDU, or the MSDU) starts.
    body: usize,
    /// Where the next byte goes.
    at: usize,
    subframes: u8,
    ccmp: bool,
}

impl QosData {
    /// The header, the CCMP header if any, and `first` as a subframe.
    pub fn begin(
        buf: &mut [u8],
        bssid: [u8; 6],
        own: [u8; 6],
        ccmp: Option<(u64, u8)>,
        first: &[u8],
    ) -> Result<Self, WriteError> {
        let body = QOS_HEADER + if ccmp.is_some() { CCMP_HEADER } else { 0 };
        let header = buf.get_mut(..body).ok_or(WriteError::TooLong)?;
        // Frame Control: QoS Data (type 2, subtype 8), To DS, Protected
        header[0] = 0x88;
        header[1] = 0x01 | if ccmp.is_some() { 0x40 } else { 0 };
        header[2..4].fill(0);
        header[4..10].copy_from_slice(&bssid);
        header[10..16].copy_from_slice(&own);
        // Address 3 for an A-MSDU (802.11-2020 Table 9-30, To DS 1 From DS
        // 0): the BSSID. `finish` puts the destination there for one packet
        header[16..22].copy_from_slice(&bssid);
        header[22..24].fill(0);
        // QoS Control: TID 0, normal ack, the A-MSDU Present bit
        header[24] = 0x80;
        header[25] = 0;
        if let Some((pn, key_id)) = ccmp {
            let p = pn.to_le_bytes();
            header[QOS_HEADER..body].copy_from_slice(&[
                p[0],
                p[1],
                0,
                0x20 | (key_id << 6),
                p[2],
                p[3],
                p[4],
                p[5],
            ]);
        }
        let mut frame = Self {
            body,
            at: body,
            subframes: 0,
            ccmp: ccmp.is_some(),
        };
        frame.push(buf, first)?;
        Ok(frame)
    }

    /// Packets in the frame so far.
    #[must_use]
    pub const fn packets(&self) -> u8 {
        self.subframes
    }

    /// The A-MSDU's length if an Ethernet II frame of `ethernet_len` bytes
    /// were added, padding included.
    #[must_use]
    pub const fn amsdu_len_with(&self, ethernet_len: usize) -> usize {
        (self.at - self.body).next_multiple_of(4) + subframe_len(ethernet_len)
    }

    /// Whether `packet` fits the A-MSDU and the buffer (its MIC included).
    #[must_use]
    pub fn fits(&self, buf_len: usize, ethernet_len: usize) -> bool {
        let amsdu = self.amsdu_len_with(ethernet_len);
        let crypto = if self.ccmp { CCMP_MIC } else { 0 };
        ethernet_len >= 14 && amsdu <= MAX_AMSDU && self.body + amsdu + crypto <= buf_len
    }

    /// Add `packet` as the next subframe, padding the one before it to 4
    /// bytes (counted from the A-MSDU's start).
    pub fn push(&mut self, buf: &mut [u8], packet: &[u8]) -> Result<(), WriteError> {
        if packet.len() < 14 {
            return Err(WriteError::Runt);
        }
        if self.subframes > 0 && !self.fits(buf.len(), packet.len()) {
            return Err(WriteError::TooLong);
        }
        let mut at = self.at;
        if self.subframes > 0 {
            let padded = self.body + (at - self.body).next_multiple_of(4);
            buf[at..padded].fill(0);
            at = padded;
        }
        let end = at + subframe_len(packet.len());
        let crypto = if self.ccmp { CCMP_MIC } else { 0 };
        if end + crypto > buf.len() {
            return Err(WriteError::TooLong);
        }
        let msdu = SNAP.len() + packet.len() - 12;
        buf[at..at + 12].copy_from_slice(&packet[..12]);
        buf[at + 12..at + 14].copy_from_slice(&(msdu as u16).to_be_bytes());
        self.at = write_msdu(buf, at + SUBFRAME_HEADER, packet);
        self.subframes += 1;
        Ok(())
    }

    /// Close the frame: a single packet becomes a plain MSDU, the MIC's
    /// room is zeroed. Returns the MPDU's length.
    pub fn finish(self, buf: &mut [u8]) -> usize {
        let mut at = self.at;
        if self.subframes == 1 {
            let (dst, body) = (self.body, self.body + SUBFRAME_HEADER);
            let mut da = [0u8; 6];
            da.copy_from_slice(&buf[dst..dst + 6]);
            buf[16..22].copy_from_slice(&da);
            buf[24] = 0;
            buf.copy_within(body..at, dst);
            at -= SUBFRAME_HEADER;
        }
        if self.ccmp {
            buf[at..at + CCMP_MIC].fill(0);
            at += CCMP_MIC;
        }
        at
    }
}

/// Write a QoS data frame carrying `packets` (Ethernet II frames): one as
/// a plain MSDU, more as an A-MSDU ([`QosData`] in one call). Returns the
/// MPDU's length.
pub fn write_qos_data(
    buf: &mut [u8],
    bssid: [u8; 6],
    own: [u8; 6],
    ccmp: Option<(u64, u8)>,
    packets: &[&[u8]],
) -> Result<usize, WriteError> {
    let (first, rest) = packets.split_first().ok_or(WriteError::Empty)?;
    let mut frame = QosData::begin(buf, bssid, own, ccmp, first)?;
    for p in rest {
        frame.push(buf, p)?;
    }
    Ok(frame.finish(buf))
}

/// A QoS data frame from a station this device is bridging, one Ethernet
/// frame, no A-MSDU. To DS and From DS are both set: address 1 is the
/// parent (RA), address 2 this device (TA), address 3 the Ethernet
/// destination, address 4 the Ethernet source — the station, as itself.
/// `tid` is the QoS priority (1: background, behind the device's own
/// traffic). The sequence number is left 0 for the driver. Not Wi-Fi certified.
pub fn write_four_address(
    buf: &mut [u8],
    bssid: [u8; 6],
    transmitter: [u8; 6],
    ccmp: Option<(u64, u8)>,
    ethernet: &[u8],
    tid: u8,
) -> Result<usize, WriteError> {
    if ethernet.len() < 14 {
        return Err(WriteError::Runt);
    }
    const HEADER: usize = 32;
    let ccmp_len = if ccmp.is_some() { CCMP_HEADER } else { 0 };
    let body = HEADER + ccmp_len;
    let msdu = SNAP.len() + ethernet.len() - 12;
    let mic = if ccmp.is_some() { CCMP_MIC } else { 0 };
    if body + msdu + mic > buf.len() {
        return Err(WriteError::TooLong);
    }
    buf[0] = 0x88;
    buf[1] = 0x03 | if ccmp.is_some() { 0x40 } else { 0 };
    buf[2..4].fill(0);
    buf[4..10].copy_from_slice(&bssid);
    buf[10..16].copy_from_slice(&transmitter);
    buf[16..22].copy_from_slice(&ethernet[..6]);
    buf[22..24].fill(0);
    buf[24..30].copy_from_slice(&ethernet[6..12]);
    buf[30] = tid & 0x0f;
    buf[31] = 0;
    if let Some((pn, key_id)) = ccmp {
        let p = pn.to_le_bytes();
        buf[HEADER..body].copy_from_slice(&[
            p[0],
            p[1],
            0,
            0x20 | (key_id << 6),
            p[2],
            p[3],
            p[4],
            p[5],
        ]);
    }
    let at = write_msdu(buf, body, ethernet);
    if ccmp.is_some() {
        buf[at..at + CCMP_MIC].fill(0);
    }
    Ok(at + mic)
}

/// An Ethernet II frame's MSDU at `at`: LLC/SNAP, the ether type, the
/// payload. Returns the offset past it.
fn write_msdu(buf: &mut [u8], at: usize, ethernet: &[u8]) -> usize {
    buf[at..at + 6].copy_from_slice(&SNAP);
    buf[at + 6..at + 8].copy_from_slice(&ethernet[12..14]);
    let payload = &ethernet[14..];
    buf[at + 8..at + 8 + payload.len()].copy_from_slice(payload);
    at + 8 + payload.len()
}

/// Category: Block Ack (802.11-2020 Table 9-51).
pub const BLOCK_ACK_CATEGORY: u8 = 3;
/// Status: the request has been declined.
pub const REQUEST_DECLINED: u16 = 37;

/// An ADDBA Request the access point sent: what a response echoes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddbaRequest {
    /// Its sender (the access point).
    pub from: [u8; 6],
    pub dialog_token: u8,
    /// The Block Ack Parameter Set, as sent.
    pub parameters: u16,
}

/// The ADDBA Request in a received management frame, if it is one
/// addressed to `own` (802.11-2020 9.6.4.2): action, category Block Ack,
/// action 0.
#[must_use]
pub fn addba_request(mpdu: &[u8], own: [u8; 6]) -> Option<AddbaRequest> {
    // Frame Control: management, Action (subtype 13)
    if mpdu.len() < 24 + 9 || mpdu[0] != 0xd0 || mpdu[4..10] != own {
        return None;
    }
    let body = &mpdu[24..];
    if body[0] != BLOCK_ACK_CATEGORY || body[1] != 0 {
        return None;
    }
    let mut from = [0; 6];
    from.copy_from_slice(&mpdu[10..16]);
    Some(AddbaRequest {
        from,
        dialog_token: body[2],
        parameters: u16::from_le_bytes([body[3], body[4]]),
    })
}

/// The ADDBA Response that declines `request` (802.11-2020 9.6.4.3):
/// status 37, its dialog token and parameters echoed, timeout 0. The
/// station agrees to no block-ack, so its access point sends it no
/// A-MPDU. Returns the MPDU's length.
pub fn write_addba_decline(
    buf: &mut [u8],
    own: [u8; 6],
    bssid: [u8; 6],
    request: &AddbaRequest,
) -> Result<usize, WriteError> {
    let buf = buf.get_mut(..24 + 9).ok_or(WriteError::TooLong)?;
    buf[0] = 0xd0;
    buf[1] = 0;
    buf[2..4].fill(0);
    buf[4..10].copy_from_slice(&request.from);
    buf[10..16].copy_from_slice(&own);
    buf[16..22].copy_from_slice(&bssid);
    buf[22..24].fill(0);
    let p = request.parameters.to_le_bytes();
    let s = REQUEST_DECLINED.to_le_bytes();
    buf[24..33].copy_from_slice(&[
        BLOCK_ACK_CATEGORY,
        1, // ADDBA Response
        request.dialog_token,
        s[0],
        s[1],
        p[0],
        p[1],
        0,
        0, // timeout
    ]);
    Ok(33)
}

/// The block-ack agreement the station asks for: immediate policy, no
/// A-MSDU inside the A-MPDU, `tid`, `buffer_size` MPDUs, no timeout,
/// starting at `ssn` (802.11-2020 9.6.4.2, 9.4.1.14). Returns the MPDU's
/// length.
pub fn write_addba_request(
    buf: &mut [u8],
    own: [u8; 6],
    bssid: [u8; 6],
    dialog_token: u8,
    tid: u8,
    buffer_size: u16,
    ssn: u16,
) -> Result<usize, WriteError> {
    let buf = buf.get_mut(..24 + 9).ok_or(WriteError::TooLong)?;
    buf[0] = 0xd0;
    buf[1] = 0;
    buf[2..4].fill(0);
    buf[4..10].copy_from_slice(&bssid);
    buf[10..16].copy_from_slice(&own);
    buf[16..22].copy_from_slice(&bssid);
    buf[22..24].fill(0);
    // Block Ack Parameter Set: A-MSDU not supported (bit 0), immediate
    // (bit 1), TID (bits 2-5), buffer size (bits 6-15)
    let parameters = 0x0002 | (u16::from(tid & 0xf) << 2) | ((buffer_size & 0x3ff) << 6);
    let p = parameters.to_le_bytes();
    let s = ((ssn & 0x0fff) << 4).to_le_bytes();
    buf[24..33].copy_from_slice(&[
        BLOCK_ACK_CATEGORY,
        0, // ADDBA Request
        dialog_token,
        p[0],
        p[1],
        0,
        0, // timeout: none
        s[0],
        s[1],
    ]);
    Ok(33)
}

/// An ADDBA Response the access point sent (802.11-2020 9.6.4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddbaResponse {
    /// Its sender (the access point).
    pub from: [u8; 6],
    pub dialog_token: u8,
    /// 0: the agreement is made.
    pub status: u16,
    /// The Block Ack Parameter Set the access point agreed to.
    pub parameters: u16,
}

impl AddbaResponse {
    /// The TID the agreement is for.
    #[must_use]
    pub const fn tid(&self) -> u8 {
        ((self.parameters >> 2) & 0xf) as u8
    }
    /// How many MPDUs the access point holds for reordering: the most one
    /// A-MPDU may carry. 0 means the recipient leaves it to the originator
    /// (802.11-2020 10.25.2); read as 64, HT's largest.
    #[must_use]
    pub const fn buffer_size(&self) -> u16 {
        match (self.parameters >> 6) & 0x3ff {
            0 => 64,
            n => n,
        }
    }
}

/// The ADDBA Response in a received management frame, if it is one
/// addressed to `own`: action, category Block Ack, action 1.
#[must_use]
pub fn addba_response(mpdu: &[u8], own: [u8; 6]) -> Option<AddbaResponse> {
    if mpdu.len() < 24 + 9 || mpdu[0] != 0xd0 || mpdu[4..10] != own {
        return None;
    }
    let body = &mpdu[24..];
    if body[0] != BLOCK_ACK_CATEGORY || body[1] != 1 {
        return None;
    }
    let mut from = [0; 6];
    from.copy_from_slice(&mpdu[10..16]);
    Some(AddbaResponse {
        from,
        dialog_token: body[2],
        status: u16::from_le_bytes([body[3], body[4]]),
        parameters: u16::from_le_bytes([body[5], body[6]]),
    })
}

/// A compressed BlockAckReq for `tid` starting at `ssn` (802.11-2020
/// 9.3.1.7): it moves the recipient's reordering window to `ssn`, so a
/// subframe the originator gave up on stops holding back the ones after it.
/// Returns the frame's length (FCS not counted).
pub fn write_block_ack_request(
    buf: &mut [u8],
    own: [u8; 6],
    bssid: [u8; 6],
    tid: u8,
    ssn: u16,
) -> Result<usize, WriteError> {
    let buf = buf.get_mut(..20).ok_or(WriteError::TooLong)?;
    buf[0] = 0x84; // control, BlockAckReq
    buf[1] = 0;
    buf[2..4].fill(0);
    buf[4..10].copy_from_slice(&bssid);
    buf[10..16].copy_from_slice(&own);
    // BAR Control: compressed bitmap (bit 2), TID (bits 12-15)
    let control = 0x0004u16 | (u16::from(tid & 0xf) << 12);
    buf[16..18].copy_from_slice(&control.to_le_bytes());
    buf[18..20].copy_from_slice(&((ssn & 0x0fff) << 4).to_le_bytes());
    Ok(20)
}

/// The prefix the ESP32-S3's MAC takes in front of each A-MPDU subframe's
/// MPDU in its DMA buffer, as esp-radio lays it (read off silicon, E8,
/// 2026-10-08; signal's ledger): the MPDU's length with its FCS, the
/// subframe's sequence number, four zero bytes. The MAC builds the A-MPDU
/// delimiters itself; none are in memory.
#[must_use]
pub const fn ampdu_prefix(mpdu_len_with_fcs: u16, sequence_number: u16) -> [u8; 8] {
    let l = mpdu_len_with_fcs.to_le_bytes();
    let s = sequence_number.to_le_bytes();
    [l[0], l[1], s[0], s[1], 0, 0, 0, 0]
}

/// The A-MPDU's length on the air (the HT-SIG length): each subframe a
/// 4-byte delimiter and its MPDU with FCS, padded to 4 bytes but the last
/// (802.11-2020 10.12.2).
#[must_use]
pub fn ampdu_psdu_length(mpdu_lens_with_fcs: &[usize]) -> usize {
    let n = mpdu_lens_with_fcs.len();
    mpdu_lens_with_fcs
        .iter()
        .enumerate()
        .map(|(i, len)| {
            let sub = 4 + len;
            if i + 1 < n {
                sub.next_multiple_of(4)
            } else {
                sub
            }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_ack_request_layout() {
        let mut out = [0u8; 32];
        let n = write_block_ack_request(
            &mut out,
            [2, 0, 0, 0, 0, 1],
            [0x0a, 1, 2, 3, 4, 5],
            0,
            0x123,
        )
        .unwrap();
        assert_eq!(n, 20);
        assert_eq!(&out[..2], &[0x84, 0]);
        assert_eq!(&out[16..20], &[0x04, 0x00, 0x30, 0x12]);
    }

    #[test]
    fn the_psdu_length_esp_radio_wrote() {
        // three 1,482-byte MPDUs: HT-SIG read 0x116E
        assert_eq!(ampdu_psdu_length(&[1482, 1482, 1482]), 0x116e);
        assert_eq!(ampdu_psdu_length(&[100]), 104);
        assert_eq!(ampdu_psdu_length(&[101, 101]), 108 + 105);
    }

    #[test]
    fn the_prefix_esp_radio_wrote() {
        // the first word read 0x001405CA: length 0x05CA, sequence 0x14
        assert_eq!(
            ampdu_prefix(0x05ca, 0x14),
            [0xca, 0x05, 0x14, 0x00, 0, 0, 0, 0]
        );
    }

    #[test]
    fn addba_request_and_response() {
        let own = [0x02, 0, 0, 0, 0, 1];
        let ap = [0x0a, 1, 2, 3, 4, 5];
        let mut out = [0u8; 64];
        let n = write_addba_request(&mut out, own, ap, 9, 0, 64, 0x123).unwrap();
        assert_eq!(n, 33);
        // parameters: immediate, TID 0, 64 buffers -> 0x1002
        assert_eq!(&out[24..33], &[3, 0, 9, 0x02, 0x10, 0, 0, 0x30, 0x12]);
        // the answer: the request's frame with the action and addresses turned round
        let mut resp = std::vec![0xd0, 0, 0, 0];
        resp.extend_from_slice(&own);
        resp.extend_from_slice(&ap);
        resp.extend_from_slice(&ap);
        resp.extend_from_slice(&[0, 0]);
        resp.extend_from_slice(&[3, 1, 9, 0, 0, 0x02, 0x08, 0, 0]);
        let r = addba_response(&resp, own).unwrap();
        assert_eq!(
            (r.from, r.dialog_token, r.status, r.tid(), r.buffer_size()),
            (ap, 9, 0, 0, 32)
        );
        assert_eq!(addba_response(&resp, ap), None);
        // a request is not a response
        assert_eq!(addba_response(&out[..n], ap), None);
    }

    #[test]
    fn ht_airtime_matches_hand_computed_values() {
        // 1,500 bytes: 12,022 bits
        assert_eq!(ht_airtime_us(7, false, 1500), 36 + 4 * 47);
        assert_eq!(ht_airtime_us(7, true, 1500), 36 + 4 * 43);
        assert_eq!(ht_airtime_us(0, false, 1500), 36 + 4 * 463);
        assert_eq!(ht_airtime_us(0, true, 1500), 36 + 4 * 417);
        assert_eq!(ht_airtime_us(4, false, 1500), 36 + 4 * 78);
    }

    #[test]
    fn negotiated_needs_wmm_for_ht() {
        let mut ht_only = HT_CAPABILITIES_ELEMENT.to_vec();
        assert_eq!(
            negotiated(&ht_only),
            Link {
                qos: false,
                ht: None
            }
        );
        ht_only.extend_from_slice(&WMM_INFORMATION_ELEMENT);
        assert_eq!(
            negotiated(&ht_only),
            Link {
                qos: true,
                ht: Some(HtLink {
                    short_gi: true,
                    mcs: 0xff
                })
            }
        );
        assert_eq!(
            negotiated(&WMM_INFORMATION_ELEMENT),
            Link {
                qos: true,
                ht: None
            }
        );
    }

    #[test]
    fn negotiated_survives_truncation_and_junk() {
        let mut bytes = WMM_INFORMATION_ELEMENT.to_vec();
        bytes.extend_from_slice(&HT_CAPABILITIES_ELEMENT[..20]);
        let link = negotiated(&bytes);
        assert_eq!(
            link,
            Link {
                qos: true,
                ht: None
            }
        );
        for n in 0..bytes.len() {
            let _ = negotiated(&bytes[..n]);
        }
    }

    #[test]
    fn highest_mcs() {
        assert_eq!(
            HtLink {
                short_gi: false,
                mcs: 0xff
            }
            .highest_mcs(),
            Some(7)
        );
        assert_eq!(
            HtLink {
                short_gi: false,
                mcs: 0x1f
            }
            .highest_mcs(),
            Some(4)
        );
        assert_eq!(
            HtLink {
                short_gi: false,
                mcs: 0
            }
            .highest_mcs(),
            None
        );
    }

    fn ethernet(dst: u8, len: usize) -> std::vec::Vec<u8> {
        let mut e = std::vec![dst, 2, 3, 4, 5, 6, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00];
        e.extend((0..len).map(|i| i as u8));
        e
    }

    #[test]
    fn amsdu_pads_between_subframes_not_after_the_last() {
        let a = ethernet(0x10, 21);
        let b = ethernet(0x20, 5);
        let mut buf = [0xeeu8; 200];
        let n = write_qos_data(&mut buf, [9; 6], [0x02, 0, 0, 0, 0, 1], None, &[&a, &b]).unwrap();
        // first subframe 14 + 8 + 21 = 43, padded to 44; second 14 + 8 + 5
        assert_eq!(n, QOS_HEADER + 44 + 27);
        assert_eq!(buf[24], 0x80);
        assert_eq!(&buf[16..22], &[9; 6]);
        assert_eq!(&buf[26 + 12..26 + 14], &29u16.to_be_bytes());
        assert_eq!(buf[26 + 43], 0, "padding is zero");
        assert_eq!(&buf[26 + 44..26 + 50], &b[..6]);
        assert_eq!(&buf[26 + 44 + 12..26 + 44 + 14], &13u16.to_be_bytes());
    }

    #[test]
    fn a_bridged_station_is_address_4() {
        let mut eth = ethernet(0x10, 20);
        eth[6] = 0xaa;
        let mut buf = [0u8; 128];
        let n = write_four_address(&mut buf, [9; 6], [0x02, 0, 0, 0, 0, 1], None, &eth, 1).unwrap();
        assert_eq!((buf[0], buf[1]), (0x88, 0x03));
        assert_eq!(&buf[4..10], &[9; 6]);
        assert_eq!(&buf[10..16], &[0x02, 0, 0, 0, 0, 1]);
        assert_eq!(&buf[16..22], &eth[..6]);
        assert_eq!(&buf[24..30], &eth[6..12]);
        assert_eq!(buf[30], 1);
        assert_eq!(&buf[32..38], &[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]);
        assert_eq!(&buf[38..40], &eth[12..14]);
        assert_eq!(n, 32 + 8 + 20);
        let protected = write_four_address(
            &mut buf,
            [9; 6],
            [0x02, 0, 0, 0, 0, 1],
            Some((0x0102_0304_0506, 1)),
            &eth,
            1,
        )
        .unwrap();
        assert_eq!(buf[1], 0x43);
        assert_eq!(&buf[32..40], &[0x06, 0x05, 0, 0x60, 0x04, 0x03, 0x02, 0x01]);
        assert_eq!(protected, 32 + 8 + 8 + 20 + 8);
    }

    #[test]
    fn fits() {
        assert!(amsdu_fits(&[1514, 1514]));
        assert!(!amsdu_fits(&[1514, 1514, 1514]));
        assert!(amsdu_fits(&[1514]));
        assert!(!amsdu_fits(&[10]));
    }

    #[test]
    fn addba_round_trip() {
        let own = [0x02, 0, 0, 0, 0, 1];
        let ap = [0x0a, 1, 2, 3, 4, 5];
        let mut req = std::vec![0xd0, 0, 0, 0];
        req.extend_from_slice(&own);
        req.extend_from_slice(&ap);
        req.extend_from_slice(&ap);
        req.extend_from_slice(&[0x10, 0]);
        req.extend_from_slice(&[3, 0, 7, 0x02, 0x10, 0, 0, 0x10, 0]);
        let r = addba_request(&req, own).unwrap();
        assert_eq!(
            r,
            AddbaRequest {
                from: ap,
                dialog_token: 7,
                parameters: 0x1002
            }
        );
        assert_eq!(addba_request(&req, [1; 6]), None);
        let mut out = [0u8; 64];
        let n = write_addba_decline(&mut out, own, ap, &r).unwrap();
        assert_eq!(n, 33);
        assert_eq!(&out[4..10], &ap);
        assert_eq!(&out[24..33], &[3, 1, 7, 37, 0, 0x02, 0x10, 0, 0]);
    }
}

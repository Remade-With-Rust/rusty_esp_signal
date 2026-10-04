//! ESP-NOW's frame on the air, laid out and parsed by hand (Janus E4; the
//! family's addition to the open MAC). With the blob, `libespnow` builds
//! this frame and the application never sees it; on the open MAC a vendor
//! action frame is ours to build and parse, so the mID link rides the same
//! bytes with no Espressif code behind them, and a node on the open MAC and
//! a node on the blob hear each other. **Not Wi-Fi certified.**
//!
//! The layout is Espressif's published one (ESP-IDF's ESP-NOW guide):
//!
//! ```text
//! | MAC header | Category | OUI      | Random | Vendor element                              |
//! | 24 bytes   | 127      | 18 FE 34 | 4      | 221, len, 18 FE 34, type 4, version, body   |
//! ```
//!
//! The MAC header is an 802.11 Action frame's (management, subtype 13),
//! ToDS and FromDS clear, address 1 the destination, address 2 the source,
//! address 3 the broadcast address. The element's length counts its OUI,
//! type, version and body, so a body is at most 250 bytes. Version 1 is the
//! whole version octet; version 2 (ESP-IDF 5.4 and later) keeps the version
//! in the low four bits and uses bit 4 for "more data" (a payload continued
//! in further elements): a version 2 radio takes version 1 frames, and this
//! writes version 1. Encrypted ESP-NOW (the Protected bit, CCMP under a
//! pairwise key the blob holds) is not read: the link above this is
//! authenticated and sealed by its own session.
//!
//! No hardware, no clock, no randomness in here: the caller brings the four
//! random octets and the radio.

#![no_std]

/// A MAC address.
pub type Address = [u8; 6];

/// The broadcast address: every station in range, and address 3 of every
/// ESP-NOW frame.
pub const BROADCAST: Address = [0xff; 6];
/// Espressif's OUI, which names the vendor action frame and its element.
pub const ESPRESSIF_OUI: [u8; 3] = [0x18, 0xfe, 0x34];
/// The Action frame's category: vendor specific.
pub const CATEGORY_VENDOR_SPECIFIC: u8 = 127;
/// The vendor-specific element's ID.
pub const ELEMENT_VENDOR_SPECIFIC: u8 = 221;
/// The element's type octet: ESP-NOW.
pub const TYPE_ESP_NOW: u8 = 4;
/// The version this writes.
pub const VERSION: u8 = 1;
/// Frame Control's first octet: protocol 0, management, subtype 13 (Action).
pub const FRAME_CONTROL_ACTION: u8 = 0xd0;

/// The 802.11 MAC header of a management frame.
pub const MAC_HEADER: usize = 24;
/// Category, OUI, the random octets.
pub const ACTION_HEADER: usize = 1 + 3 + 4;
/// Element ID, length, OUI, type, version.
pub const ELEMENT_HEADER: usize = 2 + 3 + 1 + 1;
/// Everything around a body.
pub const OVERHEAD: usize = MAC_HEADER + ACTION_HEADER + ELEMENT_HEADER;
/// The longest body: the element's one-octet length less its OUI, type and
/// version.
pub const MAX_BODY: usize = 250;
/// The longest frame this writes (without the FCS the radio appends).
pub const MAX_FRAME: usize = OVERHEAD + MAX_BODY;

/// Lay an ESP-NOW frame carrying `body` from `from` to `to` into `out`: the
/// length written, or `None` when the body is over [`MAX_BODY`] or `out` is
/// short. Duration and sequence control are zero: the radio's. `random` is
/// the four octets the format carries against replayed frames.
#[must_use]
pub fn write(
    out: &mut [u8],
    to: &Address,
    from: &Address,
    random: [u8; 4],
    body: &[u8],
) -> Option<usize> {
    if body.len() > MAX_BODY {
        return None;
    }
    let total = OVERHEAD + body.len();
    let frame = out.get_mut(..total)?;
    frame[0] = FRAME_CONTROL_ACTION;
    frame[1] = 0;
    frame[2..4].fill(0);
    frame[4..10].copy_from_slice(to);
    frame[10..16].copy_from_slice(from);
    frame[16..22].copy_from_slice(&BROADCAST);
    frame[22..24].fill(0);
    frame[24] = CATEGORY_VENDOR_SPECIFIC;
    frame[25..28].copy_from_slice(&ESPRESSIF_OUI);
    frame[28..32].copy_from_slice(&random);
    frame[32] = ELEMENT_VENDOR_SPECIFIC;
    // the OUI, the type, the version, the body
    frame[33] = (5 + body.len()) as u8;
    frame[34..37].copy_from_slice(&ESPRESSIF_OUI);
    frame[37] = TYPE_ESP_NOW;
    frame[38] = VERSION;
    frame[OVERHEAD..].copy_from_slice(body);
    Some(total)
}

/// An ESP-NOW frame as received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Address 1: who it is for (a station or [`BROADCAST`]).
    pub to: Address,
    /// Address 2: who sent it.
    pub from: Address,
    /// The four random octets.
    pub random: [u8; 4],
    /// The version, 1 or 2 (the low four bits of the version octet).
    pub version: u8,
    /// Version 2's "more data": the payload continues in further elements,
    /// which this does not join. A body of up to 250 bytes never sets it.
    pub more_data: bool,
    /// The first element's body.
    pub body: &'a [u8],
}

/// Read an MPDU (without its FCS) as an ESP-NOW frame. `None` for anything
/// else: another frame type, another vendor, another element type, an
/// encrypted frame, a length that runs past the frame. Octets after the
/// first element are left alone.
#[must_use]
pub fn parse(mpdu: &[u8]) -> Option<Frame<'_>> {
    if mpdu.len() < OVERHEAD {
        return None;
    }
    // an Action frame between two stations, in the clear
    if mpdu[0] != FRAME_CONTROL_ACTION || mpdu[1] & (0x01 | 0x02 | 0x40) != 0 {
        return None;
    }
    if mpdu[24] != CATEGORY_VENDOR_SPECIFIC || mpdu[25..28] != ESPRESSIF_OUI {
        return None;
    }
    if mpdu[32] != ELEMENT_VENDOR_SPECIFIC
        || mpdu[34..37] != ESPRESSIF_OUI
        || mpdu[37] != TYPE_ESP_NOW
    {
        return None;
    }
    let body_len = usize::from(mpdu[33]).checked_sub(5)?;
    let body = mpdu.get(OVERHEAD..OVERHEAD + body_len)?;
    let version = mpdu[38] & 0x0f;
    if version == 0 {
        return None;
    }
    Some(Frame {
        to: mpdu[4..10].try_into().ok()?,
        from: mpdu[10..16].try_into().ok()?,
        random: mpdu[28..32].try_into().ok()?,
        version,
        more_data: mpdu[38] & 0x10 != 0,
        body,
    })
}

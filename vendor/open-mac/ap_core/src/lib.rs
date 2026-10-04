//! The open MAC's access point as pure functions (Janus E3, P2; the
//! family's addition to FoA): the frames an access point sends, laid out by
//! hand from 802.11-2020 (so the tests read them back with `ieee80211`'s
//! parsers, two implementations checking each other), the station table and
//! the association decisions, the RSN element a station may offer, and
//! WPA2-PSK's authenticator, the mirror of `sta_handshake`. No hardware, no
//! clock, no randomness in here: `foa_ap` brings the radio, the timers and
//! the nonces. **Not Wi-Fi certified.**

#![no_std]

pub mod elements;
pub mod frames;
pub mod handshake;
pub mod hold;
pub mod request;
pub mod rsn;
pub mod stations;

/// A MAC address.
pub type Address = [u8; 6];

/// The broadcast address.
pub const BROADCAST: Address = [0xff; 6];

/// 802.11 status codes this access point answers with (802.11-2020 Table
/// 9-80).
pub mod status {
    /// Success.
    pub const SUCCESS: u16 = 0;
    /// Unspecified failure.
    pub const UNSPECIFIED: u16 = 1;
    /// The authentication algorithm is not supported.
    pub const UNSUPPORTED_AUTH_ALGORITHM: u16 = 13;
    /// The transaction sequence number is out of order.
    pub const AUTH_OUT_OF_SEQUENCE: u16 = 14;
    /// The access point cannot take another station.
    pub const TOO_MANY_STATIONS: u16 = 17;
    /// The element was not valid.
    pub const INVALID_ELEMENT: u16 = 40;
    /// The group cipher is not valid.
    pub const INVALID_GROUP_CIPHER: u16 = 41;
    /// The pairwise cipher is not valid.
    pub const INVALID_PAIRWISE_CIPHER: u16 = 42;
    /// The AKM is not valid.
    pub const INVALID_AKMP: u16 = 43;
    /// The RSN element's version is not supported.
    pub const UNSUPPORTED_RSNE_VERSION: u16 = 44;
    /// The RSN capabilities are not valid.
    pub const INVALID_RSNE_CAPABILITIES: u16 = 45;
}

/// 802.11 reason codes (802.11-2020 Table 9-79).
pub mod reason {
    /// Unspecified.
    pub const UNSPECIFIED: u16 = 1;
    /// Disassociated for inactivity.
    pub const INACTIVITY: u16 = 4;
    /// The access point is leaving (or cannot serve the station).
    pub const LEAVING: u16 = 3;
    /// Class 2 frame from a station not authenticated.
    pub const CLASS2_FROM_NONAUTH: u16 = 6;
    /// Class 3 frame from a station not associated.
    pub const CLASS3_FROM_NONASSOC: u16 = 7;
    /// The 4-way handshake timed out.
    pub const FOURWAY_HANDSHAKE_TIMEOUT: u16 = 15;
    /// The group-key handshake timed out.
    pub const GROUP_KEY_HANDSHAKE_TIMEOUT: u16 = 16;
}

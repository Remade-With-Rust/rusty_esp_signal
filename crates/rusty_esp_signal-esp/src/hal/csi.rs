//! A Wi-Fi CSI measurement borrowed into the core's [`CsiFrame`].
//!
//! esp-radio delivers channel state information to a callback as a
//! [`WifiCsiInfo`], which borrows the raw `i8` I/Q buffer the PHY wrote.
//! [`csi_frame`] wraps that borrow in the core's [`CsiFrame`] without copying,
//! so the callback can run it straight through a `radar::csi::PresenceDetector`.
//!
//! ## Registering the callback
//!
//! The callback is installed on the running Wi-Fi (or ESP-NOW) controller with
//! `set_csi`, which takes a `FnMut(WifiCsiInfo) + Send`. That closure captures
//! the detector and the presence sink, so it lives in the firmware, not here —
//! its exact captures are the firmware's. This module owns only the pure
//! conversion and the layout choice, which are the parts worth testing and
//! sharing. See `firmware/c6-mesh-node` for the wiring.
//!
//! ## Which layout
//!
//! [`recommended_layout`] returns the [`Layout`] to parse a C6 HT20 capture
//! with: the promiscuous-capture order the ledger's oracle dataset uses. A
//! capture on a different chip or bandwidth needs a different layout; the
//! core carries the others.

use esp_radio::wifi::csi::WifiCsiInfo;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::radar::csi::{CsiFrame, Layout};

/// Borrow a delivered CSI measurement as a core [`CsiFrame`], timestamped
/// `now`. No copy: the frame borrows esp-radio's PHY buffer, so it must be
/// consumed before the callback returns.
///
/// `first_word_invalid` is honoured by zero-length handling in the core's
/// feature extractor for a too-short buffer; on the chips with the hardware
/// limitation the first two I/Q pairs (subcarriers 0 and 1) are garbage, which
/// the C6 natural-order layout already treats as guard entries.
#[must_use]
pub fn csi_frame<'a>(info: &'a WifiCsiInfo<'a>, now: Micros) -> CsiFrame<'a> {
    CsiFrame {
        timestamp: now,
        rssi: info.rssi(),
        channel: info.channel(),
        iq: info.buf(),
    }
}

/// The [`Layout`] to parse an ESP32-C6 20 MHz HT capture with: natural
/// subcarrier order, 56 live subcarriers, matching the ledger's oracle
/// dataset. Use the core's other layouts for a different chip or bandwidth.
#[must_use]
pub const fn recommended_layout() -> Layout {
    Layout::C6_HT20_NATURAL
}

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_esp_signal-core` — the pure heart of `rusty_esp_signal`: the radio
//! *application* layer with no radio in it.
//!
//! - [`radar`] — presence and motion from Wi-Fi CSI ([`radar::csi`]) and the
//!   HLK-LD2410 mmWave UART protocol ([`radar::ld2410`]).
//! - [`link`] — the mID-authenticated session and the MAC'd frame envelope
//!   every ESP-NOW and LoRa frame travels in.
//! - [`wifi`] — credentials that never print, and the station policy
//!   (reconnect back-off, fallback to provisioning).
//! - [`ble`] — the GATT table (provisioning, manifest, telemetry) as data.
//! - [`lora`] — modem parameters, exact time-on-air, region duty cycle, the
//!   discovery beacon.
//!
//! Rules this crate lives by (from the Janus mission plan):
//!
//! 1. `no_std` by default; `alloc` is a feature, never an assumption.
//! 2. No drivers, no HAL types, no `esp-*` crate, no allocator. Backends live
//!    in `rusty_esp_signal-esp`.
//! 3. Every type that crosses to another Janus package comes from
//!    `rusty_esp_core`; identity comes from `rusty_esp_mid-core`.
//! 4. Frames and buffers are **borrowed over caller-owned memory**; nothing
//!    here allocates per frame on a hot path.
//! 5. `forbid(unsafe)`. Detectors are fixed-point and developed on the host
//!    from recorded captures against an external oracle before any radio.
//! 6. Sign the session, MAC the frames: P-256 ECDH under the device DID for
//!    the session key, HMAC-SHA256 truncated to 16 bytes per frame.

#[cfg(feature = "alloc")]
extern crate alloc;

pub use rusty_esp_core as esp_core;
pub use rusty_esp_mid_core as mid;

pub mod ble;
pub mod link;
pub mod lora;
pub mod provision;
pub mod radar;
pub mod wifi;

/// The names a sketch or firmware wants in scope.
pub mod prelude {
    pub use rusty_esp_core::prelude::*;

    pub use crate::ble::{Characteristic, GattTable, Props, Service};
    pub use crate::link::{Envelope, Handshake, Session};
    pub use crate::lora::{Beacon, DutyCycle, Params as LoraParams, Region};
    pub use crate::provision::{Provisioner, ScanEntry, ScanList};
    pub use crate::radar::csi::{CsiFrame, Features, PresenceDetector, Verdict};
    pub use crate::radar::ld2410::{Parser as Ld2410Parser, Report as Ld2410Report};
    pub use crate::wifi::{Action, Credentials, Event, Phase, StationPolicy};
}

/// Crate version, for capability manifests and logs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

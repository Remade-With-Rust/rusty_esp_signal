//! Track B backends: esp-hal + esp-radio, `no_std`.
//!
//! Each submodule wraps one radio and feeds the pure core. See the crate
//! docs for the map. Everything here is compiled by a firmware that selected
//! the chip; the host build never reaches this module.

// esp-hal only.
pub mod ld2410;
pub mod rng;

// These need esp-radio (the Wi-Fi/ESP-NOW driver).
#[cfg(feature = "esp-radio")]
pub mod csi;
#[cfg(feature = "esp-radio")]
pub mod link;
#[cfg(feature = "esp-radio")]
pub mod station;

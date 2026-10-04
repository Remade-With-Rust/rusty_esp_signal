//! The Wi-Fi station on the open lower MAC, for the ESP32-S3 (the umbrella's
//! experiments plan, row E1). **Not Wi-Fi certified.**
//!
//! The MAC is `esp-wifi-hal` and the 802.11 station FoA's, vendored in this
//! repository at pinned upstream commits and ported to the family's esp-hal
//! 1.2 (`vendor/open-mac/UPSTREAM.md`). The PHY is still Espressif's
//! `libphy`, the one radio blob in an image built on this crate; nothing here
//! sets transmit power, channels or regulatory tables. Its first boot is on a
//! sacrificial S3, never the bench board first.
//!
//! The shape is `rusty_esp_signal-esp`'s `hal::netstack`, so a cell swaps
//! one for the other: [`stack`] gives the embassy-net [`Stack`] and the
//! tasks to spawn, [`station_task`] keeps the station joined under the
//! core's [`StationPolicy`]; [`access_point::hosted_stack`] hosts a network
//! instead (the plan's E3). esp-radio is not in the graph.
//!
//! The crate is empty unless a firmware turns on `esp32s3`.
#![no_std]

#[cfg(feature = "esp32s3")]
mod station;

/// The access point (E3): `hosted_stack` and its tasks, in the shape of
/// `hal::netstack`'s hosting half.
#[cfg(feature = "esp32s3")]
pub mod access_point;

#[cfg(feature = "esp32s3")]
pub use station::*;

#[cfg(feature = "esp32s3")]
pub use rusty_esp_signal_core::wifi::{PolicyConfig, StationPolicy};

#[cfg(feature = "esp32s3")]
pub use embassy_net::Stack;

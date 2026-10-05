//! The Wi-Fi station on the open lower MAC, for the ESP32-S3 (the umbrella's
//! experiments plan, row E1). **Not Wi-Fi certified.**
//!
//! The MAC is `esp-wifi-hal` and the 802.11 station FoA's, vendored in this
//! repository at pinned upstream commits and ported to the family's esp-hal
//! 1.2 (`vendor/open-mac/UPSTREAM.md`). The PHY is still Espressif's
//! `libphy`, the one radio blob in an image built on this crate; nothing here
//! sets channels or regulatory tables. The transmit power is capped where
//! esp-radio caps it, 5 dBm, by the vendored esp-phy's `phy_max_tx_power`
//! option (quarter dBm; `ESP_PHY_CONFIG_PHY_MAX_TX_POWER` in a firmware's
//! `[env]`, 80 for ESP-IDF's 20 dBm).
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

/// The mID link on raw ESP-NOW frames (E4): `RawLink` in the shape of
/// `hal::link::UdpLink`, no association and no IP under it.
#[cfg(feature = "esp32s3")]
pub mod raw_link;

#[cfg(feature = "esp32s3")]
pub use station::*;

/// FoA's resources, one block for the firmware: the station, the access
/// point and the bare raw link each bring the MAC up from it, and a firmware
/// brings up one of them per boot (a second bring-up panics, as it did with
/// a block each). A cell with a setup boot that hosts and a station boot
/// that joins (espino's C18) had two blocks of 29.7 KB in `.bss`, which on
/// the S3 is the main stack's. Built in place (`foa::StaticFoAResources`):
/// moved into a `StaticCell` from a temporary, it was also 28 KB of main
/// stack at bring-up, which tripped C18's stack guard inside `hosted_stack`.
#[cfg(feature = "esp32s3")]
pub(crate) static FOA: foa::StaticFoAResources = foa::StaticFoAResources::new();

#[cfg(feature = "esp32s3")]
pub use rusty_esp_signal_core::wifi::{PolicyConfig, StationPolicy};

#[cfg(feature = "esp32s3")]
pub use embassy_net::Stack;

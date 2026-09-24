#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
//! `rusty_esp_signal-esp` — chip backends for `rusty_esp_signal`.
//!
//! This is the **wrap** crate of the package: where the silicon must be
//! touched, it calls the esp-rs HAL (Track B, `esp-hal` + `esp-radio`) or
//! ESP-IDF (Track A, `esp-idf`) and feeds bytes into the pure core's state
//! machines. Nothing product- or protocol-specific lives here; that is the
//! core's job. This crate ingests the signal; the core interprets it.
//!
//! ## Track B is compiled by a firmware, never on its own
//!
//! esp-hal refuses to build unless exactly one chip feature (`esp32c6`, …) is
//! set, and a library that selected one would fix the chip for every consumer.
//! So the chip is chosen by the firmware binary, which turns on this crate's
//! `esp-hal` feature and its own `esp-hal`/`esp-radio` chip feature; cargo's
//! feature unification then compiles the backends below for that chip. The
//! host build and the workspace tests use **no** feature here and see only the
//! [`Track`] marker, so they never need a chip.
//!
//! ## The radios
//!
//! Each backend feeds one core module ([`rusty_esp_signal_core`]):
//!
//! - [`hal::rng`] — the hardware TRNG behind the core's `Rng` seam, for device
//!   keys and session ephemerals.
//! - [`hal::link`] — the ESP-NOW datagram transport under the mID-authenticated
//!   `link::Session`, plus the handshake driven over it.
//! - [`hal::csi`] — a Wi-Fi CSI frame borrowed into `radar::csi::CsiFrame`;
//!   `idf::csi` (feature `esp-idf-csi`) is its Track A twin, a callback on
//!   ESP-IDF's Wi-Fi task parked into a ring the sketch drains. The ring and
//!   the buffer's ingest are [`csi_queue`], compiled on the host and tested
//!   there, because a callback cannot be tested on a board.
//! - [`hal::ld2410`] — a UART reader feeding `radar::ld2410::Parser`.
//! - [`hal::station`] — Wi-Fi station events driving `wifi::StationPolicy`.
//! - [`lora`] (feature `lora`) — `lora::Params` mapped to `lora-phy`
//!   modulation and packet parameters, and the P2P link over them.
//! - [`ble`] (feature `ble`) — a `trouble-host` GATT server built from the
//!   core's `ble::GATT_TABLE`.
//!
//! The last two touch no esp crate: they are generic over the modem and the
//! HCI controller, so a firmware can take either without the radio stack.

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "esp-hal", feature = "esp-idf"))]
compile_error!("enable exactly one track: `esp-hal` (no_std) or `esp-idf` (std)");

pub use rusty_esp_signal_core as core_crate;

/// Which track this build of the backend crate was compiled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    /// No chip backend compiled in: host build, traits only.
    Host,
    /// Track B — bare metal, esp-hal + esp-radio + Embassy.
    EspHal,
    /// Track A — std on ESP-IDF.
    EspIdf,
}

/// The track this crate was built with.
pub const TRACK: Track = if cfg!(feature = "esp-hal") {
    Track::EspHal
} else if cfg!(feature = "esp-idf") {
    Track::EspIdf
} else {
    Track::Host
};

pub mod csi_queue;

#[cfg(feature = "esp-hal")]
pub mod hal;

#[cfg(feature = "lora")]
pub mod lora;

#[cfg(feature = "ble")]
pub mod ble;

#[cfg(feature = "esp-idf")]
pub mod idf;

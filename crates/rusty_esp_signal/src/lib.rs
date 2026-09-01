#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_esp_signal` — The radio-application layer remade in Rust: Wi-Fi CSI radar (presence/motion), LoRa point-to-point over lora-phy, BLE provisioning and telemetry over trouble-host, Wi-Fi station/AP lifecycle and ESP-NOW framing — every frame mID-signed. Memory safe, no_std core.
//!
//! This is the facade: it re-exports the `no_std` core and exposes the
//! chip backends under [`esp`]. Depend on this crate; reach into the
//! sub-crates only when you are building a backend.
//!
//! Part of Janus (Remade With Rust). Plan: `docs/plans/rusty_esp_signal.md`.

pub use rusty_esp_signal_core::*;

/// Chip backends (`esp-hal` for Track B, `esp-idf` for Track A).
pub mod esp {
    pub use rusty_esp_signal_esp::*;
}

/// The names a sketch or firmware wants in scope.
pub mod prelude {
    pub use rusty_esp_signal_core::prelude::*;
}

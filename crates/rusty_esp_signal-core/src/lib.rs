#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
//! `rusty_esp_signal-core` — the pure heart of `rusty_esp_signal`.
//!
//! Rules this crate lives by (from the Janus mission plan):
//!
//! 1. `no_std` by default; `alloc` is a feature, never an assumption.
//! 2. No drivers, no HAL types, no `esp-*` crate, no allocator. Backends live
//!    in `rusty_esp_signal-esp`.
//! 3. Every type that crosses to another Janus package comes from
//!    `rusty_esp_core`, so packages compose without conversions.
//! 4. Frames and buffers are **borrowed over caller-owned memory**; nothing
//!    here allocates per frame on a hot path.
//! 5. `forbid(unsafe)`. The scalar path is the oracle; any faster path is gated
//!    byte-identical against it.

#[cfg(feature = "alloc")]
extern crate alloc;

pub use rusty_esp_core as esp_core;

/// The names a sketch or firmware wants in scope.
pub mod prelude {
    pub use rusty_esp_core::prelude::*;
}

/// Crate version, for capability manifests and logs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

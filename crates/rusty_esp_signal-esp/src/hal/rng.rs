//! The hardware TRNG behind the core's [`Rng`] seam.
//!
//! `rusty_esp_mid` generates the device key and `rusty_esp_signal-core`'s
//! `link` draws session ephemerals through `rusty_esp_core::Rng`. On the chip
//! that must be the hardware true-RNG: a predictable device key is a
//! compromised device, and the core's seam documents that an implementation
//! must never fall back to a deterministic generator without an error.
//!
//! esp-hal exposes two generators. [`esp_hal::rng::Rng`] is seeded from the
//! RC oscillator and is only cryptographically strong while the radio is on;
//! [`esp_hal::rng::Trng`] adds an ADC entropy source and is a true-RNG. This
//! wrapper takes the `Trng`, so a caller cannot accidentally key a device from
//! the weaker source. The firmware keeps a [`esp_hal::rng::TrngSource`] alive
//! (it owns the RNG and ADC1 peripherals and enables the entropy source);
//! [`esp_hal::rng::Trng::try_new`] then hands out a handle this wraps.

use esp_hal::rng::Trng;
use rusty_esp_signal_core::esp_core::error::Result;
use rusty_esp_signal_core::esp_core::{Error, Rng};

/// The chip's true-RNG behind the core's [`Rng`] seam.
///
/// Construct it from an esp-hal [`Trng`] handle ([`Trng::try_new`], which
/// succeeds only while a `TrngSource` is alive). Every `fill` reads the
/// hardware; there is no deterministic fallback, which the core's seam forbids.
pub struct EspTrng {
    trng: Trng,
}

impl EspTrng {
    /// Wrap an esp-hal [`Trng`] handle.
    #[must_use]
    pub fn new(trng: Trng) -> Self {
        Self { trng }
    }
}

impl Rng for EspTrng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        // `Trng::read` fills from the hardware true-RNG and cannot report a
        // fault through its signature; the entropy source is guaranteed live
        // by the `Trng` type. There is no silent deterministic fallback, which
        // is what the core's `Rng` contract forbids.
        self.trng.read(buf);
        Ok(())
    }
}

/// A guard: the `Rng` seam must not be satisfied by the weaker
/// [`esp_hal::rng::Rng`]. This function exists only to be pointed at in docs
/// and to fail compilation if someone tries — it takes the strong type.
///
/// Returns `Err(Error::Crypto)` never; it is total, and the type is the check.
#[doc(hidden)]
pub fn assert_true_rng(_trng: &Trng) -> Result<()> {
    Ok(())
}

#[allow(dead_code)]
fn _unused(_: Error) {}

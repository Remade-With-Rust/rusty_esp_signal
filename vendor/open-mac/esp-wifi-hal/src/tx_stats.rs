//! Transmit counters (E1, the family's addition to the vendored driver):
//! for every frame handed to `transmit_with_retry`, the attempts it took,
//! whether the first succeeded, and the time from the first attempt's start
//! to the last attempt's result (contention, RTS/CTS when on, air time, the
//! ACK, the retries). A handful of relaxed atomic adds a frame; read with
//! [`snapshot`].

use core::sync::atomic::{AtomicU32, Ordering};

use portable_atomic::AtomicU64;

use crate::async_driver::TxError;

static FRAMES: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
static FIRST_OK: AtomicU32 = AtomicU32::new(0);
static ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static RADIO_US: AtomicU64 = AtomicU64::new(0);

/// One frame's outcome: `Ok(i)` is the index of the attempt that succeeded.
pub(crate) fn record(result: &Result<u8, TxError>, micros: u64) {
    FRAMES.fetch_add(1, Ordering::Relaxed);
    RADIO_US.fetch_add(micros, Ordering::Relaxed);
    match result {
        Ok(i) => {
            ATTEMPTS.fetch_add(u32::from(*i) + 1, Ordering::Relaxed);
            if *i == 0 {
                FIRST_OK.fetch_add(1, Ordering::Relaxed);
            }
        }
        Err(_) => {
            FAILED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The counters since boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxStats {
    /// Frames handed to the driver.
    pub frames: u32,
    /// Frames whose every attempt failed.
    pub failed: u32,
    /// Frames sent on the first attempt.
    pub first_ok: u32,
    /// Attempts the successful frames took, in all.
    pub attempts: u32,
    /// Microseconds from first start to last result, summed over frames.
    pub radio_us: u64,
}

/// Read the counters.
#[must_use]
pub fn snapshot() -> TxStats {
    TxStats {
        frames: FRAMES.load(Ordering::Relaxed),
        failed: FAILED.load(Ordering::Relaxed),
        first_ok: FIRST_OK.load(Ordering::Relaxed),
        attempts: ATTEMPTS.load(Ordering::Relaxed),
        radio_us: RADIO_US.load(Ordering::Relaxed),
    }
}

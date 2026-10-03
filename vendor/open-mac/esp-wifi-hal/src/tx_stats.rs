//! Transmit counters (E1, the family's addition to the vendored driver):
//! for every frame handed to `transmit_with_retry`, the attempts it took,
//! whether the first succeeded, and the time from the first attempt's start
//! to the last attempt's result (contention, RTS/CTS when on, air time, the
//! ACK, the retries). A handful of relaxed atomic adds a frame; read with
//! [`snapshot`].

use core::sync::atomic::{AtomicU32, Ordering};

use portable_atomic::AtomicU64;

use crate::async_driver::TxError;
use crate::ll::{ChannelAccessError, MacProtocolError};

static FRAMES: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
static FIRST_OK: AtomicU32 = AtomicU32::new(0);
static ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static RADIO_US: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static ACK_TIMEOUT: AtomicU32 = AtomicU32::new(0);
static MAC_OTHER: AtomicU32 = AtomicU32::new(0);
static ACCESS_TIMEOUT: AtomicU32 = AtomicU32::new(0);
static ACCESS_COLLISION: AtomicU32 = AtomicU32::new(0);
static OTHER: AtomicU32 = AtomicU32::new(0);
/// Per hardware slot: when the attempt started, and when its interrupt came.
static STARTED_AT: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
static SIGNALLED_AT: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
static HW_US: AtomicU64 = AtomicU64::new(0);
static WAKE_US: AtomicU64 = AtomicU64::new(0);
static TIMED: AtomicU32 = AtomicU32::new(0);

fn now_us() -> u64 {
    esp_hal::time::Instant::now().duration_since_epoch().as_micros()
}

/// An attempt is about to start on `slot`.
pub(crate) fn started(slot: usize) {
    if let Some(at) = STARTED_AT.get(slot) {
        at.store(now_us(), Ordering::Relaxed);
    }
}

/// The MAC interrupt is signalling `slot`'s result (called in the handler).
pub(crate) fn mark(slot: usize) {
    if let Some(at) = SIGNALLED_AT.get(slot) {
        at.store(now_us(), Ordering::Relaxed);
    }
}

/// The task waiting on `slot` is running again: split the attempt into the
/// hardware's part (start to interrupt: contention, air, the ACK or its
/// timeout) and the wake's (interrupt to the task resuming).
pub(crate) fn woke(slot: usize) {
    let (Some(started), Some(signalled)) = (STARTED_AT.get(slot), SIGNALLED_AT.get(slot)) else {
        return;
    };
    let (start, signal, now) =
        (started.load(Ordering::Relaxed), signalled.load(Ordering::Relaxed), now_us());
    if start == 0 || signal < start || now < signal {
        return;
    }
    HW_US.fetch_add(signal - start, Ordering::Relaxed);
    WAKE_US.fetch_add(now - signal, Ordering::Relaxed);
    TIMED.fetch_add(1, Ordering::Relaxed);
}

/// One attempt's outcome, by kind: what a failed attempt failed of.
pub(crate) fn attempt<T>(result: &Result<T, TxError>) {
    let counter = match result {
        Ok(_) => return,
        Err(TxError::MacProtocol(MacProtocolError::AckTimeout)) => &ACK_TIMEOUT,
        Err(TxError::MacProtocol(_)) => &MAC_OTHER,
        Err(TxError::ChannelAccess(ChannelAccessError::Timeout)) => &ACCESS_TIMEOUT,
        Err(TxError::ChannelAccess(ChannelAccessError::Collision)) => &ACCESS_COLLISION,
        #[allow(unreachable_patterns)]
        Err(_) => &OTHER,
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

/// One frame's outcome: `Ok(i)` is the index of the attempt that succeeded.
pub(crate) fn record(result: &Result<u8, TxError>, micros: u64, len: usize) {
    FRAMES.fetch_add(1, Ordering::Relaxed);
    RADIO_US.fetch_add(micros, Ordering::Relaxed);
    match result {
        Ok(i) => {
            BYTES.fetch_add(len as u64, Ordering::Relaxed);
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
    /// MPDU bytes of the frames that were delivered (acknowledged).
    pub bytes: u64,
    /// Failed attempts: no ACK in time.
    pub ack_timeout: u32,
    /// Failed attempts: another MAC protocol error (CTS timeout, key...).
    pub mac_other: u32,
    /// Failed attempts: channel access timed out.
    pub access_timeout: u32,
    /// Failed attempts: channel access collided (another queue won).
    pub access_collision: u32,
    /// Failed attempts of any other kind.
    pub other: u32,
    /// Attempts timed for the split below.
    pub timed: u32,
    /// Their microseconds from start to the interrupt: the hardware's part.
    pub hw_us: u64,
    /// Their microseconds from the interrupt to the task resuming: the wake.
    pub wake_us: u64,
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
        bytes: BYTES.load(Ordering::Relaxed),
        ack_timeout: ACK_TIMEOUT.load(Ordering::Relaxed),
        mac_other: MAC_OTHER.load(Ordering::Relaxed),
        access_timeout: ACCESS_TIMEOUT.load(Ordering::Relaxed),
        access_collision: ACCESS_COLLISION.load(Ordering::Relaxed),
        other: OTHER.load(Ordering::Relaxed),
        timed: TIMED.load(Ordering::Relaxed),
        hw_us: HW_US.load(Ordering::Relaxed),
        wake_us: WAKE_US.load(Ordering::Relaxed),
    }
}

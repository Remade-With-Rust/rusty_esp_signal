//! Transmit counters (E1, the family's addition to the vendored driver):
//! for every frame handed to `transmit_with_retry`, the attempts it took,
//! whether the first succeeded, and the time from the first attempt's start
//! to the last attempt's result (contention, RTS/CTS when on, air time, the
//! ACK, the retries). A handful of relaxed atomic adds a frame; read with
//! [`snapshot`].

use core::sync::atomic::{AtomicU32, Ordering};

use portable_atomic::AtomicU64;

use crate::async_driver::TxError;
use crate::rates::{OfdmRate, PhyRate, TxPhyRate};
use crate::ll::{ChannelAccessError, MacProtocolError};

static FRAMES: AtomicU32 = AtomicU32::new(0);
static FAILED: AtomicU32 = AtomicU32::new(0);
static FIRST_OK: AtomicU32 = AtomicU32::new(0);
static ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static RADIO_US: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
static ACK_TIMEOUT: AtomicU32 = AtomicU32::new(0);
static MAC_OTHER: AtomicU32 = AtomicU32::new(0);
/// InvalidKeyId, also counted in `MAC_OTHER` so the existing fail_mac total
/// stays comparable. A protected frame on the wrong interface reads as this.
static INVALID_KEY: AtomicU32 = AtomicU32::new(0);
/// The MAC errors that are neither an ACK timeout nor a key id, by kind, and
/// every MAC error by interface (0, 1): which side of P2 fails, and how.
static MAC_CTS: AtomicU32 = AtomicU32::new(0);
static MAC_RTS: AtomicU32 = AtomicU32::new(0);
static MAC_UNKNOWN: AtomicU32 = AtomicU32::new(0);
static MAC_IF: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
/// The last MAC error other than an ACK timeout: interface << 24 | kind << 16
/// (1 CTS, 2 RTS access, 3 key id, 4 unknown) | error << 8 | sub-error.
static MAC_LAST: AtomicU32 = AtomicU32::new(0);
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

/// Per OFDM rate, 54 down to 6 Mbit/s: the frames whose first attempt went
/// on the air at that rate (answered, or timed out waiting for the ACK),
/// and those answered. Only first attempts: a retry follows a failure, so
/// it carries that failure's conditions, and counting retries made the
/// rates the retry chain falls to read worse than the rate above them
/// (2026-10-03: 24 Mbit/s at 69 %, 36 at 97 %).
/// E8: the HT rates follow the OFDM ones, MCS 7 down to 0 at 8..16 (the
/// short and the long guard interval share an MCS's place: a build uses
/// one).
static RATE_ATTEMPTS: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
static RATE_ACKED: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];

/// Where `rate` sits in [`rate_snapshot`]: 54 Mbit/s first, 6 last.
#[must_use]
pub const fn ofdm_index(rate: OfdmRate) -> usize {
    match rate {
        OfdmRate::Mbits54 => 0,
        OfdmRate::Mbits48 => 1,
        OfdmRate::Mbits36 => 2,
        OfdmRate::Mbits24 => 3,
        OfdmRate::Mbits18 => 4,
        OfdmRate::Mbits12 => 5,
        OfdmRate::Mbits9 => 6,
        OfdmRate::Mbits6 => 7,
    }
}

/// One attempt at `rate`: counted for the rate if it was a frame's first,
/// went on the air, and was either answered or not (a lost channel-access
/// contest says nothing about the rate).
pub(crate) fn attempt_at<T>(rate: &TxPhyRate, result: &Result<T, TxError>, first: bool) {
    if !first {
        return;
    }
    let i = match rate {
        PhyRate::Ofdm(rate) => ofdm_index(*rate),
        PhyRate::Ht(ht) if ht.mcs_index() < 8 => 8 + usize::from(7 - ht.mcs_index()),
        _ => return,
    };
    let acked = match result {
        Ok(_) => true,
        Err(TxError::MacProtocol(MacProtocolError::AckTimeout)) => false,
        Err(_) => return,
    };
    RATE_ATTEMPTS[i].fetch_add(1, Ordering::Relaxed);
    if acked {
        RATE_ACKED[i].fetch_add(1, Ordering::Relaxed);
    }
}

/// E8: an A-MPDU's first round at `rate`: `sent` subframes, `acked` of them
/// in the block-ack. Counted with the single frames' first attempts, so the
/// rate control judges a rate by the MPDUs it delivers, not by whether an
/// aggregate drew any block-ack at all.
pub fn record_subframes(rate: &TxPhyRate, sent: u32, acked: u32) {
    let i = match rate {
        PhyRate::Ofdm(rate) => ofdm_index(*rate),
        PhyRate::Ht(ht) if ht.mcs_index() < 8 => 8 + usize::from(7 - ht.mcs_index()),
        _ => return,
    };
    RATE_ATTEMPTS[i].fetch_add(sent, Ordering::Relaxed);
    RATE_ACKED[i].fetch_add(acked.min(sent), Ordering::Relaxed);
}

/// Per OFDM rate (54 down to 6 Mbit/s): frames whose first attempt was on
/// the air at that rate, and how many of those were acknowledged, since
/// boot.
#[must_use]
pub fn rate_snapshot() -> [(u32, u32); 8] {
    core::array::from_fn(|i| {
        (RATE_ATTEMPTS[i].load(Ordering::Relaxed), RATE_ACKED[i].load(Ordering::Relaxed))
    })
}

/// The same per HT rate, MCS 7 down to MCS 0 (E8).
#[must_use]
pub fn ht_rate_snapshot() -> [(u32, u32); 8] {
    core::array::from_fn(|i| {
        (RATE_ATTEMPTS[8 + i].load(Ordering::Relaxed), RATE_ACKED[8 + i].load(Ordering::Relaxed))
    })
}

/// [`attempt`], and a MAC error's interface and kind besides.
pub(crate) fn attempt_on<T>(interface: usize, result: &Result<T, TxError>) {
    if let Err(TxError::MacProtocol(e)) = result {
        if let Some(c) = MAC_IF.get(interface) {
            c.fetch_add(1, Ordering::Relaxed);
        }
        let (kind, code) = match e {
            MacProtocolError::AckTimeout => (0, 0),
            MacProtocolError::CtsTimeout => {
                MAC_CTS.fetch_add(1, Ordering::Relaxed);
                (1, 0)
            }
            MacProtocolError::RtsChannelAccessError(_) => {
                MAC_RTS.fetch_add(1, Ordering::Relaxed);
                (2, 0)
            }
            MacProtocolError::InvalidKeyId => (3, 0x04c0),
            MacProtocolError::Unknown { error, sub_error } => {
                MAC_UNKNOWN.fetch_add(1, Ordering::Relaxed);
                (4, (u32::from(*error) << 8) | u32::from(*sub_error))
            }
        };
        if kind != 0 {
            MAC_LAST.store(((interface as u32 & 0xff) << 24) | (kind << 16) | code, Ordering::Relaxed);
        }
    }
    attempt(result);
}

/// One attempt's outcome, by kind: what a failed attempt failed of.
pub(crate) fn attempt<T>(result: &Result<T, TxError>) {
    let counter = match result {
        Ok(_) => return,
        Err(TxError::MacProtocol(MacProtocolError::AckTimeout)) => &ACK_TIMEOUT,
        Err(TxError::MacProtocol(MacProtocolError::InvalidKeyId)) => {
            INVALID_KEY.fetch_add(1, Ordering::Relaxed);
            &MAC_OTHER
        }
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
    /// [`Self::invalid_key`] is the key-id part of this, counted here too.
    pub mac_other: u32,
    /// Failed attempts whose MAC error was an invalid key id. Also included
    /// in `mac_other`.
    pub invalid_key: u32,
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

/// The MAC errors in detail: which interface failed, and how (P2's fault).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacDetail {
    /// MAC errors (every kind, ACK timeouts included) on interface 0 and 1.
    pub by_interface: [u32; 2],
    /// CTS timeouts.
    pub cts: u32,
    /// RTS channel-access errors.
    pub rts: u32,
    /// Errors the driver does not name.
    pub unknown: u32,
    /// The last one that was not an ACK timeout: interface << 24 | kind << 16
    /// (1 CTS, 2 RTS access, 3 key id, 4 unknown) | error << 8 | sub-error.
    pub last: u32,
}

/// Read [`MacDetail`].
#[must_use]
pub fn mac_detail() -> MacDetail {
    MacDetail {
        by_interface: [MAC_IF[0].load(Ordering::Relaxed), MAC_IF[1].load(Ordering::Relaxed)],
        cts: MAC_CTS.load(Ordering::Relaxed),
        rts: MAC_RTS.load(Ordering::Relaxed),
        unknown: MAC_UNKNOWN.load(Ordering::Relaxed),
        last: MAC_LAST.load(Ordering::Relaxed),
    }
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
        invalid_key: INVALID_KEY.load(Ordering::Relaxed),
        access_timeout: ACCESS_TIMEOUT.load(Ordering::Relaxed),
        access_collision: ACCESS_COLLISION.load(Ordering::Relaxed),
        other: OTHER.load(Ordering::Relaxed),
        timed: TIMED.load(Ordering::Relaxed),
        hw_us: HW_US.load(Ordering::Relaxed),
        wake_us: WAKE_US.load(Ordering::Relaxed),
    }
}

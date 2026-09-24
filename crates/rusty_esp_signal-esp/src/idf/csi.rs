//! Wi-Fi channel state on ESP-IDF, feeding the core's [`CsiFrame`].
//!
//! The Track A twin of [`crate::hal::csi`], and the reason it exists is a
//! track split: every camera cell and the mesh are `std` on ESP-IDF, and
//! until now CSI was esp-radio only, so a device that watched the room
//! could not also show it or reach the owner over iroh. With this, a camera
//! cell can carry `presence-csi` on the same board
//! (`espino/docs/plans/ruview-function.md`, W4).
//!
//! # How ESP-IDF hands CSI over, and what this does with it
//!
//! ESP-IDF delivers channel state to a C callback on the Wi-Fi task, with a
//! buffer that is valid only for the duration of the call. So the callback
//! does the one thing that must happen inside it -- copy the buffer and
//! [`ingest`] it, a few thousand integer operations -- and parks the frame
//! in a ring the sketch drains with [`poll`] on its own thread. Nothing else
//! crosses: the detector, the estimators and the telemetry all live with
//! the sketch.
//!
//! The ring holds [`CAPACITY`] frames. A sketch later than that sees the
//! latest sixteen and a count of the ones it missed ([`Stats::dropped`]);
//! the callback never blocks the Wi-Fi task, because it uses `try_lock` and
//! counts a miss rather than waiting. The ring and the ingest are
//! [`crate::csi_queue`], compiled and tested on the host; this module is
//! the FFI around them.
//!
//! # Which training field, and why it is the caller's choice
//!
//! The buffer's order depends on which fields are enabled. [`Config::recommended`]
//! enables the legacy LTF only: every OFDM frame carries one, so any data
//! frame from the access point or any ESP-NOW frame produces a reading, and
//! the buffer is exactly the 64 entries [`Layout::LLTF_20MHZ`] describes.
//! HT-LTF only is the other supported shape ([`Layout::HTLTF_20MHZ`], HT
//! frames only). Both enabled is refused: the buffer then concatenates
//! fields in an order this crate has not verified on silicon, and a layout
//! guessed wrong reads a room from the wrong subcarriers with every status
//! clean.
//!
//! The channel filter is **off** by default, on ESP-IDF's own advice for
//! keeping adjacent subcarriers independent -- which is what a per-subcarrier
//! statistic wants.
//!
//! # What the ledger will say
//!
//! Nothing here has run on a board yet. The judge is CSI frames per second on
//! the XIAO with the MJPEG page streaming, because radio contention is the
//! risk and it is measured, not assumed.

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use std::sync::Mutex;

use esp_idf_svc::sys::{self, EspError};
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::radar::csi::Layout;

pub use crate::csi_queue::Frame;
use crate::csi_queue::{Ring, ingest};

/// Frames the ring holds: 320 ms at 50 Hz, longer than any pass of a
/// camera loop (`csi_queue` says why).
pub const CAPACITY: usize = 16;

/// Which training fields to capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// The legacy long training field, present on every OFDM frame.
    pub lltf: bool,
    /// The HT long training field, present on HT (802.11n) frames only.
    pub htltf: bool,
    /// ESP-IDF's smoothing across adjacent subcarriers. Off keeps them
    /// independent, which a per-subcarrier statistic wants.
    pub channel_filter: bool,
}

impl Config {
    /// Legacy LTF only, no channel filter: every OFDM frame yields the 64
    /// entries of [`Layout::LLTF_20MHZ`].
    #[must_use]
    pub const fn recommended() -> Self {
        Config {
            lltf: true,
            htltf: false,
            channel_filter: false,
        }
    }

    /// HT LTF only, no channel filter: HT frames yield the 64 entries of
    /// [`Layout::HTLTF_20MHZ`] -- the Cuenca captures' 56 live subcarriers,
    /// but nothing from a legacy-rate frame.
    #[must_use]
    pub const fn ht_only() -> Self {
        Config {
            lltf: false,
            htltf: true,
            channel_filter: false,
        }
    }

    /// The layout the buffer will have, or `None` for a combination this
    /// crate has not verified on silicon and refuses to guess.
    #[must_use]
    pub const fn layout(&self) -> Option<&'static Layout> {
        match (self.lltf, self.htltf) {
            (true, false) => Some(&Layout::LLTF_20MHZ),
            (false, true) => Some(&Layout::HTLTF_20MHZ),
            _ => None,
        }
    }
}

/// Counters, since [`begin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Callbacks that produced a frame.
    pub received: u32,
    /// Frames overwritten before the sketch polled them (the ring was
    /// full), or that arrived while the sketch held the ring.
    pub dropped: u32,
    /// Callbacks whose buffer was shorter than the layout needs.
    pub short: u32,
}

static RING: Mutex<Ring<CAPACITY>> = Mutex::new(Ring::new());
static RECEIVED: AtomicU32 = AtomicU32::new(0);
static DROPPED: AtomicU32 = AtomicU32::new(0);
static SHORT: AtomicU32 = AtomicU32::new(0);
/// 0 none, 1 LLTF, 2 HT-LTF: which layout the callback parses with.
static LAYOUT: AtomicU8 = AtomicU8::new(0);

/// The largest buffer one training field produces at 20 MHz.
const MAX_BUF: usize = 256;

fn layout_for(tag: u8) -> Option<&'static Layout> {
    match tag {
        1 => Some(&Layout::LLTF_20MHZ),
        2 => Some(&Layout::HTLTF_20MHZ),
        _ => None,
    }
}

/// Start capturing. Wi-Fi must already be started (as a station or an
/// access point); ESP-IDF refuses the calls otherwise, and that refusal is
/// returned.
///
/// # Errors
///
/// [`EspError`] from ESP-IDF, or `ESP_ERR_INVALID_ARG` when `config` names
/// a field combination this crate does not support.
#[allow(unsafe_code)]
pub fn begin(config: Config) -> Result<(), EspError> {
    let Some(_layout) = config.layout() else {
        return Err(EspError::from_infallible::<{ sys::ESP_ERR_INVALID_ARG }>());
    };
    LAYOUT.store(if config.lltf { 1 } else { 2 }, Ordering::Release);
    RECEIVED.store(0, Ordering::Relaxed);
    DROPPED.store(0, Ordering::Relaxed);
    SHORT.store(0, Ordering::Relaxed);
    if let Ok(mut ring) = RING.lock() {
        ring.clear();
    }
    // SAFETY: an all-zero `wifi_csi_config_t` is a valid value (every field
    // is a bool, a u8 or a bitfield unit), and the three calls are plain
    // ESP-IDF entry points handed pointers to values that outlive the call.
    // The callback registered is `on_csi` below, whose contract is ESP-IDF's:
    // it is invoked on the Wi-Fi task with a pointer valid for the duration
    // of the call, and it neither retains the pointer nor blocks.
    unsafe {
        let mut cfg: sys::wifi_csi_config_t = core::mem::zeroed();
        cfg.lltf_en = config.lltf;
        cfg.htltf_en = config.htltf;
        cfg.stbc_htltf2_en = false;
        cfg.ltf_merge_en = false;
        cfg.channel_filter_en = config.channel_filter;
        cfg.manu_scale = false;
        cfg.shift = 0;
        cfg.dump_ack_en = false;
        EspError::convert(sys::esp_wifi_set_csi_config(&cfg))?;
        EspError::convert(sys::esp_wifi_set_csi_rx_cb(
            Some(on_csi),
            core::ptr::null_mut(),
        ))?;
        EspError::convert(sys::esp_wifi_set_csi(true))?;
    }
    Ok(())
}

/// Stop capturing and unregister the callback.
///
/// # Errors
///
/// [`EspError`] from ESP-IDF.
#[allow(unsafe_code)]
pub fn end() -> Result<(), EspError> {
    // SAFETY: plain ESP-IDF entry points; unregistering with `None` is the
    // documented way to remove the callback.
    unsafe {
        EspError::convert(sys::esp_wifi_set_csi(false))?;
        EspError::convert(sys::esp_wifi_set_csi_rx_cb(None, core::ptr::null_mut()))?;
    }
    LAYOUT.store(0, Ordering::Release);
    Ok(())
}

/// The oldest frame the radio delivered that the sketch has not taken;
/// drain with `while let Some(frame) = poll()`.
#[must_use]
pub fn poll() -> Option<Frame> {
    RING.lock().ok().and_then(|mut ring| ring.pop())
}

/// The counters since [`begin`].
#[must_use]
pub fn stats() -> Stats {
    Stats {
        received: RECEIVED.load(Ordering::Relaxed),
        dropped: DROPPED.load(Ordering::Relaxed),
        short: SHORT.load(Ordering::Relaxed),
    }
}

/// The callback ESP-IDF invokes on the Wi-Fi task.
///
/// It copies the buffer out, [`ingest`]s it for the configured layout and
/// parks the frame. It never blocks: a contended ring is a dropped frame,
/// not a stalled radio.
#[allow(unsafe_code)]
unsafe extern "C" fn on_csi(_ctx: *mut core::ffi::c_void, data: *mut sys::wifi_csi_info_t) {
    let Some(layout) = layout_for(LAYOUT.load(Ordering::Acquire)) else {
        return;
    };
    // SAFETY: ESP-IDF's contract for `wifi_csi_cb_t`: `data` points to a
    // `wifi_csi_info_t` valid for the duration of this call, and `buf` to
    // `len` bytes valid likewise. Both are read here and nowhere else, and
    // nothing is retained past the return.
    let (len, first_word_invalid, rssi, channel, mut copy) = unsafe {
        let info = &*data;
        let len = usize::from(info.len).min(MAX_BUF);
        let mut copy = [0i8; MAX_BUF];
        if !info.buf.is_null() && len > 0 {
            core::ptr::copy_nonoverlapping(info.buf, copy.as_mut_ptr(), len);
        }
        (
            len,
            info.first_word_invalid,
            info.rx_ctrl.rssi() as i8,
            info.rx_ctrl.channel() as u8,
            copy,
        )
    };
    // SAFETY: `esp_timer_get_time` reads the system timer; no arguments.
    let at = Micros(unsafe { sys::esp_timer_get_time() }.unsigned_abs());
    let Ok(frame) = ingest(
        &mut copy[..len],
        first_word_invalid,
        layout,
        rssi,
        channel,
        at,
    ) else {
        SHORT.fetch_add(1, Ordering::Relaxed);
        return;
    };
    RECEIVED.fetch_add(1, Ordering::Relaxed);
    match RING.try_lock() {
        Ok(mut ring) => {
            if ring.push(frame) {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        Err(_) => {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

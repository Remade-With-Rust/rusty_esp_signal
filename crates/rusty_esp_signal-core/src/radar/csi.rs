//! Presence and motion from Wi-Fi channel state information.
//!
//! A Wi-Fi receiver estimates, for every OFDM subcarrier, how the channel
//! attenuated and rotated the known training symbols: one complex number per
//! subcarrier per frame. A body in the room changes the multipath, so the
//! per-subcarrier **amplitude wanders over time** when someone moves and sits
//! still when the room is empty. That wander is what `esp-radar` and every
//! CSI presence paper measure; this module measures it in fixed point.
//!
//! The pipeline, one frame at a time:
//!
//! 1. [`CsiFrame`] borrows the raw buffer the radio handed over (ESP-IDF's
//!    `wifi_csi_info_t.buf`: signed 8-bit **imaginary, then real** per entry,
//!    in the order the [`Layout`] describes).
//! 2. [`CsiFrame::features`] turns it into [`Features`]: an integer
//!    amplitude per valid subcarrier with two fractional bits
//!    (`isqrt(16 · (i² + q²))`, at most 724), the mean and the
//!    across-subcarrier variance. The fractional bits matter: real captures
//!    sit at amplitudes of 20–40, where whole-number rounding alone would
//!    add a wander floor as large as an empty room's signal.
//! 3. [`PresenceDetector::push`] keeps the last `W` amplitude vectors and
//!    computes the **wander**: for each subcarrier, the standard deviation
//!    over the window divided by its mean (a coefficient of variation in
//!    permille, so absolute signal level cancels), averaged over the
//!    subcarriers. Hysteresis (an *on* and an *off* threshold) and a hold
//!    time turn that into a [`Verdict`].
//!
//! Everything is integer arithmetic; a `W = 32` window over 64 subcarriers is
//! 4 KiB of state and a few thousand multiplies per frame. The thresholds are
//! configuration ([`Config`]) because they are room- and rate-dependent; the
//! defaults come from the recorded captures the ledger names, and a product
//! calibrates them with [`PresenceDetector::wander`] in an empty room.
//!
//! Breathing detection (0.2–0.5 Hz on the amplitude time series) is the S2
//! item and is not here yet.

use rusty_esp_core::error::Result;
use rusty_esp_core::{Error, Micros};

/// Most subcarrier entries a layout can carry: ESP32's LLTF/HT-LTF buffers
/// hold 64 entries per 20 MHz training field.
pub const MAX_SUBCARRIERS: usize = 64;

/// Which entries of a raw CSI buffer are data subcarriers.
///
/// The raw buffer is a flat list of complex entries; a layout names the
/// ranges of entry indices that carry data (guard bands and DC are skipped).
/// Entry `k` holds bytes `2k` (imaginary) and `2k + 1` (real).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Ranges of valid entry indices, in the order they are stored.
    pub valid: &'static [core::ops::Range<usize>],
    /// Number of entries the buffer holds for this training field.
    pub entries: usize,
}

impl Layout {
    /// The legacy long training field of a 20 MHz, non-HT frame as ESP32
    /// delivers it: 64 entries, subcarriers `0..=31` then `-32..=-1`; the
    /// data subcarriers are `-26..=-1` and `1..=26`, i.e. entries `1..=26`
    /// and `38..=63`. 52 valid entries.
    pub const LLTF_20MHZ: Layout = Layout {
        valid: &[1..27, 38..64],
        entries: 64,
    };

    /// The HT long training field of a 20 MHz HT frame: the same 64-entry
    /// order with `-28..=-1` and `1..=28` carrying data (entries `1..=28`
    /// and `36..=63`). 56 valid entries.
    pub const HTLTF_20MHZ: Layout = Layout {
        valid: &[1..29, 36..64],
        entries: 64,
    };

    /// A 20 MHz HT capture in **natural** subcarrier order `-32..=31`
    /// (entries `0..=3` guards, `32` DC, `61..=63` guards; data `-28..=-1`
    /// and `1..=28` at entries `4..=31` and `33..=60`). 56 valid entries.
    /// This is the order the ESP32-C6 promiscuous captures in the ledger's
    /// oracle dataset arrive in (empirical: those entries are always zero).
    pub const C6_HT20_NATURAL: Layout = Layout {
        valid: &[4..32, 33..61],
        entries: 64,
    };

    /// Every entry, for a collector that has already stripped the guards.
    // A one-range slice is the point here (`valid` is a list of ranges).
    #[allow(clippy::single_range_in_vec_init)]
    pub const DENSE_64: Layout = Layout {
        valid: &[0..64],
        entries: 64,
    };

    /// Number of valid subcarriers.
    #[must_use]
    pub fn count(&self) -> usize {
        self.valid.iter().map(ExactSizeIterator::len).sum()
    }

    /// Iterate the valid entry indices in storage order.
    pub fn indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.valid.iter().flat_map(Clone::clone)
    }
}

/// One CSI measurement, borrowed over the radio's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CsiFrame<'a> {
    /// When the radio delivered it (device monotonic clock).
    pub timestamp: Micros,
    /// Received signal strength of the frame, dBm.
    pub rssi: i8,
    /// Primary channel the frame was received on.
    pub channel: u8,
    /// Interleaved `imaginary, real` signed 8-bit pairs; at least
    /// `2 * layout.entries` bytes long for the layout used.
    pub iq: &'a [i8],
}

impl CsiFrame<'_> {
    /// Amplitude features for the valid subcarriers of `layout`.
    ///
    /// `InvalidGeometry` when the buffer is shorter than the layout needs.
    pub fn features(&self, layout: &Layout) -> Result<Features> {
        if self.iq.len() < 2 * layout.entries || layout.count() > MAX_SUBCARRIERS {
            return Err(Error::InvalidGeometry);
        }
        let mut f = Features {
            amplitude: [0; MAX_SUBCARRIERS],
            count: 0,
            mean: 0,
            variance: 0,
        };
        let mut sum: u32 = 0;
        // The valid entries come in CONTIGUOUS ranges, so each range is one
        // slice: a bounds check per range instead of two per subcarrier, and
        // the `2 * k` scaling becomes the walk itself.
        for r in layout.valid {
            if r.start >= r.end {
                continue;
            }
            for p in self.iq[2 * r.start..2 * r.end].chunks_exact(2) {
                let im = i32::from(p[0]);
                let re = i32::from(p[1]);
                // |i|,|q| ≤ 128 → 16 · (i² + q²) ≤ 524 288; isqrt ≤ 724.
                let a = isqrt((16 * (im * im + re * re)) as u32);
                f.amplitude[f.count as usize] = a as u16;
                f.count += 1;
                sum += a;
            }
        }
        if f.count == 0 {
            return Err(Error::InvalidGeometry);
        }
        let n = u32::from(f.count);
        f.mean = (sum / n) as u16;
        // The whole reduction fits u32, and the INPUT TYPE is what proves it:
        // `iq` is `&[i8]`, so |im|, |re| <= 128, so 16*(im^2 + re^2) <=
        // 524 288, and every amplitude is `isqrt` of that, i.e. <= 724. A mean
        // of values <= 724 is <= 724, so |d| <= 724 and d^2 <= 524 176; with
        // `count <= MAX_SUBCARRIERS = 64` the total is at most 33 547 264.
        //
        // It matters because a u64 accumulator on a 32-bit core is not one
        // add: the ELF census showed `add.n` + `bltu` + a carry `mov` for
        // every element. One u32 accumulator is one `add.n`, and one chain
        // fits the register window where two u64s had begun to spill.
        let mean = i32::from(f.mean);
        let mut ss: u32 = 0;
        for &a in &f.amplitude[..f.count as usize] {
            let d = (i32::from(a) - mean).unsigned_abs();
            debug_assert!(d <= 724, "amplitude outside what &[i8] guarantees");
            ss += d * d;
        }
        f.variance = ss / n;
        Ok(f)
    }
}

/// Per-frame amplitude features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    /// `isqrt(16 · (i² + q²))` — the amplitude with two fractional bits —
    /// per valid subcarrier, in layout order; only the first `count`
    /// entries are meaningful.
    pub amplitude: [u16; MAX_SUBCARRIERS],
    /// Valid subcarriers in `amplitude`.
    pub count: u8,
    /// Mean amplitude across subcarriers (same two-fractional-bit scale).
    pub mean: u16,
    /// Population variance of the amplitude across subcarriers (the
    /// frequency-selectivity of the channel, a static-room fingerprint).
    pub variance: u32,
}

impl Features {
    /// The valid amplitudes.
    #[must_use]
    pub fn amplitudes(&self) -> &[u16] {
        &self.amplitude[..self.count as usize]
    }
}

/// What the detector concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not enough frames yet to say.
    Warming,
    /// The room reads static.
    Absent,
    /// Something moves; `motion` is the wander clipped to `0..=255`.
    Present {
        /// Motion level, [`PresenceDetector::wander`] clipped to a byte.
        motion: u8,
    },
}

impl Verdict {
    /// Wire tag for the telemetry characteristic: 0 warming, 1 absent,
    /// 2 present.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Verdict::Warming => 0,
            Verdict::Absent => 1,
            Verdict::Present { .. } => 2,
        }
    }

    /// The motion level, 0 unless present.
    #[must_use]
    pub const fn motion(self) -> u8 {
        match self {
            Verdict::Present { motion } => motion,
            _ => 0,
        }
    }
}

/// Detector thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Wander (permille) at or above which the verdict switches to present.
    pub on_permille: u16,
    /// Wander (permille) at or below which it may switch back to absent.
    pub off_permille: u16,
    /// Minimum time the verdict stays present after the last frame above
    /// `on_permille` (a person standing still for a moment is still there).
    pub hold: Micros,
}

impl Default for Config {
    /// `on` 42 ‰, `off` 32 ‰, hold 3 s.
    ///
    /// Derived on the ledger's ESP32-C6 captures with a one-second window:
    /// an empty room never exceeds 28 ‰ of wander over a full minute, so
    /// `on` is 1.5 × that ceiling and `off` sits just above it; a person
    /// walking across the line of sight reads 45–120 ‰. A product
    /// calibrates per room from [`PresenceDetector::wander`].
    fn default() -> Self {
        Config {
            on_permille: 42,
            off_permille: 32,
            hold: Micros::from_secs(3),
        }
    }
}

/// Presence from the wander of the amplitude over the last `W` frames.
///
/// `W` frames at the collector's rate is the observation window: 32 frames
/// at 20 Hz is 1.6 s. Larger windows smooth more and react slower.
pub struct PresenceDetector<const W: usize> {
    config: Config,
    ring: [[u16; MAX_SUBCARRIERS]; W],
    count: u8,
    filled: usize,
    next: usize,
    wander: u16,
    present: bool,
    last_motion: Micros,
    frames: u32,
}

impl<const W: usize> core::fmt::Debug for PresenceDetector<W> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PresenceDetector")
            .field("window", &W)
            .field("filled", &self.filled)
            .field("wander", &self.wander)
            .field("present", &self.present)
            .field("frames", &self.frames)
            .finish_non_exhaustive()
    }
}

impl<const W: usize> PresenceDetector<W> {
    /// `W` frames of a `u16` must fit a `u32` sum, which is what lets
    /// `compute_wander` accumulate in 32 bits. At the ceiling that is
    /// 65 536 * 65 535 = 4 294 901 760, just inside `u32::MAX`. A window that
    /// long would be 8 GB of ring and cannot be built, so this states the
    /// obvious -- to the COMPILER, where it is load-bearing.
    const W_FITS_U32_SUM: () = assert!(W <= 65_536);

    /// A detector with `config`.
    #[must_use]
    pub const fn new(config: Config) -> Self {
        PresenceDetector {
            config,
            ring: [[0; MAX_SUBCARRIERS]; W],
            count: 0,
            filled: 0,
            next: 0,
            wander: 0,
            present: false,
            last_motion: Micros::ZERO,
            frames: 0,
        }
    }

    /// The thresholds in use.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Replace the thresholds (calibration) without dropping the window.
    pub fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    /// The last computed wander, permille: mean over subcarriers of
    /// `1000 · std / mean` across the window. The number to log while
    /// calibrating a room.
    #[must_use]
    pub const fn wander(&self) -> u16 {
        self.wander
    }

    /// Frames pushed so far.
    #[must_use]
    pub const fn frames(&self) -> u32 {
        self.frames
    }

    /// True once the window holds `W` frames.
    #[must_use]
    pub const fn warm(&self) -> bool {
        self.filled >= W
    }

    /// Forget the window (after a channel change, for instance).
    pub fn reset(&mut self) {
        self.filled = 0;
        self.next = 0;
        self.count = 0;
        self.wander = 0;
        self.present = false;
    }

    /// Push one frame's features taken at `now` and get the verdict.
    ///
    /// A frame with a different subcarrier count than the window holds
    /// resets the window (`InvalidGeometry` is not raised: the collector
    /// switching training fields is not the detector's error).
    pub fn push(&mut self, features: &Features, now: Micros) -> Verdict {
        if features.count == 0 {
            return self.verdict_now(now);
        }
        if self.filled > 0 && features.count != self.count {
            self.reset();
        }
        self.count = features.count;
        self.ring[self.next][..features.count as usize].copy_from_slice(features.amplitudes());
        self.next = (self.next + 1) % W;
        if self.filled < W {
            self.filled += 1;
        }
        self.frames = self.frames.wrapping_add(1);
        if self.filled < W {
            return Verdict::Warming;
        }
        self.wander = self.compute_wander();
        if self.wander >= self.config.on_permille {
            self.present = true;
            self.last_motion = now;
        } else if self.present
            && self.wander <= self.config.off_permille
            && now.0.saturating_sub(self.last_motion.0) >= self.config.hold.0
        {
            self.present = false;
        }
        self.verdict_now(now)
    }

    const fn verdict_now(&self, _now: Micros) -> Verdict {
        if self.filled < W {
            Verdict::Warming
        } else if self.present {
            Verdict::Present {
                motion: if self.wander > 255 {
                    255
                } else {
                    self.wander as u8
                },
            }
        } else {
            Verdict::Absent
        }
    }

    /// Mean over subcarriers of `1000 · std_time / mean_time`, where the
    /// statistics run over the `W` frames of the window for one subcarrier.
    fn compute_wander(&self) -> u16 {
        // `.min` is a no-op on the value -- `push` cannot store a count above
        // MAX_SUBCARRIERS without panicking in its own `copy_from_slice` --
        // but it is not a no-op on the CODE. It is what lets the compiler see
        // that every `frame[sc]` below indexes a `[u16; MAX_SUBCARRIERS]`
        // inside its bounds, so the per-element compare-and-branch to a panic
        // block goes. That check ran W * n times per CSI frame.
        let n = (self.count as usize).min(MAX_SUBCARRIERS);
        if n == 0 || W == 0 {
            return 0;
        }
        let w = W as u64;
        let mut total: u64 = 0;
        for sc in 0..n {
            // ONE accumulator each, and the sum in u32.
            //
            // This loop previously carried FOUR u64 accumulators -- two for
            // the sum and two for the squares, to break the dependency chain.
            // A census of the FLASHED ELF showed what that actually bought:
            // eight 32-bit registers is past the Xtensa register window, and
            // the loop was spending TEN of its 34 instructions on
            // `l32i.n a?, a1, N` reloads plus a spill store. It is the same
            // law this family already wrote down once -- eight u16 maxima fit
            // the window, eight i64 accumulators do not -- and the split was
            // never measured on its own before it was kept.
            //
            // The SQUARE is still formed in u32: `a` is a u16, so
            // a^2 <= 65535^2 = 4 294 836 225, exact there, which is one
            // `mull` instead of the 64x64 sequence. Only the sum of SQUARES
            // needs the wider type; `sum` cannot exceed W * 65 535, and
            // `W_FITS_U32_SUM` is what makes that a fact the COMPILER holds
            // rather than one the reader does.
            //
            // REFUTED, measured worse, reverted: ONE pass over the ring
            // accumulating every subcarrier into `[u64; MAX_SUBCARRIERS]`
            // pairs turns this kernel's 128-byte-stride walk into sequential
            // loads, and cost +28.1% against a 1.4% null arm (2026-09-19) --
            // the array form read-modify-writes memory for every element, and
            // that costs more than the stride saves.
            let () = Self::W_FITS_U32_SUM;
            let mut sum32: u32 = 0;
            let mut sumsq: u64 = 0;
            for frame in &self.ring {
                let a = u32::from(frame[sc]);
                sum32 += a;
                sumsq += u64::from(a * a);
            }
            let sum = u64::from(sum32);
            let mean = sum / w;
            if mean == 0 {
                continue;
            }
            // Population variance = E[a²] − E[a]² with the mean kept at
            // 1/W resolution: W²·var = W·Σa² − (Σa)². Then std with four
            // fractional bits: isqrt(256 · W²·var) / W = 16 · std.
            let var_w2 = (w * sumsq).saturating_sub(sum * sum);
            let std16 = u64::from(isqrt((256 * var_w2).min(u64::from(u32::MAX)) as u32)) / w;
            // `std16 ≤ 65 535` (an isqrt of a u32, then divided) and
            // `mean ≤ 65 535` (a sum of u16 over W, divided by W), so
            // `std16 · 1000 ≤ 65 535 000` and `mean · 16 ≤ 1 048 560` -- both
            // exact in u32. That turns a runtime 64-bit division, which is a
            // LIBCALL on a 32-bit core, into one `quou`. It ran once per
            // subcarrier on every CSI frame: ~56 libcalls at 20-50 Hz.
            total += u64::from((std16 as u32) * 1000 / ((mean as u32) * 16));
        }
        (total / n as u64).min(u64::from(u16::MAX)) as u16
    }
}

/// Integer square root, `floor(sqrt(v))` — `rusty_esp_dsp`'s (moved there in
/// D0, 2026-09-02), at the path this module always had.
pub use rusty_esp_dsp::int::isqrt;

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_from_amplitudes(amps: &[i8; 64], buf: &mut [i8; 128]) {
        for (k, &a) in amps.iter().enumerate() {
            buf[2 * k] = 0; // imaginary
            buf[2 * k + 1] = a; // real
        }
    }

    #[test]
    fn layouts_count_the_data_subcarriers() {
        assert_eq!(Layout::LLTF_20MHZ.count(), 52);
        assert_eq!(Layout::HTLTF_20MHZ.count(), 56);
        assert_eq!(Layout::DENSE_64.count(), 64);
        let idx: std::vec::Vec<usize> = Layout::LLTF_20MHZ.indices().collect();
        assert_eq!(idx[0], 1);
        assert_eq!(idx[25], 26);
        assert_eq!(idx[26], 38);
        assert_eq!(idx[51], 63);
    }

    #[test]
    fn features_take_amplitude_per_valid_entry() {
        let mut buf = [0i8; 128];
        // entry 5: i = 3, q = 4 → 5 ; entry 0 (DC, not valid) huge.
        buf[0] = 127;
        buf[1] = 127;
        buf[2 * 5] = 3;
        buf[2 * 5 + 1] = 4;
        let f = CsiFrame {
            timestamp: Micros::ZERO,
            rssi: -40,
            channel: 6,
            iq: &buf,
        };
        let feat = f.features(&Layout::LLTF_20MHZ).unwrap();
        assert_eq!(feat.count, 52);
        assert_eq!(feat.amplitudes()[4], 20); // entry 5 is the 5th valid (1..=26): 5 × 4
        assert_eq!(feat.amplitudes()[0], 0);
        assert_eq!(feat.mean, 0); // 20 / 52 rounds to 0
        let short = CsiFrame {
            iq: &buf[..100],
            ..f
        };
        assert_eq!(
            short.features(&Layout::LLTF_20MHZ),
            Err(Error::InvalidGeometry)
        );
    }

    #[test]
    fn static_room_is_absent_and_motion_is_present_with_hysteresis() {
        let layout = Layout::DENSE_64;
        let mut det = PresenceDetector::<8>::new(Config {
            on_permille: 60,
            off_permille: 30,
            hold: Micros::from_millis(500),
        });
        let mut buf = [0i8; 128];
        let base = [40i8; 64];
        let mut t = Micros::ZERO;
        let step = Micros::from_millis(50);
        // Warm up with a static channel.
        for k in 0..8 {
            frame_from_amplitudes(&base, &mut buf);
            let f = CsiFrame {
                timestamp: t,
                rssi: -50,
                channel: 1,
                iq: &buf,
            }
            .features(&layout)
            .unwrap();
            let v = det.push(&f, t);
            if k < 7 {
                assert_eq!(v, Verdict::Warming);
            } else {
                assert_eq!(v, Verdict::Absent);
            }
            t = Micros(t.0 + step.0);
        }
        assert_eq!(det.wander(), 0);
        // A person: amplitudes swing ±50 % frame to frame.
        let mut v = Verdict::Absent;
        for k in 0..8 {
            let amps: [i8; 64] = core::array::from_fn(|_| if k % 2 == 0 { 20 } else { 60 });
            frame_from_amplitudes(&amps, &mut buf);
            let f = CsiFrame {
                timestamp: t,
                rssi: -50,
                channel: 1,
                iq: &buf,
            }
            .features(&layout)
            .unwrap();
            v = det.push(&f, t);
            t = Micros(t.0 + step.0);
        }
        assert!(
            matches!(v, Verdict::Present { motion } if motion >= 60),
            "{v:?} wander {}",
            det.wander()
        );
        // Static again. The window still holds motion frames for the next
        // W − 1 = 7 frames (the wander of one leftover alternating frame in
        // seven static ones is ~176 ‰, still above `on`), so the hold clock
        // restarts at static frame 6; 500 ms = 10 frames later, at static
        // frame 16, the verdict drops. Exactly there, not before.
        let mut first_absent = None;
        for s in 0..=20 {
            frame_from_amplitudes(&base, &mut buf);
            let f = CsiFrame {
                timestamp: t,
                rssi: -50,
                channel: 1,
                iq: &buf,
            }
            .features(&layout)
            .unwrap();
            let v = det.push(&f, t);
            t = Micros(t.0 + step.0);
            if v == Verdict::Absent && first_absent.is_none() {
                first_absent = Some(s);
            }
            if s == 7 {
                assert_eq!(det.wander(), 0, "window fully static by now");
            }
        }
        assert_eq!(first_absent, Some(16));
        assert_eq!(det.frames(), 8 + 8 + 21);
    }

    #[test]
    fn a_layout_change_resets_the_window() {
        let mut det = PresenceDetector::<4>::new(Config::default());
        let mut buf = [0i8; 128];
        frame_from_amplitudes(&[30; 64], &mut buf);
        let dense = CsiFrame {
            timestamp: Micros::ZERO,
            rssi: 0,
            channel: 1,
            iq: &buf,
        }
        .features(&Layout::DENSE_64)
        .unwrap();
        let lltf = CsiFrame {
            timestamp: Micros::ZERO,
            rssi: 0,
            channel: 1,
            iq: &buf,
        }
        .features(&Layout::LLTF_20MHZ)
        .unwrap();
        for _ in 0..4 {
            det.push(&dense, Micros::ZERO);
        }
        assert!(det.warm());
        assert_eq!(det.push(&lltf, Micros::ZERO), Verdict::Warming);
        assert!(!det.warm());
    }
}

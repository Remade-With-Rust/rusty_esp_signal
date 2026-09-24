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
//! # Normalise the amplitude by its frame's mean
//!
//! A receiver's gain is not the room. Three two-second events in the
//! ledger's empty-room capture read 74–85 ‰ of wander and were flagged as
//! presence; the phase detector, which cannot see gain, read nothing at
//! all. Dividing every subcarrier's amplitude by that frame's mean cancels
//! a common gain step exactly and leaves a change of *shape* -- which is
//! what a body does -- untouched. Through [`Features::normalised`] the same
//! capture reads **0** present frames and a ceiling of 21 ‰, and the walk
//! keeps 74 % of its frames. That is the trade this module now recommends:
//! [`Config::normalised_default`] carries the thresholds re-derived for it.
//!
//! The phase half of the same entry -- sanitised per frame, its circular
//! variance over the window -- is [`super::phase`], on the same raw buffer.
//! Both read a gain step as nothing; [`Verdict::either`] fuses them.
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

    /// The same features with every amplitude divided by this frame's
    /// mean, scaled so the mean lands near 1 024.
    ///
    /// A receiver's gain multiplies every subcarrier by the same factor,
    /// and so does a change in transmit power or in the frame's own
    /// strength; a body in the room changes the *shape* across the
    /// subcarriers. Dividing by the frame's mean cancels the first exactly
    /// and keeps the second. On the ledger's empty-room capture it removes
    /// three two-second gain events that read as presence, and it costs the
    /// walking capture twelve points of its present frames -- the trade
    /// [`Config::normalised_default`] is derived for.
    ///
    /// `mean` and `variance` are recomputed over the normalised amplitudes,
    /// so the variance stays the gain-free room fingerprint it is meant to
    /// be. A frame whose mean is zero is returned unchanged.
    #[must_use]
    pub fn normalised(&self) -> Features {
        let n = usize::from(self.count).min(MAX_SUBCARRIERS);
        // Divide by the exact SUM, not the stored mean. `mean` is an
        // integer, floored: a gain step of ×3 on a sum that is not a multiple
        // of `n` floors to something other than 3× the old mean, and the
        // ratios then differ by the rounding -- about 1 % at these
        // amplitudes, which is a real wander the room did not make. With
        // `a · 1024 · n / Σa` a common factor cancels exactly.
        let total: u32 = self.amplitude[..n].iter().map(|&a| u32::from(a)).sum();
        if n == 0 || total == 0 {
            return *self;
        }
        let mut out = Features {
            amplitude: [0; MAX_SUBCARRIERS],
            count: self.count,
            mean: 0,
            variance: 0,
        };
        let mut sum: u32 = 0;
        let n32 = n as u32;
        for (dst, &a) in out.amplitude[..n].iter_mut().zip(&self.amplitude[..n]) {
            // a ≤ 724 (see `features`) and n ≤ 64, so a · 1024 · n ≤
            // 47 448 064: u32 with room. The result is a ratio to the mean,
            // clipped to u16 -- a frame where one subcarrier carries 64× the
            // mean is not a frame this detector should be reasoning from.
            let v = (u32::from(a) * 1024 * n32 / total).min(u32::from(u16::MAX)) as u16;
            *dst = v;
            sum += u32::from(v);
        }
        out.mean = (sum / n32) as u16;
        let mean = i32::from(out.mean);
        let mut ss: u64 = 0;
        for &a in &out.amplitude[..n] {
            let d = i64::from(i32::from(a) - mean).unsigned_abs();
            ss += d * d;
        }
        out.variance = (ss / u64::from(n32)).min(u64::from(u32::MAX)) as u32;
        out
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

    /// One verdict from two detectors: present if either is, with the
    /// larger motion; warming if either is still filling; else absent.
    ///
    /// The fusion of a normalised-amplitude detector and a phase detector.
    /// It is free on the ledger's empty room -- both read zero present
    /// frames, so their union does too -- and it inherits the more
    /// sensitive detector's walk. The two `motion` levels are on different
    /// scales (permille of amplitude wander, tens of ppm of phase wander);
    /// the larger is reported, which is a level to show and not a number
    /// to add.
    #[must_use]
    pub const fn either(self, other: Verdict) -> Verdict {
        match (self, other) {
            (Verdict::Present { motion: a }, Verdict::Present { motion: b }) => Verdict::Present {
                motion: if a > b { a } else { b },
            },
            (p @ Verdict::Present { .. }, _) | (_, p @ Verdict::Present { .. }) => p,
            (Verdict::Warming, _) | (_, Verdict::Warming) => Verdict::Warming,
            (Verdict::Absent, Verdict::Absent) => Verdict::Absent,
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

impl Config {
    /// Thresholds for features passed through [`Features::normalised`].
    ///
    /// The normalised wander sits lower -- the gain jitter that was part of
    /// the raw floor is gone -- so the defaults for raw features are wrong
    /// for it: `on` 42 ‰ reads a walk present less than half the time. By
    /// the same rule as [`Config::default`], on the same captures: the
    /// normalised empty room's ceiling is 21 ‰ over its whole minute, so
    /// `on` is 1.5 × that and `off` sits just above it. The walk reads
    /// 74 % present at these, the empty room 0 % (`docs/LEDGER.md`).
    #[must_use]
    pub const fn normalised_default() -> Self {
        Config {
            on_permille: 32,
            off_permille: 23,
            hold: Micros::from_secs(3),
        }
    }
}

impl Default for Config {
    /// `on` 42 ‰, `off` 32 ‰, hold 3 s, for RAW features. For features
    /// through [`Features::normalised`] see [`Config::normalised_default`].
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
    /// Running `sum[sc] = SUM over the ring of ring[f][sc]`, and likewise the
    /// sum of squares. See `push`: the ring is a SLIDING WINDOW, so these are
    /// maintained by the one frame that changes rather than rebuilt from all
    /// `W` of them.
    sum: [u32; MAX_SUBCARRIERS],
    sumsq: [u64; MAX_SUBCARRIERS],
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
            sum: [0; MAX_SUBCARRIERS],
            sumsq: [0; MAX_SUBCARRIERS],
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
        // Maintain the window's sums from the ONE frame that changes.
        //
        // `compute_wander` used to rebuild them from the whole ring on every
        // push: W * n multiply-accumulates, 2600 of them at W = 50 and 52
        // subcarriers, to fold in a single new frame. A ring is a sliding
        // window -- exactly one frame leaves and one arrives -- so the sums
        // can be carried: subtract what the slot held, add what replaces it.
        // That is `n` updates instead of `W * n`.
        //
        // The invariant is `sum[sc] == SUM_f ring[f][sc]` for EVERY sc, and
        // it holds by construction: zero at `new` over a zeroed ring, and
        // preserved by this update whichever slot is written. `reset` does
        // not disturb it -- it never touches the ring, so it must not touch
        // these either. Indices at or above `count` are not written below, so
        // their sums are already correct and are left alone. Integer
        // arithmetic is exact, so every total is the u32/u64 it was, and
        // `sum >= old` because `old` is one of the terms in it.
        let amps = features.amplitudes();
        let slot = &mut self.ring[self.next];
        for (sc, (&new, old)) in amps.iter().zip(slot[..amps.len()].iter_mut()).enumerate() {
            let (o, x) = (u32::from(*old), u32::from(new));
            self.sum[sc] = self.sum[sc] - o + x;
            self.sumsq[sc] = self.sumsq[sc] - u64::from(o * o) + u64::from(x * x);
            *old = new;
        }
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
        // u32: each term is at most 65 535 * 1000 / 16 = 4 095 937 (std16 is
        // an isqrt of a u32 then divided, and `mean == 0` is skipped), and
        // there are at most MAX_SUBCARRIERS = 64 of them, so the total cannot
        // pass 262 139 968. A u64 add on this core is add + carry-test + a
        // move, once per subcarrier, for range that cannot be reached.
        let mut total: u32 = 0;
        for sc in 0..n {
            // Both totals are already correct -- `push` carried them in as
            // the window slid. What used to be W multiply-accumulates per
            // subcarrier is now two array loads.
            //
            // The SQUARE is still formed in u32 where it is formed, in
            // `push`: `a` is a u16, so a^2 <= 65535^2 = 4 294 836 225, exact
            // there, which is one `mull` instead of the 64x64 sequence. Only
            // the sum of SQUARES needs the wider type; `sum` cannot exceed
            // W * 65 535, and `W_FITS_U32_SUM` is what makes that a fact the
            // COMPILER holds rather than one the reader does.
            //
            // REFUTED along the way, both measured and both reverted: TWO
            // accumulators each to break the dependency chain put four u64s
            // -- eight 32-bit registers -- past the Xtensa window, and the
            // loop spent ten of its 34 instructions on stack reloads; and one
            // frame-order pass over the ring accumulating every subcarrier
            // into `[u64; MAX_SUBCARRIERS]` pairs cost +28.1%, because the
            // array form read-modify-writes memory per element.
            let () = Self::W_FITS_U32_SUM;
            let sum = u64::from(self.sum[sc]);
            let sumsq = self.sumsq[sc];
            let mean = sum / w;
            if mean == 0 {
                continue;
            }
            // Population variance = E[a²] − E[a]² with the mean kept at
            // 1/W resolution: W²·var = W·Σa² − (Σa)². Then std with four
            // fractional bits: isqrt(256 · W²·var) / W = 16 · std.
            let var_w2 = (w * sumsq).saturating_sub(sum * sum);
            // The u32 root when it fits, which for raw amplitudes (≤ 724,
            // a window std of a few units) it always does on the ledger's
            // captures -- this is the path the ELF census measured. It stops
            // fitting when the window's std passes ~82 units, which
            // gain-normalised amplitudes (a mean near 1 024) reach during a
            // walk: saturating there read the walk 40 ‰ under the float
            // replica at its peaks. A u64 root takes the rest, exactly.
            let scaled = 256 * var_w2;
            let std16 = if scaled <= u64::from(u32::MAX) {
                u64::from(isqrt(scaled as u32)) / w
            } else {
                isqrt64(scaled) / w
            };
            // `std16 ≤ 65 535` (an isqrt of a u32, then divided) and
            // `mean ≤ 65 535` (a sum of u16 over W, divided by W), so
            // `std16 · 1000 ≤ 65 535 000` and `mean · 16 ≤ 1 048 560` -- both
            // exact in u32. That turns a runtime 64-bit division, which is a
            // LIBCALL on a 32-bit core, into one `quou`. It ran once per
            // subcarrier on every CSI frame: ~56 libcalls at 20-50 Hz.
            total += (std16 as u32) * 1000 / ((mean as u32) * 16);
        }
        (total / n as u32).min(u32::from(u16::MAX)) as u16
    }
}

/// Integer square root, `floor(sqrt(v))` — `rusty_esp_dsp`'s (moved there in
/// D0, 2026-09-02), at the path this module always had.
pub use rusty_esp_dsp::int::isqrt;

/// `floor(sqrt(v))` for a `u64`, digit by digit.
///
/// Only reached when `256 · W² · var` leaves `u32`, i.e. a window whose
/// standard deviation is past ~82 amplitude units -- normalised features
/// during motion. Thirty-two iterations of shifts and compares, no
/// multiply; on the chip it runs on the few subcarriers in a frame that
/// are moving that much, and never on a still room.
#[must_use]
pub const fn isqrt64(v: u64) -> u64 {
    let mut rem = v;
    let mut root: u64 = 0;
    let mut bit: u64 = 1 << 62;
    while bit > rem {
        bit >>= 2;
    }
    while bit != 0 {
        if rem >= root + bit {
            rem -= root + bit;
            root = (root >> 1) + bit;
        } else {
            root >>= 1;
        }
        bit >>= 2;
    }
    root
}

#[cfg(test)]
mod carried_sums {
    use super::*;

    fn feats(count: u8, seed: u32) -> Features {
        let mut f = Features {
            amplitude: [0; MAX_SUBCARRIERS],
            count,
            mean: 0,
            variance: 0,
        };
        let mut sum = 0u32;
        for (i, a) in f.amplitude[..count as usize].iter_mut().enumerate() {
            // the full u16 range, not just the <= 724 a real capture gives:
            // `Features` has public fields, so the carried sums must stay
            // exact for anything that can be put in one.
            *a = ((seed.wrapping_mul(2_654_435_761) >> 8) as u16)
                .wrapping_add((i as u16).wrapping_mul(9_973));
            sum += u32::from(*a);
        }
        f.mean = (sum / u32::from(count.max(1))) as u16;
        f
    }

    /// The window is the last `W` frames and NOTHING before them. That is the
    /// property the carried sums have to preserve: a detector with a long,
    /// varied history must agree with a fresh one shown only the final `W`
    /// frames. A sum that failed to subtract what left the ring would leak
    /// that history, and no fixture-replay test would notice.
    #[test]
    fn wander_ignores_everything_before_the_window() {
        const W: usize = 8;
        for count in [1u8, 7, 52, MAX_SUBCARRIERS as u8] {
            let tail: Vec<Features> = (0..W).map(|k| feats(count, 900 + k as u32)).collect();

            let mut fresh = PresenceDetector::<W>::new(Config::default());
            for (k, f) in tail.iter().enumerate() {
                fresh.push(f, Micros(k as u64 * 20_000));
            }

            let mut aged = PresenceDetector::<W>::new(Config::default());
            for k in 0..(5 * W) {
                aged.push(&feats(count, k as u32), Micros(k as u64 * 20_000));
            }
            for (k, f) in tail.iter().enumerate() {
                aged.push(f, Micros((5 * W + k) as u64 * 20_000));
            }

            assert!(fresh.warm() && aged.warm(), "count={count}");
            assert_eq!(
                aged.wander(),
                fresh.wander(),
                "history leaked into the window at count={count}"
            );
        }
    }

    /// `reset` restarts the window without touching the ring, so the carried
    /// sums must not be touched either -- and the detector must still agree
    /// with a fresh one once it has warmed again.
    #[test]
    fn reset_then_refill_matches_a_fresh_detector() {
        const W: usize = 6;
        let tail: Vec<Features> = (0..W).map(|k| feats(30, 5_000 + k as u32)).collect();

        let mut fresh = PresenceDetector::<W>::new(Config::default());
        for (k, f) in tail.iter().enumerate() {
            fresh.push(f, Micros(k as u64 * 20_000));
        }

        let mut reused = PresenceDetector::<W>::new(Config::default());
        for k in 0..(3 * W) {
            reused.push(&feats(30, k as u32), Micros(k as u64 * 20_000));
        }
        reused.reset();
        assert!(!reused.warm(), "reset must un-warm");
        for (k, f) in tail.iter().enumerate() {
            reused.push(f, Micros((100 + k) as u64 * 20_000));
        }
        assert_eq!(reused.wander(), fresh.wander(), "reset left the sums stale");
    }

    /// A change of subcarrier count resets the window; the sums for the
    /// indices that were never written must not poison the new ones.
    #[test]
    fn a_count_change_does_not_poison_the_sums() {
        const W: usize = 5;
        let mut d = PresenceDetector::<W>::new(Config::default());
        for k in 0..(2 * W) {
            d.push(&feats(52, k as u32), Micros(k as u64 * 20_000));
        }
        // now a narrower layout, long enough to warm again
        for k in 0..(2 * W) {
            d.push(&feats(20, 700 + k as u32), Micros((50 + k) as u64 * 20_000));
        }
        let mut fresh = PresenceDetector::<W>::new(Config::default());
        for k in (2 * W - W)..(2 * W) {
            fresh.push(&feats(20, 700 + k as u32), Micros(k as u64 * 20_000));
        }
        assert_eq!(d.wander(), fresh.wander(), "count change poisoned the sums");
    }
}

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

    /// A common gain step is invisible after normalisation; a change of
    /// shape is not. The receiver-gain events in the ledger's empty room,
    /// as a unit test.
    #[test]
    fn normalising_cancels_a_gain_step_and_keeps_a_shape_change() {
        let base: Vec<u16> = (0..56u16).map(|k| 80 + (k * 7) % 23).collect();
        let feats = |amps: &[u16]| {
            let mut f = Features {
                amplitude: [0; MAX_SUBCARRIERS],
                count: amps.len() as u8,
                mean: 0,
                variance: 0,
            };
            f.amplitude[..amps.len()].copy_from_slice(amps);
            f.mean = (amps.iter().map(|&a| u32::from(a)).sum::<u32>() / amps.len() as u32) as u16;
            f
        };
        let a = feats(&base);
        // Every subcarrier × 3: a gain step.
        let tripled: Vec<u16> = base.iter().map(|&x| x * 3).collect();
        let b = feats(&tripled);
        assert_ne!(a.amplitudes(), b.amplitudes(), "the raw frames differ");
        let (na, nb) = (a.normalised(), b.normalised());
        // Integer division leaves a ±1 in 1 024 between the two.
        for (x, y) in na.amplitudes().iter().zip(nb.amplitudes()) {
            assert!(i32::from(*x).abs_diff(i32::from(*y)) <= 1, "{x} vs {y}");
        }
        assert!(na.mean.abs_diff(nb.mean) <= 1, "{} vs {}", na.mean, nb.mean);
        // One subcarrier doubled: a shape change, which survives.
        let mut shaped = base.clone();
        shaped[20] *= 2;
        let c = feats(&shaped).normalised();
        assert!(
            c.amplitude[20] > na.amplitude[20] * 3 / 2,
            "{} vs {}",
            c.amplitude[20],
            na.amplitude[20]
        );
        // And the variance is the gain-free fingerprint: same for a and b.
        assert!(na.variance.abs_diff(nb.variance) <= na.variance / 50 + 2);
        // A zero-mean frame comes back unchanged rather than dividing by it.
        let z = feats(&[0u16; 4]);
        assert_eq!(z.normalised(), z);
    }

    #[test]
    fn either_fuses_two_verdicts() {
        use Verdict::{Absent, Present, Warming};
        assert_eq!(Absent.either(Absent), Absent);
        assert_eq!(Warming.either(Absent), Warming);
        assert_eq!(Absent.either(Warming), Warming);
        assert_eq!(Present { motion: 7 }.either(Absent), Present { motion: 7 });
        assert_eq!(Warming.either(Present { motion: 7 }), Present { motion: 7 });
        assert_eq!(
            Present { motion: 7 }.either(Present { motion: 9 }),
            Present { motion: 9 }
        );
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

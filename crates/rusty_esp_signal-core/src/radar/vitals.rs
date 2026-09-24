//! Breathing (and, with caveats, heart rate) from the slow rhythm in Wi-Fi
//! channel state.
//!
//! A chest rising and falling changes a path length by a centimetre or so,
//! which at 2.4 GHz is a fraction of a wavelength -- enough to move the
//! amplitude and phase of some subcarriers by a few percent, periodically,
//! at the breathing rate. Nobody moving otherwise, that rhythm is the
//! strongest thing in the channel. This module finds it.
//!
//! # The pipeline
//!
//! 1. **Decimate.** A frame every 20 ms is far more than a rhythm at 0.2 to
//!    0.5 Hz needs. Blocks of `decim` frames are averaged per subcarrier
//!    into one sample, which is also an anti-alias filter. 50 Hz in, 10 Hz
//!    out, is the shape the ledger's captures suggest.
//! 2. **Window.** The last `N` decimated samples per subcarrier -- 200 at
//!    10 Hz is twenty seconds, four periods of the slowest breath.
//! 3. **Autocorrelate**, per subcarrier, over the band's lag range only:
//!    breathing at 0.15–0.55 Hz is a period of 1.8–6.7 s, lags 18–67 at
//!    10 Hz -- and from lag 2 upward, for the reason in step 4.
//!    Each subcarrier's autocorrelation is normalised by its own energy and
//!    corrected for the shrinking overlap, then they are **summed** -- the
//!    rhythm adds across subcarriers while their noise does not.
//! 4. **Pick the FIRST significant peak, scanning up from lag 2**, refine it
//!    with a parabola through its neighbours, and read a rate off it. The
//!    first, not the highest, and from below the band, not from its edge:
//!    a rhythm's autocorrelation peaks at every multiple of its period, so
//!    a heartbeat at 1.2 Hz has a perfect peak at 2.5 s -- inside the
//!    breathing band -- and would be read as 24 breaths a minute. Scanning
//!    from lag 2 finds its true period first, below the band, and the
//!    estimate is reported and **flagged** rather than accepted. The
//!    peak's height is the confidence: a subcarrier whose signal repeats
//!    exactly one period later has an autocorrelation of 1 there, noise ~0.
//!    An estimate is accepted only strictly inside its band; on an edge
//!    the rhythm is beyond it.
//!
//! Everything is integer. The two inner products are
//! [`rusty_esp_dsp::sample::dot_i16`] and `sum_sq_i16`, which are the
//! house's vectorised kernels on the S3 and plain loops on a RISC-V part.
//!
//! # Feed it normalised features, and know what that means
//!
//! [`super::csi::Features::normalised`] cancels a common gain, which is
//! what W1b found the amplitude detector's false presence to be. Breathing
//! survives normalisation because it is not common-mode: a changing path
//! is frequency-selective, so different subcarriers move by different
//! amounts and in different directions. A modulation that hit every
//! subcarrier identically would be normalised away -- and would not be a
//! body. The estimator takes either; the ledger's numbers are on
//! normalised features.
//!
//! # Heart rate, honestly
//!
//! The same machinery with a 0.7–2.0 Hz band and a faster sample rate. The
//! signal is ten times smaller than breathing and one link at 20 MHz has
//! little to resolve it with; RuView reports it from the same hardware, and
//! it is offered here as a band to try, **not** as a measurement to trust
//! without a reference count beside it. [`VitalsConfig::heart`] says so in
//! its name and its docs.
//!
//! # What the numbers are, and are not
//!
//! Derived and checked against synthetic captures with known rates and an
//! independent float replica (`tools/csi_vitals_oracle.py`), and held to
//! one property on the real captures the ledger names: **an empty room must
//! not grow a breathing rate.** No accuracy against a person is claimed; the
//! Cuenca dataset has no vitals labels, and a recording of our own with a
//! reference count is the plan's hardware step.

use rusty_esp_core::Micros;
use rusty_esp_dsp::sample::{dot_i16, sum_sq_i16};

use super::csi::{Features, MAX_SUBCARRIERS};

/// A frequency band, in millihertz, so a configuration is integers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Band {
    /// Lowest rate of interest.
    pub lo_mhz: u32,
    /// Highest rate of interest.
    pub hi_mhz: u32,
}

impl Band {
    /// Breathing: 9 to 30 per minute -- resting adults and sleep. Not lower:
    /// the slowest breath must fit three times in the window, and a 20 s
    /// window at 9 per minute holds exactly three.
    pub const BREATHING: Band = Band {
        lo_mhz: 150,
        hi_mhz: 550,
    };
    /// Heart: 42 to 132 per minute.
    ///
    /// Both bands reach a little past the rates they are for, because an
    /// estimate is accepted only strictly inside its band: a peak sitting on
    /// an edge means the rhythm is beyond it, not on it.
    pub const HEART: Band = Band {
        lo_mhz: 700,
        hi_mhz: 2200,
    };

    /// The lag range (inclusive) this band covers at `rate_hz` samples per
    /// second: a period of `1/hi` to `1/lo` seconds.
    #[must_use]
    pub const fn lags(self, rate_hz: u32) -> (usize, usize) {
        // period in samples = rate / f = rate * 1000 / f_mhz; the shortest
        // period is the highest rate, rounded in, the longest rounded out.
        let lo = (rate_hz * 1000) / self.hi_mhz;
        let hi = (rate_hz * 1000).div_ceil(self.lo_mhz);
        (if lo < 2 { 2 } else { lo as usize }, hi as usize)
    }
}

/// How to estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VitalsConfig {
    /// Frames averaged into one sample. `1` means no decimation.
    pub decim: u16,
    /// The decimated sample rate, Hz. The caller knows the frame rate and
    /// chose `decim`; this is `frame_rate / decim`, stated rather than
    /// measured, because the frames' own timestamps are the transport's
    /// business and a wrong rate here reads as a wrong BPM, not a crash.
    pub rate_hz: u32,
    /// The band to search.
    pub band: Band,
    /// Samples between estimates. Ten at 10 Hz is once a second.
    pub update_every: u16,
    /// The confidence (permille) at or above which an estimate is
    /// `accepted`. Below it the rate is still reported, flagged.
    pub accept_permille: u16,
    /// Samples of centred moving average to subtract before analysis, or 0.
    ///
    /// A high-pass, for the heart band: breathing is a few percent of the
    /// amplitude and a heartbeat a fraction of one, so over the heart's
    /// short lags the autocorrelation is the breath's slow curve with the
    /// heartbeat as a ripple on it, and the peak sits at the band's edge.
    /// Subtracting a one-second moving average cuts 0.2 Hz by about 24 dB
    /// and passes 1.2 Hz nearly whole. Breathing needs none.
    pub highpass: u16,
}

impl VitalsConfig {
    /// Breathing from `frame_hz` frames per second, decimated to 10 Hz,
    /// an estimate every second.
    ///
    /// `frame_hz` must be a multiple of 10; the ledger's captures are 50.
    #[must_use]
    pub const fn breathing(frame_hz: u32) -> Self {
        VitalsConfig {
            decim: (frame_hz / 10) as u16,
            rate_hz: 10,
            band: Band::BREATHING,
            update_every: 10,
            accept_permille: 400,
            highpass: 0,
        }
    }

    /// Heart rate from `frame_hz` frames per second, decimated to 25 Hz,
    /// an estimate every second. **A band to try, not a number to trust**
    /// without a reference beside it; see the module note.
    ///
    /// `frame_hz` must be a multiple of 25.
    #[must_use]
    pub const fn heart(frame_hz: u32) -> Self {
        VitalsConfig {
            decim: (frame_hz / 25) as u16,
            rate_hz: 25,
            band: Band::HEART,
            update_every: 25,
            accept_permille: 400,
            highpass: 25,
        }
    }
}

/// One estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vitals {
    /// The rate, in tenths of a cycle per minute (`152` is 15.2 BPM).
    pub bpm_x10: u16,
    /// The peak of the summed, normalised autocorrelation, permille: how
    /// much of the window repeats one period later. `0` when nothing does.
    pub confidence: u16,
    /// The refined lag the rate was read from, in sixteenths of a sample.
    pub lag_x16: u32,
    /// `confidence >= accept_permille` AND the rhythm sits strictly inside
    /// the band. A rhythm faster than the band -- a heartbeat seen through
    /// the breathing band, a walker's gait -- is reported here with the
    /// rate it actually has and `accepted` false.
    pub accepted: bool,
    /// When the window ended.
    pub at: Micros,
}

/// The estimator: a window of `N` decimated samples per subcarrier.
///
/// `N` decimated samples at [`VitalsConfig::rate_hz`] is the observation
/// window: 200 at 10 Hz is twenty seconds. The ring is `N × 64 × 2` bytes
/// -- 25.6 KiB at `N = 200` -- which is the cost of watching twenty seconds
/// of fifty-six subcarriers; a device that watches fewer may pass a layout
/// with fewer.
pub struct VitalsEstimator<const N: usize> {
    config: VitalsConfig,
    /// Decimated samples, one row per sample, in ring order.
    ring: [[i16; MAX_SUBCARRIERS]; N],
    /// The block being averaged into the next sample.
    acc: [i32; MAX_SUBCARRIERS],
    acc_n: u16,
    count: u8,
    filled: usize,
    next: usize,
    since_update: u16,
    last: Option<Vitals>,
}

impl<const N: usize> core::fmt::Debug for VitalsEstimator<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VitalsEstimator")
            .field("window", &N)
            .field("filled", &self.filled)
            .field("last", &self.last)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> VitalsEstimator<N> {
    /// A window of `N` samples at `config.rate_hz`.
    #[must_use]
    pub const fn new(config: VitalsConfig) -> Self {
        VitalsEstimator {
            config,
            ring: [[0; MAX_SUBCARRIERS]; N],
            acc: [0; MAX_SUBCARRIERS],
            acc_n: 0,
            count: 0,
            filled: 0,
            next: 0,
            since_update: 0,
            last: None,
        }
    }

    /// The configuration in use.
    #[must_use]
    pub const fn config(&self) -> &VitalsConfig {
        &self.config
    }

    /// The most recent estimate, if the window has produced one.
    #[must_use]
    pub const fn last(&self) -> Option<Vitals> {
        self.last
    }

    /// True once the window holds `N` samples.
    #[must_use]
    pub const fn warm(&self) -> bool {
        self.filled >= N
    }

    /// Forget the window (a channel change, a layout change).
    pub fn reset(&mut self) {
        self.filled = 0;
        self.next = 0;
        self.acc_n = 0;
        self.count = 0;
        self.since_update = 0;
        self.last = None;
    }

    /// Feed one frame's features; an estimate comes back every
    /// `update_every` decimated samples once the window is full.
    ///
    /// The amplitudes are averaged over `decim` frames into one sample. A
    /// frame with a different subcarrier count resets the window, as the
    /// presence detectors do.
    pub fn push(&mut self, features: &Features, now: Micros) -> Option<Vitals> {
        let n = usize::from(features.count).min(MAX_SUBCARRIERS);
        if n == 0 {
            return None;
        }
        if self.count != 0 && features.count != self.count {
            self.reset();
        }
        self.count = features.count;
        for (a, &v) in self.acc[..n].iter_mut().zip(&features.amplitude[..n]) {
            *a += i32::from(v);
        }
        self.acc_n += 1;
        if self.acc_n < self.config.decim.max(1) {
            return None;
        }
        // One decimated sample: the block mean, which fits i16 because every
        // amplitude does (≤ 4 096 normalised, ≤ 724 raw).
        let d = i32::from(self.acc_n);
        let slot = &mut self.ring[self.next];
        for (s, a) in slot[..n].iter_mut().zip(self.acc[..n].iter_mut()) {
            *s = (*a / d) as i16;
            *a = 0;
        }
        self.acc_n = 0;
        self.next = (self.next + 1) % N;
        if self.filled < N {
            self.filled += 1;
        }
        self.since_update += 1;
        if self.filled < N || self.since_update < self.config.update_every.max(1) {
            return None;
        }
        self.since_update = 0;
        let v = self.estimate(now);
        self.last = Some(v);
        Some(v)
    }

    /// The estimate over the current window.
    fn estimate(&self, now: Micros) -> Vitals {
        let n_sc = usize::from(self.count).min(MAX_SUBCARRIERS);
        let (lo, hi) = self.config.band.lags(self.config.rate_hz);
        let hi = hi.min(N.saturating_sub(2));
        let empty = Vitals {
            bpm_x10: 0,
            confidence: 0,
            lag_x16: 0,
            accepted: false,
            at: now,
        };
        if lo >= hi || n_sc == 0 {
            return empty;
        }
        // The summed normalised autocorrelation from lag 1 to one past the
        // band, one permille value per lag: the scan starts at 2 (see the
        // module note) and the parabola wants a neighbour each side.
        let lo_ext = 1;
        let hi_ext = (hi + 1).min(N - 1);
        let mut summed = [0i32; MAX_LAGS];
        let width = hi_ext - lo_ext + 1;
        if width > MAX_LAGS {
            return empty;
        }
        let mut used = 0u32;
        let mut x = [0i16; N];
        for sc in 0..n_sc {
            // The subcarrier's series in time order, mean removed. The mean
            // is the thing normalised features hold near 1 024 and a body
            // does not move; what is left is the rhythm and the noise.
            let mut sum: i64 = 0;
            for f in 0..N {
                sum += i64::from(self.ring[(self.next + f) % N][sc]);
            }
            let mean = (sum / N as i64) as i32;
            for (f, slot) in x.iter_mut().enumerate() {
                let v = i32::from(self.ring[(self.next + f) % N][sc]) - mean;
                *slot = v.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
            }
            if self.config.highpass > 1 {
                highpass(&mut x, usize::from(self.config.highpass));
            }
            let energy = sum_sq_i16(&x);
            if energy <= 0 {
                continue;
            }
            used += 1;
            for (i, lag) in (lo_ext..=hi_ext).enumerate() {
                // r[lag], corrected for the shrinking overlap so a long lag
                // is not penalised for having fewer terms: r · N / (N − lag).
                let r = dot_i16(&x[..N - lag], &x[lag..]);
                let rho = r * 1000 * N as i64 / ((N - lag) as i64 * energy);
                summed[i] += rho.clamp(-2000, 2000) as i32;
            }
        }
        if used == 0 {
            return empty;
        }
        // The FIRST significant peak from lag 2 up to the band's top, not
        // the highest. A rhythm's autocorrelation peaks at its period and
        // at every multiple of it, and the overlap correction favours the
        // longer lag slightly, so the highest peak can be a sub-harmonic (a
        // 12 per minute breath read as 6 -- the float replica made exactly
        // that mistake before this rule) and a peak inside the band can be
        // a harmonic of a faster rhythm below it (a heartbeat read as 24
        // breaths). Scan upward from 2 and take the first local maximum
        // within 15 % of the highest.
        let mut global = i32::MIN;
        for lag in 2..=hi {
            global = global.max(summed[lag - lo_ext]);
        }
        let floor = if global > 0 {
            global - global * 15 / 100
        } else {
            global
        };
        let mut best = lo;
        let mut best_v = i32::MIN;
        for lag in 2..=hi {
            let i = lag - lo_ext;
            let v = summed[i];
            if v >= floor && v >= summed[i - 1] && v >= summed[i + 1] {
                best = lag;
                best_v = v;
                break;
            }
        }
        if best_v == i32::MIN {
            // No local maximum reached the floor (a monotone curve): the
            // highest value, which will sit on an edge and not be accepted.
            for lag in 2..=hi {
                let v = summed[lag - lo_ext];
                if v > best_v {
                    best_v = v;
                    best = lag;
                }
            }
        }
        let confidence = (best_v / used as i32).clamp(0, 1000) as u16;
        let inside = best > lo && best < hi;
        // Parabolic refinement through the neighbours, in sixteenths.
        let (a, b, c) = (
            summed[best - 1 - lo_ext],
            summed[best - lo_ext],
            summed[best + 1 - lo_ext],
        );
        let denom = a - 2 * b + c;
        let delta_x16 = if denom < 0 {
            // vertex offset = (a − c) / (2 · (a − 2b + c)), in [−0.5, 0.5]
            ((a - c) * 8 / denom).clamp(-8, 8)
        } else {
            0
        };
        let lag_x16 = (best as i32 * 16 + delta_x16).max(16) as u32;
        // BPM × 10 = 600 · rate / lag = 600 · rate · 16 / lag_x16.
        let bpm_x10 =
            ((9600 * self.config.rate_hz + lag_x16 / 2) / lag_x16).min(u32::from(u16::MAX)) as u16;
        Vitals {
            bpm_x10,
            confidence,
            lag_x16,
            accepted: inside && confidence >= self.config.accept_permille,
            at: now,
        }
    }
}

/// Subtract a centred moving average of `m` samples from `x`, in place.
///
/// The edges use the average over what is inside the series. `m` even is
/// treated as `m − 1`, so the window is symmetric.
fn highpass<const N: usize>(x: &mut [i16; N], m: usize) {
    let half = (m.min(N) / 2).max(1);
    let mut y = [0i16; N];
    // A running sum over [i − half, i + half] ∩ [0, N).
    let mut sum: i32 = 0;
    let mut lo = 0usize;
    let mut hi = 0usize; // exclusive
    for i in 0..N {
        let want_lo = i.saturating_sub(half);
        let want_hi = (i + half + 1).min(N);
        while hi < want_hi {
            sum += i32::from(x[hi]);
            hi += 1;
        }
        while lo < want_lo {
            sum -= i32::from(x[lo]);
            lo += 1;
        }
        let avg = sum / (hi - lo) as i32;
        y[i] = (i32::from(x[i]) - avg).clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16;
    }
    *x = y;
}

/// Room for the widest band this module defines and then some: breathing
/// at 10 Hz is lags 20..=67, heart at 25 Hz is 12..=36, plus a neighbour
/// each side. 128 `i32`s of stack. A band wider than this is refused with
/// an empty estimate rather than a truncated one.
const MAX_LAGS: usize = 128;

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// A frame of normalised-scale amplitudes: each subcarrier its own
    /// static level near 1 024, modulated by a rhythm with its own depth
    /// and sign -- a changing path is frequency-selective -- plus noise.
    fn frame(t: f64, rhythms: &[(f64, f64)], noise: f64, seed: &mut u32) -> Features {
        let mut f = Features {
            amplitude: [0; MAX_SUBCARRIERS],
            count: 56,
            mean: 0,
            variance: 0,
        };
        let mut sum = 0u32;
        for k in 0..56usize {
            let base = 900.0 + ((k * 37) % 250) as f64;
            let mut v = base;
            for (i, &(hz, depth)) in rhythms.iter().enumerate() {
                let sign = if (k + i) % 3 == 0 { -1.0 } else { 1.0 };
                let d = depth * (0.5 + ((k * 11 + i * 5) % 10) as f64 / 10.0);
                v *= 1.0 + sign * d * (core::f64::consts::TAU * hz * t + k as f64 * 0.7).sin();
            }
            // xorshift noise, uniform in [-noise, noise]
            *seed ^= *seed << 13;
            *seed ^= *seed >> 17;
            *seed ^= *seed << 5;
            let u = (*seed as f64 / u32::MAX as f64) * 2.0 - 1.0;
            v += u * noise;
            let a = v.round().max(0.0) as u16;
            f.amplitude[k] = a;
            sum += u32::from(a);
        }
        f.mean = (sum / 56) as u16;
        f
    }

    fn run(hz: f64, depth: f64, noise: f64, seconds: f64, cfg: VitalsConfig) -> Vec<Vitals> {
        let mut est = VitalsEstimator::<200>::new(cfg);
        let mut seed = 0x1234_5678u32;
        let mut out = Vec::new();
        let frames = (seconds * 50.0) as usize;
        for n in 0..frames {
            let t = n as f64 / 50.0;
            let f = frame(t, &[(hz, depth)], noise, &mut seed);
            if let Some(v) = est.push(&f, Micros(n as u64 * 20_000)) {
                out.push(v);
            }
        }
        out
    }

    #[test]
    fn the_bands_map_to_the_right_lags() {
        assert_eq!(Band::BREATHING.lags(10), (18, 67));
        assert_eq!(Band::HEART.lags(25), (11, 36));
        assert_eq!(VitalsConfig::breathing(50).decim, 5);
        assert_eq!(VitalsConfig::heart(50).decim, 2);
    }

    #[test]
    fn a_clean_breath_at_15_bpm_is_read_to_a_tenth() {
        let out = run(0.25, 0.03, 0.0, 40.0, VitalsConfig::breathing(50));
        assert!(
            !out.is_empty(),
            "the window fills at 20 s and reports every second"
        );
        let last = out.last().unwrap();
        assert!((i32::from(last.bpm_x10) - 150).abs() <= 3, "{last:?}");
        assert!(last.confidence > 900, "{last:?}");
        assert!(last.accepted);
    }

    #[test]
    fn a_noisy_breath_at_12_bpm_is_still_read() {
        // 3 % modulation under noise of ±20 on a level near 1 024 (2 %).
        let out = run(0.2, 0.03, 20.0, 40.0, VitalsConfig::breathing(50));
        let last = out.last().unwrap();
        assert!((i32::from(last.bpm_x10) - 120).abs() <= 8, "{last:?}");
        assert!(last.accepted, "{last:?}");
    }

    #[test]
    fn noise_alone_is_not_a_breath() {
        let out = run(0.25, 0.0, 20.0, 40.0, VitalsConfig::breathing(50));
        let last = out.last().unwrap();
        assert!(!last.accepted, "noise read as breathing: {last:?}");
        assert!(last.confidence < 300, "{last:?}");
    }

    #[test]
    fn a_rate_outside_the_band_is_not_reported_as_inside_it() {
        // 1.2 Hz (72 per minute) through the BREATHING band. Its
        // autocorrelation has a perfect peak at 2.5 s -- three periods --
        // which is inside the band, and a global-max or in-band-only rule
        // read it as 24 breaths a minute at 99 % confidence. Scanning from
        // lag 2 finds the true period first and flags the estimate.
        let out = run(1.2, 0.03, 5.0, 40.0, VitalsConfig::breathing(50));
        let last = out.last().unwrap();
        assert!(!last.accepted, "a heartbeat accepted as a breath: {last:?}");
        // and the rate it reports is the rhythm's own
        assert!((i32::from(last.bpm_x10) - 720).abs() <= 40, "{last:?}");
    }

    #[test]
    fn heart_at_72_bpm_is_read_from_the_heart_band_on_a_clean_signal() {
        let out = run(1.2, 0.006, 0.0, 40.0, VitalsConfig::heart(50));
        let last = out.last().unwrap();
        assert!((i32::from(last.bpm_x10) - 720).abs() <= 15, "{last:?}");
        assert!(last.accepted, "{last:?}");
    }

    #[test]
    fn a_count_change_resets_the_window() {
        let cfg = VitalsConfig::breathing(50);
        let mut est = VitalsEstimator::<200>::new(cfg);
        let mut seed = 1u32;
        for n in 0..1100 {
            est.push(
                &frame(n as f64 / 50.0, &[(0.25, 0.03)], 0.0, &mut seed),
                Micros(n),
            );
        }
        assert!(est.warm());
        let mut short = frame(0.0, &[], 0.0, &mut seed);
        short.count = 52;
        est.push(&short, Micros(2000));
        assert!(!est.warm());
        assert!(est.last().is_none());
    }
}

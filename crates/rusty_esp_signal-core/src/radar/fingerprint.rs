//! The room's fingerprint: how far the channel's shape has drifted from a
//! calibrated baseline.
//!
//! [`super::csi::Features::variance`] is the spread of amplitude across the
//! subcarriers in one frame -- the frequency-selectivity of the channel,
//! which is the multipath's shape and therefore the room's. On gain-
//! normalised features it is free of the receiver's gain, so what changes it
//! is furniture moved, a door opened, a body standing where none stood: the
//! static state of the room, as opposed to the motion the presence
//! detectors watch.
//!
//! A [`Baseline`] is calibrated from a run of frames in the room's reference
//! state; [`Baseline::distance`] is the permille departure of a frame's
//! variance from it. It is one number, and it is deliberately not a verdict:
//! what a distance of 200 ‰ *means* is the application's to decide, per
//! room, from the numbers it logged while the room was as expected.

use super::csi::Features;

/// A calibrated reference for the room's fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Baseline {
    sum: u64,
    frames: u32,
    /// The mean variance over the calibration frames, once settled.
    mean: u32,
}

impl Default for Baseline {
    fn default() -> Self {
        Self::new()
    }
}

impl Baseline {
    /// Nothing learned yet.
    #[must_use]
    pub const fn new() -> Self {
        Baseline {
            sum: 0,
            frames: 0,
            mean: 0,
        }
    }

    /// Feed a frame taken while the room is in its reference state.
    ///
    /// Normalised features, so a gain step during calibration does not move
    /// the baseline. Frames with no subcarriers are ignored.
    pub fn calibrate(&mut self, features: &Features) {
        if features.count == 0 {
            return;
        }
        self.sum += u64::from(features.variance);
        self.frames += 1;
        self.mean = (self.sum / u64::from(self.frames)).min(u64::from(u32::MAX)) as u32;
    }

    /// Frames calibrated so far.
    #[must_use]
    pub const fn frames(&self) -> u32 {
        self.frames
    }

    /// The baseline's mean variance, 0 until calibrated.
    #[must_use]
    pub const fn mean(&self) -> u32 {
        self.mean
    }

    /// How far `features` sits from the baseline, in permille of the
    /// baseline: `1000 · |variance − mean| / mean`, clipped to `u16`.
    ///
    /// `0` when nothing has been calibrated -- an uncalibrated fingerprint
    /// reports nothing rather than a distance from zero.
    #[must_use]
    pub fn distance(&self, features: &Features) -> u16 {
        if self.mean == 0 || features.count == 0 {
            return 0;
        }
        let d = u64::from(features.variance.abs_diff(self.mean));
        (d * 1000 / u64::from(self.mean)).min(u64::from(u16::MAX)) as u16
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::radar::csi::MAX_SUBCARRIERS;
    use std::vec::Vec;

    fn feats(amps: &[u16]) -> Features {
        let mut f = Features {
            amplitude: [0; MAX_SUBCARRIERS],
            count: amps.len() as u8,
            mean: 0,
            variance: 0,
        };
        f.amplitude[..amps.len()].copy_from_slice(amps);
        let n = amps.len() as u32;
        let sum: u32 = amps.iter().map(|&a| u32::from(a)).sum();
        f.mean = (sum / n) as u16;
        let m = i32::from(f.mean);
        f.variance = amps
            .iter()
            .map(|&a| (i32::from(a) - m).unsigned_abs().pow(2))
            .sum::<u32>()
            / n;
        f
    }

    fn shape(k: usize) -> Vec<u16> {
        (0..56u16).map(|i| 80 + ((i * 7 + k as u16) % 23)).collect()
    }

    #[test]
    fn uncalibrated_reports_nothing() {
        let b = Baseline::new();
        assert_eq!(b.distance(&feats(&shape(0)).normalised()), 0);
        assert_eq!(b.frames(), 0);
    }

    #[test]
    fn the_reference_state_is_at_distance_zero_and_a_gain_step_stays_there() {
        let mut b = Baseline::new();
        for k in 0..20 {
            b.calibrate(&feats(&shape(k % 3)).normalised());
        }
        assert_eq!(b.frames(), 20);
        let same = feats(&shape(0)).normalised();
        assert!(b.distance(&same) < 60, "{}", b.distance(&same));
        // The same room three times louder: normalised, the same shape.
        let louder: Vec<u16> = shape(0).iter().map(|&a| a * 3).collect();
        let d = b.distance(&feats(&louder).normalised());
        assert!(d < 60, "a gain step moved the fingerprint by {d} ‰");
    }

    #[test]
    fn a_change_of_shape_is_a_distance() {
        let mut b = Baseline::new();
        for k in 0..20 {
            b.calibrate(&feats(&shape(k % 3)).normalised());
        }
        // Half the subcarriers doubled: a different multipath.
        let mut moved = shape(0);
        for a in moved.iter_mut().step_by(2) {
            *a *= 2;
        }
        let d = b.distance(&feats(&moved).normalised());
        assert!(d > 300, "a shape change read as {d} ‰");
    }
}

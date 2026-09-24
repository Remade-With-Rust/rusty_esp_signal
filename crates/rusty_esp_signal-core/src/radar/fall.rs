//! A fall, as a shape in the channel's wander: moving, then a burst larger
//! than walking makes, then stillness that begins within seconds and lasts.
//!
//! W7 of the RuView plan (`espino/docs/plans/ruview-function.md`). It runs
//! on the wander [`super::csi::PresenceDetector`] already computes, so on a
//! chip it costs a few comparisons a frame and no memory beyond its state.
//!
//! # What it can and cannot tell
//!
//! Three things end in stillness after motion: a fall, sitting down, and
//! walking out of the room. The burst separates the first from the second
//! -- a body hitting the floor moves more paths faster than a body lowering
//! itself -- and nothing in the wander separates the first from the third:
//! an empty room and a person lying still read the same amplitude. What
//! does is breathing ([`super::vitals`]), which a still person has and an
//! empty room does not. So an event says "suspected", with when the burst
//! was and how long the stillness has lasted, and the caller asks the
//! breathing estimator before it calls anyone.
//!
//! # What is measured, and what is not
//!
//! No labelled fall recording from an ESP32 under a licence we can use has
//! been found. What IS measured is what sinks a fall detector in a home:
//! false alarms, over real captures with no falls in them (walking, traffic,
//! empty), with the burst threshold set on half of them and counted on the
//! other half (`rusty_esp_sense bench-fall`). Detection is shown only on
//! splices of real segments, and called synthetic where it is reported.

use rusty_esp_core::Micros;

/// Thresholds and durations. Wander is the detector's, in permille of
/// gain-normalised amplitude.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallConfig {
    /// At or above: someone is moving.
    pub active_permille: u16,
    /// At or above, after moving: a burst.
    pub burst_permille: u16,
    /// At or below: still.
    pub still_permille: u16,
    /// Moving for at least this long before a burst counts: a fall happens
    /// to someone who was up.
    pub min_active: Micros,
    /// Motion ends only after this long of continuous stillness. A walker
    /// is not above threshold between every step, and the first version of
    /// this detector, which ended motion on the first dip, caught one
    /// synthetic fall in ten because of it.
    pub quiet_grace: Micros,
    /// Stillness must begin within this long after the burst; the window
    /// behind the wander still holds the burst for about a second.
    pub settle: Micros,
    /// Stillness must last this long before an event.
    pub still_for: Micros,
    /// After an event, nothing for this long.
    pub refractory: Micros,
}

impl FallConfig {
    /// For the normalised detector's wander, from the TUNING half of the
    /// Cuenca captures only (`rusty_esp_sense bench-fall`; the other half
    /// judges them).
    ///
    /// `active` is the presence threshold
    /// ([`super::csi::Config::normalised_default`]). `still` is 30 ‰: the
    /// empty room's one-second wander reaches 28 ‰ on the tuning half, so
    /// the presence detector's `off` (23 ‰, derived on one capture) would
    /// leave a person lying still in that room "not yet still" often
    /// enough to lose the event. `burst` is 232 ‰: 1.3 × the highest wander
    /// any tuning capture reached (178 ‰, walking; traffic peaked at 35 ‰).
    /// It is a floor above what walking does in that room, not a
    /// measurement of what a fall does -- none has been recorded -- and a
    /// deployment sets it from its own room's walking.
    #[must_use]
    pub const fn normalised_default() -> Self {
        FallConfig {
            active_permille: 32,
            burst_permille: 232,
            still_permille: 30,
            min_active: Micros::from_secs(2),
            quiet_grace: Micros::from_secs(3),
            settle: Micros::from_secs(3),
            still_for: Micros::from_secs(10),
            refractory: Micros::from_secs(60),
        }
    }
}

impl Default for FallConfig {
    fn default() -> Self {
        Self::normalised_default()
    }
}

/// A suspected fall.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallEvent {
    /// When the burst began.
    pub burst_at: Micros,
    /// The burst's peak wander, permille.
    pub peak_permille: u16,
    /// When the stillness began.
    pub still_since: Micros,
    /// When the event was raised (`still_since + still_for`).
    pub at: Micros,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Active {
        since: Micros,
        quiet_since: Option<Micros>,
    },
    Burst {
        at: Micros,
        peak: u16,
    },
    Settling {
        burst_at: Micros,
        peak: u16,
        still_since: Micros,
    },
    Refractory {
        until: Micros,
    },
}

/// The detector: feed it the presence detector's wander once per frame.
#[derive(Debug, Clone)]
pub struct FallDetector {
    config: FallConfig,
    phase: Phase,
    events: u32,
}

impl FallDetector {
    /// A detector with `config`.
    #[must_use]
    pub const fn new(config: FallConfig) -> Self {
        FallDetector {
            config,
            phase: Phase::Idle,
            events: 0,
        }
    }

    /// Its thresholds.
    #[must_use]
    pub const fn config(&self) -> &FallConfig {
        &self.config
    }

    /// Events raised so far.
    #[must_use]
    pub const fn events(&self) -> u32 {
        self.events
    }

    /// Whether a burst has happened and the stillness is being timed.
    #[must_use]
    pub const fn pending(&self) -> bool {
        matches!(self.phase, Phase::Burst { .. } | Phase::Settling { .. })
    }

    /// Forget everything.
    pub fn reset(&mut self) {
        self.phase = Phase::Idle;
    }

    /// One frame's wander at `now`; an event when a fall's shape completes.
    pub fn push(&mut self, wander: u16, now: Micros) -> Option<FallEvent> {
        let c = self.config;
        let since = |t: Micros| now.0.saturating_sub(t.0);
        match self.phase {
            Phase::Refractory { until } => {
                if now.0 >= until.0 {
                    self.phase = Phase::Idle;
                }
                None
            }
            Phase::Idle => {
                if wander >= c.active_permille {
                    self.phase = Phase::Active {
                        since: now,
                        quiet_since: None,
                    };
                }
                None
            }
            Phase::Active {
                since: start,
                quiet_since,
            } => {
                if wander >= c.burst_permille && since(start) >= c.min_active.0 {
                    self.phase = Phase::Burst {
                        at: now,
                        peak: wander,
                    };
                } else if wander <= c.still_permille {
                    let q = quiet_since.unwrap_or(now);
                    self.phase = if since(q) >= c.quiet_grace.0 {
                        // Stopped without a burst: sat down, stood still, left.
                        Phase::Idle
                    } else {
                        Phase::Active {
                            since: start,
                            quiet_since: Some(q),
                        }
                    };
                } else {
                    self.phase = Phase::Active {
                        since: start,
                        quiet_since: None,
                    };
                }
                None
            }
            Phase::Burst { at, peak } => {
                if wander <= c.still_permille {
                    self.phase = Phase::Settling {
                        burst_at: at,
                        peak,
                        still_since: now,
                    };
                } else if since(at) > c.settle.0 {
                    // Kept moving after the burst: not lying still.
                    self.phase = Phase::Active {
                        since: now,
                        quiet_since: None,
                    };
                } else {
                    self.phase = Phase::Burst {
                        at,
                        peak: peak.max(wander),
                    };
                }
                None
            }
            Phase::Settling {
                burst_at,
                peak,
                still_since,
            } => {
                if wander >= c.active_permille {
                    // Got up again.
                    self.phase = Phase::Active {
                        since: now,
                        quiet_since: None,
                    };
                    return None;
                }
                if wander > c.still_permille {
                    // Between still and active: neither restarts nor
                    // counts; the stillness is timed from when it began.
                    return None;
                }
                if since(still_since) >= c.still_for.0 {
                    self.phase = Phase::Refractory {
                        until: Micros(now.0.saturating_add(c.refractory.0)),
                    };
                    self.events = self.events.saturating_add(1);
                    return Some(FallEvent {
                        burst_at,
                        peak_permille: peak,
                        still_since,
                        at: now,
                    });
                }
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: u64 = 20_000;

    /// Push `n` frames of `wander` starting at frame `t0`; the events.
    fn run(d: &mut FallDetector, t0: u64, n: u64, wander: u16) -> Vec<FallEvent> {
        (t0..t0 + n)
            .filter_map(|k| d.push(wander, Micros(k * FRAME)))
            .collect()
    }

    fn secs(s: u64) -> u64 {
        s * 50
    }

    #[test]
    fn walking_then_a_burst_then_stillness_is_a_fall() {
        let mut d = FallDetector::new(FallConfig::normalised_default());
        assert!(run(&mut d, 0, secs(5), 60).is_empty(), "walking");
        assert!(run(&mut d, secs(5), 25, 300).is_empty(), "the burst");
        assert!(d.pending());
        let mut t = secs(5) + 25;
        assert!(
            run(&mut d, t, secs(9), 18).is_empty(),
            "nine seconds still is not yet ten"
        );
        t += secs(9);
        let e = run(&mut d, t, secs(2), 18);
        assert_eq!(e.len(), 1, "{e:?}");
        assert_eq!(e[0].peak_permille, 300);
        assert_eq!(e[0].burst_at, Micros(secs(5) * FRAME));
        assert_eq!(d.events(), 1);
    }

    #[test]
    fn a_walker_dipping_between_steps_is_still_up_when_the_burst_comes() {
        // Walking that drops below `still` for half a second at a time.
        let mut d = FallDetector::new(FallConfig::normalised_default());
        let mut t = 0;
        for _ in 0..5 {
            run(&mut d, t, secs(1), 70);
            run(&mut d, t + secs(1), 25, 20);
            t += secs(1) + 25;
        }
        run(&mut d, t, 25, 300);
        assert!(d.pending(), "the dips did not end the motion");
        assert_eq!(run(&mut d, t + 25, secs(12), 18).len(), 1);
    }

    #[test]
    fn stopping_without_a_burst_is_not_a_fall() {
        // Walking, then an empty or still room: sat down, or left.
        let mut d = FallDetector::new(FallConfig::normalised_default());
        run(&mut d, 0, secs(10), 90);
        assert!(run(&mut d, secs(10), secs(60), 17).is_empty());
        assert!(!d.pending());
    }

    #[test]
    fn a_burst_followed_by_more_movement_is_not_a_fall() {
        let mut d = FallDetector::new(FallConfig::normalised_default());
        run(&mut d, 0, secs(5), 60);
        run(&mut d, secs(5), 25, 300);
        // kept moving for longer than `settle`
        assert!(run(&mut d, secs(5) + 25, secs(5), 70).is_empty());
        assert!(!d.pending());
        assert!(
            run(&mut d, secs(11), secs(30), 17).is_empty(),
            "and stopping later is a plain stop"
        );
    }

    #[test]
    fn a_burst_from_stillness_is_not_a_fall() {
        // Nobody was up: a door slam, a burst of traffic, a pet.
        let mut d = FallDetector::new(FallConfig::normalised_default());
        run(&mut d, 0, secs(5), 17);
        run(&mut d, secs(5), 10, 300); // 0.2 s: too short to be `min_active` of motion
        assert!(run(&mut d, secs(5) + 10, secs(30), 17).is_empty());
    }

    #[test]
    fn getting_up_during_the_stillness_cancels_it() {
        let mut d = FallDetector::new(FallConfig::normalised_default());
        run(&mut d, 0, secs(5), 60);
        run(&mut d, secs(5), 25, 300);
        run(&mut d, secs(5) + 25, secs(5), 18);
        run(&mut d, secs(11), secs(2), 80);
        assert!(!d.pending());
        assert!(run(&mut d, secs(13), secs(30), 17).is_empty());
    }

    #[test]
    fn one_fall_raises_one_event_and_then_waits() {
        let mut d = FallDetector::new(FallConfig::normalised_default());
        run(&mut d, 0, secs(5), 60);
        run(&mut d, secs(5), 25, 300);
        let first = run(&mut d, secs(5) + 25, secs(15), 18);
        assert_eq!(first.len(), 1);
        // The same shape again inside the refractory minute: nothing.
        let t = secs(21);
        run(&mut d, t, secs(5), 60);
        run(&mut d, t + secs(5), 25, 300);
        assert!(run(&mut d, t + secs(5) + 25, secs(15), 18).is_empty());
        assert_eq!(d.events(), 1);
    }
}

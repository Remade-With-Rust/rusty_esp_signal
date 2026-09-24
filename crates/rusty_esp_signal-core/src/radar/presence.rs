//! What a presence sensor says, whatever the sensor is.
//!
//! [`ld2410`](super::ld2410) speaks a millimetre-wave module's UART and
//! [`csi`](super::csi) reads Wi-Fi channel state, and they answer in their
//! own vocabularies: a [`Report`](super::ld2410::Report) of distances and
//! energies, a [`Verdict`](super::csi::Verdict) of warming, absent or
//! present. A device that sends presence to its owner should not make the
//! owner learn both, and the transport should not learn either.
//!
//! [`Presence`] is the one record both become. It is fixed-width, big-endian
//! and versioned, so a home computer decodes it without knowing which sensor
//! produced it, and a sensor we add later fills the same fields or leaves
//! them zero. Distances are centimetres and energies are `0..=100`, exactly
//! as the module reports them; nothing is scaled on the device.
//!
//! # Version 2: vitals and a fingerprint
//!
//! Version 2 appends what [`super::vitals`] and [`super::fingerprint`]
//! produce: breathing and heart rate in tenths per minute with their
//! confidences in permille, and the room's fingerprint distance. A version 1
//! record still decodes -- the new fields read as zero -- so a home computer
//! built after this change reads a device flashed before it.
//!
//! **A rate is on the wire only when it was accepted.** An estimate the
//! estimator flagged (a heartbeat at seven percent confidence, a walker's
//! gait through the breathing band) carries its confidence and a rate of
//! zero, so a consumer that reads the rate and not the confidence still
//! cannot be misled. The confidence is there for the consumer that wants to
//! know the sensor tried.

use rusty_esp_core::prelude::{Error, Result};
use rusty_esp_core::time::Micros;

/// What the sensor concluded about the space in front of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Occupancy {
    /// The sensor has not settled yet (a detector still filling its window).
    #[default]
    Unknown,
    /// Nothing is there.
    Absent,
    /// Something is moving.
    Moving,
    /// Something is there and still (breathing, a person at a desk).
    Stationary,
    /// Both a moving and a stationary target.
    Both,
}

impl Occupancy {
    /// Stable wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Occupancy::Unknown => 0,
            Occupancy::Absent => 1,
            Occupancy::Moving => 2,
            Occupancy::Stationary => 3,
            Occupancy::Both => 4,
        }
    }

    /// The tag's meaning, or `None` for one this version does not know.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Occupancy::Unknown,
            1 => Occupancy::Absent,
            2 => Occupancy::Moving,
            3 => Occupancy::Stationary,
            4 => Occupancy::Both,
            _ => return None,
        })
    }

    /// Whether anything is there at all, moving or still.
    #[must_use]
    pub const fn occupied(self) -> bool {
        matches!(
            self,
            Occupancy::Moving | Occupancy::Stationary | Occupancy::Both
        )
    }
}

/// The version byte every encoding starts with.
pub const VERSION: u8 = 2;

/// Bytes of a version 1 record, which [`Presence::decode`] still accepts.
pub const V1_LEN: usize = 18;

/// Bytes of one encoded [`Presence`] (version 2).
pub const ENCODED_LEN: usize = 28;

/// One presence reading, ready to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Presence {
    /// What the sensor concluded.
    pub state: Occupancy,
    /// Distance to the moving target in centimetres, 0 when there is none.
    pub moving_cm: u16,
    /// Moving-target energy `0..=100`, 0 when there is none.
    pub moving_energy: u8,
    /// Distance to the stationary target in centimetres, 0 when none.
    pub stationary_cm: u16,
    /// Stationary-target energy `0..=100`, 0 when there is none.
    pub stationary_energy: u8,
    /// The sensor's own detection distance in centimetres, 0 when it does
    /// not report one.
    pub detection_cm: u16,
    /// Device time of the reading.
    pub at: Micros,
    /// Breathing, tenths per minute; 0 when none was accepted.
    pub breathing_bpm_x10: u16,
    /// The breathing estimate's confidence, permille, whether or not it was
    /// accepted; 0 when no estimator ran.
    pub breathing_confidence: u16,
    /// Heart rate, tenths per minute; 0 when none was accepted -- which, on
    /// one amplitude link, is the usual case (see [`super::vitals`]).
    pub heart_bpm_x10: u16,
    /// The heart estimate's confidence, permille; 0 when no estimator ran.
    pub heart_confidence: u16,
    /// Distance of the room's current fingerprint from its calibrated
    /// baseline, permille ([`super::fingerprint`]); 0 when uncalibrated.
    pub fingerprint: u16,
}

impl Presence {
    /// The reading an LD2410 report carries, at device time `at`.
    #[must_use]
    pub fn from_ld2410(report: &super::ld2410::Report, at: Micros) -> Self {
        use super::ld2410::TargetState;
        Presence {
            state: match report.state {
                TargetState::None => Occupancy::Absent,
                TargetState::Moving => Occupancy::Moving,
                TargetState::Stationary => Occupancy::Stationary,
                TargetState::Both => Occupancy::Both,
            },
            moving_cm: report.moving_distance_cm,
            moving_energy: report.moving_energy,
            stationary_cm: report.stationary_distance_cm,
            stationary_energy: report.stationary_energy,
            detection_cm: report.detection_distance_cm,
            at,
            // No vitals from a radar module; the estimators fill these.
            ..Presence::default()
        }
    }

    /// The reading a Wi-Fi sensing verdict carries, at device time `at`.
    ///
    /// Channel state gives motion, not distance: the motion level lands in
    /// `moving_energy` and every distance stays zero.
    #[must_use]
    pub fn from_csi(verdict: super::csi::Verdict, at: Micros) -> Self {
        use super::csi::Verdict;
        let (state, moving_energy) = match verdict {
            Verdict::Warming => (Occupancy::Unknown, 0),
            Verdict::Absent => (Occupancy::Absent, 0),
            Verdict::Present { motion } => (Occupancy::Moving, motion),
        };
        Presence {
            state,
            moving_energy,
            at,
            ..Presence::default()
        }
    }

    /// Add what the vitals estimators found.
    ///
    /// A rate is carried only from an **accepted** estimate; a flagged one
    /// contributes its confidence and a rate of zero. `None` for a band no
    /// estimator ran leaves both fields zero.
    #[must_use]
    pub fn with_vitals(
        mut self,
        breathing: Option<&super::vitals::Vitals>,
        heart: Option<&super::vitals::Vitals>,
    ) -> Self {
        let carry = |v: Option<&super::vitals::Vitals>| match v {
            Some(v) if v.accepted => (v.bpm_x10, v.confidence),
            Some(v) => (0, v.confidence),
            None => (0, 0),
        };
        (self.breathing_bpm_x10, self.breathing_confidence) = carry(breathing);
        (self.heart_bpm_x10, self.heart_confidence) = carry(heart);
        self
    }

    /// Add the room's fingerprint distance from its calibrated baseline.
    #[must_use]
    pub const fn with_fingerprint(mut self, permille: u16) -> Self {
        self.fingerprint = permille;
        self
    }

    /// Write the record into `out`, returning the bytes written.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] when `out` is shorter than
    /// [`ENCODED_LEN`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let out = out.get_mut(..ENCODED_LEN).ok_or(Error::BufferTooSmall {
            needed: ENCODED_LEN,
        })?;
        out[0] = VERSION;
        out[1] = self.state.tag();
        out[2..4].copy_from_slice(&self.moving_cm.to_be_bytes());
        out[4] = self.moving_energy;
        out[5..7].copy_from_slice(&self.stationary_cm.to_be_bytes());
        out[7] = self.stationary_energy;
        out[8..10].copy_from_slice(&self.detection_cm.to_be_bytes());
        out[10..18].copy_from_slice(&self.at.0.to_be_bytes());
        out[18..20].copy_from_slice(&self.breathing_bpm_x10.to_be_bytes());
        out[20..22].copy_from_slice(&self.breathing_confidence.to_be_bytes());
        out[22..24].copy_from_slice(&self.heart_bpm_x10.to_be_bytes());
        out[24..26].copy_from_slice(&self.heart_confidence.to_be_bytes());
        out[26..28].copy_from_slice(&self.fingerprint.to_be_bytes());
        Ok(ENCODED_LEN)
    }

    /// Read a record written by [`encode`](Self::encode), at version 2 or
    /// version 1.
    ///
    /// A version 1 record -- a device flashed before vitals existed --
    /// decodes with every version 2 field zero, which is what "no estimator
    /// ran" encodes anyway.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] when the bytes are short for their version,
    /// the version is one this build does not know, or the state tag is.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let version = *bytes.first().ok_or(Error::InvalidFormat)?;
        let len = match version {
            1 => V1_LEN,
            VERSION => ENCODED_LEN,
            _ => return Err(Error::InvalidFormat),
        };
        let b = bytes.get(..len).ok_or(Error::InvalidFormat)?;
        let state = Occupancy::from_tag(b[1]).ok_or(Error::InvalidFormat)?;
        let u16_at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        let mut at = [0u8; 8];
        at.copy_from_slice(&b[10..18]);
        let mut p = Presence {
            state,
            moving_cm: u16_at(2),
            moving_energy: b[4],
            stationary_cm: u16_at(5),
            stationary_energy: b[7],
            detection_cm: u16_at(8),
            at: Micros(u64::from_be_bytes(at)),
            ..Presence::default()
        };
        if version == VERSION {
            p.breathing_bpm_x10 = u16_at(18);
            p.breathing_confidence = u16_at(20);
            p.heart_bpm_x10 = u16_at(22);
            p.heart_confidence = u16_at(24);
            p.fingerprint = u16_at(26);
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::radar::csi::Verdict;
    use crate::radar::ld2410::{Report, TargetState};

    fn sample() -> Presence {
        Presence {
            state: Occupancy::Both,
            moving_cm: 187,
            moving_energy: 64,
            stationary_cm: 240,
            stationary_energy: 31,
            detection_cm: 300,
            at: Micros(1_234_567_890),
            breathing_bpm_x10: 152,
            breathing_confidence: 633,
            heart_bpm_x10: 0,
            heart_confidence: 74,
            fingerprint: 210,
        }
    }

    #[test]
    fn a_record_survives_the_wire_unchanged() {
        let p = sample();
        let mut buf = [0u8; ENCODED_LEN];
        assert_eq!(p.encode(&mut buf).unwrap(), ENCODED_LEN);
        assert_eq!(buf[0], VERSION);
        assert_eq!(Presence::decode(&buf).unwrap(), p);
        // a longer buffer writes the same bytes and decodes the same
        let mut roomy = [0xAAu8; ENCODED_LEN + 8];
        assert_eq!(p.encode(&mut roomy).unwrap(), ENCODED_LEN);
        assert_eq!(&roomy[..ENCODED_LEN], &buf[..]);
        assert_eq!(Presence::decode(&roomy).unwrap(), p);
    }

    #[test]
    fn the_refusals_name_what_is_wrong() {
        let p = sample();
        let mut small = [0u8; ENCODED_LEN - 1];
        assert!(matches!(
            p.encode(&mut small),
            Err(Error::BufferTooSmall {
                needed: ENCODED_LEN
            })
        ));
        let mut buf = [0u8; ENCODED_LEN];
        p.encode(&mut buf).unwrap();
        // short, a version we do not know, a state tag we do not know
        assert!(Presence::decode(&buf[..ENCODED_LEN - 1]).is_err());
        assert!(Presence::decode(&[]).is_err());
        let mut wrong = buf;
        wrong[0] = VERSION + 1;
        assert!(Presence::decode(&wrong).is_err());
        let mut wrong = buf;
        wrong[1] = 9;
        assert!(Presence::decode(&wrong).is_err());
    }

    #[test]
    fn every_byte_pattern_decodes_or_refuses_without_panicking() {
        for a in 0u8..=255 {
            for len in 0..=ENCODED_LEN + 1 {
                let mut buf = [a; ENCODED_LEN + 1];
                buf[0] = if a % 3 == 0 { VERSION } else { a };
                let _ = Presence::decode(&buf[..len]);
            }
        }
    }

    #[test]
    fn both_sensors_become_the_same_record() {
        let report = Report {
            state: TargetState::Moving,
            moving_distance_cm: 150,
            moving_energy: 80,
            stationary_distance_cm: 0,
            stationary_energy: 0,
            detection_distance_cm: 150,
            engineering: None,
        };
        let p = Presence::from_ld2410(&report, Micros(42));
        assert_eq!(p.state, Occupancy::Moving);
        assert!(p.state.occupied());
        assert_eq!(p.moving_cm, 150);
        assert_eq!(p.at, Micros(42));

        let warm = Presence::from_csi(Verdict::Warming, Micros(7));
        assert_eq!(warm.state, Occupancy::Unknown);
        assert!(!warm.state.occupied());
        let seen = Presence::from_csi(Verdict::Present { motion: 33 }, Micros(9));
        assert_eq!(seen.state, Occupancy::Moving);
        assert_eq!(seen.moving_energy, 33);
        assert_eq!(seen.moving_cm, 0, "channel state gives motion, not range");
        assert!(seen.state.occupied());
        let gone = Presence::from_csi(Verdict::Absent, Micros(11));
        assert_eq!(gone.state, Occupancy::Absent);
        assert!(!gone.state.occupied());

        // and each one round-trips
        for p in [p, warm, seen, gone] {
            let mut buf = [0u8; ENCODED_LEN];
            p.encode(&mut buf).unwrap();
            assert_eq!(Presence::decode(&buf).unwrap(), p);
        }
    }

    #[test]
    fn the_wire_tags_are_stable() {
        assert_eq!(Occupancy::Unknown.tag(), 0);
        assert_eq!(Occupancy::Absent.tag(), 1);
        assert_eq!(Occupancy::Moving.tag(), 2);
        assert_eq!(Occupancy::Stationary.tag(), 3);
        assert_eq!(Occupancy::Both.tag(), 4);
        assert_eq!(Occupancy::from_tag(5), None);
        // Pinned on purpose, so a change to the wire is a decision someone
        // made: version 2 on 2026-09-23, when the record gained vitals and
        // a fingerprint (W3). Version 1 stays decodable at its old length.
        assert_eq!(VERSION, 2);
        assert_eq!(ENCODED_LEN, 28);
        assert_eq!(V1_LEN, 18);
    }

    /// A device flashed before vitals existed writes 18 bytes at version 1;
    /// a home computer built after must read it, with the new fields zero.
    #[test]
    fn a_version_one_record_still_decodes_with_zero_vitals() {
        let mut v1 = [0u8; V1_LEN];
        v1[0] = 1;
        v1[1] = Occupancy::Stationary.tag();
        v1[5..7].copy_from_slice(&240u16.to_be_bytes());
        v1[7] = 31;
        v1[10..18].copy_from_slice(&99u64.to_be_bytes());
        let p = Presence::decode(&v1).expect("version 1 decodes");
        assert_eq!(p.state, Occupancy::Stationary);
        assert_eq!(p.stationary_cm, 240);
        assert_eq!(p.stationary_energy, 31);
        assert_eq!(p.at, Micros(99));
        assert_eq!(
            (
                p.breathing_bpm_x10,
                p.breathing_confidence,
                p.heart_bpm_x10,
                p.heart_confidence,
                p.fingerprint
            ),
            (0, 0, 0, 0, 0)
        );
        // and a version 1 record that is short for version 1 is refused
        assert_eq!(
            Presence::decode(&v1[..V1_LEN - 1]),
            Err(Error::InvalidFormat)
        );
        // a version nobody knows is refused, however long
        let mut v9 = [0u8; ENCODED_LEN];
        v9[0] = 9;
        assert_eq!(Presence::decode(&v9), Err(Error::InvalidFormat));
    }

    /// The wire carries a rate only from an accepted estimate. A flagged one
    /// -- a heartbeat at seven percent -- contributes its confidence and a
    /// rate of zero, so a consumer reading the rate alone cannot be misled.
    #[test]
    fn a_flagged_estimate_puts_its_confidence_and_no_rate_on_the_wire() {
        use crate::radar::vitals::Vitals;
        let accepted = Vitals {
            bpm_x10: 150,
            confidence: 633,
            lag_x16: 640,
            accepted: true,
            at: Micros(1),
        };
        let flagged = Vitals {
            bpm_x10: 784,
            confidence: 74,
            lag_x16: 306,
            accepted: false,
            at: Micros(1),
        };
        let p = Presence::default().with_vitals(Some(&accepted), Some(&flagged));
        assert_eq!((p.breathing_bpm_x10, p.breathing_confidence), (150, 633));
        assert_eq!(
            (p.heart_bpm_x10, p.heart_confidence),
            (0, 74),
            "flagged: confidence, no rate"
        );
        let none = Presence::default().with_vitals(None, None);
        assert_eq!(
            (
                none.breathing_bpm_x10,
                none.breathing_confidence,
                none.heart_confidence
            ),
            (0, 0, 0)
        );
        // and it all survives the wire
        let mut buf = [0u8; ENCODED_LEN];
        p.with_fingerprint(210).encode(&mut buf).unwrap();
        let back = Presence::decode(&buf).unwrap();
        assert_eq!(
            (
                back.breathing_bpm_x10,
                back.heart_bpm_x10,
                back.heart_confidence,
                back.fingerprint
            ),
            (150, 0, 74, 210)
        );
    }

    #[test]
    fn the_lengths_are_what_the_layout_says() {
        assert_eq!(VERSION, 2);
        assert_eq!(V1_LEN, 18);
        assert_eq!(ENCODED_LEN, V1_LEN + 5 * 2);
    }
}

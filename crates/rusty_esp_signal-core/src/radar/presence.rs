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
pub const VERSION: u8 = 1;

/// Bytes of one encoded [`Presence`].
pub const ENCODED_LEN: usize = 18;

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
        Ok(ENCODED_LEN)
    }

    /// Read a record written by [`encode`](Self::encode).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] when the bytes are short, the version is not
    /// [`VERSION`], or the state tag is one this version does not know.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let b = bytes.get(..ENCODED_LEN).ok_or(Error::InvalidFormat)?;
        if b[0] != VERSION {
            return Err(Error::InvalidFormat);
        }
        let state = Occupancy::from_tag(b[1]).ok_or(Error::InvalidFormat)?;
        let u16_at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        let mut at = [0u8; 8];
        at.copy_from_slice(&b[10..18]);
        Ok(Presence {
            state,
            moving_cm: u16_at(2),
            moving_energy: b[4],
            stationary_cm: u16_at(5),
            stationary_energy: b[7],
            detection_cm: u16_at(8),
            at: Micros(u64::from_be_bytes(at)),
        })
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
        assert_eq!(ENCODED_LEN, 18);
        assert_eq!(VERSION, 1);
    }
}

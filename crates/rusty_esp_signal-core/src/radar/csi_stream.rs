//! One CSI frame on the wire: the RuView plan's W5 stream
//! (`espino/docs/plans/ruview-function.md`).
//!
//! Raw I/Q, not features. Features are what the on-device detector wants,
//! but a subscriber wants everything the radio delivered: the phase half
//! ([`super::phase`]) needs I/Q, a recording in the ledger's own fixture
//! format is I/Q, and a model trained later will want what was measured,
//! not what one release of this crate summarised. At 64 entries a sample is
//! 141 bytes; at 50 Hz that is 7 KB/s per node, which ESP-NOW, the bridge
//! and the LAN all carry without noticing.
//!
//! # Wire form (version 1)
//!
//! ```text
//! version (1)   = 1
//! layout (1)    a tag naming the buffer's layout: 1 LLTF 20 MHz, 2 HT-LTF
//!               20 MHz, 3 C6 HT20 natural, 4 dense 64; 0 unknown
//! rssi (1)      i8, dBm
//! channel (1)   the primary channel
//! at (8)        device clock, microseconds, little-endian
//! len (1)       bytes of I/Q that follow, at most 128
//! iq (len)      i8, interleaved as the chip delivered them
//! ```
//!
//! A receiver that knows the tag computes the same [`Features`] the device
//! did ([`Sample::features`]); one that does not still has the bytes.

use rusty_esp_core::Micros;
use rusty_esp_core::error::{Error, Result};

use super::csi::{CsiFrame, Features, Layout, MAX_SUBCARRIERS};

/// The version byte every encoding starts with.
pub const VERSION: u8 = 1;
/// Bytes before the I/Q: version, layout, rssi, channel, `at`, `len`.
pub const HEADER_LEN: usize = 13;
/// Most I/Q bytes one sample carries: 64 entries, two bytes each.
pub const MAX_IQ: usize = 2 * MAX_SUBCARRIERS;
/// Bytes of the largest encoding.
pub const MAX_ENCODED_LEN: usize = HEADER_LEN + MAX_IQ;

/// A layout this crate does not name; the bytes still ride.
pub const TAG_UNKNOWN: u8 = 0;
/// [`Layout::LLTF_20MHZ`].
pub const TAG_LLTF_20MHZ: u8 = 1;
/// [`Layout::HTLTF_20MHZ`].
pub const TAG_HTLTF_20MHZ: u8 = 2;
/// [`Layout::C6_HT20_NATURAL`].
pub const TAG_C6_HT20_NATURAL: u8 = 3;
/// [`Layout::DENSE_64`].
pub const TAG_DENSE_64: u8 = 4;

const TAGS: [(u8, &Layout); 4] = [
    (TAG_LLTF_20MHZ, &Layout::LLTF_20MHZ),
    (TAG_HTLTF_20MHZ, &Layout::HTLTF_20MHZ),
    (TAG_C6_HT20_NATURAL, &Layout::C6_HT20_NATURAL),
    (TAG_DENSE_64, &Layout::DENSE_64),
];

/// The layout a tag names, or `None` for one this crate does not know.
#[must_use]
pub fn layout_of(tag: u8) -> Option<&'static Layout> {
    TAGS.iter().find(|(t, _)| *t == tag).map(|(_, l)| *l)
}

/// The tag for a layout this crate names, or `None`.
#[must_use]
pub fn tag_of(layout: &Layout) -> Option<u8> {
    TAGS.iter().find(|(_, l)| *l == layout).map(|(t, _)| *t)
}

/// One frame as the radio delivered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// The device clock when the radio delivered it.
    pub at: Micros,
    /// Received signal strength, dBm.
    pub rssi: i8,
    /// The primary channel.
    pub channel: u8,
    /// The buffer's layout, as a tag ([`layout_of`]).
    pub layout: u8,
    /// Bytes of `iq` that are the frame; at most [`MAX_IQ`].
    pub len: u8,
    /// Interleaved I/Q, as the chip delivered them.
    pub iq: [i8; MAX_IQ],
}

impl Sample {
    /// A sample from the bytes the chip delivered.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidGeometry`] when `iq` is longer than [`MAX_IQ`].
    pub fn from_iq(at: Micros, rssi: i8, channel: u8, layout: u8, iq: &[i8]) -> Result<Self> {
        if iq.len() > MAX_IQ {
            return Err(Error::InvalidGeometry);
        }
        let mut buf = [0i8; MAX_IQ];
        buf[..iq.len()].copy_from_slice(iq);
        Ok(Sample {
            at,
            rssi,
            channel,
            layout,
            len: u8::try_from(iq.len()).map_err(|_| Error::InvalidGeometry)?,
            iq: buf,
        })
    }

    /// The frame's I/Q bytes.
    #[must_use]
    pub fn iq(&self) -> &[i8] {
        &self.iq[..usize::from(self.len).min(MAX_IQ)]
    }

    /// Bytes [`Sample::encode`] writes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN + self.iq().len()
    }

    /// Write the sample into `out`, returning the bytes written.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] when `out` is shorter than
    /// [`Sample::encoded_len`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let iq = self.iq();
        let needed = HEADER_LEN + iq.len();
        let out = out
            .get_mut(..needed)
            .ok_or(Error::BufferTooSmall { needed })?;
        out[0] = VERSION;
        out[1] = self.layout;
        out[2] = self.rssi.to_le_bytes()[0];
        out[3] = self.channel;
        out[4..12].copy_from_slice(&self.at.0.to_le_bytes());
        out[12] = u8::try_from(iq.len()).map_err(|_| Error::InvalidGeometry)?;
        for (o, s) in out[HEADER_LEN..].iter_mut().zip(iq) {
            *o = s.to_le_bytes()[0];
        }
        Ok(needed)
    }

    /// Read a sample. The whole of `bytes` must be the sample: a version
    /// nobody knows, a header that does not fit, a `len` over [`MAX_IQ`] or
    /// one the bytes do not match is [`Error::InvalidFormat`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`], as above.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let header = bytes.get(..HEADER_LEN).ok_or(Error::InvalidFormat)?;
        if header[0] != VERSION {
            return Err(Error::InvalidFormat);
        }
        let n = usize::from(header[12]);
        if n > MAX_IQ || bytes.len() != HEADER_LEN + n {
            return Err(Error::InvalidFormat);
        }
        let mut at = [0u8; 8];
        at.copy_from_slice(&header[4..12]);
        let mut iq = [0i8; MAX_IQ];
        for (d, &b) in iq.iter_mut().zip(&bytes[HEADER_LEN..]) {
            *d = i8::from_le_bytes([b]);
        }
        Ok(Sample {
            at: Micros(u64::from_le_bytes(at)),
            rssi: i8::from_le_bytes([header[2]]),
            channel: header[3],
            layout: header[1],
            len: header[12],
            iq,
        })
    }

    /// The features the device computed, from the layout the tag names.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for a tag this crate does not know;
    /// [`Error::InvalidGeometry`] when the bytes cannot fill that layout.
    pub fn features(&self) -> Result<Features> {
        let layout = layout_of(self.layout).ok_or(Error::Unsupported)?;
        CsiFrame {
            timestamp: self.at,
            rssi: self.rssi,
            channel: self.channel,
            iq: self.iq(),
        }
        .features(layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iq128() -> [i8; MAX_IQ] {
        let mut iq = [0i8; MAX_IQ];
        for (k, v) in iq.iter_mut().enumerate() {
            *v = i8::try_from((k % 41) as i32 - 20).unwrap();
        }
        iq
    }

    fn sample() -> Sample {
        Sample::from_iq(Micros(1_234_567_890), -47, 11, TAG_LLTF_20MHZ, &iq128()).unwrap()
    }

    #[test]
    fn a_sample_round_trips_every_field() {
        let s = sample();
        let mut wire = [0u8; MAX_ENCODED_LEN];
        let n = s.encode(&mut wire).unwrap();
        assert_eq!(n, MAX_ENCODED_LEN);
        assert_eq!(n, s.encoded_len());
        assert_eq!(wire[0], VERSION);
        let back = Sample::decode(&wire[..n]).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.iq(), &iq128()[..]);
    }

    #[test]
    fn a_short_sample_carries_its_own_length() {
        let s = Sample::from_iq(Micros(7), -60, 1, TAG_UNKNOWN, &[1, -1, 2, -2]).unwrap();
        let mut wire = [0u8; MAX_ENCODED_LEN];
        let n = s.encode(&mut wire).unwrap();
        assert_eq!(n, HEADER_LEN + 4);
        let back = Sample::decode(&wire[..n]).unwrap();
        assert_eq!(back.iq(), &[1, -1, 2, -2]);
        assert_eq!(back.len, 4);
        assert!(back.features().is_err(), "an unknown tag computes nothing");
    }

    #[test]
    fn the_receiver_computes_the_features_the_device_did() {
        let s = sample();
        let device = CsiFrame {
            timestamp: s.at,
            rssi: s.rssi,
            channel: s.channel,
            iq: s.iq(),
        }
        .features(&Layout::LLTF_20MHZ)
        .unwrap();
        let mut wire = [0u8; MAX_ENCODED_LEN];
        let n = s.encode(&mut wire).unwrap();
        let receiver = Sample::decode(&wire[..n]).unwrap().features().unwrap();
        assert_eq!(receiver, device);
        assert_eq!(usize::from(receiver.count), Layout::LLTF_20MHZ.count());
    }

    #[test]
    fn what_is_not_a_sample_is_refused_not_guessed() {
        let s = sample();
        let mut wire = [0u8; MAX_ENCODED_LEN];
        let n = s.encode(&mut wire).unwrap();
        assert!(
            Sample::decode(&wire[..HEADER_LEN - 1]).is_err(),
            "no header"
        );
        assert!(
            Sample::decode(&wire[..n - 1]).is_err(),
            "a byte short of its len"
        );
        let mut longer = [0u8; MAX_ENCODED_LEN + 1];
        longer[..n].copy_from_slice(&wire[..n]);
        assert!(Sample::decode(&longer).is_err(), "a byte over its len");
        let mut version = wire;
        version[0] = 2;
        assert!(
            Sample::decode(&version[..n]).is_err(),
            "a version nobody knows"
        );
        let mut len = wire;
        len[12] = 129;
        assert!(Sample::decode(&len[..n]).is_err(), "a len over MAX_IQ");
        assert!(Sample::decode(&[]).is_err());
        let mut small = [0u8; HEADER_LEN + 10];
        assert!(matches!(
            s.encode(&mut small),
            Err(Error::BufferTooSmall { needed }) if needed == MAX_ENCODED_LEN
        ));
        assert!(Sample::from_iq(Micros(0), 0, 0, 0, &[0i8; MAX_IQ + 1]).is_err());
    }

    #[test]
    fn every_named_layout_has_a_tag_and_back() {
        for (tag, layout) in TAGS {
            assert_eq!(tag_of(layout), Some(tag));
            assert_eq!(layout_of(tag), Some(layout));
        }
        assert_eq!(layout_of(TAG_UNKNOWN), None);
        assert_eq!(layout_of(200), None);
    }
}

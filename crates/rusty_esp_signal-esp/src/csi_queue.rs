//! The seam between a CSI callback and the sketch that reads it: the frame
//! a callback makes of the chip's buffer, and the ring it parks it in.
//!
//! Compiled on every track and on the host, because the two things a
//! callback must get right -- what to make of the buffer, and what happens
//! when frames arrive faster than the sketch drains them -- are exactly the
//! two things a callback cannot be tested for on a board. The ESP-IDF
//! backend ([`crate::idf::csi`]) is the FFI wrapper around these; the
//! esp-radio one may use them too.
//!
//! # Why a ring, and why sixteen
//!
//! The first backend parked ONE frame. A sketch that shares its loop with a
//! camera drains it every pass, and a pass is a frame grab -- twenty to
//! forty milliseconds -- while a steady transmitter delivers channel state
//! every twenty. Half the frames were overwritten before the sketch saw
//! them, and the estimators downstream decimate by count, so the rate they
//! were configured for was wrong by the same half. A ring of sixteen is
//! 320 ms at 50 Hz, longer than any pass of a camera loop; a sketch later
//! than that sees the latest sixteen and the count of the ones it missed,
//! never a stalled radio, never a silent gap.

use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::radar::csi::{CsiFrame, Features, Layout};

/// One reading the sketch drains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// The device clock when the radio delivered it.
    pub at: Micros,
    /// Received signal strength, dBm.
    pub rssi: i8,
    /// The primary channel.
    pub channel: u8,
    /// Amplitude features for the configured layout, computed where the raw
    /// buffer lives because it does not outlive the callback.
    pub features: Features,
}

/// Why a buffer produced no frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Short {
    /// Fewer bytes than the layout's entries need (`2 × entries`).
    Buffer,
    /// The layout's valid entries were not all in the buffer.
    Layout,
}

/// The chip's buffer into a [`Frame`], for `layout`.
///
/// `iq` is the callback's own copy of the buffer (interleaved I/Q, `i8`),
/// and it is modified: when the chip flags the first word invalid, entries
/// 0 and 1 are blanked rather than read, because the legacy layout keeps
/// entry 1. `rssi` and `channel` ride through; `at` is the caller's clock.
///
/// # Errors
///
/// [`Short`] when the buffer cannot fill the layout; the caller counts it.
pub fn ingest(
    iq: &mut [i8],
    first_word_invalid: bool,
    layout: &Layout,
    rssi: i8,
    channel: u8,
    at: Micros,
) -> Result<Frame, Short> {
    if iq.len() < 2 * layout.entries {
        return Err(Short::Buffer);
    }
    if first_word_invalid {
        iq[..4].fill(0);
    }
    let raw = CsiFrame {
        timestamp: at,
        rssi,
        channel,
        iq,
    };
    let features = raw.features(layout).map_err(|_| Short::Layout)?;
    Ok(Frame {
        at,
        rssi,
        channel,
        features,
    })
}

/// A fixed ring of frames: the callback pushes, the sketch pops oldest
/// first, and when the sketch is late the oldest frame goes, counted.
#[derive(Debug, Clone)]
pub struct Ring<const N: usize> {
    frames: [Option<Frame>; N],
    /// Index of the oldest frame.
    head: usize,
    len: usize,
    dropped: u32,
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Ring<N> {
    /// Empty.
    #[must_use]
    pub const fn new() -> Self {
        Ring {
            frames: [None; N],
            head: 0,
            len: 0,
            dropped: 0,
        }
    }

    /// Park a frame. When the ring is full the oldest is overwritten and
    /// counted; returns whether that happened.
    pub fn push(&mut self, frame: Frame) -> bool {
        if N == 0 {
            self.dropped = self.dropped.wrapping_add(1);
            return true;
        }
        let overwrote = self.len == N;
        let tail = (self.head + self.len) % N;
        self.frames[tail] = Some(frame);
        if overwrote {
            self.head = (self.head + 1) % N;
            self.dropped = self.dropped.wrapping_add(1);
        } else {
            self.len += 1;
        }
        overwrote
    }

    /// The oldest frame, if any.
    pub fn pop(&mut self) -> Option<Frame> {
        if self.len == 0 {
            return None;
        }
        let frame = self.frames[self.head].take();
        self.head = (self.head + 1) % N;
        self.len -= 1;
        frame
    }

    /// Frames waiting.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing waits.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Frames overwritten before they were popped, since [`Ring::clear`].
    #[must_use]
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Forget every frame and the count.
    pub fn clear(&mut self) {
        self.frames = [None; N];
        self.head = 0;
        self.len = 0;
        self.dropped = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A buffer where every entry is I = `i`, Q = 0: amplitude `4·|i|`.
    fn buffer(entries: usize, i: i8) -> Vec<i8> {
        let mut v = vec![0i8; 2 * entries];
        for e in 0..entries {
            v[2 * e] = i;
        }
        v
    }

    fn frame(at: u64) -> Frame {
        let mut iq = buffer(Layout::LLTF_20MHZ.entries, 10);
        ingest(&mut iq, false, &Layout::LLTF_20MHZ, -50, 6, Micros(at)).unwrap()
    }

    #[test]
    fn a_full_buffer_is_a_frame_with_the_layouts_subcarriers() {
        let layout = &Layout::LLTF_20MHZ;
        let mut iq = buffer(layout.entries, 10);
        let f = ingest(&mut iq, false, layout, -47, 11, Micros(5)).unwrap();
        assert_eq!((f.rssi, f.channel, f.at), (-47, 11, Micros(5)));
        assert_eq!(usize::from(f.features.count), layout.count());
        assert!(
            f.features.amplitudes().iter().all(|&a| a == 40),
            "{:?}",
            f.features.amplitudes()
        );
    }

    #[test]
    fn a_short_buffer_is_counted_not_read() {
        let layout = &Layout::LLTF_20MHZ;
        let mut iq = buffer(layout.entries - 1, 10);
        assert_eq!(
            ingest(&mut iq, false, layout, 0, 0, Micros(0)).unwrap_err(),
            Short::Buffer
        );
        let mut two = [10i8, 0];
        assert_eq!(
            ingest(&mut two, false, layout, 0, 0, Micros(0)).unwrap_err(),
            Short::Buffer
        );
    }

    #[test]
    fn the_first_word_is_blanked_when_the_chip_says_so() {
        let layout = &Layout::LLTF_20MHZ;
        // The legacy layout keeps entry 1, so the flag must reach it.
        assert_eq!(layout.indices().next(), Some(1));
        let mut iq = buffer(layout.entries, 10);
        let flagged = ingest(&mut iq, true, layout, 0, 0, Micros(0)).unwrap();
        assert_eq!(iq[..4], [0, 0, 0, 0]);
        assert_eq!(flagged.features.amplitudes()[0], 0, "entry 1 blanked");
        assert!(flagged.features.amplitudes()[1..].iter().all(|&a| a == 40));
        let mut iq = buffer(layout.entries, 10);
        let clean = ingest(&mut iq, false, layout, 0, 0, Micros(0)).unwrap();
        assert_eq!(
            clean.features.amplitudes()[0],
            40,
            "and only when it says so"
        );
    }

    #[test]
    fn the_ring_hands_frames_back_oldest_first() {
        let mut ring: Ring<4> = Ring::new();
        assert!(ring.is_empty());
        assert_eq!(ring.pop(), None);
        for at in 1..=3 {
            assert!(!ring.push(frame(at)));
        }
        assert_eq!(ring.len(), 3);
        assert_eq!(ring.pop().map(|f| f.at), Some(Micros(1)));
        assert_eq!(ring.pop().map(|f| f.at), Some(Micros(2)));
        assert!(!ring.push(frame(4)));
        assert_eq!(ring.pop().map(|f| f.at), Some(Micros(3)));
        assert_eq!(ring.pop().map(|f| f.at), Some(Micros(4)));
        assert_eq!(ring.pop(), None);
        assert_eq!(ring.dropped(), 0);
    }

    #[test]
    fn a_late_sketch_sees_the_latest_n_and_the_count_it_missed() {
        let mut ring: Ring<4> = Ring::new();
        for at in 1..=10 {
            let overwrote = ring.push(frame(at));
            assert_eq!(overwrote, at > 4, "at {at}");
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(ring.dropped(), 6);
        let seen: Vec<u64> = core::iter::from_fn(|| ring.pop()).map(|f| f.at.0).collect();
        assert_eq!(seen, [7, 8, 9, 10], "the latest four, in order");
        assert!(ring.is_empty());
        ring.clear();
        assert_eq!(ring.dropped(), 0);
    }

    #[test]
    fn a_zero_capacity_ring_drops_everything_and_says_so() {
        let mut ring: Ring<0> = Ring::new();
        assert!(ring.push(frame(1)));
        assert_eq!(ring.pop(), None);
        assert_eq!(ring.dropped(), 1);
    }
}

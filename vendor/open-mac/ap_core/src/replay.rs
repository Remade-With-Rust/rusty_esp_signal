//! CCMP's replay check on a station's frames (IEEE 802.11-2020 12.5.3.4.4):
//! the packet number must climb -- **per traffic identifier** for QoS data,
//! since a transmitter numbers every frame from one counter but sends each
//! TID from its own queue, so frames of two TIDs can arrive out of order.
//! A single counter per station (as the access point had) dropped such
//! frames as replays: a P3 run with two phones counted 148 (2026-10-10),
//! where C6s and the laptop, on TID 0 alone, had none.
//!
//! A frame at or below its counter is told apart by the Retry bit: a
//! retransmission the station sent again because our ACK was lost
//! (dropped, as 802.11's duplicate detection would) or a true replay.

/// The verdict on one protected frame's packet number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Newer than any before on its TID: accept (the counter moves).
    Fresh,
    /// Not newer, and marked as a retransmission: drop.
    Duplicate,
    /// Not newer and not a retransmission: drop and count.
    Replay,
}

/// One station's receive counters: one per TID (0-15) and one for non-QoS
/// data frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    tid: [u64; 16],
    non_qos: u64,
    seen: u32,
}

impl Window {
    /// Fresh counters: a new pairwise key starts every counter over.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tid: [0; 16],
            non_qos: 0,
            seen: 0,
        }
    }

    /// Check packet number `pn` of a frame on `tid` (`None`: not QoS data),
    /// `retry` its Retry bit.
    pub fn check(&mut self, tid: Option<u8>, pn: u64, retry: bool) -> Verdict {
        let (counter, bit) = match tid {
            Some(t) => {
                let t = usize::from(t & 0x0f);
                (&mut self.tid[t], 1u32 << t)
            }
            None => (&mut self.non_qos, 1 << 16),
        };
        // the first frame on a counter is fresh even at packet number 0
        let first = self.seen & bit == 0;
        if first || pn > *counter {
            *counter = pn;
            self.seen |= bit;
            Verdict::Fresh
        } else if retry {
            Verdict::Duplicate
        } else {
            Verdict::Replay
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_tids_out_of_order_are_both_fresh() {
        // the phones' run: PN 10 on TID 6 (voice) overtakes PN 9 on TID 0
        let mut w = Window::new();
        assert_eq!(w.check(Some(0), 8, false), Verdict::Fresh);
        assert_eq!(w.check(Some(6), 10, false), Verdict::Fresh);
        assert_eq!(w.check(Some(0), 9, false), Verdict::Fresh);
    }

    #[test]
    fn on_one_tid_the_number_must_climb() {
        let mut w = Window::new();
        assert_eq!(w.check(Some(0), 5, false), Verdict::Fresh);
        assert_eq!(w.check(Some(0), 5, false), Verdict::Replay);
        assert_eq!(w.check(Some(0), 4, false), Verdict::Replay);
        assert_eq!(w.check(Some(0), 6, false), Verdict::Fresh);
    }

    #[test]
    fn a_retransmission_is_a_duplicate_not_a_replay() {
        let mut w = Window::new();
        assert_eq!(w.check(Some(3), 7, false), Verdict::Fresh);
        assert_eq!(w.check(Some(3), 7, true), Verdict::Duplicate);
    }

    #[test]
    fn non_qos_frames_have_their_own_counter() {
        let mut w = Window::new();
        assert_eq!(w.check(Some(0), 20, false), Verdict::Fresh);
        assert_eq!(w.check(None, 3, false), Verdict::Fresh);
        assert_eq!(w.check(None, 3, false), Verdict::Replay);
    }

    #[test]
    fn the_first_frame_on_a_counter_is_fresh_at_zero() {
        let mut w = Window::new();
        assert_eq!(w.check(Some(0), 0, false), Verdict::Fresh);
        assert_eq!(w.check(Some(0), 0, false), Verdict::Replay);
        // a new key starts over
        w = Window::new();
        assert_eq!(w.check(Some(0), 0, false), Verdict::Fresh);
    }
}

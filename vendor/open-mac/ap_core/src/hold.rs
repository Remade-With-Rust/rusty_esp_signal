//! Frames held for stations that doze (802.11-2020 11.2.3.5, the access
//! point's side of power save). A dozing station's frames wait here until it
//! asks (PS-Poll) or wakes (a frame with the Power Management bit clear);
//! group-addressed frames wait while any station dozes, until the DTIM
//! beacon has named them. The frames are kept as the network stack hands
//! them (Ethernet: destination, source, EtherType, payload), the form the
//! runner's transmit takes, so nothing is laid out twice. The pool is one
//! fixed array: no allocation, oldest first per station, a full pool refuses
//! and the caller counts the drop. Which station dozes and when the DTIM
//! falls is the caller's; this is the bookkeeping only.

use crate::Address;

/// The frames the pool holds at once, across all stations.
pub const HELD_FRAMES: usize = 8;
/// The longest frame held: an Ethernet frame of 1500 bytes of payload.
pub const HELD_FRAME_BYTES: usize = 1514;

/// The pool is full: the frame was not held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

#[derive(Clone, Copy)]
struct Slot {
    /// The order the frame arrived in; 0 is an empty slot.
    sequence: u32,
    group: bool,
    len: u16,
    bytes: [u8; HELD_FRAME_BYTES],
}

impl Slot {
    const EMPTY: Self = Self {
        sequence: 0,
        group: false,
        len: 0,
        bytes: [0; HELD_FRAME_BYTES],
    };
    fn destination(&self) -> Address {
        self.bytes[..6].try_into().unwrap_or([0; 6])
    }
}

/// The frames held, by station and for the group.
pub struct Held {
    slots: [Slot; HELD_FRAMES],
    next_sequence: u32,
}

impl Default for Held {
    fn default() -> Self {
        Self::new()
    }
}

impl Held {
    /// Nothing held.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [Slot::EMPTY; HELD_FRAMES],
            next_sequence: 1,
        }
    }

    /// Hold an Ethernet frame for its destination: `group` for a
    /// group-addressed one. A frame too long or a full pool is refused.
    pub fn push(&mut self, frame: &[u8], group: bool) -> Result<(), Full> {
        if frame.len() < 14 || frame.len() > HELD_FRAME_BYTES {
            return Err(Full);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.sequence == 0)
            .ok_or(Full)?;
        slot.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);
        slot.group = group;
        slot.len = frame.len() as u16;
        slot.bytes[..frame.len()].copy_from_slice(frame);
        Ok(())
    }

    fn oldest(&self, pick: impl Fn(&Slot) -> bool) -> Option<usize> {
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.sequence != 0 && pick(s))
            .min_by_key(|(_, s)| s.sequence)
            .map(|(i, _)| i)
    }

    /// The oldest frame held for `station`, taken out; `more` whether any
    /// remain for it (the More Data bit).
    pub fn pop(&mut self, station: &Address) -> Option<(Taken<'_>, bool)> {
        let i = self.oldest(|s| !s.group && s.destination() == *station)?;
        let more = self.count(station) > 1;
        Some((self.take(i), more))
    }

    /// The oldest group frame held, taken out; `more` whether any remain.
    pub fn pop_group(&mut self) -> Option<(Taken<'_>, bool)> {
        let i = self.oldest(|s| s.group)?;
        let more = self.group_count() > 1;
        Some((self.take(i), more))
    }

    fn take(&mut self, i: usize) -> Taken<'_> {
        let slot = &mut self.slots[i];
        slot.sequence = 0;
        let len = usize::from(slot.len);
        Taken {
            frame: &slot.bytes[..len],
        }
    }

    /// How many frames wait for `station` (the TIM's count for it).
    #[must_use]
    pub fn count(&self, station: &Address) -> u16 {
        self.slots
            .iter()
            .filter(|s| s.sequence != 0 && !s.group && s.destination() == *station)
            .count() as u16
    }

    /// How many group frames wait (the TIM's group-buffered bit).
    #[must_use]
    pub fn group_count(&self) -> u16 {
        self.slots
            .iter()
            .filter(|s| s.sequence != 0 && s.group)
            .count() as u16
    }

    /// Frames held for a station that left: dropped; how many.
    pub fn clear(&mut self, station: &Address) -> u16 {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if s.sequence != 0 && !s.group && s.destination() == *station {
                s.sequence = 0;
                n += 1;
            }
        }
        n
    }

    /// Slots free.
    #[must_use]
    pub fn free(&self) -> usize {
        self.slots.iter().filter(|s| s.sequence == 0).count()
    }
}

/// A frame taken out of the pool, borrowed until the next call.
pub struct Taken<'a> {
    /// The Ethernet frame as it was held.
    pub frame: &'a [u8],
}

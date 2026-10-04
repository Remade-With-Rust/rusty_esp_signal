//! The stations the access point serves, and the decisions on their
//! authentication and association requests. Four at most, as the family's
//! hosted cells serve today.
//!
//! Beyond joining (E3, a robust access point): when each station was last
//! heard, so one that went away is dropped rather than holding a slot
//! (`inactive`); whether it dozes (the Power Management bit of its frames)
//! and how many frames wait for it, from which the beacon's TIM is built
//! (`tim`; the frames themselves are the driver's to hold, P5). A station
//! roaming in re-associates: it keeps its AID and runs the 4-way handshake
//! again.

use crate::{Address, rsn, status};

/// How many stations the access point serves at once.
pub const MAX_STATIONS: usize = 4;
/// The longest RSN element kept from an association request (its two
/// header octets included): message 2 must carry the same bytes.
pub const MAX_RSN_ELEMENT: usize = 64;

/// Where a station is in joining.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Open-system authentication done.
    Authenticated,
    /// Associated, with an AID; on a WPA2 network the 4-way handshake
    /// follows.
    Associated,
    /// Keys installed (WPA2) or associated (open): data may flow.
    Connected,
}

/// A station.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Station {
    /// Its address.
    pub address: Address,
    /// Its association ID, 1 to [`MAX_STATIONS`] (0 until associated).
    pub aid: u16,
    /// Where it is.
    pub state: State,
    /// When it was last heard, in the caller's clock (microseconds).
    pub last_heard_us: u64,
    /// It dozes: its last frame had the Power Management bit set.
    pub power_save: bool,
    /// Frames the access point holds for it while it dozes.
    pub queued: u16,
    rsne: [u8; MAX_RSN_ELEMENT],
    rsne_len: usize,
}

impl Station {
    /// The RSN element its association request carried, header included.
    #[must_use]
    pub fn rsn_element(&self) -> &[u8] {
        &self.rsne[..self.rsne_len]
    }
}

/// The station table.
#[derive(Clone, Debug, Default)]
pub struct Stations {
    slots: [Option<Station>; MAX_STATIONS],
}

impl Stations {
    /// No station.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_STATIONS],
        }
    }

    /// The station with this address.
    #[must_use]
    pub fn get(&self, address: &Address) -> Option<&Station> {
        self.slots.iter().flatten().find(|s| s.address == *address)
    }

    /// The stations held.
    pub fn iter(&self) -> impl Iterator<Item = &Station> {
        self.slots.iter().flatten()
    }

    fn get_mut(&mut self, address: &Address) -> Option<&mut Station> {
        self.slots
            .iter_mut()
            .flatten()
            .find(|s| s.address == *address)
    }

    /// An authentication request's first frame: the status to answer
    /// with. Open system only. A station already known starts again from
    /// authenticated (its association and keys are gone).
    pub fn authenticate(&mut self, address: Address, algorithm: u16, sequence: u16) -> u16 {
        if algorithm != 0 {
            return status::UNSUPPORTED_AUTH_ALGORITHM;
        }
        if sequence != 1 {
            return status::AUTH_OUT_OF_SEQUENCE;
        }
        let fresh = Station {
            address,
            aid: 0,
            state: State::Authenticated,
            last_heard_us: 0,
            power_save: false,
            queued: 0,
            rsne: [0; MAX_RSN_ELEMENT],
            rsne_len: 0,
        };
        if let Some(station) = self.get_mut(&address) {
            *station = fresh;
            return status::SUCCESS;
        }
        match self.slots.iter_mut().find(|s| s.is_none()) {
            Some(slot) => {
                *slot = Some(fresh);
                status::SUCCESS
            }
            None => status::TOO_MANY_STATIONS,
        }
    }

    /// An association request: its AID or the status to refuse with.
    /// `ssid_matches` is whether it asked for this network; `rsn_element`
    /// the RSN element it carried, header included. A WPA2 network wants
    /// one this access point takes (`rsn::check_station`); an open one
    /// wants none. Only a station already authenticated associates.
    pub fn associate(
        &mut self,
        address: Address,
        ssid_matches: bool,
        rsn_element: Option<&[u8]>,
        protected: bool,
    ) -> Result<u16, u16> {
        let in_use: [u16; MAX_STATIONS] =
            core::array::from_fn(|i| self.slots[i].map_or(0, |s| s.aid));
        let station = self.get_mut(&address).ok_or(status::UNSPECIFIED)?;
        if !ssid_matches {
            return Err(status::UNSPECIFIED);
        }
        match (protected, rsn_element) {
            (true, None) => return Err(status::INVALID_ELEMENT),
            (true, Some(element)) => {
                if element.len() > MAX_RSN_ELEMENT {
                    return Err(status::INVALID_ELEMENT);
                }
                rsn::check_station(element.get(2..).ok_or(status::INVALID_ELEMENT)?)?;
            }
            (false, Some(_)) => return Err(status::INVALID_ELEMENT),
            (false, None) => {}
        }
        // keep its AID across a re-association, else the lowest free
        let aid = if station.aid != 0 {
            station.aid
        } else {
            (1..=MAX_STATIONS as u16)
                .find(|aid| !in_use.contains(aid))
                .ok_or(status::TOO_MANY_STATIONS)?
        };
        station.aid = aid;
        station.state = if protected {
            State::Associated
        } else {
            State::Connected
        };
        let element = rsn_element.unwrap_or(&[]);
        station.rsne[..element.len()].copy_from_slice(element);
        station.rsne_len = element.len();
        Ok(aid)
    }

    /// The 4-way handshake finished: data may flow.
    pub fn connected(&mut self, address: &Address) -> bool {
        match self.get_mut(address) {
            Some(station) if station.state == State::Associated => {
                station.state = State::Connected;
                true
            }
            _ => false,
        }
    }

    /// A frame from `address` at `now_us`, its Power Management bit
    /// `power_save`: it is alive, and dozes or not. False for a station not
    /// held (a class 2 or 3 frame from a stranger: the caller deauthenticates).
    pub fn heard(&mut self, address: &Address, now_us: u64, power_save: bool) -> bool {
        match self.get_mut(address) {
            Some(station) => {
                station.last_heard_us = now_us;
                station.power_save = power_save;
                true
            }
            None => false,
        }
    }

    /// The frames held for a dozing station, as the driver's queue changes.
    pub fn set_queued(&mut self, address: &Address, queued: u16) {
        if let Some(station) = self.get_mut(address) {
            station.queued = queued;
        }
    }

    /// A station not heard for `limit_us`: the next to drop (reason
    /// [`crate::reason::INACTIVITY`]), oldest first. The caller removes it.
    #[must_use]
    pub fn inactive(&self, now_us: u64, limit_us: u64) -> Option<Address> {
        self.iter()
            .filter(|s| now_us.saturating_sub(s.last_heard_us) > limit_us)
            .min_by_key(|s| s.last_heard_us)
            .map(|s| s.address)
    }

    /// The beacon's TIM: frames wait for the associated stations whose AIDs
    /// are set (dozing ones with frames queued); the DTIM fields are the
    /// caller's.
    #[must_use]
    pub fn tim(&self, dtim_count: u8, dtim_period: u8, group_buffered: bool) -> crate::frames::Tim {
        let buffered_aids = self
            .iter()
            .filter(|s| s.aid != 0 && s.aid < 16 && s.queued > 0)
            .fold(0u16, |bits, s| bits | 1 << s.aid);
        crate::frames::Tim {
            dtim_count,
            dtim_period,
            group_buffered,
            buffered_aids,
        }
    }

    /// A station gone (deauthenticated, disassociated, timed out).
    pub fn remove(&mut self, address: &Address) -> Option<Station> {
        let slot = self
            .slots
            .iter_mut()
            .find(|s| s.is_some_and(|s| s.address == *address))?;
        slot.take()
    }
}

//! Elements, read: a bounds-checked walk over the type-length-value
//! elements of a management frame's body, ours rather than `ieee80211`'s so
//! the access point's decisions rest on code the corpus runs directly.

/// The elements of a frame body, in order: `(id, body)` for each one that
/// fits; the walk stops at the first that does not.
#[derive(Clone, Copy, Debug)]
pub struct Elements<'a> {
    rest: &'a [u8],
}

impl<'a> Elements<'a> {
    /// The elements in `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    /// The first element with this ID.
    #[must_use]
    pub fn first(self, id: u8) -> Option<&'a [u8]> {
        let mut all = self;
        all.find(|(i, _)| *i == id).map(|(_, body)| body)
    }

    /// The first element with this ID, its two-byte header included.
    #[must_use]
    pub fn first_whole(self, id: u8) -> Option<&'a [u8]> {
        let mut rest = self.rest;
        while let [i, len, tail @ ..] = rest {
            let len = usize::from(*len);
            let whole = rest.get(..2 + len)?;
            if *i == id {
                return Some(whole);
            }
            rest = tail.get(len..)?;
        }
        None
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = (u8, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        let [id, len, tail @ ..] = self.rest else {
            self.rest = &[];
            return None;
        };
        let len = usize::from(*len);
        let Some(body) = tail.get(..len) else {
            self.rest = &[];
            return None;
        };
        let (id, rest) = (*id, &tail[len..]);
        self.rest = rest;
        Some((id, body))
    }
}

/// Element IDs this access point reads and writes.
pub mod id {
    /// SSID.
    pub const SSID: u8 = 0;
    /// Supported Rates.
    pub const SUPPORTED_RATES: u8 = 1;
    /// DSSS Parameter Set.
    pub const DSSS: u8 = 3;
    /// Traffic Indication Map.
    pub const TIM: u8 = 5;
    /// ERP.
    pub const ERP: u8 = 42;
    /// RSN.
    pub const RSN: u8 = 48;
    /// Extended Supported Rates.
    pub const EXTENDED_RATES: u8 = 50;
}

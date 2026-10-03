//! Message framing (protocol sections 4, 5.0 and 8): `u8 VERSION || u8 kind
//! || body`, the Discover body, and the code table `Error` and Result share.

use rusty_esp_core::error::{Error, Result};

use super::{DEVPUB_LEN, SALT_LEN, VERSION};

/// The longest message, header included (ATT's largest attribute value).
pub const MAX_MESSAGE: usize = 512;

/// Bytes of a message's header.
pub const HEADER_LEN: usize = 2;

/// The message kinds of v1.
pub mod kind {
    /// Discover: the device, public.
    pub const DISCOVER: u8 = 0x00;
    /// Start: the browser's share.
    pub const START: u8 = 0x01;
    /// Reply: the device's share, confirmation and signature.
    pub const REPLY: u8 = 0x02;
    /// Confirm: the browser's confirmation.
    pub const CONFIRM: u8 = 0x03;
    /// Ready: sealed, the phase and the scan list.
    pub const READY: u8 = 0x04;
    /// Settings: sealed, the settings record.
    pub const SETTINGS: u8 = 0x05;
    /// Result: sealed, applied or refused, and the phase.
    pub const RESULT: u8 = 0x06;
    /// Error: plaintext, one code.
    pub const ERROR: u8 = 0x7F;
}

/// Suite 1, the setup code (Discover's bit 0, Start's suite byte).
pub const SUITE_CODE: u8 = 0x01;

/// The code table `Error` and Result share (protocol section 8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ResultCode {
    /// The settings record was applied.
    Applied = 0x00,
    /// A message, or the record, did not decode.
    Malformed = 0x01,
    /// No common version or suite.
    Version = 0x02,
    /// Another session is in flight.
    Busy = 0x03,
    /// Outside the window, or locked out.
    WindowClosed = 0x04,
    /// Too soon after a failure.
    Backoff = 0x05,
    /// The device has no verifier: no code suite.
    NoVerifier = 0x06,
    /// A message out of turn.
    Order = 0x07,
    /// `confirmP` did not verify: a wrong code.
    Confirm = 0x08,
    /// A sealed message did not open.
    Seal = 0x09,
    /// The network's name or passphrase was refused.
    BadNetwork = 0x20,
    /// The device's name was refused.
    BadName = 0x21,
    /// The maker was not a `did:mata`.
    BadMaker = 0x22,
    /// A new verifier was refused.
    BadVerifier = 0x23,
    /// The adoption was refused (another device, a bad signature, another owner).
    BadAdoption = 0x24,
    /// An unknown or repeated tag.
    UnknownTag = 0x25,
    /// The device could not store the record.
    StoreFailed = 0x26,
}

impl ResultCode {
    /// The code in words, for a person: what a browser shows when the
    /// device refuses.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            ResultCode::Applied => "applied",
            ResultCode::Malformed => "the device could not read a message",
            ResultCode::Version => "the device does not speak this version of the setup protocol",
            ResultCode::Busy => "the device is in another setup session",
            ResultCode::WindowClosed => {
                "the device is not taking setup now: press its button or power it off and on                  (after five wrong codes, each power-on allows one more try)"
            }
            ResultCode::Backoff => "too soon after a wrong code: wait a little and try again",
            ResultCode::NoVerifier => "the device has no setup code",
            ResultCode::Order => "a message reached the device out of turn",
            ResultCode::Confirm => "the device refused the code",
            ResultCode::Seal => "a sealed message did not open on the device",
            ResultCode::BadNetwork => "the device refused the network's name or passphrase",
            ResultCode::BadName => "the device refused its name",
            ResultCode::BadMaker => "the device refused the maker: not a did:mata",
            ResultCode::BadVerifier => "the device refused the new setup code",
            ResultCode::BadAdoption => "the device refused the adoption",
            ResultCode::UnknownTag => "the device does not know a setting it was sent",
            ResultCode::StoreFailed => "the device could not store the settings",
        }
    }

    /// The code a byte names, if any.
    #[must_use]
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => ResultCode::Applied,
            0x01 => ResultCode::Malformed,
            0x02 => ResultCode::Version,
            0x03 => ResultCode::Busy,
            0x04 => ResultCode::WindowClosed,
            0x05 => ResultCode::Backoff,
            0x06 => ResultCode::NoVerifier,
            0x07 => ResultCode::Order,
            0x08 => ResultCode::Confirm,
            0x09 => ResultCode::Seal,
            0x20 => ResultCode::BadNetwork,
            0x21 => ResultCode::BadName,
            0x22 => ResultCode::BadMaker,
            0x23 => ResultCode::BadVerifier,
            0x24 => ResultCode::BadAdoption,
            0x25 => ResultCode::UnknownTag,
            0x26 => ResultCode::StoreFailed,
            _ => return None,
        })
    }

    /// Whether the code counts as a failed guess (section 9).
    #[must_use]
    pub fn is_failure(self) -> bool {
        matches!(self, ResultCode::Confirm | ResultCode::Seal)
    }
}

/// Splits a message into its kind and body: `InvalidFormat` when it is
/// shorter than a header or longer than [`MAX_MESSAGE`], `Unsupported` when
/// its version is not [`VERSION`].
pub fn split(message: &[u8]) -> Result<(u8, &[u8])> {
    if message.len() < HEADER_LEN || message.len() > MAX_MESSAGE {
        return Err(Error::InvalidFormat);
    }
    if message[0] != VERSION {
        return Err(Error::Unsupported);
    }
    Ok((message[1], &message[HEADER_LEN..]))
}

/// The header of a message of `kind`.
#[must_use]
pub const fn header(kind: u8) -> [u8; HEADER_LEN] {
    [VERSION, kind]
}

/// Writes an `Error` message with `code` into `out`; returns its length.
pub fn write_error(code: ResultCode, out: &mut [u8]) -> Result<usize> {
    let Some(out) = out.get_mut(..3) else {
        return Err(Error::BufferTooSmall { needed: 3 });
    };
    out.copy_from_slice(&[VERSION, kind::ERROR, code as u8]);
    Ok(3)
}

/// Discover's body (protocol section 5.0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discover {
    /// Bit 0: suite 1 offered. Bit 1: suite 2 (reserved).
    pub suites: u8,
    /// The device's compressed public key: its `did:mata`.
    pub devpub: [u8; DEVPUB_LEN],
    /// The verifier's salt (zeros when suite 1 is not offered).
    pub salt: [u8; SALT_LEN],
    /// The verifier's PBKDF2 iterations (0 when suite 1 is not offered).
    pub iterations: u32,
    /// Seconds the window stays open; `0xFFFF` open until provisioned.
    pub window_s: u16,
    /// Failures left before the lockout.
    pub attempts_left: u8,
}

/// Bytes of a Discover message.
pub const DISCOVER_LEN: usize = HEADER_LEN + 1 + DEVPUB_LEN + SALT_LEN + 4 + 2 + 1;

/// Discover's `window_s` while the device is unprovisioned.
pub const WINDOW_UNTIL_PROVISIONED: u16 = 0xFFFF;

impl Discover {
    /// Writes the Discover message into `out`; returns [`DISCOVER_LEN`].
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let Some(out) = out.get_mut(..DISCOVER_LEN) else {
            return Err(Error::BufferTooSmall {
                needed: DISCOVER_LEN,
            });
        };
        out[..2].copy_from_slice(&header(kind::DISCOVER));
        out[2] = self.suites;
        out[3..36].copy_from_slice(&self.devpub);
        out[36..52].copy_from_slice(&self.salt);
        out[52..56].copy_from_slice(&self.iterations.to_be_bytes());
        out[56..58].copy_from_slice(&self.window_s.to_be_bytes());
        out[58] = self.attempts_left;
        Ok(DISCOVER_LEN)
    }

    /// Reads a Discover message.
    pub fn read(message: &[u8]) -> Result<Self> {
        let (k, body) = split(message)?;
        if k != kind::DISCOVER || body.len() != DISCOVER_LEN - HEADER_LEN {
            return Err(Error::InvalidFormat);
        }
        let mut devpub = [0u8; DEVPUB_LEN];
        devpub.copy_from_slice(&body[1..34]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&body[34..50]);
        Ok(Discover {
            suites: body[0],
            devpub,
            salt,
            iterations: u32::from_be_bytes([body[50], body[51], body[52], body[53]]),
            window_s: u16::from_be_bytes([body[54], body[55]]),
            attempts_left: body[56],
        })
    }

    /// Whether suite 1 (the setup code) is offered.
    #[must_use]
    pub fn offers_code(&self) -> bool {
        self.suites & SUITE_CODE != 0
    }
}

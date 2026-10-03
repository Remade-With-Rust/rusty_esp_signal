//! The browser's session: what the portal's wasm runs against a device
//! (protocol sections 5 and 6, the prover's side).
//!
//! Discover, the code and (when the portal knows it) the device's expected
//! key go in; Start, Confirm and Settings come out; the device's answers are
//! checked at every step. A device's `Error` comes back as
//! [`Failure::Remote`] with its code.

use rusty_esp_core::error::Error;
use rusty_esp_core::hal::Rng;
use zeroize::Zeroize;

use super::message::{header, kind, split, Discover, ResultCode, MAX_MESSAGE, SUITE_CODE};
use super::seal::{Opener, Sealer};
use super::spake::{reply_prehash, verify_reply, Prover, CONFIRM_LEN, SHARE_LEN, SIG_LEN};
use super::{Code as SetupCode, Context, Secrets, DEVPUB_LEN};

/// Why a browser step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The device answered with an `Error`.
    Remote(ResultCode),
    /// The browser refused: a message that did not decode or verify, the
    /// wrong device (`Denied`), a wrong code (`Crypto` at Reply), a step out
    /// of order (`Denied`).
    Local(Error),
}

impl From<Error> for Failure {
    fn from(e: Error) -> Self {
        Failure::Local(e)
    }
}

/// A browser step's result.
pub type Outcome<T> = core::result::Result<T, Failure>;

enum State {
    Started { prover: Prover },
    Confirmed { send: Sealer, recv: Opener },
    Sent { recv: Opener },
    Done,
}

/// The browser's side of one session.
pub struct Browser {
    devpub: [u8; DEVPUB_LEN],
    state: State,
}

/// What Ready carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ready {
    /// The device's phase (`wifi::Phase::as_u8`).
    pub phase: u8,
    /// Bytes of the scan list written to the caller's buffer.
    pub scan_len: usize,
}

impl Browser {
    /// Starts a session from the device's Discover and the code the person
    /// typed, on carrier `label`. `expect`: the device's key when the portal
    /// knows it (read at flash time); any other key is `Local(Denied)`.
    /// Derives the secrets (PBKDF2, the slow step) and writes Start into
    /// `out`.
    pub fn start(
        discover: &[u8],
        code: &SetupCode,
        expect: Option<&[u8; DEVPUB_LEN]>,
        label: &[u8],
        rng: &mut impl Rng,
        out: &mut [u8],
    ) -> Outcome<(Self, usize)> {
        let d = Discover::read(discover)?;
        if let Some(expected) = expect {
            if *expected != d.devpub {
                return Err(Failure::Local(Error::Denied));
            }
        }
        if !d.offers_code() {
            return Err(Failure::Remote(ResultCode::NoVerifier));
        }
        let needed = 3 + SHARE_LEN;
        if out.len() < needed {
            return Err(Failure::Local(Error::BufferTooSmall { needed }));
        }
        let secrets = Secrets::derive(code, &d.salt, d.iterations)?;
        let prover = Prover::start(secrets, Context::new(label, &d.devpub)?, rng)?;
        out[..2].copy_from_slice(&header(kind::START));
        out[2] = SUITE_CODE;
        out[3..needed].copy_from_slice(prover.share_p());
        Ok((
            Browser {
                devpub: d.devpub,
                state: State::Started { prover },
            },
            needed,
        ))
    }

    /// Takes Reply: checks the device's share, its confirmation (a wrong
    /// code is `Local(Crypto)`) and its signature (another device is
    /// `Local(Crypto)`), then writes Confirm into `out`.
    pub fn on_reply(&mut self, message: &[u8], out: &mut [u8]) -> Outcome<usize> {
        let body = expect(message, kind::REPLY)?;
        let State::Started { prover } = core::mem::replace(&mut self.state, State::Done) else {
            return Err(Failure::Local(Error::Denied));
        };
        if body.len() != SHARE_LEN + CONFIRM_LEN + SIG_LEN {
            return Err(Failure::Local(Error::InvalidFormat));
        }
        let needed = 2 + CONFIRM_LEN;
        if out.len() < needed {
            return Err(Failure::Local(Error::BufferTooSmall { needed }));
        }
        let share_v: &[u8; SHARE_LEN] = body[..SHARE_LEN]
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        let confirm_v: &[u8; CONFIRM_LEN] = body[SHARE_LEN..SHARE_LEN + CONFIRM_LEN]
            .try_into()
            .map_err(|_| Error::InvalidFormat)?;
        let sig = &body[SHARE_LEN + CONFIRM_LEN..];
        let prehash = reply_prehash(prover.context(), prover.share_p(), share_v, confirm_v);
        let (confirm_p, established) = prover.finish(share_v, confirm_v)?;
        verify_reply(&self.devpub, &prehash, sig)?;
        let (send, recv) = established.split();
        out[..2].copy_from_slice(&header(kind::CONFIRM));
        out[2..needed].copy_from_slice(&confirm_p);
        self.state = State::Confirmed { send, recv };
        Ok(needed)
    }

    /// Takes Ready: the device's phase, and its scan list into `scan`.
    pub fn on_ready(&mut self, message: &[u8], scan: &mut [u8]) -> Outcome<Ready> {
        let body = expect(message, kind::READY)?;
        let State::Confirmed { recv, .. } = &mut self.state else {
            return Err(Failure::Local(Error::Denied));
        };
        let mut plain = [0u8; MAX_MESSAGE];
        let n = recv.open(&header(kind::READY), body, &mut plain)?;
        if n == 0 {
            return Err(Failure::Local(Error::InvalidFormat));
        }
        let scan_len = n - 1;
        if scan.len() < scan_len {
            plain.zeroize();
            return Err(Failure::Local(Error::BufferTooSmall { needed: scan_len }));
        }
        scan[..scan_len].copy_from_slice(&plain[1..n]);
        let phase = plain[0];
        plain.zeroize();
        Ok(Ready { phase, scan_len })
    }

    /// Seals the settings `record` (see [`super::RecordWriter`]) as Settings
    /// into `out`.
    pub fn send_settings(&mut self, record: &[u8], out: &mut [u8]) -> Outcome<usize> {
        let State::Confirmed { mut send, recv } = core::mem::replace(&mut self.state, State::Done)
        else {
            return Err(Failure::Local(Error::Denied));
        };
        if out.len() < 2 {
            return Err(Failure::Local(Error::BufferTooSmall {
                needed: 2 + record.len() + 16,
            }));
        }
        out[..2].copy_from_slice(&header(kind::SETTINGS));
        let n = send.seal(&header(kind::SETTINGS), record, &mut out[2..])?;
        if 2 + n > MAX_MESSAGE {
            return Err(Failure::Local(Error::InvalidFormat));
        }
        self.state = State::Sent { recv };
        Ok(2 + n)
    }

    /// Takes Result: the device's code (`Applied`, or a refusal) and its
    /// phase. The session is over.
    pub fn on_result(&mut self, message: &[u8]) -> Outcome<(ResultCode, u8)> {
        let body = expect(message, kind::RESULT)?;
        let State::Sent { mut recv } = core::mem::replace(&mut self.state, State::Done) else {
            return Err(Failure::Local(Error::Denied));
        };
        let mut plain = [0u8; 2];
        let n = recv.open(&header(kind::RESULT), body, &mut plain)?;
        if n != 2 {
            return Err(Failure::Local(Error::InvalidFormat));
        }
        let code = ResultCode::from_u8(plain[0]).ok_or(Failure::Local(Error::InvalidFormat))?;
        Ok((code, plain[1]))
    }
}

/// The body of `message` when it is of kind `want`; a device `Error` is
/// `Remote`.
fn expect(message: &[u8], want: u8) -> Outcome<&[u8]> {
    let (k, body) = split(message)?;
    if k == kind::ERROR {
        let code = body
            .first()
            .and_then(|b| ResultCode::from_u8(*b))
            .ok_or(Failure::Local(Error::InvalidFormat))?;
        return Err(Failure::Remote(code));
    }
    if k != want {
        return Err(Failure::Local(Error::InvalidFormat));
    }
    Ok(body)
}

//! The device's session (protocol sections 5, 6 and 9): the state machine
//! a carrier feeds messages to, the window, the backoff and the lockout.
//!
//! Storage is two [`Kv`] stores: `settings`, the owner's settings namespace
//! (`janus`: the network, the name, `setup.v`, `setup.fail`), and
//! `identity`, mID's (where an accepted adoption and its owner pin go). The
//! device's key signs through mID's [`DeviceSigner`]; the session never
//! holds it.

use rusty_esp_core::Micros;
use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::{Kv, Rng};
use rusty_esp_mid_core::adoption::{Adoption, KV_ADOPTION, KV_OWNER_PIN, OwnerPin};
use rusty_esp_mid_core::did::{Did, MAX_DID_LEN};
use rusty_esp_mid_core::setup as mid_setup;
use rusty_esp_mid_core::signer::DeviceSigner;
use zeroize::Zeroize;

use super::message::{
    Discover, MAX_MESSAGE, ResultCode, SUITE_CODE, WINDOW_UNTIL_PROVISIONED, header, kind, split,
    write_error,
};
use super::record::Record;
use super::seal::{Opener, Sealer};
use super::spake::{Response, SHARE_LEN, reply_prehash, respond};
use super::{Context, DEVPUB_LEN, SALT_LEN, Verifier};
use crate::provision::SCAN_MAX_LEN;
use crate::wifi::Credentials;

/// A session's longest pause between messages.
pub const IDLE_TIMEOUT_US: u64 = 60_000_000;
/// How long the window stays open after a power-on reset or the button.
pub const WINDOW_AFTER_RESET_US: u64 = 600_000_000;
/// Consecutive failures that close the window.
pub const MAX_FAILURES: u8 = 5;

/// The keys the session reads and writes.
pub mod key {
    /// The verifier, in `settings` (mID's name for it).
    pub const SETUP_V: &str = rusty_esp_mid_core::setup::KV_SETUP_VERIFIER;
    /// The consecutive failure count, one byte, in `settings` (mID's name).
    pub const FAIL: &str = rusty_esp_mid_core::setup::KV_SETUP_FAILURES;
    /// The network's name, in `settings`.
    pub const SSID: &str = "wifi.ssid";
    /// The network's passphrase, in `settings`.
    pub const PSK: &str = "wifi.psk";
    /// The device's name, in `settings`.
    pub const NAME: &str = "name";
    /// The maker's `did:mata`, in `settings`.
    pub const MAKER: &str = "maker";
    /// `blink_ms`, `u32` little-endian (NVS's primitive form), in `settings`.
    pub const BLINK_MS: &str = "blink_ms";
    /// `fps`, one byte, in `settings`.
    pub const FPS: &str = "fps";
}

/// What brought the device up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reset {
    /// A power-on reset: the window opens, and a locked-out device gets one
    /// more guess.
    PowerOn,
    /// Anything else (software, watchdog, brown-out): the window stays as it
    /// was, closed unless the device is unprovisioned.
    Other,
}

/// What Ready reports: the phase (`wifi::Phase::as_u8`) and the scan list,
/// already encoded (`ScanList::encode`, at most [`SCAN_MAX_LEN`] bytes).
#[derive(Clone, Copy, Debug)]
pub struct Status<'s> {
    /// The station's phase.
    pub phase: u8,
    /// The encoded scan list.
    pub scan: &'s [u8],
}

/// What an applied record changed, for the firmware to act on.
#[derive(Debug, Default)]
pub struct Applied {
    /// The network to join, when the record carried one.
    pub network: Option<Credentials>,
    /// The record carried a new verifier: the old code no longer works.
    pub code_rotated: bool,
    /// The record carried an adoption, accepted and stored.
    pub adopted: bool,
}

/// The device's answer to one message: `len` bytes of `out` to send back,
/// and what was applied when the message was an accepted Settings.
#[derive(Debug)]
pub struct Answer {
    /// Bytes of the answer in `out`.
    pub len: usize,
    /// The applied record, if this answer was its Result.
    pub applied: Option<Applied>,
}

/// The window as Discover reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// Start is accepted.
    pub open: bool,
    /// Discover's `window_s`.
    pub window_s: u16,
    /// Failures left before the lockout.
    pub attempts_left: u8,
}

enum State {
    Idle,
    Replied {
        response: Response,
        at: Micros,
    },
    Confirmed {
        send: Sealer,
        recv: Opener,
        at: Micros,
    },
}

/// The device's side of the setup session on one carrier.
pub struct Device {
    label: &'static [u8],
    devpub: [u8; DEVPUB_LEN],
    state: State,
    window_opened: Option<Micros>,
    last_failure: Option<Micros>,
}

impl Device {
    /// The session for carrier `label` (see [`super::label`]) on the device
    /// whose compressed public key is `devpub`, after `reset` at `now`. A
    /// power-on reset opens the window and gives a locked-out device one
    /// more guess (`setup.fail` becomes at most `MAX_FAILURES - 1`).
    pub fn new(
        label: &'static [u8],
        devpub: [u8; DEVPUB_LEN],
        reset: Reset,
        now: Micros,
        settings: &mut impl Kv,
    ) -> Result<Self> {
        Context::new(label, &devpub)?;
        let mut window_opened = None;
        if reset == Reset::PowerOn {
            window_opened = Some(now);
            if failures(settings) >= MAX_FAILURES {
                mid_setup::store_failures(settings, MAX_FAILURES - 1)?;
            }
        }
        Ok(Device {
            label,
            devpub,
            state: State::Idle,
            window_opened,
            last_failure: None,
        })
    }

    /// The board's button: the window opens for [`WINDOW_AFTER_RESET_US`].
    pub fn button(&mut self, now: Micros) {
        self.window_opened = Some(now);
    }

    /// The window at `now`.
    pub fn window(&self, now: Micros, settings: &impl Kv) -> Window {
        let fail = failures(settings);
        let attempts_left = MAX_FAILURES.saturating_sub(fail);
        if fail >= MAX_FAILURES {
            return Window {
                open: false,
                window_s: 0,
                attempts_left,
            };
        }
        if !provisioned(settings) {
            return Window {
                open: true,
                window_s: WINDOW_UNTIL_PROVISIONED,
                attempts_left,
            };
        }
        match self.window_opened {
            Some(t) if now.since(t) < WINDOW_AFTER_RESET_US => {
                let left = (WINDOW_AFTER_RESET_US - now.since(t)).div_ceil(1_000_000);
                Window {
                    open: true,
                    window_s: left.min(0xFFFE) as u16,
                    attempts_left,
                }
            }
            _ => Window {
                open: false,
                window_s: 0,
                attempts_left,
            },
        }
    }

    /// Whether a carrier that advertises (BLE) should advertise now.
    pub fn advertising(&self, now: Micros, settings: &impl Kv) -> bool {
        self.window(now, settings).open
    }

    /// Writes Discover into `out`.
    pub fn discover(&self, now: Micros, settings: &impl Kv, out: &mut [u8]) -> Result<usize> {
        let window = self.window(now, settings);
        let verifier = load_verifier(settings);
        let (suites, salt, iterations) = match &verifier {
            Some(v) => (SUITE_CODE, *v.salt(), v.iterations()),
            None => (0, [0u8; SALT_LEN], 0),
        };
        Discover {
            suites,
            devpub: self.devpub,
            salt,
            iterations,
            window_s: window.window_s,
            attempts_left: window.attempts_left,
        }
        .write(out)
    }

    /// Whether a session is in flight.
    #[must_use]
    pub fn in_session(&self) -> bool {
        !matches!(self.state, State::Idle)
    }

    /// The carrier's session ended (a disconnect): the session is dropped,
    /// its secrets with it. Not a failure.
    pub fn carrier_closed(&mut self) {
        self.state = State::Idle;
    }

    /// Ends a session idle for longer than [`IDLE_TIMEOUT_US`]. Not a
    /// failure.
    pub fn tick(&mut self, now: Micros) {
        let at = match &self.state {
            State::Idle => return,
            State::Replied { at, .. } | State::Confirmed { at, .. } => *at,
        };
        if now.since(at) > IDLE_TIMEOUT_US {
            self.state = State::Idle;
        }
    }

    /// One message from the carrier, answered into `out` (at least
    /// [`MAX_MESSAGE`] bytes). Every refusal is an `Error` message; an `Err`
    /// is the device's own trouble (storage, the RNG, a short `out`).
    #[allow(clippy::too_many_arguments)]
    pub fn on_message(
        &mut self,
        message: &[u8],
        now: Micros,
        settings: &mut impl Kv,
        identity: &mut impl Kv,
        rng: &mut impl Rng,
        signer: &impl DeviceSigner,
        status: &Status<'_>,
        out: &mut [u8],
    ) -> Result<Answer> {
        if out.len() < MAX_MESSAGE {
            return Err(Error::BufferTooSmall {
                needed: MAX_MESSAGE,
            });
        }
        self.tick(now);
        let (k, body) = match split(message) {
            Ok(parts) => parts,
            Err(Error::Unsupported) => return self.end_with(ResultCode::Version, out),
            Err(_) => return self.end_with(ResultCode::Malformed, out),
        };
        match k {
            kind::START => self.on_start(body, now, settings, rng, signer, out),
            kind::CONFIRM => self.on_confirm(body, now, settings, status, out),
            kind::SETTINGS => self.on_settings(body, now, settings, identity, status, out),
            _ => self.end_with(ResultCode::Order, out),
        }
    }

    fn end_with(&mut self, code: ResultCode, out: &mut [u8]) -> Result<Answer> {
        self.state = State::Idle;
        Ok(Answer {
            len: write_error(code, out)?,
            applied: None,
        })
    }

    fn refuse(code: ResultCode, out: &mut [u8]) -> Result<Answer> {
        Ok(Answer {
            len: write_error(code, out)?,
            applied: None,
        })
    }

    fn on_start(
        &mut self,
        body: &[u8],
        now: Micros,
        settings: &mut impl Kv,
        rng: &mut impl Rng,
        signer: &impl DeviceSigner,
        out: &mut [u8],
    ) -> Result<Answer> {
        if self.in_session() {
            // the session in flight is not disturbed
            return Self::refuse(ResultCode::Busy, out);
        }
        if !self.window(now, settings).open {
            return Self::refuse(ResultCode::WindowClosed, out);
        }
        let fail = failures(settings);
        if fail >= 1 {
            if let Some(t) = self.last_failure {
                let wait = 1_000_000u64 << (fail - 1).min(31);
                if now.since(t) < wait {
                    return Self::refuse(ResultCode::Backoff, out);
                }
            }
        }
        if body.len() != 1 + SHARE_LEN {
            return Self::refuse(ResultCode::Malformed, out);
        }
        if body[0] != SUITE_CODE {
            return Self::refuse(ResultCode::Version, out);
        }
        let Some(verifier) = load_verifier(settings) else {
            return Self::refuse(ResultCode::NoVerifier, out);
        };
        let context = Context::new(self.label, &self.devpub)?;
        let share_p: &[u8; SHARE_LEN] = body[1..].try_into().map_err(|_| Error::InvalidFormat)?;
        let response = match respond(&verifier, &context, share_p, rng) {
            Ok(r) => r,
            Err(Error::InvalidFormat) => return Self::refuse(ResultCode::Malformed, out),
            Err(e) => return Err(e),
        };
        // A Reply lets the starter check one guess of the code offline
        // (`confirmV`), so every answered Start counts as a failure until its
        // Confirm verifies; abandoning a session does not escape the count.
        self.record_failure(now, settings)?;
        let prehash = reply_prehash(&context, share_p, response.share_v(), response.confirm_v());
        let sig = mid_setup::sign_reply(signer, &prehash);
        let mut at = 0;
        for part in [
            &header(kind::REPLY)[..],
            response.share_v(),
            response.confirm_v(),
            &sig,
        ] {
            out[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        self.state = State::Replied { response, at: now };
        Ok(Answer {
            len: at,
            applied: None,
        })
    }

    fn on_confirm(
        &mut self,
        body: &[u8],
        now: Micros,
        settings: &mut impl Kv,
        status: &Status<'_>,
        out: &mut [u8],
    ) -> Result<Answer> {
        let State::Replied { response, .. } = core::mem::replace(&mut self.state, State::Idle)
        else {
            return self.end_with(ResultCode::Order, out);
        };
        if body.len() != 32 {
            return self.end_with(ResultCode::Malformed, out);
        }
        let Ok(established) = response.confirm(body) else {
            // already counted when the Start was answered
            return self.end_with(ResultCode::Confirm, out);
        };
        mid_setup::store_failures(settings, 0)?;
        self.last_failure = None;
        let (mut send, recv) = established.split();
        if status.scan.len() > SCAN_MAX_LEN {
            return Err(Error::InvalidFormat);
        }
        let mut plain = [0u8; 1 + SCAN_MAX_LEN];
        plain[0] = status.phase;
        plain[1..1 + status.scan.len()].copy_from_slice(status.scan);
        out[..2].copy_from_slice(&header(kind::READY));
        let n = send.seal(
            &header(kind::READY),
            &plain[..1 + status.scan.len()],
            &mut out[2..],
        )?;
        plain.zeroize();
        self.state = State::Confirmed {
            send,
            recv,
            at: now,
        };
        Ok(Answer {
            len: 2 + n,
            applied: None,
        })
    }

    fn on_settings(
        &mut self,
        body: &[u8],
        now: Micros,
        settings: &mut impl Kv,
        identity: &mut impl Kv,
        status: &Status<'_>,
        out: &mut [u8],
    ) -> Result<Answer> {
        let State::Confirmed {
            mut send, mut recv, ..
        } = core::mem::replace(&mut self.state, State::Idle)
        else {
            return self.end_with(ResultCode::Order, out);
        };
        let mut plain = [0u8; MAX_MESSAGE];
        let Ok(n) = recv.open(&header(kind::SETTINGS), body, &mut plain) else {
            self.record_failure(now, settings)?;
            return self.end_with(ResultCode::Seal, out);
        };
        let (code, applied) = self.apply(&plain[..n], settings, identity);
        plain.zeroize();
        out[..2].copy_from_slice(&header(kind::RESULT));
        let len = 2 + send.seal(
            &header(kind::RESULT),
            &[code as u8, status.phase],
            &mut out[2..],
        )?;
        Ok(Answer { len, applied })
    }

    /// Checks the whole record (an adoption against this device and its
    /// pinned owner too), then writes it. Nothing is written unless
    /// everything checks.
    fn apply(
        &self,
        plain: &[u8],
        settings: &mut impl Kv,
        identity: &mut impl Kv,
    ) -> (ResultCode, Option<Applied>) {
        let record = match Record::decode(plain) {
            Ok(r) => r,
            Err(code) => return (code, None),
        };
        let mut pin_bytes = [0u8; OwnerPin::LEN];
        let mut pin_len = 0;
        if let Some(bytes) = record.adoption {
            let Ok(adoption) = Adoption::decode(bytes) else {
                return (ResultCode::BadAdoption, None);
            };
            let mut did_buf = [0u8; MAX_DID_LEN];
            let Ok(did) = Did::from_pubkey(&self.devpub) else {
                return (ResultCode::BadAdoption, None);
            };
            let Ok(my_did) = did.write(&mut did_buf) else {
                return (ResultCode::BadAdoption, None);
            };
            let pin = load_pin(identity);
            let Ok(new_pin) = adoption.accept(my_did, pin.as_ref(), None) else {
                return (ResultCode::BadAdoption, None);
            };
            match new_pin.encode(&mut pin_bytes) {
                Ok(n) => pin_len = n,
                Err(_) => return (ResultCode::BadAdoption, None),
            }
        }
        let stored = (|| -> Result<()> {
            if let Some(net) = &record.network {
                settings.put(key::SSID, net.ssid())?;
                settings.put(key::PSK, net.psk())?;
            }
            if let Some(name) = record.name {
                settings.put(key::NAME, name.as_bytes())?;
            }
            if let Some(maker) = record.maker {
                settings.put(key::MAKER, maker.as_bytes())?;
            }
            if let Some(ms) = record.blink_ms {
                settings.put(key::BLINK_MS, &ms.to_le_bytes())?;
            }
            if let Some(fps) = record.fps {
                settings.put(key::FPS, &[fps])?;
            }
            if let Some(adoption) = record.adoption {
                identity.put(KV_ADOPTION, adoption)?;
                identity.put(KV_OWNER_PIN, &pin_bytes[..pin_len])?;
            }
            if let Some(v) = record.setup_v {
                settings.put(key::SETUP_V, v)?;
            }
            Ok(())
        })();
        if stored.is_err() {
            return (ResultCode::StoreFailed, None);
        }
        let applied = Applied {
            network: record.network,
            code_rotated: record.setup_v.is_some(),
            adopted: record.adoption.is_some(),
        };
        (ResultCode::Applied, Some(applied))
    }

    fn record_failure(&mut self, now: Micros, settings: &mut impl Kv) -> Result<()> {
        let fail = failures(settings).saturating_add(1);
        mid_setup::store_failures(settings, fail)?;
        self.last_failure = Some(now);
        Ok(())
    }
}

/// `setup.fail`; an unreadable count reads as locked (fail closed).
fn failures(settings: &impl Kv) -> u8 {
    mid_setup::load_failures(settings).unwrap_or(MAX_FAILURES)
}

fn provisioned(settings: &impl Kv) -> bool {
    let mut buf = [0u8; 32];
    matches!(settings.get(key::SSID, &mut buf), Ok(Some(n)) if n > 0)
}

fn load_verifier(settings: &impl Kv) -> Option<Verifier> {
    let mut buf = mid_setup::load_verifier(settings).ok()??;
    let verifier = Verifier::decode(&buf).ok();
    buf.zeroize();
    verifier
}

fn load_pin(identity: &impl Kv) -> Option<OwnerPin> {
    let mut buf = [0u8; OwnerPin::LEN];
    match identity.get(KV_OWNER_PIN, &mut buf) {
        Ok(Some(n)) if n == OwnerPin::LEN => OwnerPin::decode(&buf).ok(),
        _ => None,
    }
}

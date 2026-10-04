//! The setup session's cryptographic core (enc-ble M1): the protocol of
//! `docs/setup-protocol.md` in the Janus umbrella, v1, suite 1.
//!
//! A person proves they may set a device up by knowing its setup code; the
//! device proves it holds the verifier made from that code, and signs the
//! session with its `did:mata` key; both then share two keys that seal the
//! settings record. The same code runs on the device and, built to wasm, in
//! the browser, so the two halves cannot drift.
//!
//! | piece | module |
//! |---|---|
//! | the setup code: normalisation, display, generation | [`Code`] |
//! | the verifier: PBKDF2 derivation, the stored `setup.v` record | [`Secrets`], [`Verifier`] |
//! | SPAKE2+ (RFC 9383, P-256): both roles, the key schedule, the Reply signature's prehash | [`Prover`], [`respond`], [`reply_prehash`], [`verify_reply`] |
//! | ChaCha20-Poly1305 sealing with counted nonces | [`Sealer`], [`Opener`] |
//!
//! Message framing, the session's state machine, the window and the lockout
//! are the session's (M2), not this module's. Every function is `no_std`,
//! allocation-free and constant-time where a secret is involved; secrets are
//! zeroised on drop.
//!
//! Held to: RFC 9383's P-256 test vector (`spake::tests`), and one complete
//! session computed by `tools/setup_golden.py`, an independent Python oracle
//! that checks its own primitives against RFC 8439, RFC 6979 and RFC 9383
//! (`tests/session_vectors.rs`).

mod browser;
mod code;
pub mod device;
pub mod message;
pub mod record;
mod seal;
mod spake;
mod verifier;

pub use browser::{Browser, Failure, Outcome, Ready};
pub use code::{ALPHABET, CODE_SYMBOLS, Code, DISPLAY_LEN};
pub use device::{Answer, Applied, Device, Reset, Status, Window};
pub use message::{Discover, MAX_MESSAGE, ResultCode};
pub use record::{Record, RecordWriter};
pub use seal::{Opener, Sealer, TAG_LEN};
#[doc(hidden)]
pub use spake::respond_with_scalar;
pub use spake::{
    CONFIRM_LEN, Established, Prover, Response, SHARE_LEN, SIG_LEN, reply_prehash, respond,
    verify_reply,
};
pub use verifier::{MAX_ITERATIONS, MIN_ITERATIONS, SALT_LEN, SETUP_V_LEN, Secrets, Verifier};

use rusty_esp_core::error::{Error, Result};

/// The protocol version, the first byte of every message.
pub const VERSION: u8 = 0x01;

/// The Context's fixed prefix (and the domain of every derived key).
pub const CONTEXT_PREFIX: &[u8] = b"janus-setup-v1";

/// The length of a device public key, SEC1 compressed: the bytes of its
/// `did:mata`.
pub const DEVPUB_LEN: usize = 33;

/// The longest carrier label a Context takes.
pub const MAX_LABEL_LEN: usize = 16;

const MAX_CONTEXT_LEN: usize = CONTEXT_PREFIX.len() + 1 + MAX_LABEL_LEN + DEVPUB_LEN;

/// The carrier labels v1 defines.
pub mod label {
    /// Bluetooth LE.
    pub const BLE: &[u8] = b"ble";
    /// The device's own page.
    pub const PAGE: &[u8] = b"page";
    /// The serial console.
    pub const USB: &[u8] = b"usb";
    /// The mesh link, through the bridge.
    pub const LINK: &[u8] = b"link";
}

/// The session's Context (protocol section 5.1):
/// `"janus-setup-v1" || u8 len(label) || label || devpub`. It binds a
/// session to one device and one carrier.
#[derive(Clone, PartialEq, Eq)]
pub struct Context {
    buf: [u8; MAX_CONTEXT_LEN],
    len: usize,
}

impl Context {
    /// The Context of a session on carrier `label` with the device whose
    /// compressed public key is `devpub`. A label is 1 to
    /// [`MAX_LABEL_LEN`] bytes.
    pub fn new(label: &[u8], devpub: &[u8; DEVPUB_LEN]) -> Result<Self> {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(Error::InvalidFormat);
        }
        let mut buf = [0u8; MAX_CONTEXT_LEN];
        let mut at = 0;
        for part in [CONTEXT_PREFIX, &[label.len() as u8], label, devpub] {
            buf[at..at + part.len()].copy_from_slice(part);
            at += part.len();
        }
        Ok(Context { buf, len: at })
    }

    /// The Context's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

// The sizes mID's half of the protocol uses (`rusty_esp_mid_core::setup`)
// are this module's: one protocol, two crates.
const _: () = assert!(SETUP_V_LEN == rusty_esp_mid_core::setup::SETUP_VERIFIER_LEN);
const _: () = assert!(SHARE_LEN == rusty_esp_mid_core::setup::SHARE_LEN);
const _: () = assert!(CONFIRM_LEN == rusty_esp_mid_core::setup::CONFIRM_LEN);

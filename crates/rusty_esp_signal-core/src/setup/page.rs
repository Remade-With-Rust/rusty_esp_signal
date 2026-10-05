//! The device's own page as a setup carrier (protocol section 11.2, label
//! [`super::label::PAGE`]): the experiments plan's E7, provisioning with no
//! Bluetooth at all.
//!
//! `GET /setup` answers Discover. `POST /setup`, body one message, answers
//! the device's message. The header `X-Setup-Session` (16 hex digits the
//! browser chooses) names the carrier session: the first message while the
//! device is idle opens it, and a different value while it is in flight is
//! `Busy` -- refused here, before the session sees the message. Bluetooth
//! had this for free (one peer per connection); HTTP has no connection to
//! hold, so without it a second browser's Confirm or Settings would land in
//! the first one's session. Both bodies are `application/octet-stream`; an
//! `Error` is also an HTTP status (`400` Malformed, Version, Order; `409`
//! Busy; `403` WindowClosed, Backoff, NoVerifier; `401` Confirm, Seal).
//!
//! The carrier session ends when the session does (Result, a refusal that
//! ends it, or [`super::device::IDLE_TIMEOUT_US`]): HTTP has no disconnect
//! to report. So a Start under the name in flight begins the session again,
//! as a reconnect does on Bluetooth: a browser that learned its code was
//! wrong at Reply never sends Confirm, and without this the person who
//! retypes the code would wait out the idle minute (E7's bench, run 2: 63 s
//! of Busy). The failure that Reply counted stands, and the backoff applies
//! to the new Start, so starting again escapes nothing. This module parses nothing of HTTP itself: a server hands it
//! the method and path it matched, the header's value and the body, and
//! sends back the status and the bytes.

use rusty_esp_core::Micros;
use rusty_esp_core::error::Result;
use rusty_esp_core::hal::{Kv, Rng};
use rusty_esp_mid_core::signer::DeviceSigner;

use super::device::{Answer, Applied, Device, Status};
use super::message::{self, ResultCode, kind};

/// The header that names the carrier session.
pub const SESSION_HEADER: &str = "X-Setup-Session";
/// The path both requests use.
pub const PATH: &str = "/setup";
/// The content type of both bodies.
pub const CONTENT_TYPE: &str = "application/octet-stream";
/// Hex digits in the session's name.
pub const SESSION_DIGITS: usize = 16;

/// The page a device serves at `/` on its open setup network: the setup
/// session's browser half (the same wasm and session script as
/// `docs/provision.html`) with a form for the code and the network,
/// gzip-compressed. Serve it with [`SETUP_PAGE_HEAD`]. Built by
/// `tools/build-provision-page.py`, which checks it is what the build makes.
#[cfg(feature = "setup-page")]
pub const SETUP_PAGE_GZ: &[u8] = include_bytes!("setup-page.html.gz");

/// The response head for [`SETUP_PAGE_GZ`], up to its `Content-Length`
/// value (the server writes the length, then a blank line, then the bytes).
/// Not cached: the page and the device's state go together.
#[cfg(feature = "setup-page")]
pub const SETUP_PAGE_HEAD: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Encoding: gzip\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: ";

/// What one request answers: the HTTP status, the body's length in `out`,
/// and what an accepted Settings changed (the credentials it carries: not
/// `Clone`, as the session's own [`Answer`] is not).
#[derive(Debug)]
pub struct PageAnswer {
    /// The HTTP status.
    pub status: u16,
    /// Bytes of the body in `out`.
    pub len: usize,
    /// The applied record, when this answer was its Result.
    pub applied: Option<Applied>,
}

/// The carrier: which browser's session is in flight.
#[derive(Debug, Default, Clone)]
pub struct Page {
    session: Option<u64>,
}

/// The HTTP status an answer travels with: 200 unless it is an `Error`.
#[must_use]
pub fn status_of(answer: &[u8]) -> u16 {
    match message::split(answer) {
        Ok((kind::ERROR, body)) => match body.first().copied().and_then(ResultCode::from_u8) {
            Some(ResultCode::Busy) => 409,
            Some(ResultCode::WindowClosed | ResultCode::Backoff | ResultCode::NoVerifier) => 403,
            Some(ResultCode::Confirm | ResultCode::Seal) => 401,
            _ => 400,
        },
        _ => 200,
    }
}

/// The session's name from the header's value: exactly 16 hex digits.
#[must_use]
pub fn parse_session(value: &[u8]) -> Option<u64> {
    if value.len() != SESSION_DIGITS {
        return None;
    }
    let mut n = 0u64;
    for &c in value {
        let digit = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        n = (n << 4) | u64::from(digit);
    }
    Some(n)
}

impl Page {
    /// No carrier session.
    #[must_use]
    pub const fn new() -> Self {
        Page { session: None }
    }

    /// Whether a browser's session is in flight on this carrier.
    #[must_use]
    pub fn in_flight(&self) -> bool {
        self.session.is_some()
    }

    /// `GET /setup`: Discover, into `out`.
    pub fn discover(
        &mut self,
        device: &mut Device,
        now: Micros,
        settings: &impl Kv,
        out: &mut [u8],
    ) -> Result<PageAnswer> {
        self.settle(device, now);
        let len = device.discover(now, settings, out)?;
        Ok(PageAnswer {
            status: 200,
            len,
            applied: None,
        })
    }

    /// `POST /setup`: `header` is `X-Setup-Session`'s value (absent: empty),
    /// `body` the message; the answer goes into `out` (at least
    /// [`message::MAX_MESSAGE`] bytes).
    #[allow(clippy::too_many_arguments)]
    pub fn post(
        &mut self,
        device: &mut Device,
        header: &[u8],
        body: &[u8],
        now: Micros,
        settings: &mut impl Kv,
        identity: &mut impl Kv,
        rng: &mut impl Rng,
        signer: &impl DeviceSigner,
        status: &Status<'_>,
        out: &mut [u8],
    ) -> Result<PageAnswer> {
        self.settle(device, now);
        let Some(session) = parse_session(header) else {
            return Self::refuse(ResultCode::Malformed, out);
        };
        match self.session {
            // another browser's session is in flight: it never sees this
            Some(current) if current != session => return Self::refuse(ResultCode::Busy, out),
            // the same browser starting again: its half-finished session goes
            Some(_) if body.get(1) == Some(&kind::START) => device.carrier_closed(),
            Some(_) => {}
            // idle: this message opens the carrier session
            None => self.session = Some(session),
        }
        let Answer { len, applied } =
            device.on_message(body, now, settings, identity, rng, signer, status, out)?;
        // the session ended with this answer (a Result, a refusal that ends
        // it), or never began (a refused Start): so does the carrier's
        self.settle(device, now);
        Ok(PageAnswer {
            status: status_of(&out[..len]),
            len,
            applied,
        })
    }

    /// The carrier session follows the session: ended there (completed,
    /// refused, idle for too long), ended here.
    fn settle(&mut self, device: &mut Device, now: Micros) {
        device.tick(now);
        if !device.in_session() {
            self.session = None;
        }
    }

    fn refuse(code: ResultCode, out: &mut [u8]) -> Result<PageAnswer> {
        let len = message::write_error(code, out)?;
        Ok(PageAnswer {
            status: status_of(&out[..len]),
            len,
            applied: None,
        })
    }
}

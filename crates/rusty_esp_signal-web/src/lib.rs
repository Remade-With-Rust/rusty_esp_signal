//! The provisioning page's wasm: the setup session's browser half
//! (`rusty_esp_signal-core::setup`, the Janus umbrella's
//! `docs/setup-protocol.md`), bound for JavaScript.
//!
//! `docs/provision.html` moves bytes over Web Bluetooth: it reads
//! `discover`, writes each message this hands it to `setup`, and reads the
//! device's answer when its header is notified. Everything checked, derived
//! or sealed is here: the device's key against the one the page was told to
//! expect, the code (PBKDF2, then SPAKE2+), the device's signature over the
//! session, and the settings, sealed. A failure comes back as an error whose
//! message is for a person.
//!
//! With `sim`, [`sim::SimDevice`] is the device half behind the firmware's own
//! GATT router, for the host test that drives the page's script against it.

#![no_std]

extern crate alloc;
#[cfg(feature = "sim")]
extern crate std;

#[cfg(feature = "sim")]
pub mod sim;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use rusty_esp_core::error::{Error, Result as CoreResult};
use rusty_esp_core::hal::Rng;
use rusty_esp_signal_core::mid::did::Did;
use rusty_esp_signal_core::setup::message::WINDOW_UNTIL_PROVISIONED;
use rusty_esp_signal_core::setup::{
    Browser, Code, Discover, Failure, MAX_MESSAGE, RecordWriter, ResultCode, TAG_LEN, label,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

/// What a device's Discover says, before anything is typed.
#[wasm_bindgen(getter_with_clone)]
pub struct Offer {
    /// The device's `did:mata`.
    pub did: String,
    /// Whether it takes a setup code at all.
    pub takes_code: bool,
    /// Seconds left in its window; `-1` while it is unprovisioned (open
    /// until it is).
    pub window_s: i32,
    /// Wrong codes it will take before it locks.
    pub attempts_left: u8,
}

/// Reads a device's Discover (the `discover` value).
#[wasm_bindgen]
pub fn offer(discover: &[u8]) -> Result<Offer, JsError> {
    let d = Discover::read(discover).map_err(|e| undecoded("Discover", e))?;
    let did = Did::from_pubkey(&d.devpub)
        .map_err(|_| JsError::new("the device's key is not a P-256 point"))?;
    Ok(Offer {
        did: did.to_string(),
        takes_code: d.offers_code(),
        window_s: if d.window_s == WINDOW_UNTIL_PROVISIONED {
            -1
        } else {
            i32::from(d.window_s)
        },
        attempts_left: d.attempts_left,
    })
}

/// One setup session over BLE, the browser's side. Each step takes the
/// device's answer and returns the next message to write.
#[wasm_bindgen]
pub struct SetupSession {
    browser: Browser,
    start: Vec<u8>,
    phase: u8,
    scan: Vec<u8>,
}

#[wasm_bindgen]
impl SetupSession {
    /// Starts a session from the device's Discover and the code the person
    /// typed. `expect_did`: the device the page was sent to set up, when it
    /// knows it; any other device is refused before a guess is spent. Runs
    /// PBKDF2, the slow step; the Start to write is [`Self::start_message`].
    #[wasm_bindgen(constructor)]
    pub fn new(
        discover: &[u8],
        code: &str,
        expect_did: Option<String>,
    ) -> Result<SetupSession, JsError> {
        let code = Code::parse(code).map_err(|_| {
            JsError::new("a setup code is ten letters and digits, like 7KXQ3-M9PRT")
        })?;
        let expect = match expect_did
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(did) => Some(
                *Did::parse(did)
                    .map_err(|_| JsError::new("the expected device is not a did:mata"))?
                    .pubkey(),
            ),
            None => None,
        };
        let mut out = [0u8; MAX_MESSAGE];
        let (browser, n) = Browser::start(
            discover,
            &code,
            expect.as_ref(),
            label::BLE,
            &mut CryptoRng,
            &mut out,
        )
        .map_err(|f| match f {
            Failure::Local(Error::Denied) => {
                JsError::new("this is not the device you were sent to set up: its key is different")
            }
            f => failure("Discover", f),
        })?;
        Ok(SetupSession {
            browser,
            start: out[..n].to_vec(),
            phase: 0,
            scan: Vec::new(),
        })
    }

    /// Start, to write to `setup`.
    pub fn start_message(&self) -> Vec<u8> {
        self.start.clone()
    }

    /// Takes the device's Reply and returns Confirm. A wrong code fails
    /// here.
    pub fn on_reply(&mut self, reply: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut out = [0u8; MAX_MESSAGE];
        let n = self
            .browser
            .on_reply(reply, &mut out)
            .map_err(|f| match f {
                Failure::Local(Error::Crypto) => JsError::new(
                    "the code is wrong, or the device could not prove it is the one it claims",
                ),
                f => failure("Reply", f),
            })?;
        Ok(out[..n].to_vec())
    }

    /// Takes the device's Ready: its phase ([`Self::phase`]) and the networks
    /// it can see ([`Self::scan`]).
    pub fn on_ready(&mut self, ready: &[u8]) -> Result<(), JsError> {
        let mut scan = [0u8; MAX_MESSAGE];
        let r = self
            .browser
            .on_ready(ready, &mut scan)
            .map_err(|f| failure("Ready", f))?;
        self.phase = r.phase;
        self.scan = scan[..r.scan_len].to_vec();
        Ok(())
    }

    /// The device's Wi-Fi phase, from Ready or Result.
    #[wasm_bindgen(getter)]
    pub fn phase(&self) -> u8 {
        self.phase
    }

    /// The networks the device can see, from Ready, in the scan-list TLV.
    #[wasm_bindgen(getter)]
    pub fn scan(&self) -> Vec<u8> {
        self.scan.clone()
    }

    /// The settings to send, sealed: the network (both or neither) and the
    /// device's name (empty: unchanged). Checked here first.
    pub fn settings(&mut self, ssid: &str, psk: &str, name: &str) -> Result<Vec<u8>, JsError> {
        let mut record = [0u8; MAX_MESSAGE - 2 - TAG_LEN];
        let n = write_record(&mut record, ssid, psk, name);
        let sealed = n.and_then(|n| {
            let mut out = [0u8; MAX_MESSAGE];
            let m = self
                .browser
                .send_settings(&record[..n], &mut out)
                .map_err(|f| failure("Settings", f))?;
            Ok(out[..m].to_vec())
        });
        record.zeroize();
        sealed
    }

    /// Takes the device's Result: its Wi-Fi phase once the settings are
    /// applied; a refusal is an error naming what was refused.
    pub fn on_result(&mut self, result: &[u8]) -> Result<u8, JsError> {
        match self.browser.on_result(result) {
            Ok((ResultCode::Applied, phase)) => {
                self.phase = phase;
                Ok(phase)
            }
            Ok((code, _)) => Err(JsError::new(code.describe())),
            Err(f) => Err(failure("Result", f)),
        }
    }
}

fn write_record(buf: &mut [u8], ssid: &str, psk: &str, name: &str) -> Result<usize, JsError> {
    let full = |_| JsError::new("the settings do not fit one message");
    let mut w = RecordWriter::new(buf);
    match (ssid.is_empty(), psk.is_empty()) {
        (false, false) => {
            if ssid.len() > 32 {
                return Err(JsError::new("a network name is at most 32 bytes"));
            }
            if !(8..=63).contains(&psk.len()) {
                return Err(JsError::new("the passphrase must be 8 to 63 characters"));
            }
            w.network(ssid.as_bytes(), psk.as_bytes()).map_err(full)?;
        }
        (true, true) => {}
        _ => {
            return Err(JsError::new(
                "a network needs both its name and its passphrase",
            ));
        }
    }
    if !name.is_empty() {
        w.name(name).map_err(full)?;
    }
    if w.is_empty() {
        return Err(JsError::new("nothing to send"));
    }
    Ok(w.len())
}

fn undecoded(step: &str, e: Error) -> JsError {
    JsError::new(&format!("the device's {step} did not decode ({e:?})"))
}

fn failure(step: &str, f: Failure) -> JsError {
    match f {
        Failure::Remote(code) => JsError::new(code.describe()),
        Failure::Local(Error::Denied) => JsError::new(&format!("{step} came out of turn")),
        Failure::Local(e) => undecoded(step, e),
    }
}

/// `crypto.getRandomValues`, from whichever global has it (a page, a
/// worker, node).
struct CryptoRng;

impl Rng for CryptoRng {
    fn fill(&mut self, buf: &mut [u8]) -> CoreResult<()> {
        let crypto = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
            .map_err(|_| Error::Hardware)?;
        let get = js_sys::Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
            .map_err(|_| Error::Hardware)?;
        let get: js_sys::Function = get.dyn_into().map_err(|_| Error::Hardware)?;
        // getRandomValues fills at most 65,536 bytes a call
        for chunk in buf.chunks_mut(65_536) {
            let array = js_sys::Uint8Array::new_with_length(chunk.len() as u32);
            get.call1(&crypto, &array).map_err(|_| Error::Hardware)?;
            array.copy_to(chunk);
        }
        Ok(())
    }
}

/// The page's build, for its footer.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

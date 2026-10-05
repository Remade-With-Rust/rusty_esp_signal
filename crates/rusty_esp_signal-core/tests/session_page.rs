//! E7: the setup session over the device's own page (protocol section 11.2,
//! `setup::page`), the browser's half against the device's as an HTTP
//! server would carry them: the session end to end, a second browser that
//! never reaches the first one's session, the header, the statuses, the
//! idle timeout, and a session built for another carrier.

use rusty_esp_core::Micros;
use rusty_esp_core::hal::Kv;
use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_signal_core::mid::key::DeviceKey;
use rusty_esp_signal_core::setup::device::{IDLE_TIMEOUT_US, key};
use rusty_esp_signal_core::setup::message::{kind, write_error};
use rusty_esp_signal_core::setup::page::{Page, parse_session, status_of};
use rusty_esp_signal_core::setup::{
    Browser, Code, Device, MAX_MESSAGE, RecordWriter, Reset, ResultCode, Secrets, Status, Verifier,
    label,
};

const CODE: &str = "7KXQ3-M9PRT";
const SALT: [u8; 16] = *b"janus-test-salt!";
const SCAN: &[u8] = &[
    1, 9, b'b', b'e', b'n', b'c', b'h', b'-', b'n', b'e', b't', 3, 1, 0xCD, 4, 1, 1,
];
const A: &[u8] = b"00112233445566aa";
const B: &[u8] = b"FFEEDDCCBBAA9988";

struct Bench {
    device: Device,
    page: Page,
    settings: MemoryKv,
    identity: MemoryKv,
    key: DeviceKey,
    rng: InsecureTestRng,
    now: Micros,
}

impl Bench {
    fn new() -> Self {
        let mut settings = MemoryKv::new();
        let secrets = Secrets::derive(&Code::parse(CODE).unwrap(), &SALT, 1_000).unwrap();
        settings
            .put(
                key::SETUP_V,
                &Verifier::from_secrets(&secrets, &SALT, 1_000).encode(),
            )
            .unwrap();
        let key = DeviceKey::from_secret(&[0x11; 32], "bench").unwrap();
        let now = Micros::from_secs(5);
        let device = Device::new(
            label::PAGE,
            *key.did().pubkey(),
            Reset::PowerOn,
            now,
            &mut settings,
        )
        .unwrap();
        Bench {
            device,
            page: Page::new(),
            settings,
            identity: MemoryKv::new(),
            key,
            rng: InsecureTestRng::seeded(7),
            now,
        }
    }

    /// `GET /setup`.
    fn get(&mut self) -> (u16, Vec<u8>) {
        let mut out = [0u8; 64];
        let a = self
            .page
            .discover(&mut self.device, self.now, &self.settings, &mut out)
            .unwrap();
        (a.status, out[..a.len].to_vec())
    }

    /// `POST /setup` with `X-Setup-Session: header`.
    fn post(&mut self, header: &[u8], body: &[u8]) -> (u16, Vec<u8>, bool) {
        let mut out = [0u8; MAX_MESSAGE];
        let status = Status {
            phase: 0,
            scan: SCAN,
        };
        let a = self
            .page
            .post(
                &mut self.device,
                header,
                body,
                self.now,
                &mut self.settings,
                &mut self.identity,
                &mut self.rng,
                &self.key,
                &status,
                &mut out,
            )
            .unwrap();
        (a.status, out[..a.len].to_vec(), a.applied.is_some())
    }

    fn browser(&mut self, carrier: &[u8], seed: u64) -> (Browser, Vec<u8>) {
        let (_, discover) = self.get();
        let mut brng = InsecureTestRng::seeded(seed);
        let mut buf = [0u8; MAX_MESSAGE];
        let devpub = *self.key.did().pubkey();
        let (browser, n) = Browser::start(
            &discover,
            &Code::parse(CODE).unwrap(),
            Some(&devpub),
            carrier,
            &mut brng,
            &mut buf,
        )
        .unwrap();
        (browser, buf[..n].to_vec())
    }

    fn fails(&self) -> u8 {
        let mut b = [0u8; 1];
        match self.settings.get(key::FAIL, &mut b).unwrap() {
            Some(1) => b[0],
            _ => 0,
        }
    }
}

fn error_code(message: &[u8]) -> Option<ResultCode> {
    (message.len() == 3 && message[1] == kind::ERROR)
        .then(|| ResultCode::from_u8(message[2]).unwrap())
}

fn settings_record() -> Vec<u8> {
    let mut buf = [0u8; MAX_MESSAGE];
    let mut w = RecordWriter::new(&mut buf);
    w.network(b"bench-net", b"example-pass-1").unwrap();
    let n = w.len();
    buf[..n].to_vec()
}

#[test]
fn a_device_is_set_up_over_its_own_page() {
    let mut b = Bench::new();
    let (status, discover) = b.get();
    assert_eq!((status, discover[1]), (200, kind::DISCOVER));
    let (mut browser, start) = b.browser(label::PAGE, 1);
    let (status, reply, _) = b.post(A, &start);
    assert_eq!((status, reply[1]), (200, kind::REPLY));
    assert!(b.page.in_flight());
    let mut buf = [0u8; MAX_MESSAGE];
    let n = browser.on_reply(&reply, &mut buf).unwrap();
    let (status, ready, _) = b.post(A, &buf[..n]);
    assert_eq!((status, ready[1]), (200, kind::READY));
    let mut scan = [0u8; 256];
    browser.on_ready(&ready, &mut scan).unwrap();
    let n = browser.send_settings(&settings_record(), &mut buf).unwrap();
    let (status, result, applied) = b.post(A, &buf[..n]);
    assert_eq!(status, 200);
    assert!(applied, "the record was applied");
    assert_eq!(
        browser.on_result(&result).unwrap(),
        (ResultCode::Applied, 0)
    );
    let mut v = [0u8; 32];
    let n = b.settings.get(key::SSID, &mut v).unwrap().unwrap();
    assert_eq!(&v[..n], b"bench-net");
    // the session is over, and so is the carrier's
    assert!(!b.device.in_session() && !b.page.in_flight());
}

#[test]
fn a_second_browser_never_reaches_the_first_ones_session() {
    let mut b = Bench::new();
    let (mut first, start) = b.browser(label::PAGE, 1);
    let (_, reply, _) = b.post(A, &start);
    let mut buf = [0u8; MAX_MESSAGE];
    let n = first.on_reply(&reply, &mut buf).unwrap();
    let confirm = buf[..n].to_vec();
    // the session counts its failure at Reply and clears it at a verified
    // Confirm (a guesser who walks away is still counted)
    let pending = b.fails();

    // the second browser's Start: Busy, from the carrier
    let (_, start_b) = b.browser(label::PAGE, 2);
    let (status, busy, _) = b.post(B, &start_b);
    assert_eq!((status, error_code(&busy)), (409, Some(ResultCode::Busy)));
    // the first browser's own Confirm, copied by the second: Busy too, and
    // it never reached the session (which would have taken it as the next
    // message and moved on)
    let (status, busy, _) = b.post(B, &confirm);
    assert_eq!((status, error_code(&busy)), (409, Some(ResultCode::Busy)));
    // garbage under another name changes nothing either
    let (status, _, _) = b.post(B, &[1, kind::SETTINGS, 9, 9, 9]);
    assert_eq!(status, 409);
    assert_eq!(b.fails(), pending, "nothing counted for the stranger");

    // the first browser goes on as if nobody had called
    let (status, ready, _) = b.post(A, &confirm);
    assert_eq!((status, ready[1]), (200, kind::READY));
    let mut scan = [0u8; 256];
    first.on_ready(&ready, &mut scan).unwrap();
    let n = first.send_settings(&settings_record(), &mut buf).unwrap();
    let (status, result, applied) = b.post(A, &buf[..n]);
    assert!(status == 200 && applied);
    assert_eq!(first.on_result(&result).unwrap(), (ResultCode::Applied, 0));
    assert_eq!(b.fails(), 0, "the verified Confirm cleared it");

    // and once it is over, the second browser may start
    let (status, reply, _) = b.post(B, &start_b);
    assert_eq!((status, reply[1]), (200, kind::REPLY));
}

#[test]
fn the_header_names_sixteen_hex_digits() {
    for good in [&b"0123456789abcdef"[..], b"0123456789ABCDEF"] {
        assert!(parse_session(good).is_some(), "{good:?}");
    }
    for bad in [
        &b""[..],
        b"0123456789abcde",
        b"0123456789abcdef0",
        b"0123456789abcdeg",
        b"01234567 9abcdef",
    ] {
        assert_eq!(parse_session(bad), None, "{bad:?}");
    }
    let mut b = Bench::new();
    let (_, start) = b.browser(label::PAGE, 1);
    for bad in [&b""[..], b"not-a-session-id"] {
        let (status, answer, _) = b.post(bad, &start);
        assert_eq!(
            (status, error_code(&answer)),
            (400, Some(ResultCode::Malformed))
        );
    }
    assert!(!b.device.in_session(), "a bad header starts nothing");
}

#[test]
fn every_error_is_also_its_http_status() {
    let mut out = [0u8; 3];
    for (code, want) in [
        (ResultCode::Malformed, 400),
        (ResultCode::Version, 400),
        (ResultCode::Order, 400),
        (ResultCode::Busy, 409),
        (ResultCode::WindowClosed, 403),
        (ResultCode::Backoff, 403),
        (ResultCode::NoVerifier, 403),
        (ResultCode::Confirm, 401),
        (ResultCode::Seal, 401),
    ] {
        let n = write_error(code, &mut out).unwrap();
        assert_eq!(status_of(&out[..n]), want, "{code:?}");
    }
    assert_eq!(status_of(&[1, kind::REPLY, 0, 0]), 200);
}

#[test]
fn an_abandoned_session_frees_the_carrier_after_the_idle_timeout() {
    let mut b = Bench::new();
    let (_, start) = b.browser(label::PAGE, 1);
    b.post(A, &start);
    let (_, start_b) = b.browser(label::PAGE, 2);
    let (status, _, _) = b.post(B, &start_b);
    assert_eq!(status, 409);
    // the first browser walks away
    b.now = b.now.add_micros(IDLE_TIMEOUT_US + 1);
    let (status, reply, _) = b.post(B, &start_b);
    assert_eq!((status, reply[1]), (200, kind::REPLY));
}

#[test]
fn a_session_built_for_bluetooth_does_not_verify_on_the_page() {
    // the carrier's label is in the Context (protocol section 5.1): the
    // browser computed its session for "ble", the device runs "page"
    let mut b = Bench::new();
    let (mut browser, start) = b.browser(label::BLE, 1);
    let (_, reply, _) = b.post(A, &start);
    let mut buf = [0u8; MAX_MESSAGE];
    assert!(
        browser.on_reply(&reply, &mut buf).is_err(),
        "the device's proof does not verify"
    );
}

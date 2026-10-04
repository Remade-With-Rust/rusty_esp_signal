//! enc-ble M2: the setup session end to end on the host, the browser's half
//! against the device's, over the message bytes a carrier would move: the
//! happy path, every refusal, the window, the backoff and the lockout, a
//! replay, the idle timeout, the record's checks and its atomicity.

use rusty_esp_core::Micros;
use rusty_esp_core::error::Error;
use rusty_esp_core::hal::Kv;
use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_signal_core::mid::adoption::{AdoptionFields, CapList, KV_ADOPTION, KV_OWNER_PIN};
use rusty_esp_signal_core::mid::key::DeviceKey;
use rusty_esp_signal_core::setup::device::{
    IDLE_TIMEOUT_US, MAX_FAILURES, WINDOW_AFTER_RESET_US, key,
};
use rusty_esp_signal_core::setup::message::{WINDOW_UNTIL_PROVISIONED, kind};
use rusty_esp_signal_core::setup::{
    Browser, Code, Device, Discover, Failure, MAX_MESSAGE, RecordWriter, Reset, ResultCode,
    Secrets, Status, Verifier, label,
};

const CODE: &str = "7KXQ3-M9PRT";
const SALT: [u8; 16] = *b"janus-test-salt!";
const SCAN: &[u8] = &[
    1, 9, b'b', b'e', b'n', b'c', b'h', b'-', b'n', b'e', b't', 3, 1, 0xCD, 4, 1, 1,
];

fn verifier_record(code: &str) -> [u8; 118] {
    let secrets = Secrets::derive(&Code::parse(code).unwrap(), &SALT, 1_000).unwrap();
    Verifier::from_secrets(&secrets, &SALT, 1_000).encode()
}

struct Bench {
    device: Device,
    settings: MemoryKv,
    identity: MemoryKv,
    key: DeviceKey,
    rng: InsecureTestRng,
    now: Micros,
}

impl Bench {
    fn new(provisioned: bool, reset: Reset) -> Self {
        let mut settings = MemoryKv::new();
        settings.put(key::SETUP_V, &verifier_record(CODE)).unwrap();
        if provisioned {
            settings.put(key::SSID, b"old-net").unwrap();
            settings.put(key::PSK, b"old-pass-123").unwrap();
        }
        let key = DeviceKey::from_secret(&[0x11; 32], "bench").unwrap();
        let devpub = *key.did().pubkey();
        let now = Micros::from_secs(5);
        let device = Device::new(label::BLE, devpub, reset, now, &mut settings).unwrap();
        Bench {
            device,
            settings,
            identity: MemoryKv::new(),
            key,
            rng: InsecureTestRng::seeded(7),
            now,
        }
    }

    fn devpub(&self) -> [u8; 33] {
        *self.key.did().pubkey()
    }

    fn discover(&self) -> Vec<u8> {
        let mut out = [0u8; 64];
        let n = self
            .device
            .discover(self.now, &self.settings, &mut out)
            .unwrap();
        out[..n].to_vec()
    }

    fn send(&mut self, message: &[u8]) -> (Vec<u8>, Option<rusty_esp_signal_core::setup::Applied>) {
        let mut out = [0u8; MAX_MESSAGE];
        let status = Status {
            phase: 0,
            scan: SCAN,
        };
        let answer = self
            .device
            .on_message(
                message,
                self.now,
                &mut self.settings,
                &mut self.identity,
                &mut self.rng,
                &self.key,
                &status,
                &mut out,
            )
            .unwrap();
        (out[..answer.len].to_vec(), answer.applied)
    }

    fn fails(&self) -> u8 {
        let mut b = [0u8; 1];
        match self.settings.get(key::FAIL, &mut b).unwrap() {
            Some(1) => b[0],
            _ => 0,
        }
    }

    fn advance(&mut self, us: u64) {
        self.now = self.now.add_micros(us);
    }

    /// A browser session up to Confirm with `code`; returns the browser and
    /// the device's Ready (or the failure).
    fn confirm(&mut self, code: &str, seed: u64) -> Result<(Browser, Vec<u8>), Failure> {
        let mut brng = InsecureTestRng::seeded(seed);
        let mut buf = [0u8; MAX_MESSAGE];
        let devpub = self.devpub();
        let (mut browser, n) = Browser::start(
            &self.discover(),
            &Code::parse(code).unwrap(),
            Some(&devpub),
            label::BLE,
            &mut brng,
            &mut buf,
        )?;
        let (reply, _) = self.send(&buf[..n]);
        let n = browser.on_reply(&reply, &mut buf)?;
        let (ready, _) = self.send(&buf[..n]);
        Ok((browser, ready))
    }
}

fn error_code(message: &[u8]) -> Option<ResultCode> {
    (message.len() == 3 && message[1] == kind::ERROR)
        .then(|| ResultCode::from_u8(message[2]).unwrap())
}

fn record(build: impl FnOnce(&mut RecordWriter<'_>)) -> Vec<u8> {
    let mut buf = [0u8; MAX_MESSAGE];
    let mut w = RecordWriter::new(&mut buf);
    build(&mut w);
    let n = w.len();
    buf[..n].to_vec()
}

#[test]
fn a_device_is_set_up_end_to_end() {
    let mut b = Bench::new(false, Reset::PowerOn);
    let d = Discover::read(&b.discover()).unwrap();
    assert!(d.offers_code());
    assert_eq!(d.window_s, WINDOW_UNTIL_PROVISIONED);
    assert_eq!(d.attempts_left, MAX_FAILURES);
    assert_eq!(d.devpub, b.devpub());

    let (mut browser, ready) = b.confirm(CODE, 1).unwrap();
    assert_eq!(b.fails(), 0, "a verified Confirm clears the count");
    let mut scan = [0u8; 256];
    let r = browser.on_ready(&ready, &mut scan).unwrap();
    assert_eq!((r.phase, &scan[..r.scan_len]), (0, SCAN));

    let maker = DeviceKey::from_secret(&[0x22; 32], "maker").unwrap();
    let mut did_buf = [0u8; 64];
    let maker_did = maker.did().write(&mut did_buf).unwrap().to_owned();
    let rec = record(|w| {
        w.network(b"bench-net", b"example-pass-1").unwrap();
        w.name("porch camera").unwrap();
        w.maker(&maker_did).unwrap();
        w.blink_ms(250).unwrap();
        w.fps(12).unwrap();
    });
    let mut buf = [0u8; MAX_MESSAGE];
    let n = browser.send_settings(&rec, &mut buf).unwrap();
    let (result, applied) = b.send(&buf[..n]);
    assert_eq!(
        browser.on_result(&result).unwrap(),
        (ResultCode::Applied, 0)
    );

    let applied = applied.expect("applied");
    let net = applied.network.expect("a network");
    assert_eq!(
        (net.ssid(), net.psk()),
        (&b"bench-net"[..], &b"example-pass-1"[..])
    );
    assert!(!applied.code_rotated && !applied.adopted);
    let mut v = [0u8; 64];
    for (k, want) in [
        (key::SSID, &b"bench-net"[..]),
        (key::PSK, b"example-pass-1"),
        (key::NAME, b"porch camera"),
        (key::MAKER, maker_did.as_bytes()),
        (key::BLINK_MS, &250u32.to_le_bytes()),
        (key::FPS, &[12]),
    ] {
        let n = b.settings.get(k, &mut v).unwrap().unwrap();
        assert_eq!(&v[..n], want, "{k}");
    }
    assert!(!b.device.in_session());
    // provisioned now: after the window, Start is refused
    b.advance(WINDOW_AFTER_RESET_US);
    assert!(!b.device.advertising(b.now, &b.settings));
}

#[test]
fn a_wrong_code_is_counted_even_when_the_guesser_walks_away() {
    let mut b = Bench::new(false, Reset::PowerOn);
    // an honest browser with a wrong code stops at Reply (it cannot verify
    // confirmV) and never sends Confirm; the device counted the Start anyway
    assert_eq!(
        b.confirm("7KXQ3-M9PRV", 2).err(),
        Some(Failure::Local(Error::Crypto))
    );
    assert_eq!(b.fails(), 1);
    b.device.carrier_closed();
    // a hostile browser that sends a Confirm anyway: refused, still one count each
    b.advance(1_000_000);
    let mut brng = InsecureTestRng::seeded(3);
    let mut buf = [0u8; MAX_MESSAGE];
    let (_, n) = Browser::start(
        &b.discover(),
        &Code::parse("00000-00000").unwrap(),
        None,
        label::BLE,
        &mut brng,
        &mut buf,
    )
    .unwrap();
    let (reply, _) = b.send(&buf[..n]);
    assert_eq!(reply[1], kind::REPLY);
    let (answer, _) = b.send(&[
        1,
        kind::CONFIRM,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
        0xAA,
    ]);
    assert_eq!(error_code(&answer), Some(ResultCode::Confirm));
    assert_eq!(b.fails(), 2);
}

#[test]
fn backoff_lockout_and_one_guess_a_power_cycle() {
    let mut b = Bench::new(false, Reset::PowerOn);
    let mut seed = 10;
    let mut wrong = |b: &mut Bench| {
        seed += 1;
        b.confirm("ZZZZZ-ZZZZZ", seed)
    };
    assert!(wrong(&mut b).is_err());
    b.device.carrier_closed();
    // straight away: the 1 s backoff
    assert_eq!(
        wrong(&mut b).err(),
        Some(Failure::Remote(ResultCode::Backoff))
    );
    let mut wait = 1_000_000;
    for f in 2..=MAX_FAILURES {
        b.advance(wait);
        assert!(
            matches!(wrong(&mut b), Err(Failure::Local(Error::Crypto))),
            "failure {f}"
        );
        b.device.carrier_closed();
        assert_eq!(b.fails(), f);
        wait *= 2;
    }
    // five: locked, even with the right code and any wait
    b.advance(3_600_000_000);
    assert!(!b.device.advertising(b.now, &b.settings));
    assert_eq!(Discover::read(&b.discover()).unwrap().attempts_left, 0);
    assert_eq!(
        b.confirm(CODE, 99).err(),
        Some(Failure::Remote(ResultCode::WindowClosed))
    );

    // a reset that is not a power-on changes nothing
    let devpub = b.devpub();
    b.device = Device::new(label::BLE, devpub, Reset::Other, b.now, &mut b.settings).unwrap();
    assert_eq!(
        b.confirm(CODE, 98).err(),
        Some(Failure::Remote(ResultCode::WindowClosed))
    );

    // a power cycle: one guess
    b.device = Device::new(label::BLE, devpub, Reset::PowerOn, b.now, &mut b.settings).unwrap();
    assert_eq!(b.fails(), MAX_FAILURES - 1);
    assert!(wrong(&mut b).is_err());
    b.device.carrier_closed();
    assert_eq!(
        b.confirm(CODE, 97).err(),
        Some(Failure::Remote(ResultCode::WindowClosed))
    );
    // another power cycle, the right code: through, and the count cleared
    b.device = Device::new(label::BLE, devpub, Reset::PowerOn, b.now, &mut b.settings).unwrap();
    assert!(b.confirm(CODE, 96).is_ok());
    assert_eq!(b.fails(), 0);
}

#[test]
fn the_window_on_a_provisioned_device() {
    let mut b = Bench::new(true, Reset::Other);
    assert!(
        !b.device.advertising(b.now, &b.settings),
        "no power-on, no button"
    );
    assert_eq!(
        b.confirm(CODE, 1).err(),
        Some(Failure::Remote(ResultCode::WindowClosed))
    );
    b.device.button(b.now);
    let d = Discover::read(&b.discover()).unwrap();
    assert_eq!(d.window_s, 600);
    b.advance(WINDOW_AFTER_RESET_US - 1);
    assert!(b.device.advertising(b.now, &b.settings));
    b.advance(1);
    assert!(!b.device.advertising(b.now, &b.settings));
    let mut b = Bench::new(true, Reset::PowerOn);
    assert!(b.confirm(CODE, 2).is_ok());
}

#[test]
fn busy_order_and_the_idle_timeout() {
    let mut b = Bench::new(false, Reset::PowerOn);
    let mut brng = InsecureTestRng::seeded(5);
    let mut buf = [0u8; MAX_MESSAGE];
    let devpub = b.devpub();
    let (mut browser, n) = Browser::start(
        &b.discover(),
        &Code::parse(CODE).unwrap(),
        Some(&devpub),
        label::BLE,
        &mut brng,
        &mut buf,
    )
    .unwrap();
    let start = buf[..n].to_vec();
    let (reply, _) = b.send(&start);
    // a second Start mid-session: Busy, and the first session goes on
    b.advance(2_000_000);
    let (busy, _) = b.send(&start);
    assert_eq!(error_code(&busy), Some(ResultCode::Busy));
    let n = browser.on_reply(&reply, &mut buf).unwrap();
    let (ready, _) = b.send(&buf[..n]);
    assert_eq!(ready[1], kind::READY);
    // Confirm again, out of turn: Order, and the session is over
    let (order, _) = b.send(&buf[..n]);
    assert_eq!(error_code(&order), Some(ResultCode::Order));
    assert!(!b.device.in_session());
    // Settings with no session at all: Order
    let (order, _) = b.send(&[1, kind::SETTINGS, 1, 2, 3]);
    assert_eq!(error_code(&order), Some(ResultCode::Order));

    // the idle timeout: a session left after Reply is gone after 60 s
    b.advance(2_000_000);
    let (mut browser, n) = Browser::start(
        &b.discover(),
        &Code::parse(CODE).unwrap(),
        Some(&devpub),
        label::BLE,
        &mut brng,
        &mut buf,
    )
    .unwrap();
    let (reply, _) = b.send(&buf[..n]);
    let n = browser.on_reply(&reply, &mut buf).unwrap();
    b.advance(IDLE_TIMEOUT_US + 1);
    let (late, _) = b.send(&buf[..n]);
    assert_eq!(error_code(&late), Some(ResultCode::Order));
    // a version the device does not speak, and a fragment
    let (v, _) = b.send(&[2, kind::START]);
    assert_eq!(error_code(&v), Some(ResultCode::Version));
    let (m, _) = b.send(&[1]);
    assert_eq!(error_code(&m), Some(ResultCode::Malformed));
}

#[test]
fn a_replay_is_refused_at_reply_and_at_confirm() {
    // record a whole good session
    let mut b = Bench::new(false, Reset::PowerOn);
    let mut brng = InsecureTestRng::seeded(21);
    let mut buf = [0u8; MAX_MESSAGE];
    let devpub = b.devpub();
    let (mut browser, n) = Browser::start(
        &b.discover(),
        &Code::parse(CODE).unwrap(),
        Some(&devpub),
        label::BLE,
        &mut brng,
        &mut buf,
    )
    .unwrap();
    let start = buf[..n].to_vec();
    let (reply, _) = b.send(&start);
    let n = browser.on_reply(&reply, &mut buf).unwrap();
    let confirm = buf[..n].to_vec();
    let (ready, _) = b.send(&confirm);
    let mut scan = [0u8; 256];
    browser.on_ready(&ready, &mut scan).unwrap();
    let rec = record(|w| {
        w.network(b"attacker-net", b"attacker-pass").unwrap();
    });
    let n = browser.send_settings(&rec, &mut buf).unwrap();
    let settings = buf[..n].to_vec();
    let (result, _) = b.send(&settings);
    browser.on_result(&result).unwrap();

    // the device replayed to: the old Start gets a fresh Reply, the old
    // Confirm does not verify against it
    b.advance(1_000_000);
    let (fresh_reply, _) = b.send(&start);
    assert_ne!(fresh_reply, reply);
    let (refused, _) = b.send(&confirm);
    assert_eq!(error_code(&refused), Some(ResultCode::Confirm));

    // the browser replayed to: an old Reply does not verify in a new session
    b.device.carrier_closed();
    b.advance(4_000_000);
    let (mut browser2, _) = Browser::start(
        &b.discover(),
        &Code::parse(CODE).unwrap(),
        Some(&devpub),
        label::BLE,
        &mut brng,
        &mut buf,
    )
    .unwrap();
    assert_eq!(
        browser2.on_reply(&reply, &mut buf).err(),
        Some(Failure::Local(Error::Crypto))
    );

    // an old Settings inside a fresh, legitimate session does not open
    b.advance(8_000_000);
    let (_, _ready) = b.confirm(CODE, 31).unwrap();
    let (refused, applied) = b.send(&settings);
    assert_eq!(error_code(&refused), Some(ResultCode::Seal));
    assert!(applied.is_none());
}

#[test]
fn another_device_is_refused_by_the_browser() {
    let mut b = Bench::new(false, Reset::PowerOn);
    let other = DeviceKey::from_secret(&[0x33; 32], "other").unwrap();
    let mut brng = InsecureTestRng::seeded(4);
    let mut buf = [0u8; MAX_MESSAGE];
    // the portal expects another device: refused before anything is sent
    let r = Browser::start(
        &b.discover(),
        &Code::parse(CODE).unwrap(),
        Some(other.did().pubkey()),
        label::BLE,
        &mut brng,
        &mut buf,
    );
    assert_eq!(r.err(), Some(Failure::Local(Error::Denied)));
    // a device that signs with another key than the one it advertised
    let mut wrong_signer = Bench::new(false, Reset::PowerOn);
    wrong_signer.key = other;
    let devpub = b.devpub();
    let (mut browser, n) = Browser::start(
        &b.discover(),
        &Code::parse(CODE).unwrap(),
        Some(&devpub),
        label::BLE,
        &mut brng,
        &mut buf,
    )
    .unwrap();
    let (reply, _) = wrong_signer.send(&buf[..n]);
    assert_eq!(
        browser.on_reply(&reply, &mut buf).err(),
        Some(Failure::Local(Error::Crypto))
    );
    let _ = &mut b;
}

#[test]
fn a_refused_record_changes_nothing() {
    let cases: Vec<(Vec<u8>, ResultCode)> = vec![
        (
            record(|w| {
                w.name("x").unwrap();
                w.name("y").unwrap();
            }),
            ResultCode::UnknownTag,
        ),
        (vec![0x7E, 0, 1, 0], ResultCode::UnknownTag),
        (vec![0x03, 0, 9, b'a'], ResultCode::Malformed),
        (
            record(|w| {
                w.network(b"net", b"short").unwrap();
            }),
            ResultCode::BadNetwork,
        ),
        (vec![0x01, 0, 3, b'n', b'e', b't'], ResultCode::BadNetwork),
        (
            record(|w| {
                w.name("").unwrap();
            }),
            ResultCode::BadName,
        ),
        (
            record(|w| {
                w.maker("did:mata:notabase58key0OIl").unwrap();
            }),
            ResultCode::BadMaker,
        ),
        (
            record(|w| {
                w.setup_v(&[0u8; 118]).unwrap();
            }),
            ResultCode::BadVerifier,
        ),
        (
            record(|w| {
                w.adoption(b"not an adoption").unwrap();
            }),
            ResultCode::BadAdoption,
        ),
        // a good name with a bad passphrase: the name is not written either
        (
            record(|w| {
                w.name("kept out").unwrap();
                w.network(b"net", b"short").unwrap();
            }),
            ResultCode::BadNetwork,
        ),
    ];
    for (i, (rec, want)) in cases.into_iter().enumerate() {
        let mut b = Bench::new(false, Reset::PowerOn);
        let (mut browser, ready) = b.confirm(CODE, 40 + i as u64).unwrap();
        let mut scan = [0u8; 256];
        browser.on_ready(&ready, &mut scan).unwrap();
        let before = b.settings.len();
        let mut buf = [0u8; MAX_MESSAGE];
        let n = browser.send_settings(&rec, &mut buf).unwrap();
        let (result, applied) = b.send(&buf[..n]);
        assert_eq!(browser.on_result(&result).unwrap().0, want, "case {i}");
        assert!(applied.is_none(), "case {i}");
        assert_eq!(b.settings.len(), before, "case {i}: nothing written");
    }
}

#[test]
fn a_new_code_and_an_adoption() {
    let mut b = Bench::new(false, Reset::PowerOn);
    // the owner's adoption of this device, signed by the owner's key
    let owner = DeviceKey::from_secret(&[0x44; 32], "owner").unwrap();
    let mut dev_did = [0u8; 64];
    let device_did = b.key.did().write(&mut dev_did).unwrap().to_owned();
    let mut own_did = [0u8; 64];
    let owner_did = owner.did().write(&mut own_did).unwrap().to_owned();
    let owner_pub = *owner.did().pubkey();
    let fields = AdoptionFields {
        device_did: &device_did,
        owner_did: &owner_did,
        owner_genesis_pubkey: &owner_pub,
        hub_endpoint_id: &[0u8; 32],
        hub_relay: "",
        hub_host: "",
        caps: CapList::Slice(&[]),
        roster_version: 1,
        issued_at: 1_700_000_000,
        expires_at: 0,
    };
    let mut adoption = [0u8; 400];
    let n = fields.sign_into(&owner, &mut adoption).unwrap();
    let adoption = adoption[..n].to_vec();

    let (mut browser, ready) = b.confirm(CODE, 60).unwrap();
    let mut scan = [0u8; 256];
    browser.on_ready(&ready, &mut scan).unwrap();
    let new_code = "ABCDE-12345";
    let rec = record(|w| {
        w.setup_v(&verifier_record(new_code)).unwrap();
        w.adoption(&adoption).unwrap();
    });
    let mut buf = [0u8; MAX_MESSAGE];
    let n = browser.send_settings(&rec, &mut buf).unwrap();
    let (result, applied) = b.send(&buf[..n]);
    assert_eq!(browser.on_result(&result).unwrap().0, ResultCode::Applied);
    let applied = applied.unwrap();
    assert!(applied.code_rotated && applied.adopted && applied.network.is_none());
    let mut v = [0u8; 400];
    assert_eq!(
        b.identity.get(KV_ADOPTION, &mut v).unwrap(),
        Some(adoption.len())
    );
    assert!(b.identity.get(KV_OWNER_PIN, &mut v).unwrap().is_some());

    // the old code no longer opens the device; the new one does
    b.advance(1_000_000);
    assert!(b.confirm(CODE, 61).is_err());
    b.device.carrier_closed();
    b.advance(2_000_000);
    assert!(b.confirm(new_code, 62).is_ok());

    // an adoption of this device by someone else is refused: the owner is pinned
    let intruder = DeviceKey::from_secret(&[0x55; 32], "intruder").unwrap();
    let mut i_did = [0u8; 64];
    let intruder_did = intruder.did().write(&mut i_did).unwrap().to_owned();
    let intruder_pub = *intruder.did().pubkey();
    let fields = AdoptionFields {
        owner_did: &intruder_did,
        owner_genesis_pubkey: &intruder_pub,
        roster_version: 2,
        ..fields
    };
    let mut other = [0u8; 400];
    let n = fields.sign_into(&intruder, &mut other).unwrap();
    let mut b = b;
    b.device.carrier_closed();
    b.advance(1_000_000);
    let (mut browser, ready) = b.confirm(new_code, 63).unwrap();
    browser.on_ready(&ready, &mut scan).unwrap();
    let rec = record(|w| {
        w.adoption(&other[..n]).unwrap();
    });
    let n = browser.send_settings(&rec, &mut buf).unwrap();
    let (result, _) = b.send(&buf[..n]);
    assert_eq!(
        browser.on_result(&result).unwrap().0,
        ResultCode::BadAdoption
    );
}

#[test]
fn a_store_that_fails_mid_record_says_so() {
    struct Failing(MemoryKv, usize);
    impl Kv for Failing {
        fn get(&self, k: &str, out: &mut [u8]) -> rusty_esp_core::error::Result<Option<usize>> {
            self.0.get(k, out)
        }
        fn put(&mut self, k: &str, v: &[u8]) -> rusty_esp_core::error::Result<()> {
            if k == key::NAME {
                return Err(Error::Hardware);
            }
            self.1 += 1;
            self.0.put(k, v)
        }
        fn remove(&mut self, k: &str) -> rusty_esp_core::error::Result<bool> {
            self.0.remove(k)
        }
    }
    let mut b = Bench::new(false, Reset::PowerOn);
    let (mut browser, ready) = b.confirm(CODE, 70).unwrap();
    let mut scan = [0u8; 256];
    browser.on_ready(&ready, &mut scan).unwrap();
    let rec = record(|w| {
        w.name("cannot be stored").unwrap();
    });
    let mut buf = [0u8; MAX_MESSAGE];
    let n = browser.send_settings(&rec, &mut buf).unwrap();
    let mut settings = Failing(core::mem::take(&mut b.settings), 0);
    let mut out = [0u8; MAX_MESSAGE];
    let answer = b
        .device
        .on_message(
            &buf[..n],
            b.now,
            &mut settings,
            &mut b.identity,
            &mut b.rng,
            &b.key,
            &Status {
                phase: 0,
                scan: &[],
            },
            &mut out,
        )
        .unwrap();
    assert_eq!(
        browser.on_result(&out[..answer.len]).unwrap().0,
        ResultCode::StoreFailed
    );
    assert!(answer.applied.is_none());
}

#[test]
fn a_device_cannot_make_the_browser_spin() {
    let b = Bench::new(false, Reset::PowerOn);
    let mut d = Discover::read(&b.discover()).unwrap();
    d.iterations = u32::MAX;
    let mut msg = [0u8; 64];
    let n = d.write(&mut msg).unwrap();
    let mut brng = InsecureTestRng::seeded(1);
    let mut buf = [0u8; MAX_MESSAGE];
    let t = std::time::Instant::now();
    let r = Browser::start(
        &msg[..n],
        &Code::parse(CODE).unwrap(),
        None,
        label::BLE,
        &mut brng,
        &mut buf,
    );
    assert_eq!(r.err(), Some(Failure::Local(Error::InvalidFormat)));
    assert!(
        t.elapsed() < std::time::Duration::from_millis(100),
        "refused before any PBKDF2"
    );
}

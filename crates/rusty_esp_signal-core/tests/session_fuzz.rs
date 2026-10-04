//! enc-ble M2: the setup session's robustness gate, in `no_panic.rs`'s
//! shape. Every decoder, the device's state machine in each of its states
//! and the browser at each of its steps take random bytes and mutations of a
//! recorded good session; none panics, the device always answers with a
//! message no longer than `MAX_MESSAGE`, and nothing reaches the settings
//! store unless a whole, sealed, valid record does.

use std::panic::{AssertUnwindSafe, catch_unwind};

use rusty_esp_core::Micros;
use rusty_esp_core::hal::Kv;
use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_signal_core::mid::key::DeviceKey;
use rusty_esp_signal_core::setup::device::key;
use rusty_esp_signal_core::setup::message::split;
use rusty_esp_signal_core::setup::{
    Browser, Code, Device, Discover, MAX_MESSAGE, Record, RecordWriter, Reset, Secrets, Status,
    Verifier, label,
};

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let n = self.below(max_len + 1);
        (0..n).map(|_| (self.next() >> 56) as u8).collect()
    }

    fn mutate(&mut self, base: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        match self.below(6) {
            0 if !v.is_empty() => {
                let i = self.below(v.len());
                v[i] ^= 1 << self.below(8);
            }
            1 if !v.is_empty() => {
                let i = self.below(v.len());
                v.truncate(i);
            }
            2 => v.extend(self.bytes(32)),
            3 if !v.is_empty() => {
                let i = self.below(v.len());
                v[i] = (self.next() >> 56) as u8;
            }
            4 if v.len() > 2 => {
                v[1] = (self.next() >> 56) as u8; // another kind
            }
            _ => {
                let i = self.below(v.len() + 1);
                v.insert(i, (self.next() >> 56) as u8);
            }
        }
        v
    }
}

const CODE: &str = "7KXQ3-M9PRT";
const SALT: [u8; 16] = *b"janus-fuzz-salt!";

fn settings_store() -> MemoryKv {
    let secrets = Secrets::derive(&Code::parse(CODE).unwrap(), &SALT, 1_000).unwrap();
    let mut kv = MemoryKv::new();
    kv.put(
        key::SETUP_V,
        &Verifier::from_secrets(&secrets, &SALT, 1_000).encode(),
    )
    .unwrap();
    kv
}

/// One recorded good session: every message both ways.
struct Recorded {
    discover: Vec<u8>,
    start: Vec<u8>,
    reply: Vec<u8>,
    confirm: Vec<u8>,
    ready: Vec<u8>,
    settings: Vec<u8>,
    result: Vec<u8>,
}

fn record_session(dev_key: &DeviceKey) -> Recorded {
    let mut kv = settings_store();
    let mut identity = MemoryKv::new();
    let now = Micros::from_secs(1);
    let mut device = Device::new(
        label::BLE,
        *dev_key.did().pubkey(),
        Reset::PowerOn,
        now,
        &mut kv,
    )
    .unwrap();
    let mut rng = InsecureTestRng::seeded(1);
    let mut brng = InsecureTestRng::seeded(2);
    let status = Status {
        phase: 0,
        scan: &[1, 3, b'n', b'e', b't'],
    };
    let mut out = [0u8; MAX_MESSAGE];
    let mut buf = [0u8; MAX_MESSAGE];
    let n = device.discover(now, &kv, &mut out).unwrap();
    let discover = out[..n].to_vec();
    let (mut browser, n) = Browser::start(
        &discover,
        &Code::parse(CODE).unwrap(),
        None,
        label::BLE,
        &mut brng,
        &mut buf,
    )
    .unwrap();
    let start = buf[..n].to_vec();
    let mut send = |device: &mut Device, kv: &mut MemoryKv, msg: &[u8]| {
        let a = device
            .on_message(
                msg,
                now,
                kv,
                &mut identity,
                &mut rng,
                dev_key,
                &status,
                &mut out,
            )
            .unwrap();
        out[..a.len].to_vec()
    };
    let reply = send(&mut device, &mut kv, &start);
    let n = browser.on_reply(&reply, &mut buf).unwrap();
    let confirm = buf[..n].to_vec();
    let ready = send(&mut device, &mut kv, &confirm);
    browser.on_ready(&ready, &mut [0u8; 256]).unwrap();
    let mut rec = [0u8; 128];
    let mut w = RecordWriter::new(&mut rec);
    w.network(b"fuzz-net", b"fuzz-pass-1")
        .unwrap()
        .name("fuzz")
        .unwrap();
    let rn = w.len();
    let n = browser.send_settings(&rec[..rn], &mut buf).unwrap();
    let settings = buf[..n].to_vec();
    let result = send(&mut device, &mut kv, &settings);
    browser.on_result(&result).unwrap();
    Recorded {
        discover,
        start,
        reply,
        confirm,
        ready,
        settings,
        result,
    }
}

fn guard(what: &str, input: &[u8], f: impl FnOnce()) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        panic!("{what} panicked on {input:02x?}");
    }
}

#[test]
fn decoders_never_panic() {
    let dev_key = DeviceKey::from_secret(&[0x11; 32], "fuzz").unwrap();
    let rec = record_session(&dev_key);
    let mut rng = Lcg(0x5EED_0001);
    let mut good_record = [0u8; 128];
    let mut w = RecordWriter::new(&mut good_record);
    w.network(b"n", b"password")
        .unwrap()
        .blink_ms(5)
        .unwrap()
        .fps(9)
        .unwrap();
    let gr = w.len();
    let bases: [&[u8]; 4] = [
        &rec.discover,
        &good_record[..gr],
        &settings_store_record(),
        &rec.start,
    ];
    for _ in 0..20_000 {
        let pick = rng.below(bases.len());
        let input = if rng.below(3) == 0 {
            rng.bytes(600)
        } else {
            rng.mutate(bases[pick])
        };
        guard("split", &input, || {
            let _ = split(&input);
        });
        guard("Discover::read", &input, || {
            let _ = Discover::read(&input);
        });
        guard("Record::decode", &input, || {
            let _ = Record::decode(&input);
        });
        guard("Verifier::decode", &input, || {
            let _ = Verifier::decode(&input);
        });
        guard("Code::parse", &input, || {
            if let Ok(s) = core::str::from_utf8(&input) {
                let _ = Code::parse(s);
            }
        });
    }
}

fn settings_store_record() -> Vec<u8> {
    let mut v = [0u8; 118];
    settings_store().get(key::SETUP_V, &mut v).unwrap();
    v.to_vec()
}

#[test]
fn the_device_never_panics_and_never_half_applies() {
    let dev_key = DeviceKey::from_secret(&[0x11; 32], "fuzz").unwrap();
    let rec = record_session(&dev_key);
    let mut lcg = Lcg(0x5EED_0002);
    let messages = [&rec.start, &rec.confirm, &rec.settings];
    for round in 0..3_000 {
        let mut kv = settings_store();
        let mut identity = MemoryKv::new();
        let mut now = Micros::from_secs(1);
        let mut device = Device::new(
            label::BLE,
            *dev_key.did().pubkey(),
            Reset::PowerOn,
            now,
            &mut kv,
        )
        .unwrap();
        let mut rng = InsecureTestRng::seeded(round);
        let status = Status {
            phase: 1,
            scan: &[],
        };
        let mut out = [0u8; MAX_MESSAGE];
        // walk the device into a state with real messages, then fuzz it there
        let depth = lcg.below(3);
        let mut brng = InsecureTestRng::seeded(round ^ 0xABCD);
        let mut buf = [0u8; MAX_MESSAGE];
        let (mut browser, n) = Browser::start(
            &rec.discover,
            &Code::parse(CODE).unwrap(),
            None,
            label::BLE,
            &mut brng,
            &mut buf,
        )
        .unwrap();
        if depth >= 1 {
            let a = device
                .on_message(
                    &buf[..n],
                    now,
                    &mut kv,
                    &mut identity,
                    &mut rng,
                    &dev_key,
                    &status,
                    &mut out,
                )
                .unwrap();
            if depth >= 2 {
                let reply = out[..a.len].to_vec();
                let n = browser.on_reply(&reply, &mut buf).unwrap();
                device
                    .on_message(
                        &buf[..n],
                        now,
                        &mut kv,
                        &mut identity,
                        &mut rng,
                        &dev_key,
                        &status,
                        &mut out,
                    )
                    .unwrap();
            }
        }
        for _ in 0..8 {
            let pick = lcg.below(messages.len());
            let input = if lcg.below(4) == 0 {
                lcg.bytes(600)
            } else {
                lcg.mutate(messages[pick])
            };
            now = now.add_micros(lcg.below(3_000_000) as u64);
            let before_ssid = kv.get(key::SSID, &mut [0u8; 64]).unwrap();
            let mut answer = None;
            guard("Device::on_message", &input, || {
                answer = Some(
                    device
                        .on_message(
                            &input,
                            now,
                            &mut kv,
                            &mut identity,
                            &mut rng,
                            &dev_key,
                            &status,
                            &mut out,
                        )
                        .unwrap(),
                );
            });
            let answer = answer.unwrap();
            assert!(
                answer.len >= 3 && answer.len <= MAX_MESSAGE,
                "answer of {} bytes",
                answer.len
            );
            if answer.applied.is_none() {
                assert_eq!(
                    kv.get(key::SSID, &mut [0u8; 64]).unwrap(),
                    before_ssid,
                    "a write without a Result"
                );
            }
        }
    }
}

#[test]
fn the_browser_never_panics() {
    let dev_key = DeviceKey::from_secret(&[0x11; 32], "fuzz").unwrap();
    let rec = record_session(&dev_key);
    let mut lcg = Lcg(0x5EED_0003);
    let answers = [&rec.reply, &rec.ready, &rec.result, &rec.discover];
    for round in 0..3_000 {
        let mut brng = InsecureTestRng::seeded(round);
        let mut buf = [0u8; MAX_MESSAGE];
        let discover = if lcg.below(5) == 0 {
            lcg.mutate(&rec.discover)
        } else {
            rec.discover.clone()
        };
        let mut started = None;
        guard("Browser::start", &discover, || {
            started = Some(Browser::start(
                &discover,
                &Code::parse(CODE).unwrap(),
                None,
                label::BLE,
                &mut brng,
                &mut buf,
            ));
        });
        let Some(Ok((mut browser, _))) = started else {
            continue;
        };
        for _ in 0..4 {
            let pick = lcg.below(answers.len());
            let input = if lcg.below(4) == 0 {
                lcg.bytes(600)
            } else {
                lcg.mutate(answers[pick])
            };
            guard("Browser::on_*", &input, || {
                let mut scan = [0u8; 256];
                match lcg.below(4) {
                    0 => {
                        let _ = browser.on_reply(&input, &mut buf);
                    }
                    1 => {
                        let _ = browser.on_ready(&input, &mut scan);
                    }
                    2 => {
                        let _ = browser.send_settings(&input, &mut buf);
                    }
                    _ => {
                        let _ = browser.on_result(&input);
                    }
                }
            });
        }
    }
}

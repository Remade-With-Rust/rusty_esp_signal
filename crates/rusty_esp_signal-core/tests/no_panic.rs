//! The robustness gate: every parser fed from a radio, a UART or a phone
//! returns an error on bad input; it never panics. Random inputs from an
//! LCG and mutations of valid encodings, under `catch_unwind` so a failure
//! names the parser and prints the input.

use std::panic::{AssertUnwindSafe, catch_unwind};

use rusty_esp_signal_core::link::Envelope;
use rusty_esp_signal_core::lora::Beacon;
use rusty_esp_signal_core::provision::{ScanEntry, ScanList};
use rusty_esp_signal_core::radar::ld2410::{Ack, Frame, Parser, Report};
use rusty_esp_signal_core::wifi::Credentials;

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
                v[i] = (self.next() >> 56) as u8;
            }
            2 => v.truncate(self.below(v.len() + 1)),
            3 => {
                let extra = self.bytes(16);
                v.extend_from_slice(&extra);
            }
            4 => {
                let i = self.below(v.len() + 1);
                v.insert(i, (self.next() >> 56) as u8);
            }
            _ if !v.is_empty() => {
                let i = self.below(v.len());
                v.remove(i);
            }
            _ => {}
        }
        v
    }
}

fn check<R>(name: &str, input: &[u8], f: impl FnOnce() -> R) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
        panic!("{name} panicked on {} bytes: {hex}", input.len());
    }
}

#[test]
fn provisioning_and_credential_decoders_never_panic() {
    let mut rng = Lcg(0x5165_0001);
    let creds = Credentials::new(b"home-net", b"correct horse battery").unwrap();
    let mut cbuf = [0u8; 128];
    let cn = creds.encode(&mut cbuf).unwrap();
    let valid_creds = cbuf[..cn].to_vec();
    let mut list: ScanList<4> = ScanList::new();
    list.push(ScanEntry::new(b"one", -40, true).unwrap());
    list.push(ScanEntry::new(&[b'x'; 32], -70, false).unwrap());
    let mut sbuf = [0u8; 240];
    let sn = list.encode(&mut sbuf).unwrap();
    let valid_scan = sbuf[..sn].to_vec();

    for i in 0..20_000 {
        let input = match i % 3 {
            0 => rng.bytes(260),
            1 => rng.mutate(&valid_creds),
            _ => rng.mutate(&valid_scan),
        };
        check("Credentials::decode", &input, || {
            Credentials::decode(&input).map(|c| (c.kind(), c.encoded_len()))
        });
        check("ScanEntry::decode", &input, || {
            ScanEntry::decode(&input).map(|_| ())
        });
        check("ScanList::decode", &input, || {
            ScanList::<4>::decode(&input).map(|l| {
                let mut out = [0u8; 240];
                let _ = l.encode(&mut out);
            })
        });
    }
}

#[test]
fn link_envelope_and_lora_beacon_never_panic() {
    let mut rng = Lcg(0x5165_0002);
    let beacon = Beacon::new([2u8; 33], 30, Beacon::FLAG_ACCEPTS_HANDSHAKE);
    let mut bbuf = [0u8; 64];
    let bn = beacon.encode(&mut bbuf).unwrap();
    let valid_beacon = bbuf[..bn].to_vec();
    for i in 0..30_000 {
        let input = if i % 2 == 0 {
            rng.bytes(260)
        } else {
            rng.mutate(&valid_beacon)
        };
        check("Envelope::parse", &input, || {
            Envelope::parse(&input).map(|e| e.payload.len())
        });
        check("Beacon::decode", &input, || {
            Beacon::decode(&input).map(|_| ())
        });
    }
}

#[test]
fn ld2410_parsers_never_panic() {
    let mut rng = Lcg(0x5165_0003);
    // a report frame skeleton the parser recognises, mutated
    let mut report = vec![0xF4, 0xF3, 0xF2, 0xF1, 0x0D, 0x00, 0x02, 0xAA];
    report.extend_from_slice(&[
        0x02, 0x50, 0x00, 0x38, 0x00, 0x60, 0x00, 0x39, 0x00, 0x55, 0x00,
    ]);
    report.extend_from_slice(&[0xF8, 0xF7, 0xF6, 0xF5]);
    let mut parser = Parser::new();
    for i in 0..20_000 {
        let input = match i % 3 {
            0 => rng.bytes(200),
            _ => rng.mutate(&report),
        };
        check("Frame::parse", &input, || Frame::parse(&input).map(|_| ()));
        check("Report::parse", &input, || {
            Report::parse(&input).map(|_| ())
        });
        check("Ack::parse", &input, || Ack::parse(&input).map(|_| ()));
        check("Parser::feed_slice", &input, || {
            let mut rest: &[u8] = &input;
            while !rest.is_empty() {
                let (n, frame) = parser.feed_slice(rest);
                let _ = frame.map(|f| matches!(f, Frame::Report(_)));
                rest = &rest[n.max(1).min(rest.len())..];
            }
        });
    }
    let stats = parser.stats();
    assert!(
        stats.frames + stats.resyncs > 0,
        "the stream was actually parsed"
    );
}

/// `feed_slice` takes whole DATA runs in one move; `feed` still walks a byte
/// at a time. They must agree on every split of every input, which is the
/// property the bulk arm has to preserve and the one a fuzzer cannot state.
#[test]
fn feed_slice_agrees_with_feed_on_every_split() {
    use rusty_esp_signal_core::radar::ld2410::{Parser, REPORT_HEADER};

    // Two real reports back to back, a resync in the middle, and a truncated
    // third -- so DATA runs get split at every offset by the chunking below.
    let mut stream: Vec<u8> = Vec::new();
    stream.extend_from_slice(&[
        0xF4, 0xF3, 0xF2, 0xF1, 0x23, 0x00, 0x01, 0xAA, 0x03, 0x1E, 0x00, 0x3C, 0x00, 0x00, 0x39,
        0x00, 0x00, 0x08, 0x08, 0x3C, 0x22, 0x05, 0x03, 0x03, 0x04, 0x03, 0x06, 0x05, 0x00, 0x00,
        0x39, 0x10, 0x13, 0x06, 0x06, 0x08, 0x04, 0x03, 0x05, 0x55, 0x00, 0xF8, 0xF7, 0xF6, 0xF5,
    ]);
    stream.extend_from_slice(&[0x11, 0x22, 0x33]); // garbage between frames
    stream.extend_from_slice(&[
        0xF4, 0xF3, 0xF2, 0xF1, 0x0D, 0x00, 0x02, 0xAA, 0x02, 0x51, 0x00, 0x00, 0x00, 0x00, 0x3B,
        0x00, 0x00, 0x55, 0x00, 0xF8, 0xF7, 0xF6, 0xF5,
    ]);
    stream.extend_from_slice(&REPORT_HEADER);
    stream.extend_from_slice(&[0x23, 0x00, 0x01, 0xAA]); // truncated data

    // Byte at a time through `feed`, recording every frame's raw payload.
    let mut one = Parser::new();
    let mut by_byte: Vec<String> = Vec::new();
    for &b in &stream {
        if let Some(f) = one.feed(b) {
            by_byte.push(format!("{f:?}"));
        }
    }

    // And through `feed_slice`, at every chunk size, which lands a DATA run's
    // boundary at a different offset each time.
    for chunk in 1..=stream.len() {
        let mut p = Parser::new();
        let mut got: Vec<String> = Vec::new();
        let mut at = 0usize;
        while at < stream.len() {
            let end = (at + chunk).min(stream.len());
            let (used, frame) = p.feed_slice(&stream[at..end]);
            if let Some(f) = frame {
                got.push(format!("{f:?}"));
            }
            assert!(used > 0, "feed_slice must always consume at chunk={chunk}");
            at += used;
        }
        assert_eq!(
            got, by_byte,
            "feed_slice disagreed with feed at chunk={chunk}"
        );
        assert_eq!(
            p.stats().frames,
            one.stats().frames,
            "frame count, chunk={chunk}"
        );
        assert_eq!(
            p.stats().resyncs,
            one.stats().resyncs,
            "resyncs, chunk={chunk}"
        );
    }
}

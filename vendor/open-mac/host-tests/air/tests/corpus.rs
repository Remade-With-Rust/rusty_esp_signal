//! E2's A3: a no-panic corpus over the open MAC's receive path. Valid
//! frames (synthetic, built here, and the `ieee80211` crate's own published
//! fixtures in `ieee80211/bins/`, already in the tree; nothing captured
//! from a real network, D-E2a), mutated with a fixed seed, each run through
//! the chain FoA's station runs on bytes off the air: `GenericFrame::new`,
//! the typed parse by frame type, the elements it reads, a data frame's
//! payload and LLC/SNAP and A-MSDU subframes, and the EAPOL deserialiser
//! with and without keys. Property: no input panics. `E2_CORPUS_ROUNDS`
//! (default 20,000 a seed) sets the length; CI runs the default.

use std::panic::{AssertUnwindSafe, catch_unwind};

use ieee80211::GenericFrame;
use ieee80211::common::FrameType;
use ieee80211::common::ManagementFrameSubtype;
use ieee80211::crypto::{MicState, deserialize_eapol_data_frame};
use ieee80211::data_frame::{DataFrame, DataFrameReadPayload, PotentiallyWrappedPayload};
use ieee80211::elements::kde::GtkKde;
use ieee80211::elements::rsn::{IEEE80211AkmType, RsnElement};
use ieee80211::elements::{BSSLoadElement, DSSSParameterSetElement, ReadElements, SSIDElement};
use ieee80211::mgmt_frame::{
    AssociationResponseFrame, AuthenticationFrame, BeaconFrame, DeauthenticationFrame,
    DisassociationFrame, ProbeResponseFrame,
};
use ieee80211::scroll::Pread;
use llc_rs::SnapLlcFrame;

/// xorshift64*: a fixed sequence, so a failure reproduces from its seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn header(fc0: u8, fc1: u8) -> Vec<u8> {
    let mut f = vec![fc0, fc1, 0, 0];
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    f.extend_from_slice(&[0x10, 0]);
    f
}

fn element(id: u8, body: &[u8]) -> Vec<u8> {
    let mut e = vec![id, body.len() as u8];
    e.extend_from_slice(body);
    e
}

/// WPA2-PSK, CCMP for both ciphers.
fn rsn() -> Vec<u8> {
    let mut b = vec![1, 0];
    b.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    b.extend_from_slice(&[1, 0, 0x00, 0x0f, 0xac, 4]);
    b.extend_from_slice(&[1, 0, 0x00, 0x0f, 0xac, 2]);
    b.extend_from_slice(&[0x0c, 0]);
    element(48, &b)
}

fn beacon_elements() -> Vec<u8> {
    let mut e = element(0, b"janus-test");
    e.extend(element(
        1,
        &[0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24],
    ));
    e.extend(element(3, &[6]));
    e.extend(element(5, &[0, 1, 0, 0]));
    e.extend(rsn());
    e.extend(element(11, &[1, 0, 0x20, 0, 0]));
    e.extend(element(
        221,
        &[0x00, 0x50, 0xf2, 2, 1, 1, 0, 0, 3, 0xa4, 0, 0],
    ));
    e
}

fn eapol_key(info: u16, key_data: &[u8]) -> Vec<u8> {
    let mut e = vec![2, 3];
    e.extend_from_slice(&((95 + key_data.len()) as u16).to_be_bytes());
    e.push(2);
    e.extend_from_slice(&info.to_be_bytes());
    e.extend_from_slice(&16u16.to_be_bytes());
    e.extend_from_slice(&1u64.to_be_bytes());
    e.extend_from_slice(&[0x11; 32]);
    e.extend_from_slice(&[0; 32]);
    e.extend_from_slice(&[0; 16]);
    e.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
    e.extend_from_slice(key_data);
    e
}

fn data(fc0: u8, fc1: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = header(fc0, fc1);
    if fc0 & 0x80 != 0 {
        f.extend_from_slice(&[0, 0]); // QoS control
    }
    f.extend_from_slice(payload);
    f
}

fn llc(ether_type: u16, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0xaa, 0xaa, 0x03, 0, 0, 0];
    p.extend_from_slice(&ether_type.to_be_bytes());
    p.extend_from_slice(body);
    p
}

fn seeds() -> Vec<(&'static str, Vec<u8>)> {
    let mut s = Vec::new();
    // beacon and probe response: timestamp, interval, capabilities, elements
    let fixed = [0u8; 8]
        .iter()
        .chain(&[0x64, 0, 0x11, 0x04])
        .copied()
        .collect::<Vec<_>>();
    let mut b = header(0x80, 0);
    b.extend(&fixed);
    b.extend(beacon_elements());
    s.push(("beacon", b));
    let mut p = header(0x50, 0);
    p.extend(&fixed);
    p.extend(beacon_elements());
    s.push(("probe response", p));
    // authentication (open system, sequence 2, success)
    let mut a = header(0xb0, 0);
    a.extend_from_slice(&[0, 0, 2, 0, 0, 0]);
    s.push(("authentication", a));
    // association response: capabilities, status, AID, rates
    let mut r = header(0x10, 0);
    r.extend_from_slice(&[0x11, 0x04, 0, 0, 0x01, 0xc0]);
    r.extend(element(1, &[0x82, 0x84, 0x8b, 0x96]));
    s.push(("association response", r));
    let mut d = header(0xc0, 0);
    d.extend_from_slice(&[7, 0]);
    s.push(("deauthentication", d));
    let mut x = header(0xa0, 0);
    x.extend_from_slice(&[8, 0]);
    s.push(("disassociation", x));
    // EAPOL message 1, message 3 (encrypted key data, MIC), group message 1
    s.push((
        "eapol message 1",
        data(0x08, 0x02, &llc(0x888e, &eapol_key(0x008a, &[]))),
    ));
    s.push((
        "eapol message 3",
        data(0x08, 0x02, &llc(0x888e, &eapol_key(0x13ca, &[0x5a; 56]))),
    ));
    s.push((
        "eapol group 1",
        data(0x08, 0x42, &llc(0x888e, &eapol_key(0x1382, &[0x5a; 40]))),
    ));
    // data: IPv4 plain, protected (CCMP header), QoS, A-MSDU
    s.push(("data", data(0x08, 0x02, &llc(0x0800, &[0x45; 40]))));
    let mut ccmp = vec![1, 0, 0, 0x20, 0, 0, 0, 0];
    ccmp.extend(llc(0x0800, &[0x45; 40]));
    s.push(("protected data", data(0x08, 0x42, &ccmp)));
    s.push(("qos data", data(0x88, 0x02, &llc(0x0806, &[1; 28]))));
    let mut sub = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 9];
    let inner = llc(0x0800, &[0x45; 20]);
    sub.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    sub.extend(inner);
    let mut amsdu = data(0x88, 0x02, &[]);
    let qos = amsdu.len() - 2;
    amsdu[qos] |= 0x80; // the A-MSDU present bit
    amsdu.extend(&sub);
    amsdu.extend(&sub);
    s.push(("a-msdu", amsdu));
    // the crate's own published fixtures
    let bins = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ieee80211/bins/frames");
    for entry in std::fs::read_dir(bins).expect("ieee80211/bins/frames") {
        let path = entry.unwrap().path();
        s.push(("fixture", std::fs::read(&path).unwrap()));
    }
    s
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut f = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        match rng.below(8) {
            0 if !f.is_empty() => {
                let i = rng.below(f.len());
                f[i] ^= 1 << rng.below(8);
            }
            1 if !f.is_empty() => {
                let i = rng.below(f.len());
                f[i] = rng.next() as u8;
            }
            2 => f.truncate(rng.below(f.len() + 1)),
            3 => {
                let n = rng.below(16);
                for _ in 0..n {
                    f.push(rng.next() as u8);
                }
            }
            4 if f.len() > 1 => {
                // a length field that lies: a byte set to an extreme
                let i = rng.below(f.len());
                f[i] = [0, 1, 0x7f, 0x80, 0xfe, 0xff][rng.below(6)];
            }
            5 if !f.is_empty() => {
                // repeat a slice (elements twice, overruns)
                let a = rng.below(f.len());
                let b = (a + rng.below(32)).min(f.len());
                let piece = f[a..b].to_vec();
                let at = rng.below(f.len() + 1);
                f.splice(at..at, piece);
            }
            6 if f.len() > 2 => {
                // the frame control field: another type, other flags
                f[0] = rng.next() as u8;
                f[1] = rng.next() as u8;
            }
            _ => {
                let n = rng.below(64);
                f = (0..n).map(|_| rng.next() as u8).collect();
            }
        }
    }
    f
}

fn elements(e: ReadElements<'_>) {
    let _ = e.get_first_element::<SSIDElement>();
    let _ = e.get_first_element::<RsnElement>();
    let _ = e.get_first_element::<DSSSParameterSetElement>();
    let _ = e.get_first_element::<BSSLoadElement>();
    let _ = e.get_first_element::<GtkKde>();
    for raw in e.raw_element_iterator() {
        let _ = raw;
    }
}

/// The receive path on `bytes`, as the station runs it.
fn receive(bytes: &[u8]) {
    let Ok(generic) = GenericFrame::new(bytes, false) else {
        return;
    };
    let _ = generic.address_1();
    let eapol = generic.is_eapol_key_frame();
    match generic.frame_control_field().frame_type() {
        FrameType::Management(ManagementFrameSubtype::Beacon) => {
            if let Ok(f) = bytes.pread::<BeaconFrame>(0) {
                elements(f.elements);
            }
        }
        FrameType::Management(ManagementFrameSubtype::ProbeResponse) => {
            if let Ok(f) = bytes.pread::<ProbeResponseFrame>(0) {
                elements(f.elements);
            }
        }
        FrameType::Management(ManagementFrameSubtype::Authentication) => {
            let _ = bytes.pread::<AuthenticationFrame>(0);
        }
        FrameType::Management(ManagementFrameSubtype::AssociationResponse) => {
            if let Ok(f) = bytes.pread::<AssociationResponseFrame>(0) {
                elements(f.elements);
            }
        }
        FrameType::Management(ManagementFrameSubtype::Deauthentication) => {
            let _ = bytes.pread::<DeauthenticationFrame>(0);
        }
        FrameType::Management(ManagementFrameSubtype::Disassociation) => {
            let _ = bytes.pread::<DisassociationFrame>(0);
        }
        FrameType::Data(_) => {
            if let Some(Ok(d)) = generic.parse_to_typed::<DataFrame<'_, &[u8]>>() {
                let _ = d.header.destination_address();
                let _ = d.header.source_address();
                for mic in [MicState::NotPresent, MicState::Short] {
                    let Some(w) = d.potentially_wrapped_payload(Some(mic)) else {
                        continue;
                    };
                    let payload = match w {
                        PotentiallyWrappedPayload::Unwrapped(p) => p,
                        PotentiallyWrappedPayload::CryptoWrapped(c) => c.payload,
                    };
                    match payload {
                        DataFrameReadPayload::Single(p) => {
                            let _ = p.pread::<SnapLlcFrame>(0);
                        }
                        DataFrameReadPayload::AMSDU(it) => {
                            for sub in it {
                                let _ = sub.payload.pread::<SnapLlcFrame>(0);
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    if eapol {
        let mut scratch = [0u8; 512];
        for keys in [false, true] {
            let mut copy = bytes.to_vec();
            let (kck, kek) = ([0x42u8; 16], [0x24u8; 16]);
            let _ = if keys {
                deserialize_eapol_data_frame(
                    Some(&kck),
                    Some(&kek),
                    &mut copy,
                    &mut scratch,
                    IEEE80211AkmType::Psk,
                    false,
                )
            } else {
                deserialize_eapol_data_frame(
                    None,
                    None,
                    &mut copy,
                    &mut [],
                    IEEE80211AkmType::Psk,
                    false,
                )
            };
        }
    }
}

#[test]
fn no_input_panics_the_receive_path() {
    let rounds: usize = std::env::var("E2_CORPUS_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let seeds = seeds();
    // the hook keeps where each panic happened, for the report
    std::panic::set_hook(Box::new(|info| {
        let at = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        WHERE.with(|w| *w.borrow_mut() = at);
    }));
    let mut failures = Vec::new();
    for (k, (name, seed)) in seeds.iter().enumerate() {
        // every seed first, unmutated
        if catch_unwind(AssertUnwindSafe(|| receive(seed))).is_err() {
            failures.push(format!("{name}: the seed itself"));
        }
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (k as u64 + 1));
        for round in 0..rounds {
            let input = mutate(&mut rng, seed);
            if let Err(p) = catch_unwind(AssertUnwindSafe(|| receive(&input))) {
                let why = p
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_default();
                let at = WHERE.with(|w| w.borrow().clone());
                failures.push(format!(
                    "{name} round {round}: {why}\n    at {at}\n    input {}",
                    hex(&input)
                ));
                if failures.len() > 40 {
                    break;
                }
            }
        }
    }
    let _ = std::panic::take_hook();
    assert!(
        failures.is_empty(),
        "{} panics:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

thread_local! {
    static WHERE: std::cell::RefCell<String> = const { std::cell::RefCell::new(String::new()) };
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

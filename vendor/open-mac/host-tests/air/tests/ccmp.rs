//! P2's CCMP encapsulation (`ap_core::ccmp`) against a second
//! implementation: `interop/ccmp.py` builds the additional data and the nonce
//! from 802.11-2020 clause 12.5.3 with nothing shared with the Rust, and
//! takes its AEAD from `cryptography` (OpenSSL) rather than our CCM. Every
//! frame below must come out of both byte for byte.
//!
//! The frames are chosen for what can differ without anyone noticing: bodies
//! that are and are not whole blocks, a one-octet body, a long one, both QoS
//! and not, the four-address shape bridge forwarding sends, a packet number
//! near the top of its 48 bits, a nonzero fragment number, and a frame with
//! every maskable header bit set -- that last one is the only way a wrong
//! mask in either implementation shows up as a different MIC.
//!
//! Needs Python 3 with `cryptography` (`pip install cryptography`); CI
//! installs it. Not Wi-Fi certified.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};

use ap_core::ccmp;

const TK: [u8; 16] = [
    0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85, 0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f,
];

/// A Python that has `cryptography`: `E2_PYTHON` if set, else the first of
/// `python3`, `python` that imports it (a machine may have several).
fn python() -> Command {
    let candidates = std::env::var("E2_PYTHON")
        .map(|p| vec![p])
        .unwrap_or_else(|_| vec!["python3".into(), "python".into()]);
    for name in &candidates {
        let has = Command::new(name)
            .args(["-c", "import cryptography"])
            .output()
            .is_ok_and(|o| o.status.success());
        if has {
            return Command::new(name);
        }
    }
    panic!(
        "no Python with `cryptography` among {candidates:?}: `pip install cryptography`, or set E2_PYTHON"
    );
}

/// How a frame is built. The access point lays out the same fields
/// (`access_point::mod.rs`): the header, the CCMP header, the body in the
/// clear, and room for the MIC.
struct Build {
    /// `Some(tid)` for a QoS data frame.
    qos: Option<u8>,
    /// A fourth address, as a frame being bridged carries.
    addr4: bool,
    /// The Sequence Control field whole: the sequence number and, in its low
    /// four bits, the fragment number.
    sequence_control: u16,
    /// Extra header flags on top of From DS and Protected.
    extra_flags: u8,
    /// Extra subtype bits in the first octet. The access point sends only
    /// Data and QoS Data, whose bits 4 to 6 are already clear, so without
    /// this no frame here exercises that mask at all -- found by breaking the
    /// mask on purpose and watching this test still pass.
    extra_subtype: u8,
    key_id: u8,
    packet_number: u64,
    body_len: usize,
}

impl Default for Build {
    fn default() -> Self {
        Self {
            qos: None,
            addr4: false,
            sequence_control: 0x0030,
            extra_flags: 0,
            extra_subtype: 0,
            key_id: 0,
            packet_number: 1,
            body_len: 40,
        }
    }
}

fn build(b: &Build) -> Vec<u8> {
    let mut f = Vec::new();
    f.push((if b.qos.is_some() { 0x88 } else { 0x08 }) | b.extra_subtype);
    f.push(0x40 | if b.addr4 { 0x03 } else { 0x02 } | b.extra_flags);
    f.extend_from_slice(&[0, 0]); // the duration, which is not authenticated
    f.extend_from_slice(&[0x02, 0xe3, 0, 0, 0, 0x51]); // A1, the station
    f.extend_from_slice(&[0x02, 0xe3, 0, 0, 0, 0xa1]); // A2, the access point
    f.extend_from_slice(&[0x02, 0xe3, 0, 0, 0, 0x03]); // A3
    f.extend_from_slice(&b.sequence_control.to_le_bytes());
    if b.addr4 {
        f.extend_from_slice(&[0x02, 0xe3, 0, 0, 0, 0x04]);
    }
    if let Some(tid) = b.qos {
        f.extend_from_slice(&[tid, 0]);
    }
    let pn = b.packet_number.to_le_bytes();
    f.extend_from_slice(&[
        pn[0],
        pn[1],
        0,
        0x20 | (b.key_id << 6),
        pn[2],
        pn[3],
        pn[4],
        pn[5],
    ]);
    f.extend((0..b.body_len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(3)));
    f.extend_from_slice(&[0u8; ccmp::MIC_LEN]);
    f
}

fn cases() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut add = |name: &str, b: Build| {
        out.insert(format!("frame_{name}"), build(&b));
    };
    add("01_data_40", Build::default());
    add(
        "02_data_whole_blocks",
        Build {
            body_len: 64,
            packet_number: 2,
            ..Build::default()
        },
    );
    add(
        "03_data_one_octet",
        Build {
            body_len: 1,
            packet_number: 3,
            ..Build::default()
        },
    );
    add(
        "04_qos_tid6",
        Build {
            qos: Some(6),
            body_len: 43,
            packet_number: 4,
            ..Build::default()
        },
    );
    add(
        "05_qos_tid0",
        Build {
            qos: Some(0),
            body_len: 64,
            packet_number: 5,
            ..Build::default()
        },
    );
    // what bridge forwarding sends: four addresses and QoS
    add(
        "06_four_address_qos",
        Build {
            qos: Some(3),
            addr4: true,
            body_len: 100,
            packet_number: 6,
            ..Build::default()
        },
    );
    add(
        "07_four_address_data",
        Build {
            addr4: true,
            body_len: 32,
            packet_number: 7,
            ..Build::default()
        },
    );
    add(
        "08_long",
        Build {
            body_len: 1500,
            packet_number: 8,
            ..Build::default()
        },
    );
    // the packet number near the top of its 48 bits: a byte order the two
    // implementations must agree on in the header and in the nonce
    add(
        "09_high_packet_number",
        Build {
            qos: Some(1),
            packet_number: 0xffff_ffff_fffe,
            ..Build::default()
        },
    );
    add(
        "10_fragment_number",
        Build {
            sequence_control: 0xf0f3, // sequence 0xf0f, fragment 3
            packet_number: 10,
            ..Build::default()
        },
    );
    add(
        "11_key_id",
        Build {
            key_id: 2,
            packet_number: 11,
            ..Build::default()
        },
    );
    // every maskable bit set at once: Retry, Power Management, More Data,
    // Order, and More Fragments, which is NOT masked
    add(
        "12_maskable_flags_set",
        Build {
            extra_flags: 0b1011_1100,
            packet_number: 12,
            ..Build::default()
        },
    );
    // the subtype's low bits, which 12.5.3.3.3 masks and the frames above
    // all leave clear
    add(
        "13_subtype_bits_set",
        Build {
            extra_subtype: 0b0111_0000,
            packet_number: 14,
            ..Build::default()
        },
    );
    add(
        "14_subtype_bits_set_qos",
        Build {
            qos: Some(2),
            extra_subtype: 0b0111_0000,
            packet_number: 15,
            ..Build::default()
        },
    );
    add(
        "15_maskable_flags_set_qos",
        Build {
            qos: Some(5),
            extra_flags: 0b1011_1100,
            packet_number: 13,
            ..Build::default()
        },
    );
    out
}

#[test]
fn ccmp_encapsulation_agrees_with_an_independent_implementation() {
    let cases = cases();
    let mut input = format!("tk={}\n", hex(&TK));
    for (name, frame) in &cases {
        input.push_str(&format!("{name}={}\n", hex(frame)));
    }

    let mut child = python()
        .arg("interop/ccmp.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("interop/ccmp.py runs");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("the frames go in");
    let out = child.wait_with_output().expect("it finishes");
    assert!(out.status.success(), "interop/ccmp.py failed");
    let theirs: BTreeMap<String, String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();
    assert_eq!(theirs.len(), cases.len(), "one answer per frame");

    for (name, plain) in &cases {
        let mut ours = plain.clone();
        ccmp::encapsulate(&mut ours, &TK).unwrap_or_else(|e| panic!("{name}: refused {e:?}"));
        let theirs = theirs.get(name).unwrap_or_else(|| panic!("{name}: no answer"));
        assert_eq!(&hex(&ours), theirs, "{name} differs");
        // and the encapsulation is not a no-op: the body changed and a MIC
        // was written, so an agreement cannot be two implementations both
        // doing nothing
        let body = ours.len() - ccmp::MIC_LEN;
        assert_ne!(
            ours[..body],
            plain[..body],
            "{name}: the body was left in the clear"
        );
        assert_ne!(
            ours[body..],
            [0u8; ccmp::MIC_LEN],
            "{name}: no MIC was written"
        );
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

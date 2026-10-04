//! E3's P2 against a second implementation: `interop/wpa2.py` lays out
//! WPA2-PSK's handshakes from 802.11-2020 with nothing shared with
//! `ieee80211`. It checks the access point's messages 1 and 3 and group
//! message 1 field by field (and unwraps the GTK itself), and plays the
//! station: `ap_core` must take its messages 2 and 4 and group message 2,
//! and both sides must hold one PTK. Needs Python 3 with `cryptography`
//! (`pip install cryptography`); CI installs it.

use std::io::Write;
use std::process::{Command, Stdio};

use ap_core::frames::RSN_ELEMENT;
use ap_core::handshake;
use ieee80211::element_chain;
use ieee80211::elements::rsn::RsnElement;
use ieee80211::scroll::Pwrite;
use sta_handshake::{GroupKey, PairwiseKeys};

const SSID: &str = "janus-e3-test";
const PASSPHRASE: &str = "not-a-real-network-0000";
const AP: [u8; 6] = [0x02, 0xe3, 0, 0, 0, 0xa1];
const STA: [u8; 6] = [0x02, 0xe3, 0, 0, 0, 0x51];
const ANONCE: [u8; 32] = [0xa5; 32];
const SNONCE: [u8; 32] = [0x5a; 32];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

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

#[test]
fn the_access_points_handshakes_agree_with_an_independent_implementation() {
    let mut pmk = [0u8; 32];
    ieee80211::crypto::map_passphrase_to_psk(PASSPHRASE, SSID, &mut pmk);
    let keys = PairwiseKeys::derive(&pmk, &AP, &STA, &ANONCE, &SNONCE);
    let mut station_rsn = [0u8; 64];
    let n = station_rsn
        .pwrite(element_chain! { RsnElement::WPA2_PERSONAL }, 0)
        .unwrap();
    let station_rsn = station_rsn[..n].to_vec();
    let gtk_1 = GroupKey {
        key: [0x61; 16],
        key_id: 1,
        rsc: 0x0102_0304_0506,
        replay_counter: 0,
    };
    let gtk_2 = GroupKey {
        key: [0x62; 16],
        key_id: 2,
        rsc: 0x0a0b,
        replay_counter: 0,
    };
    let (mut scratch, mut out) = (vec![0u8; 1024], vec![0u8; 1024]);

    let n = handshake::write_message_1(&mut out, &mut scratch, AP, STA, &ANONCE, 1).unwrap();
    let message_1 = out[..n].to_vec();
    let n = handshake::write_message_3(&mut out, &mut scratch, AP, STA, &keys, &ANONCE, 2, &gtk_1)
        .unwrap();
    let message_3 = out[..n].to_vec();
    // group message 1 as the station reads it: decrypted, CCMP header off
    let n =
        handshake::write_group_message_1(&mut out, &mut scratch, AP, STA, &keys, 3, &gtk_2, 5, 0)
            .unwrap();
    let mut plain = vec![0u8; 1024];
    let m = sta_handshake::unprotect(&out[..n - 8], &mut plain).unwrap();
    let group_message_1 = plain[..m].to_vec();

    let input = [
        ("passphrase", PASSPHRASE.to_string()),
        ("ssid", SSID.to_string()),
        ("bssid", hex(&AP)),
        ("station", hex(&STA)),
        ("anonce", hex(&ANONCE)),
        ("snonce", hex(&SNONCE)),
        ("ap_rsn_element", hex(&RSN_ELEMENT)),
        ("station_rsn_element", hex(&station_rsn)),
        ("message_1", hex(&message_1)),
        ("message_3", hex(&message_3)),
        ("group_message_1", hex(&group_message_1)),
        ("gtk_1", hex(&gtk_1.key)),
        ("key_id_1", gtk_1.key_id.to_string()),
        ("rsc_1", gtk_1.rsc.to_string()),
        ("gtk_2", hex(&gtk_2.key)),
        ("key_id_2", gtk_2.key_id.to_string()),
        ("rsc_2", gtk_2.rsc.to_string()),
        ("replay_1", "1".into()),
        ("replay_3", "2".into()),
        ("replay_g", "3".into()),
    ]
    .iter()
    .map(|(k, v)| format!("{k}={v}\n"))
    .collect::<String>();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/interop/wpa2.py");
    let mut child = python()
        .arg(script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "wpa2.py failed (is `cryptography` installed?):\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let get = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("no {k} in:\n{text}"))
            .to_string()
    };
    // every check of the access point's frames passed
    let failed: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("check_") && !l.ends_with("=ok"))
        .collect();
    assert!(
        failed.is_empty(),
        "the independent implementation refused:\n{}",
        failed.join("\n")
    );
    assert!(text.lines().filter(|l| l.starts_with("check_")).count() >= 15);
    // one PTK on both sides
    assert_eq!(unhex(&get("ptk")), keys.ptk.to_vec());
    // and the access point takes the independent station's replies
    let mut m2 = unhex(&get("message_2"));
    let ap_keys = handshake::read_message_2(&mut m2, &pmk, &AP, &STA, &ANONCE, 1, &station_rsn)
        .expect("the access point takes the independent message 2");
    assert_eq!(ap_keys.ptk, keys.ptk);
    let mut m4 = unhex(&get("message_4"));
    handshake::read_message_4(&mut m4, &keys, 2)
        .expect("the access point takes the independent message 4");
    let mut g2 = unhex(&get("group_message_2"));
    handshake::read_group_message_2(&mut g2, &keys, 3)
        .expect("the access point takes the independent group message 2");
}

//! E2's A4: the station's half of WPA2-PSK (`sta_handshake`, what FoA's
//! station runs) against a simulated access point's half, on the host, no
//! chip: the 4-way handshake, then a group rekey. A test SSID and passphrase
//! (D-E2a: nothing from a real network). Then the frames the station must
//! refuse, each refused without a panic.

use std::marker::PhantomData;

use ieee80211::common::{DataFrameSubtype, FCFFlags, SequenceControl};
use ieee80211::crypto::eapol::{EapolKeyFrame, KeyDescriptorVersion, KeyInformation};
use ieee80211::crypto::{
    CryptoHeader, deserialize_eapol_data_frame, map_passphrase_to_psk, serialize_eapol_data_frame,
};
use ieee80211::data_frame::DataFrame;
use ieee80211::data_frame::header::DataFrameHeader;
use ieee80211::element_chain;
use ieee80211::elements::kde::{GtkInfo, GtkKde};
use ieee80211::elements::rsn::RsnElement;
use ieee80211::mac_parser::MACAddress;
use ieee80211::scroll::Pwrite;
use llc_rs::{EtherType, SnapLlcFrame};
use sta_handshake::{
    AKM, GroupKey, PairwiseKeys, Refusal, data_frame_admitted, read_group_message_1,
    read_message_1, read_message_3, unprotect, write_group_message_2, write_message_2,
    write_message_4,
};

const SSID: &str = "janus-e2-test";
const PASSPHRASE: &str = "not-a-real-network-0000";
const AP: [u8; 6] = [0x02, 0xe2, 0, 0, 0, 0xa1];
const STA: [u8; 6] = [0x02, 0xe2, 0, 0, 0, 0x51];
const ANONCE: [u8; 32] = [0xa5; 32];
const SNONCE: [u8; 32] = [0x5a; 32];
const GTK_1: [u8; 16] = [0x61; 16];
const GTK_2: [u8; 16] = [0x62; 16];

fn pmk() -> [u8; 32] {
    let mut pmk = [0u8; 32];
    map_passphrase_to_psk(PASSPHRASE, SSID, &mut pmk);
    pmk
}

/// What the access point sends: an EAPOL-Key frame from it to the station.
fn ap_frame<E>(
    info: KeyInformation,
    replay: u64,
    rsc: u64,
    key_data: E,
    kck: Option<&[u8; 16]>,
    kek: Option<&[u8; 16]>,
) -> Vec<u8>
where
    E: ieee80211::scroll::ctx::TryIntoCtx<(), Error = ieee80211::scroll::Error>
        + ieee80211::scroll::ctx::MeasureWith<()>,
{
    let frame = DataFrame {
        header: DataFrameHeader {
            subtype: DataFrameSubtype::Data,
            fcf_flags: FCFFlags::new().with_from_ds(true),
            address_1: MACAddress::new(STA),
            address_2: MACAddress::new(AP),
            address_3: MACAddress::new(AP),
            sequence_control: SequenceControl::new(),
            ..Default::default()
        },
        payload: Some(SnapLlcFrame {
            oui: [0; 3],
            ether_type: EtherType::Eapol,
            payload: EapolKeyFrame {
                key_information: info.with_key_descriptor_version(KeyDescriptorVersion::AesHmacSha1),
                key_length: 16,
                key_replay_counter: replay,
                key_nonce: ANONCE,
                key_iv: 0,
                key_rsc: rsc,
                key_mic: [0u8; 16].as_slice(),
                key_data,
                _phantom: PhantomData,
            },
            _phantom: PhantomData,
        }),
        _phantom: PhantomData,
    };
    let mut out = vec![0u8; 512];
    let mut tmp = vec![0u8; 512];
    let n = serialize_eapol_data_frame(kck, kek, frame, &mut out, &mut tmp).expect("the AP's frame");
    out.truncate(n);
    out
}

fn message_1() -> Vec<u8> {
    ap_frame(KeyInformation::new().with_is_pairwise(true).with_key_ack(true), 1, 0, element_chain! {}, None, None)
}

fn message_3(keys: &PairwiseKeys, replay: u64, gtk: &[u8], key_id: u8) -> Vec<u8> {
    ap_frame(
        KeyInformation::new()
            .with_is_pairwise(true)
            .with_key_ack(true)
            .with_key_mic(true)
            .with_secure(true)
            .with_install(true)
            .with_encrypted_key_data(true),
        replay,
        0x77,
        element_chain! {
            RsnElement::WPA2_PERSONAL,
            GtkKde { gtk_info: GtkInfo::new().with_key_id(key_id).with_tx(true), gtk, _phantom: PhantomData }
        },
        Some(keys.kck()),
        Some(keys.kek()),
    )
}

fn group_message_1(keys: &PairwiseKeys, replay: u64, gtk: &[u8], key_id: u8, pairwise: bool) -> Vec<u8> {
    ap_frame(
        KeyInformation::new()
            .with_is_pairwise(pairwise)
            .with_key_ack(true)
            .with_key_mic(true)
            .with_secure(true)
            .with_encrypted_key_data(true),
        replay,
        0x1234,
        element_chain! {
            GtkKde { gtk_info: GtkInfo::new().with_key_id(key_id).with_tx(true), gtk, _phantom: PhantomData }
        },
        Some(keys.kck()),
        Some(keys.kek()),
    )
}

/// The frame as the station's hardware hands it over after decrypting it
/// under the PTK: the Protected bit and the CCMP header still there, the
/// MIC gone.
fn as_decrypted(plain: &[u8], packet_number: u64) -> Vec<u8> {
    let mut f = plain[..24].to_vec();
    f[1] |= 0x40;
    let mut ccmp = [0u8; 8];
    ccmp.pwrite(CryptoHeader::new(packet_number, 0).unwrap(), 0).unwrap();
    f.extend_from_slice(&ccmp);
    f.extend_from_slice(&plain[24..]);
    f
}

/// What the station's hardware would put on the air for a protected frame
/// the station laid out, as the access point reads it after decrypting:
/// the CCMP header and the MIC room taken off.
fn ap_reads_protected(laid_out: &[u8]) -> Vec<u8> {
    assert_ne!(laid_out[1] & 0x40, 0, "laid out as protected");
    let mut f = laid_out[..24].to_vec();
    f[1] &= !0x40;
    f.extend_from_slice(&laid_out[32..laid_out.len() - 8]);
    f
}

/// The station's side, through message 4.
struct Joined {
    keys: PairwiseKeys,
    gtk: GroupKey,
}

fn four_way() -> Joined {
    let pmk = pmk();
    // message 1
    let m1 = read_message_1(&mut message_1()).expect("message 1");
    assert_eq!(m1.anonce, ANONCE);
    let keys = PairwiseKeys::derive(&pmk, &AP, &STA, &m1.anonce, &SNONCE);
    // message 2, read by the access point: it takes the station's nonce,
    // derives the same PTK, and checks the MIC with it
    let (mut out, mut scratch) = (vec![0u8; 512], vec![0u8; 512]);
    let n = write_message_2(&mut out, &mut scratch, MACAddress::new(AP), MACAddress::new(STA), &keys, &SNONCE, m1.replay_counter)
        .expect("message 2");
    let snonce: [u8; 32] = out[24 + 8 + 17..24 + 8 + 49].try_into().unwrap();
    assert_eq!(snonce, SNONCE);
    let ap_keys = PairwiseKeys::derive(&pmk, &AP, &STA, &ANONCE, &snonce);
    assert_eq!(ap_keys.ptk, keys.ptk, "both sides derive one PTK");
    let m2 = deserialize_eapol_data_frame(Some(ap_keys.kck()), None, &mut out[..n], &mut [], AKM, false)
        .expect("the AP verifies message 2's MIC");
    assert_eq!(m2.key_replay_counter, 1);
    // message 3: the GTK, wrapped under the KEK
    let gtk = read_message_3(&mut message_3(&ap_keys, 2, &GTK_1, 1), &keys, &mut scratch, None).expect("message 3");
    assert_eq!((gtk.key, gtk.key_id, gtk.rsc, gtk.replay_counter), (GTK_1, 1, 0x77, 2));
    // message 4
    let n = write_message_4(&mut out, &mut scratch, MACAddress::new(AP), MACAddress::new(STA), &keys, gtk.replay_counter)
        .expect("message 4");
    let m4 = deserialize_eapol_data_frame(Some(ap_keys.kck()), None, &mut out[..n], &mut [], AKM, false)
        .expect("the AP verifies message 4's MIC");
    assert!(m4.key_information.secure() && m4.key_information.is_pairwise());
    Joined { keys, gtk }
}

#[test]
fn the_station_joins_the_simulated_access_point() {
    four_way();
}

#[test]
fn the_station_takes_a_group_rekey_and_answers_it() {
    let joined = four_way();
    let mut scratch = vec![0u8; 512];
    // the rekey arrives protected under the PTK; the hardware decrypts it
    let on_air = group_message_1(&joined.keys, 3, &GTK_2, 2, false);
    let delivered = as_decrypted(&on_air, 7);
    let mut plain = vec![0u8; delivered.len()];
    let n = unprotect(&delivered, &mut plain).expect("a protected frame");
    let gtk = read_group_message_1(&mut plain[..n], &joined.keys, &mut scratch, joined.gtk.replay_counter)
        .expect("group message 1");
    assert_eq!((gtk.key, gtk.key_id, gtk.rsc, gtk.replay_counter), (GTK_2, 2, 0x1234, 3));
    // group message 2, laid out protected for the hardware to encrypt
    let mut out = vec![0u8; 1024];
    let n = write_group_message_2(&mut out, &mut scratch, MACAddress::new(AP), MACAddress::new(STA), &joined.keys, gtk.replay_counter, 42, 0)
        .expect("group message 2");
    let mut ap_view = ap_reads_protected(&out[..n]);
    let m = deserialize_eapol_data_frame(Some(joined.keys.kck()), None, &mut ap_view, &mut [], AKM, false)
        .expect("the AP verifies group message 2's MIC");
    assert!(m.key_information.secure() && !m.key_information.is_pairwise() && m.key_information.key_mic());
    assert_eq!(m.key_replay_counter, 3);
}

#[test]
fn a_group_key_of_any_other_length_is_refused_not_a_panic() {
    // F1: a WPA/WPA2 mixed-mode router's TKIP group key is 32 bytes
    let pmk = pmk();
    let keys = PairwiseKeys::derive(&pmk, &AP, &STA, &ANONCE, &SNONCE);
    let mut scratch = vec![0u8; 512];
    for len in [0usize, 5, 15, 17, 32] {
        let gtk = vec![0x33u8; len];
        let got = read_message_3(&mut message_3(&keys, 2, &gtk, 1), &keys, &mut scratch, None);
        assert_eq!(got, Err(Refusal::GtkLength(len)), "a GTK of {len} bytes");
    }
}

#[test]
fn a_replayed_group_message_is_refused() {
    // F3: an old group message 1 would reinstall an old group key
    let joined = four_way();
    let mut scratch = vec![0u8; 512];
    for replay in [0, 1, 2] {
        let mut f = group_message_1(&joined.keys, replay, &GTK_2, 2, false);
        assert_eq!(
            read_group_message_1(&mut f, &joined.keys, &mut scratch, joined.gtk.replay_counter),
            Err(Refusal::Replay),
            "replay counter {replay} after message 3's 2"
        );
    }
}

#[test]
fn frames_that_are_not_the_message_expected_are_refused() {
    let joined = four_way();
    let keys = &joined.keys;
    let mut scratch = vec![0u8; 512];
    // a group message with the pairwise bit
    let mut f = group_message_1(keys, 9, &GTK_2, 2, true);
    assert_eq!(read_group_message_1(&mut f, keys, &mut scratch, 2), Err(Refusal::KeyInformation));
    // message 3 offered as a group message, and the reverse
    let mut f = message_3(keys, 9, &GTK_2, 2);
    assert_eq!(read_group_message_1(&mut f, keys, &mut scratch, 2), Err(Refusal::KeyInformation));
    let mut f = group_message_1(keys, 9, &GTK_2, 2, false);
    assert_eq!(read_message_3(&mut f, keys, &mut scratch, None), Err(Refusal::KeyInformation));
    // message 3 under another network's keys: the MIC fails
    let other = PairwiseKeys::derive(&[0x99; 32], &AP, &STA, &ANONCE, &SNONCE);
    let mut f = message_3(&other, 9, &GTK_2, 2);
    assert_eq!(read_message_3(&mut f, keys, &mut scratch, None), Err(Refusal::Mic));
    // a flipped byte in message 3
    let mut f = message_3(keys, 9, &GTK_2, 2);
    let last = f.len() - 1;
    f[last] ^= 1;
    assert!(read_message_3(&mut f, keys, &mut scratch, None).is_err());
    // message 3 with no GTK
    let mut f = ap_frame(
        KeyInformation::new().with_is_pairwise(true).with_key_ack(true).with_key_mic(true).with_secure(true).with_install(true).with_encrypted_key_data(true),
        9, 0, element_chain! { RsnElement::WPA2_PERSONAL }, Some(keys.kck()), Some(keys.kek()),
    );
    assert_eq!(read_message_3(&mut f, keys, &mut scratch, None), Err(Refusal::NoGtk));
    // a "message 1" that carries a MIC
    let mut f = ap_frame(KeyInformation::new().with_is_pairwise(true).with_key_ack(true).with_key_mic(true), 1, 0, element_chain! {}, Some(keys.kck()), None);
    assert!(read_message_1(&mut f).is_err());
}

#[test]
fn unprotected_data_is_not_admitted_once_keys_are_installed() {
    // F6
    assert!(data_frame_admitted(false, false));
    assert!(data_frame_admitted(false, true));
    assert!(data_frame_admitted(true, true));
    assert!(!data_frame_admitted(true, false));
}

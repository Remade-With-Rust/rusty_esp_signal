//! E3's P2 on the host: the access point's logic (`ap_core`) against our
//! station (`sta_handshake`). The access point's management frames are laid
//! out by hand from 802.11 and read back here with `ieee80211`'s parsers,
//! two implementations checking each other; `interop.rs` checks the
//! handshake against a third, in Python. A test SSID and passphrase
//! (D-E2a: nothing from a real network).

use ap_core::frames::{self, Bss, RSN_ELEMENT, Tim};
use ap_core::handshake::{self, Authenticator, Refusal};
use ap_core::request::{self, Request};
use ap_core::stations::{MAX_STATIONS, Stations};
use ap_core::{BROADCAST, status};
use ieee80211::crypto::map_passphrase_to_psk;
use ieee80211::element_chain;
use ieee80211::elements::DSSSParameterSetElement;
use ieee80211::elements::rsn::RsnElement;
use ieee80211::mac_parser::MACAddress;
use ieee80211::mgmt_frame::{
    AssociationResponseFrame, AuthenticationFrame, BeaconFrame, DeauthenticationFrame,
    ProbeResponseFrame,
};
use ieee80211::scroll::{Pread, Pwrite};
use sta_handshake::{GroupKey, GroupKeys, Install, PairwiseKeys};

const SSID: &[u8] = b"janus-e3-test";
const PASSPHRASE: &str = "not-a-real-network-0000";
const AP: [u8; 6] = [0x02, 0xe3, 0, 0, 0, 0xa1];
const STA: [u8; 6] = [0x02, 0xe3, 0, 0, 0, 0x51];
const ANONCE: [u8; 32] = [0xa5; 32];
const SNONCE: [u8; 32] = [0x5a; 32];

fn bss(protected: bool) -> Bss<'static> {
    Bss {
        bssid: AP,
        ssid: SSID,
        channel: 6,
        beacon_interval_tu: 100,
        protected,
    }
}

fn pmk() -> [u8; 32] {
    let mut pmk = [0u8; 32];
    map_passphrase_to_psk(PASSPHRASE, core::str::from_utf8(SSID).unwrap(), &mut pmk);
    pmk
}

/// The RSN element our station sends (in its association request and in
/// message 2): `ieee80211`'s WPA2-Personal, as `sta_handshake` writes it.
fn station_rsn_element() -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = buf
        .pwrite(element_chain! { RsnElement::WPA2_PERSONAL }, 0)
        .unwrap();
    buf[..n].to_vec()
}

fn mgmt(subtype: u8, from: [u8; 6], to: [u8; 6], bssid: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut f = vec![subtype << 4, 0, 0, 0];
    f.extend_from_slice(&to);
    f.extend_from_slice(&from);
    f.extend_from_slice(&bssid);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(body);
    f
}

fn assoc_request(ssid: &[u8], rsn: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![0x11, 0x04, 10, 0];
    body.push(0);
    body.push(ssid.len() as u8);
    body.extend_from_slice(ssid);
    body.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
    if let Some(rsn) = rsn {
        body.extend_from_slice(rsn);
    }
    mgmt(0, STA, AP, AP, &body)
}

// ---- the frames, read back with ieee80211 --------------------------------

#[test]
fn the_beacon_reads_back_as_laid_out() {
    let tim = Tim {
        dtim_count: 0,
        dtim_period: 2,
        group_buffered: true,
        buffered_aids: 0b110,
    };
    let mut out = [0u8; 256];
    let b = frames::beacon(&mut out, &bss(true), &tim).unwrap();
    assert_eq!(b.timestamp_at, 24);
    assert_eq!(&out[b.tim_at..b.tim_at + 7], &[5, 5, 0, 2, 1, 0b110, 0]);
    let f = out[..b.len].pread::<BeaconFrame>(0).unwrap();
    assert_eq!(f.ssid(), Some("janus-e3-test"));
    assert_eq!(f.beacon_interval, 100);
    assert_eq!(*f.header.bssid, AP);
    assert_eq!(*f.header.receiver_address, BROADCAST);
    assert!(f.capabilities_info.is_ess());
    assert!(f.capabilities_info.is_confidentiality_required());
    assert_eq!(
        f.elements
            .get_first_element::<DSSSParameterSetElement>()
            .map(|d| d.current_channel),
        Some(6)
    );
    let rsn = f
        .elements
        .get_first_element::<RsnElement>()
        .expect("an RSN element");
    let _ = rsn;
    // an open network: no RSN element, no Privacy bit
    let b = frames::beacon(&mut out, &bss(false), &tim).unwrap();
    let f = out[..b.len].pread::<BeaconFrame>(0).unwrap();
    assert!(f.elements.get_first_element::<RsnElement>().is_none());
    assert!(!f.capabilities_info.is_confidentiality_required());
}

#[test]
fn the_other_frames_read_back_as_laid_out() {
    let mut out = [0u8; 256];
    let n = frames::probe_response(&mut out, &bss(true), STA).unwrap();
    let f = out[..n].pread::<ProbeResponseFrame>(0).unwrap();
    assert_eq!(f.ssid(), Some("janus-e3-test"));
    assert_eq!(*f.header.receiver_address, STA);

    let n = frames::authentication(&mut out, AP, STA, status::SUCCESS).unwrap();
    let f = out[..n].pread::<AuthenticationFrame>(0).unwrap();
    assert_eq!(f.authentication_transaction_sequence_number, 2);
    assert_eq!(u16::from(f.status_code), 0);

    let n =
        frames::association_response(&mut out, &bss(true), STA, status::SUCCESS, 3, false).unwrap();
    let f = out[..n].pread::<AssociationResponseFrame>(0).unwrap();
    assert_eq!(u16::from(f.status_code), 0);
    assert_eq!(f.association_id.map(|a| a.aid()), Some(3));
    assert_eq!(
        f.association_id.map(u16::from),
        Some(0xc003),
        "the two high bits set, as 9.4.1.8 says"
    );

    let n = frames::deauthentication(&mut out, AP, STA, 7).unwrap();
    let f = out[..n].pread::<DeauthenticationFrame>(0).unwrap();
    assert_eq!(u16::from(f.reason), 7);
}

// ---- requests ---------------------------------------------------------------

#[test]
fn requests_are_read_and_others_ignored() {
    // a wildcard probe, broadcast
    let probe = mgmt(4, STA, BROADCAST, BROADCAST, &[0, 0]);
    assert_eq!(
        request::parse(&probe, &AP),
        Some(Request::Probe {
            from: STA,
            ssid: None
        })
    );
    let probe = mgmt(4, STA, BROADCAST, BROADCAST, &[0, 3, b'a', b'b', b'c']);
    assert_eq!(
        request::parse(&probe, &AP),
        Some(Request::Probe {
            from: STA,
            ssid: Some(b"abc")
        })
    );
    // authentication, to us and to another access point
    let auth = mgmt(11, STA, AP, AP, &[0, 0, 1, 0, 0, 0]);
    assert_eq!(
        request::parse(&auth, &AP),
        Some(Request::Authentication {
            from: STA,
            algorithm: 0,
            sequence: 1
        })
    );
    let other = [9u8; 6];
    assert_eq!(
        request::parse(&mgmt(11, STA, other, other, &[0, 0, 1, 0, 0, 0]), &AP),
        None
    );
    // the association request's RSN element, whole
    let rsn = station_rsn_element();
    let assoc = assoc_request(SSID, Some(&rsn));
    assert_eq!(
        request::parse(&assoc, &AP),
        Some(Request::Association {
            from: STA,
            ssid: Some(SSID),
            rsn_element: Some(&rsn[..]),
            reassociation: false
        })
    );
    // a protected management frame: not ours to read (no PMF)
    let mut protected = auth.clone();
    protected[1] |= 0x40;
    assert_eq!(request::parse(&protected, &AP), None);
}

// ---- the station table --------------------------------------------------------

#[test]
fn authentication_and_association_are_decided_as_802_11_says() {
    let rsn = station_rsn_element();
    let mut s = Stations::new();
    assert_eq!(
        s.authenticate(STA, 1, 1),
        status::UNSUPPORTED_AUTH_ALGORITHM
    );
    assert_eq!(s.authenticate(STA, 0, 3), status::AUTH_OUT_OF_SEQUENCE);
    // not authenticated yet
    assert_eq!(
        s.associate(STA, true, Some(&rsn), true),
        Err(status::UNSPECIFIED)
    );
    assert_eq!(s.authenticate(STA, 0, 1), status::SUCCESS);
    assert_eq!(
        s.associate(STA, false, Some(&rsn), true),
        Err(status::UNSPECIFIED)
    );
    assert_eq!(
        s.associate(STA, true, None, true),
        Err(status::INVALID_ELEMENT)
    );
    assert_eq!(s.associate(STA, true, Some(&rsn), true), Ok(1));
    assert_eq!(s.get(&STA).unwrap().rsn_element(), &rsn[..]);
    // a re-association keeps the AID
    assert_eq!(s.associate(STA, true, Some(&rsn), true), Ok(1));
    // the table holds four; the fifth is refused
    for n in 2..=MAX_STATIONS as u8 {
        let a = [2, 0, 0, 0, 0, n];
        assert_eq!(s.authenticate(a, 0, 1), status::SUCCESS);
        assert_eq!(s.associate(a, true, Some(&rsn), true), Ok(u16::from(n)));
    }
    assert_eq!(
        s.authenticate([2, 0, 0, 0, 0, 99], 0, 1),
        status::TOO_MANY_STATIONS
    );
    // one leaves, its AID is free for the next
    s.remove(&[2, 0, 0, 0, 0, 2]);
    assert_eq!(s.authenticate([2, 0, 0, 0, 0, 99], 0, 1), status::SUCCESS);
    assert_eq!(
        s.associate([2, 0, 0, 0, 0, 99], true, Some(&rsn), true),
        Ok(2)
    );
    // an open network takes no RSN element
    let mut open = Stations::new();
    open.authenticate(STA, 0, 1);
    assert_eq!(
        open.associate(STA, true, Some(&rsn), false),
        Err(status::INVALID_ELEMENT)
    );
    assert_eq!(open.associate(STA, true, None, false), Ok(1));
}

#[test]
fn the_rsn_element_offered_must_be_wpa2_psk_ccmp() {
    let check = |body: &[u8]| ap_core::rsn::check_station(body);
    let good = &station_rsn_element()[2..];
    assert_eq!(check(good), Ok(()));
    let ccmp = [0x00, 0x0f, 0xac, 4];
    let tkip = [0x00, 0x0f, 0xac, 2];
    let psk = [0x00, 0x0f, 0xac, 2];
    let dot1x = [0x00, 0x0f, 0xac, 1];
    let element =
        |version: u16, group: [u8; 4], pairwise: &[[u8; 4]], akm: &[[u8; 4]], caps: u16| {
            let mut b = version.to_le_bytes().to_vec();
            b.extend_from_slice(&group);
            b.extend_from_slice(&(pairwise.len() as u16).to_le_bytes());
            pairwise.iter().for_each(|p| b.extend_from_slice(p));
            b.extend_from_slice(&(akm.len() as u16).to_le_bytes());
            akm.iter().for_each(|a| b.extend_from_slice(a));
            b.extend_from_slice(&caps.to_le_bytes());
            b
        };
    assert_eq!(check(&element(1, ccmp, &[ccmp], &[psk], 0)), Ok(()));
    assert_eq!(
        check(&element(2, ccmp, &[ccmp], &[psk], 0)),
        Err(status::UNSUPPORTED_RSNE_VERSION)
    );
    assert_eq!(
        check(&element(1, tkip, &[ccmp], &[psk], 0)),
        Err(status::INVALID_GROUP_CIPHER)
    );
    assert_eq!(
        check(&element(1, ccmp, &[tkip], &[psk], 0)),
        Err(status::INVALID_PAIRWISE_CIPHER)
    );
    assert_eq!(
        check(&element(1, ccmp, &[ccmp, tkip], &[psk], 0)),
        Err(status::INVALID_PAIRWISE_CIPHER)
    );
    assert_eq!(
        check(&element(1, ccmp, &[ccmp], &[dot1x], 0)),
        Err(status::INVALID_AKMP)
    );
    assert_eq!(
        check(&element(1, ccmp, &[ccmp], &[psk], 1 << 6)),
        Err(status::INVALID_RSNE_CAPABILITIES)
    );
    assert_eq!(check(&[1, 0]), Err(status::INVALID_AKMP));
    assert_eq!(check(&[]), Err(status::INVALID_ELEMENT));
}

// ---- the handshakes: our station against our access point --------------------

/// The station's PTK and its group key after a whole 4-way handshake.
fn join() -> (PairwiseKeys, GroupKey, Authenticator, Vec<u8>) {
    let pmk = pmk();
    let rsn = station_rsn_element();
    let (mut out, mut scratch) = (vec![0u8; 1024], vec![0u8; 1024]);
    let mut auth = Authenticator::new(ANONCE);
    let gtk = GroupKey {
        key: [0x61; 16],
        key_id: 1,
        rsc: 0x0102_0304_0506,
        replay_counter: 0,
    };
    // message 1
    let r1 = auth.next_replay_counter();
    let n = handshake::write_message_1(&mut out, &mut scratch, AP, STA, &ANONCE, r1).unwrap();
    let m1 = sta_handshake::read_message_1(&mut out[..n]).expect("the station takes message 1");
    let sta_keys = PairwiseKeys::derive(&pmk, &AP, &STA, &m1.anonce, &SNONCE);
    // message 2
    let n = sta_handshake::write_message_2(
        &mut out,
        &mut scratch,
        MACAddress::new(AP),
        MACAddress::new(STA),
        &sta_keys,
        &SNONCE,
        m1.replay_counter,
    )
    .unwrap();
    let ap_keys = handshake::read_message_2(&mut out[..n], &pmk, &AP, &STA, &ANONCE, r1, &rsn)
        .expect("the access point takes message 2");
    assert_eq!(ap_keys.ptk, sta_keys.ptk, "one PTK on both sides");
    auth.keys = Some(ap_keys.clone());
    // message 3
    let r3 = auth.next_replay_counter();
    let n =
        handshake::write_message_3(&mut out, &mut scratch, AP, STA, &ap_keys, &ANONCE, r3, &gtk)
            .unwrap();
    let got = sta_handshake::read_message_3(&mut out[..n], &sta_keys, &mut scratch, None)
        .expect("the station takes message 3");
    assert_eq!(
        (got.key, got.key_id, got.rsc, got.replay_counter),
        (gtk.key, 1, 0x0102_0304_0506, r3)
    );
    // message 4
    let n = sta_handshake::write_message_4(
        &mut out,
        &mut scratch,
        MACAddress::new(AP),
        MACAddress::new(STA),
        &sta_keys,
        got.replay_counter,
    )
    .unwrap();
    handshake::read_message_4(&mut out[..n], &ap_keys, r3)
        .expect("the access point takes message 4");
    (sta_keys, got, auth, rsn)
}

#[test]
fn our_station_joins_our_access_point() {
    join();
}

/// A protected frame as the receiving hardware hands it over: Protected
/// bit and CCMP header kept, the MIC room the sender left gone.
fn as_received(laid_out: &[u8]) -> Vec<u8> {
    laid_out[..laid_out.len() - 8].to_vec()
}

#[test]
fn the_access_point_rekeys_and_the_station_answers() {
    let (sta_keys, first, mut auth, _) = join();
    let ap_keys = auth.keys.clone().unwrap();
    let mut station_groups = GroupKeys::new();
    station_groups.install(&first).unwrap();
    let (mut out, mut scratch, mut plain) = (vec![0u8; 1024], vec![0u8; 1024], vec![0u8; 1024]);
    let next = GroupKey {
        key: [0x62; 16],
        key_id: 2,
        rsc: 0,
        replay_counter: 0,
    };
    // group message 1, protected under the PTK
    let r = auth.next_replay_counter();
    let n =
        handshake::write_group_message_1(&mut out, &mut scratch, AP, STA, &ap_keys, r, &next, 7, 0)
            .unwrap();
    let received = as_received(&out[..n]);
    let m = sta_handshake::unprotect(&received, &mut plain).unwrap();
    let got = sta_handshake::read_group_message_1(
        &mut plain[..m],
        &sta_keys,
        &mut scratch,
        first.replay_counter,
    )
    .expect("the station takes group message 1");
    assert_eq!((got.key, got.key_id), (next.key, 2));
    assert_eq!(station_groups.install(&got), Ok(Install::Program(1)));
    // group message 2 back, protected
    let n = sta_handshake::write_group_message_2(
        &mut out,
        &mut scratch,
        MACAddress::new(AP),
        MACAddress::new(STA),
        &sta_keys,
        got.replay_counter,
        9,
        0,
    )
    .unwrap();
    let received = as_received(&out[..n]);
    let m = sta_handshake::unprotect(&received, &mut plain).unwrap();
    handshake::read_group_message_2(&mut plain[..m], &ap_keys, r)
        .expect("the access point takes group message 2");
}

#[test]
fn the_access_point_refuses_what_it_should() {
    let pmk = pmk();
    let rsn = station_rsn_element();
    let (mut out, mut scratch) = (vec![0u8; 1024], vec![0u8; 1024]);
    let keys = PairwiseKeys::derive(&pmk, &AP, &STA, &ANONCE, &SNONCE);
    let m2 = |out: &mut Vec<u8>, scratch: &mut Vec<u8>, keys: &PairwiseKeys, replay: u64| {
        sta_handshake::write_message_2(
            out,
            scratch,
            MACAddress::new(AP),
            MACAddress::new(STA),
            keys,
            &SNONCE,
            replay,
        )
        .unwrap()
    };
    // message 2 under another passphrase: the MIC fails
    let other = PairwiseKeys::derive(&[0x99; 32], &AP, &STA, &ANONCE, &SNONCE);
    let n = m2(&mut out, &mut scratch, &other, 1);
    assert_eq!(
        handshake::read_message_2(&mut out[..n], &pmk, &AP, &STA, &ANONCE, 1, &rsn).err(),
        Some(Refusal::Mic)
    );
    // message 2 answering another message 1
    let n = m2(&mut out, &mut scratch, &keys, 5);
    assert_eq!(
        handshake::read_message_2(&mut out[..n], &pmk, &AP, &STA, &ANONCE, 1, &rsn).err(),
        Some(Refusal::Replay)
    );
    // message 2 whose RSN element is not the association request's (a
    // downgrade, or a station confused)
    let mut asked = rsn.clone();
    asked[2] = 2;
    let n = m2(&mut out, &mut scratch, &keys, 1);
    assert_eq!(
        handshake::read_message_2(&mut out[..n], &pmk, &AP, &STA, &ANONCE, 1, &asked).err(),
        Some(Refusal::RsnMismatch)
    );
    // message 1 (Ack, no MIC) offered as message 4
    let n = handshake::write_message_1(&mut out, &mut scratch, AP, STA, &ANONCE, 2).unwrap();
    assert!(handshake::read_message_4(&mut out[..n], &keys, 2).is_err());
    // a message 4 answering the wrong message 3
    let n = sta_handshake::write_message_4(
        &mut out,
        &mut scratch,
        MACAddress::new(AP),
        MACAddress::new(STA),
        &keys,
        2,
    )
    .unwrap();
    assert_eq!(
        handshake::read_message_4(&mut out[..n], &keys, 3),
        Err(Refusal::Replay)
    );
    assert_eq!(handshake::read_message_4(&mut out[..n], &keys, 2), Ok(()));
}

#[test]
fn message_3_carries_the_beacons_rsn_element() {
    // the station compares message 3's RSN element with the beacon's
    let (sta_keys, _, mut auth, _) = join();
    let keys = auth.keys.clone().unwrap();
    let (mut out, mut scratch) = (vec![0u8; 1024], vec![0u8; 1024]);
    let gtk = GroupKey {
        key: [0x61; 16],
        key_id: 1,
        rsc: 0,
        replay_counter: 0,
    };
    let r = auth.next_replay_counter();
    let n = handshake::write_message_3(&mut out, &mut scratch, AP, STA, &keys, &ANONCE, r, &gtk)
        .unwrap();
    let frame = ieee80211::crypto::deserialize_eapol_data_frame(
        Some(sta_keys.kck()),
        Some(sta_keys.kek()),
        &mut out[..n],
        &mut scratch,
        sta_handshake::AKM,
        false,
    )
    .unwrap();
    assert!(frame.key_data.bytes.starts_with(&RSN_ELEMENT));
}

// ---- roaming, liveness, power save (E3: a robust access point) ---------------

#[test]
fn a_station_roaming_in_gets_a_reassociation_response_and_keeps_its_aid() {
    // the request: subtype 2, the current access point's address after the
    // capability and listen interval fields
    let rsn = station_rsn_element();
    let mut body = vec![0x11, 0x04, 10, 0];
    body.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x77]);
    body.extend_from_slice(&[0, SSID.len() as u8]);
    body.extend_from_slice(SSID);
    body.extend_from_slice(&rsn);
    let request = mgmt(2, STA, AP, AP, &body);
    let Some(Request::Association {
        reassociation,
        rsn_element,
        ..
    }) = request::parse(&request, &AP)
    else {
        panic!("a re-association request");
    };
    assert!(reassociation);
    assert_eq!(rsn_element, Some(&rsn[..]));
    // the response: subtype 3 (0x30), the status, the AID with its high bits
    let mut out = [0u8; 128];
    let n =
        frames::association_response(&mut out, &bss(true), STA, status::SUCCESS, 2, true).unwrap();
    assert_eq!(out[0], 0x30, "a re-association response");
    assert_eq!(u16::from_le_bytes([out[26], out[27]]), 0, "status success");
    assert_eq!(u16::from_le_bytes([out[28], out[29]]), 0xc002);
    assert_eq!(&out[4..10], &STA);
    let _ = n;
    // the table: a connected station that re-associates keeps its AID and
    // goes back to Associated (the 4-way handshake runs again)
    let mut s = Stations::new();
    s.authenticate(STA, 0, 1);
    let aid = s.associate(STA, true, Some(&rsn), true).unwrap();
    assert!(s.connected(&STA));
    assert_eq!(s.associate(STA, true, Some(&rsn), true), Ok(aid));
    assert_eq!(
        s.get(&STA).unwrap().state,
        ap_core::stations::State::Associated
    );
}

#[test]
fn a_station_gone_quiet_is_the_one_dropped() {
    let mut s = Stations::new();
    let (a, b) = ([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2]);
    s.authenticate(a, 0, 1);
    s.authenticate(b, 0, 1);
    assert!(s.heard(&a, 1_000_000, false));
    assert!(s.heard(&b, 9_000_000, false));
    assert!(
        !s.heard(&[9; 6], 9_000_000, false),
        "a stranger is not held"
    );
    assert_eq!(s.inactive(10_000_000, 5_000_000), Some(a));
    assert_eq!(s.inactive(10_000_000, 9_500_000), None);
    s.remove(&a);
    assert_eq!(s.inactive(20_000_000, 5_000_000), Some(b));
}

#[test]
fn the_tim_names_the_dozing_stations_with_frames_waiting() {
    let rsn = station_rsn_element();
    let mut s = Stations::new();
    let (a, b, c) = ([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 3]);
    for x in [a, b, c] {
        s.authenticate(x, 0, 1);
        s.associate(x, true, Some(&rsn), true).unwrap();
    }
    s.heard(&a, 0, true);
    s.set_queued(&a, 2);
    s.heard(&b, 0, true);
    s.heard(&c, 0, true);
    s.set_queued(&c, 1);
    let tim = s.tim(0, 2, true);
    assert_eq!(tim.buffered_aids, (1 << 1) | (1 << 3));
    assert!(tim.group_buffered);
    // and it is laid out in the beacon: the bitmap's octets from AID 0
    let mut out = [0u8; 256];
    let beacon = frames::beacon(&mut out, &bss(true), &tim).unwrap();
    assert_eq!(
        &out[beacon.tim_at..beacon.tim_at + 7],
        &[5, 5, 0, 2, 1, 0b1010, 0]
    );
}

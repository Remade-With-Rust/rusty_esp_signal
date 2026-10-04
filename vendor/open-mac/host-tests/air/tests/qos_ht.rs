//! E3's P7 on the host: the WMM and HT elements the access point lays out
//! by hand read back with `ieee80211`'s parsers, and a station's WMM and HT
//! Capabilities read out of its association request.

use ap_core::elements::Elements;
use ap_core::frames::{self, Bss, Tim};
use ap_core::qos::{self, HtCapabilities};
use ap_core::request::{self, Request};
use ap_core::stations::Stations;
use ieee80211::elements::VendorSpecificElement;
use ieee80211::elements::ht::{HTCapabilitiesElement, HTOperationElement};
use ieee80211::mgmt_frame::{AssociationResponseFrame, BeaconFrame, ProbeResponseFrame};
use ieee80211::scroll::Pread;

const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
const STA: [u8; 6] = [2, 0, 0, 0, 0, 0xa];
const SSID: &[u8] = b"janus-p7";

fn bss(ht: bool) -> Bss<'static> {
    Bss {
        bssid: AP,
        ssid: SSID,
        channel: 6,
        beacon_interval_tu: 100,
        protected: false,
        ht,
    }
}

fn mgmt(subtype: u8, body: &[u8]) -> Vec<u8> {
    let mut f = vec![subtype << 4, 0, 0, 0];
    f.extend_from_slice(&AP);
    f.extend_from_slice(&STA);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(body);
    f
}

/// A station's association request: capability, listen interval, SSID,
/// rates, and whatever `extra` elements.
fn assoc_request(extra: &[u8]) -> Vec<u8> {
    let mut body = vec![0x01, 0x04, 0x0a, 0x00];
    body.extend_from_slice(&[0, SSID.len() as u8]);
    body.extend_from_slice(SSID);
    body.extend_from_slice(&[1, 8, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    body.extend_from_slice(extra);
    mgmt(0, &body)
}

/// A station's WMM information element: OUI, type, subtype 0, version, QoS info.
const STA_WMM: [u8; 9] = [221, 7, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00];

fn sta_ht(info: u16, rx_mcs: u8) -> [u8; 28] {
    let mut e = [0u8; 28];
    e[0] = 45;
    e[1] = 26;
    e[2..4].copy_from_slice(&info.to_le_bytes());
    e[5] = rx_mcs;
    e
}

#[test]
fn the_beacon_offers_wmm_and_ht_as_laid_out() {
    let mut out = [0u8; 512];
    let b = frames::beacon(&mut out, &bss(true), &Tim::default()).unwrap();
    let f = out[..b.len].pread::<BeaconFrame>(0).unwrap();
    let caps = f
        .elements
        .get_first_element::<HTCapabilitiesElement>()
        .expect("HT Capabilities");
    assert!(caps.ht_capabilities_info.short_gi_20mhz());
    assert!(
        !caps.ht_capabilities_info.supported_channel_width_set(),
        "20 MHz only"
    );
    assert!(!caps.ht_capabilities_info.green_field());
    assert!(!caps.ht_capabilities_info.tx_stbc());
    let rx: Vec<bool> = caps.supported_mcs_set.supported_rx_mcs_indices().collect();
    assert_eq!(&rx[..8], &[true; 8], "MCS 0-7 received");
    assert!(rx[8..].iter().all(|m| !m), "and nothing above");
    assert!(
        caps.supported_mcs_set
            .supported_rx_mcs_set_flags
            .tx_mcs_set_defined()
    );
    assert!(
        !caps
            .supported_mcs_set
            .supported_rx_mcs_set_flags
            .tx_rx_mcs_set_not_equal()
    );
    let op = f
        .elements
        .get_first_element::<HTOperationElement>()
        .expect("HT Operation");
    assert_eq!(op.primary_channel, 6);
    assert!(!op.ht_operation_information.any_channel_width());
    assert!(op.ht_operation_information.nongreenfield_ht_sta_present());
    assert!(
        op.basic_ht_mcs_set.supported_rx_mcs_indices().all(|m| !m),
        "no basic MCS required"
    );
    let wmm = f
        .elements
        .get_matching_elements::<VendorSpecificElement>()
        .find_map(|v| v.get_payload_if_prefix_matches(&[0x00, 0x50, 0xf2, 0x02, 0x01, 0x01]))
        .expect("the WMM parameter element");
    // QoS info, reserved, then the four access categories' records
    assert_eq!(wmm[0], 0x00);
    assert_eq!(&wmm[2..6], &[0x03, 0xa4, 0, 0], "BE: AIFSN 3, CW 15-1023");
    assert_eq!(&wmm[6..10], &[0x27, 0xa4, 0, 0], "BK: ACI 1, AIFSN 7");
    assert_eq!(
        &wmm[10..14],
        &[0x42, 0x43, 94, 0],
        "VI: ACI 2, AIFSN 2, CW 7-15, TXOP 3.008 ms"
    );
    assert_eq!(
        &wmm[14..18],
        &[0x62, 0x32, 47, 0],
        "VO: ACI 3, AIFSN 2, CW 3-7, TXOP 1.504 ms"
    );
    // the vendor element comes last
    let ids: Vec<u8> = Elements::new(&out[36..b.len]).map(|(id, _)| id).collect();
    assert_eq!(ids.last(), Some(&221));
    assert!(ids.iter().position(|&i| i == 45) < ids.iter().position(|&i| i == 61));
}

#[test]
fn without_ht_nothing_of_it_is_offered() {
    let mut out = [0u8; 512];
    let b = frames::beacon(&mut out, &bss(false), &Tim::default()).unwrap();
    let f = out[..b.len].pread::<BeaconFrame>(0).unwrap();
    assert!(
        f.elements
            .get_first_element::<HTCapabilitiesElement>()
            .is_none()
    );
    assert!(
        f.elements
            .get_first_element::<HTOperationElement>()
            .is_none()
    );
    assert!(
        f.elements
            .get_matching_elements::<VendorSpecificElement>()
            .next()
            .is_none()
    );
}

#[test]
fn probe_and_association_responses_offer_the_same() {
    let mut out = [0u8; 512];
    let n = frames::probe_response(&mut out, &bss(true), STA).unwrap();
    let f = out[..n].pread::<ProbeResponseFrame>(0).unwrap();
    assert!(
        f.elements
            .get_first_element::<HTCapabilitiesElement>()
            .is_some()
    );
    assert_eq!(
        f.elements
            .get_first_element::<HTOperationElement>()
            .unwrap()
            .primary_channel,
        6
    );
    let n = frames::association_response(&mut out, &bss(true), STA, 0, 1, false).unwrap();
    let f = out[..n].pread::<AssociationResponseFrame>(0).unwrap();
    assert!(
        f.elements
            .get_first_element::<HTCapabilitiesElement>()
            .is_some()
    );
    assert!(
        f.elements
            .get_first_element::<HTOperationElement>()
            .is_some()
    );
    assert!(
        f.elements
            .get_matching_elements::<VendorSpecificElement>()
            .next()
            .is_some()
    );
}

#[test]
fn a_stations_wmm_and_ht_are_read_from_its_request() {
    // a legacy station: neither
    match request::parse(&assoc_request(&[]), &AP).unwrap() {
        Request::Association { qos, ht, .. } => {
            assert!(!qos);
            assert_eq!(ht, None);
        }
        other => panic!("{other:?}"),
    }
    // a WMM station without HT
    match request::parse(&assoc_request(&STA_WMM), &AP).unwrap() {
        Request::Association { qos, ht, .. } => {
            assert!(qos);
            assert_eq!(ht, None);
        }
        other => panic!("{other:?}"),
    }
    // an HT station: short GI at 20 MHz, MCS 0-7
    let mut extra = sta_ht(0x002c, 0xff).to_vec();
    extra.extend_from_slice(&STA_WMM);
    match request::parse(&assoc_request(&extra), &AP).unwrap() {
        Request::Association { qos, ht, .. } => {
            assert!(qos);
            let ht = ht.unwrap();
            assert_eq!(
                ht,
                HtCapabilities {
                    short_gi_20: true,
                    rx_mcs: 0xff
                }
            );
            assert_eq!(ht.highest_mcs(), Some(7));
        }
        other => panic!("{other:?}"),
    }
    // one that receives no short GI and only MCS 0-3
    match request::parse(&assoc_request(&sta_ht(0x000c, 0x0f)), &AP).unwrap() {
        Request::Association { qos, ht, .. } => {
            assert!(!qos);
            assert_eq!(
                ht,
                Some(HtCapabilities {
                    short_gi_20: false,
                    rx_mcs: 0x0f
                })
            );
            assert_eq!(ht.unwrap().highest_mcs(), Some(3));
        }
        other => panic!("{other:?}"),
    }
    // a short HT element is not read
    let mut short = sta_ht(0x002c, 0xff).to_vec();
    short.truncate(20);
    short[1] = 18;
    match request::parse(&assoc_request(&short), &AP).unwrap() {
        Request::Association { ht, .. } => assert_eq!(ht, None),
        other => panic!("{other:?}"),
    }
    assert_eq!(HtCapabilities::default().highest_mcs(), None);
}

#[test]
fn the_table_keeps_what_a_station_said() {
    let mut stations = Stations::new();
    stations.authenticate(STA, 0, 1);
    stations.associate(STA, true, None, false).unwrap();
    let ht = Some(HtCapabilities {
        short_gi_20: true,
        rx_mcs: 0xff,
    });
    stations.set_capabilities(&STA, true, ht);
    let s = stations.get(&STA).unwrap();
    assert!(s.qos);
    assert_eq!(s.ht, ht);
}

#[test]
fn user_priorities_map_to_access_categories_and_qos_control() {
    assert_eq!(
        [0, 1, 2, 3, 4, 5, 6, 7].map(qos::access_category),
        [0, 1, 1, 0, 2, 2, 3, 3]
    );
    assert_eq!(qos::qos_control(0), [0, 0]);
    assert_eq!(qos::qos_control(6), [6, 0]);
    assert_eq!(qos::qos_control(0x1f), [7, 0], "a TID is three bits");
}

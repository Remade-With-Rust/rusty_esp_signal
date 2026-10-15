//! E8 on the host: the station's side of 802.11n (`sta_handshake::ht`)
//! checked against two writers it does not share code with. `ap_core`,
//! the access point, reads the station's association elements and answers;
//! the station reads the answer. `ieee80211`'s typed writer lays out the
//! same QoS data frame the station lays out by hand, byte for byte, and
//! its parser (the one FoA's station receives with) reads the A-MSDU back.

use ap_core::elements::Elements;
use ap_core::frames::{self, Bss};
use ap_core::qos;
use ieee80211::GenericFrame;
use ieee80211::common::{DataFrameSubtype, FCFFlags, SequenceControl};
use ieee80211::crypto::{CryptoHeader, MicState};
use ieee80211::data_frame::header::DataFrameHeader;
use ieee80211::data_frame::{DataFrame, DataFrameReadPayload, PotentiallyWrappedPayload};
use ieee80211::mac_parser::MACAddress;
use ieee80211::scroll::{Pread, Pwrite};
use llc_rs::SnapLlcFrame;
use sta_handshake::ht::{self, HtLink, Link};

const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
const STA: [u8; 6] = [2, 0, 0, 0, 0, 0xa];

fn ethernet(dst: [u8; 6], ether_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut e = dst.to_vec();
    e.extend_from_slice(&STA);
    e.extend_from_slice(&ether_type.to_be_bytes());
    e.extend_from_slice(payload);
    e
}

#[test]
fn the_access_point_reads_the_stations_wmm_and_ht() {
    let mut body = ht::HT_CAPABILITIES_ELEMENT.to_vec();
    body.extend_from_slice(&ht::WMM_INFORMATION_ELEMENT);
    assert!(qos::station_is_qos(Elements::new(&body)));
    assert_eq!(
        qos::station_ht(Elements::new(&body)),
        Some(qos::HtCapabilities {
            short_gi_20: true,
            rx_mcs: 0xff
        })
    );
    // the station's element is the access point's, byte for byte
    assert_eq!(ht::HT_CAPABILITIES_ELEMENT, qos::HT_CAPABILITIES_ELEMENT);
}

#[test]
fn the_station_reads_the_access_points_answer() {
    let bss = |ht| Bss {
        bssid: AP,
        ssid: b"janus-e8",
        channel: 6,
        beacon_interval_tu: 100,
        protected: false,
        ht,
    };
    let mut out = [0u8; 512];
    let n = frames::association_response(&mut out, &bss(true), STA, 0, 1, false).unwrap();
    let link = ht::negotiated(&out[ht::ASSOCIATION_RESPONSE_ELEMENTS..n]);
    assert_eq!(
        link,
        Link {
            qos: true,
            ht: Some(HtLink {
                short_gi: true,
                mcs: 0xff
            })
        }
    );
    // an 802.11g access point: neither
    let n = frames::association_response(&mut out, &bss(false), STA, 0, 1, false).unwrap();
    assert_eq!(
        ht::negotiated(&out[ht::ASSOCIATION_RESPONSE_ELEMENTS..n]),
        Link::default()
    );
}

/// `ieee80211`'s typed writer for the same single-MSDU QoS data frame.
fn typed(ccmp: Option<(u64, u8)>, ethernet: &[u8], out: &mut [u8]) -> usize {
    let header = DataFrameHeader {
        subtype: DataFrameSubtype::QoSData,
        fcf_flags: FCFFlags::new().with_to_ds(true),
        address_1: MACAddress::new(AP),
        address_2: MACAddress::new(STA),
        address_3: MACAddress::new(ethernet[..6].try_into().unwrap()),
        sequence_control: SequenceControl::new(),
        qos: Some([0, 0]),
        ..Default::default()
    };
    let frame = DataFrame {
        header,
        payload: Some(SnapLlcFrame {
            oui: [0; 3],
            ether_type: u16::from_be_bytes([ethernet[12], ethernet[13]]).into(),
            payload: &ethernet[14..],
            _phantom: core::marker::PhantomData,
        }),
        _phantom: core::marker::PhantomData,
    };
    match ccmp {
        Some((pn, key_id)) => out
            .pwrite(
                frame.crypto_wrap(CryptoHeader::new(pn, key_id).unwrap(), MicState::Short),
                0,
            )
            .unwrap(),
        None => out.pwrite(frame, 0).unwrap(),
    }
}

#[test]
fn one_packet_is_laid_out_as_ieee80211_lays_it_out() {
    for ccmp in [None, Some((0x0000_0102_0304_0506, 0)), Some((1, 1))] {
        for len in [0, 1, 28, 1486, 1500] {
            let e = ethernet([0x0a, 9, 8, 7, 6, 5], 0x0800, &vec![0x45; len]);
            let mut ours = [0x5au8; 1700];
            let mut theirs = [0x5au8; 1700];
            let n = ht::write_qos_data(&mut ours, AP, STA, ccmp, &[&e]).unwrap();
            let m = typed(ccmp, &e, &mut theirs);
            assert_eq!(n, m, "{ccmp:?} {len}");
            assert_eq!(ours[..n], theirs[..m], "{ccmp:?} {len}");
        }
    }
}

/// The station's receive path, up to the MSDUs: what `handle_data_rx`
/// forwards, as (DA, SA, ether type, payload).
fn received(mpdu: &[u8]) -> Vec<([u8; 6], [u8; 6], u16, Vec<u8>)> {
    let generic = GenericFrame::new(mpdu, false).unwrap();
    let frame = generic
        .parse_to_typed::<DataFrame<'_, &[u8]>>()
        .unwrap()
        .unwrap();
    let wrapped = frame
        .potentially_wrapped_payload(Some(MicState::NotPresent))
        .unwrap();
    let payload = match wrapped {
        PotentiallyWrappedPayload::Unwrapped(p) => p,
        PotentiallyWrappedPayload::CryptoWrapped(c) => c.payload,
    };
    let llc = |p: &[u8]| {
        let l = p.pread::<SnapLlcFrame>(0).unwrap();
        (u16::from(l.ether_type), l.payload.to_vec())
    };
    match payload {
        DataFrameReadPayload::Single(p) => {
            let (t, b) = llc(p);
            vec![(
                **frame.header.destination_address().unwrap(),
                **frame.header.source_address().unwrap(),
                t,
                b,
            )]
        }
        DataFrameReadPayload::AMSDU(it) => it
            .map(|s| {
                let (t, b) = llc(s.payload);
                (*s.destination_address, *s.source_address, t, b)
            })
            .collect(),
    }
}

#[test]
fn an_amsdu_reads_back_as_its_packets() {
    let a = ethernet([0x0a, 9, 8, 7, 6, 5], 0x0800, &vec![0x45; 1486]);
    let b = ethernet([0x0b, 1, 1, 1, 1, 1], 0x0806, &[1; 28]);
    let c = ethernet([0x0c, 2, 2, 2, 2, 2], 0x0800, &[7; 3]);
    for packets in [
        vec![&a[..], &b[..]],
        vec![&b[..], &c[..]],
        vec![&c[..], &b[..], &c[..]],
    ] {
        let mut out = vec![0u8; 4000];
        let n = ht::write_qos_data(&mut out, AP, STA, None, &packets).unwrap();
        let got = received(&out[..n]);
        assert_eq!(got.len(), packets.len());
        for (g, p) in got.iter().zip(&packets) {
            assert_eq!(g.0, p[..6]);
            assert_eq!(g.1, STA);
            assert_eq!(g.2, u16::from_be_bytes([p[12], p[13]]));
            assert_eq!(g.3, p[14..]);
        }
        // protected, the CCMP header and MIC around the same A-MSDU
        let m = ht::write_qos_data(&mut out, AP, STA, Some((5, 0)), &packets).unwrap();
        assert_eq!(m, n + 16);
    }
}

#[test]
fn two_full_size_packets_fit_one_amsdu() {
    let a = ethernet([0x0a, 9, 8, 7, 6, 5], 0x0800, &vec![0x45; 1500]);
    assert!(ht::amsdu_fits(&[a.len(), a.len()]));
    let mut out = vec![0u8; 4000];
    let n = ht::write_qos_data(&mut out, AP, STA, Some((1, 0)), &[&a, &a]).unwrap();
    // header, CCMP, two subframes of 14 + 8 + 1,500 (the first padded to
    // 1,524), MIC
    assert_eq!(n, 26 + 8 + 1524 + 1522 + 8);
}

/// The regression E8 found: the Length field is big-endian. A subframe
/// laid out by hand (the corpus's) must read as one 28-byte MSDU.
#[test]
fn an_amsdu_subframes_length_is_big_endian() {
    let mut f = vec![0x88, 0x02, 0, 0];
    f.extend_from_slice(&STA);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0, 0, 0x80, 0]);
    let mut sub = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 9];
    let mut inner = vec![0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00];
    inner.extend_from_slice(&[0x45; 20]);
    sub.extend_from_slice(&(inner.len() as u16).to_be_bytes());
    sub.extend_from_slice(&inner);
    f.extend_from_slice(&sub);
    f.extend_from_slice(&[0, 0]); // 42 bytes, padded to 44
    f.extend_from_slice(&sub);
    let got = received(&f);
    assert_eq!(got.len(), 2);
    assert!(got.iter().all(|g| g.2 == 0x0800 && g.3 == [0x45; 20]));
}

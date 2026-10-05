//! E4's P1: ESP-NOW's frame as `espnow_frame` lays it out and reads it,
//! against the layout Espressif publishes written out octet by octet, read
//! back by `ieee80211`'s own vendor action frame parser, and fed everything
//! a receive path can be handed without a panic.

use espnow_frame::{BROADCAST, ESPRESSIF_OUI, Frame, MAX_BODY, MAX_FRAME, OVERHEAD, parse, write};
use ieee80211::mgmt_frame::body::action::RawVendorSpecificActionFrame;
use ieee80211::scroll::Pread;

const NODE: [u8; 6] = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01];
const PEER: [u8; 6] = [0x40, 0x4c, 0xca, 0x11, 0x22, 0x33];
const RANDOM: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

fn laid(to: &[u8; 6], body: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; MAX_FRAME];
    let n = write(&mut out, to, &NODE, RANDOM, body).expect("fits");
    out.truncate(n);
    out
}

#[test]
fn the_frame_is_the_published_layout_octet_for_octet() {
    let body = b"janus";
    let frame = laid(&PEER, body);
    #[rustfmt::skip]
    let expected: Vec<u8> = [
        // MAC header: Action (management, subtype 13), no flags; duration 0
        &[0xd0, 0x00, 0x00, 0x00][..],
        &PEER,                                  // address 1: the destination
        &NODE,                                  // address 2: the source
        &[0xff; 6],                             // address 3: broadcast
        &[0x00, 0x00],                          // sequence control: the radio's
        &[127],                                 // category: vendor specific
        &[0x18, 0xfe, 0x34],                    // Espressif's OUI
        &RANDOM,                                // the random octets
        &[221, 5 + body.len() as u8],           // the vendor element and its length
        &[0x18, 0xfe, 0x34],                    // the OUI again
        &[4],                                   // type: ESP-NOW
        &[1],                                   // version 1
        body,
    ]
    .concat();
    assert_eq!(frame, expected);
    assert_eq!(frame.len(), OVERHEAD + body.len());
    assert_eq!(OVERHEAD, 39);
    assert_eq!(MAX_FRAME, 289);
}

#[test]
fn what_is_written_reads_back() {
    for len in [0usize, 1, 18, 84, 100, 249, MAX_BODY] {
        let body: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5a).collect();
        for to in [PEER, BROADCAST] {
            let frame = laid(&to, &body);
            assert_eq!(
                parse(&frame),
                Some(Frame {
                    to,
                    from: NODE,
                    random: RANDOM,
                    version: 1,
                    more_data: false,
                    body: &body,
                }),
                "body of {len}"
            );
        }
    }
}

#[test]
fn a_body_too_long_or_a_buffer_too_short_is_refused() {
    let mut out = vec![0u8; MAX_FRAME + 16];
    assert_eq!(
        write(&mut out, &PEER, &NODE, RANDOM, &[0u8; MAX_BODY + 1]),
        None
    );
    assert_eq!(
        write(&mut out[..OVERHEAD + 9], &PEER, &NODE, RANDOM, &[0u8; 10]),
        None
    );
    assert_eq!(
        write(&mut out[..OVERHEAD + 10], &PEER, &NODE, RANDOM, &[0u8; 10]),
        Some(OVERHEAD + 10)
    );
    // an empty body is a frame (the element's length is 5)
    assert_eq!(write(&mut out, &PEER, &NODE, RANDOM, &[]), Some(OVERHEAD));
    assert_eq!(out[33], 5);
}

/// A second implementation reads what the first one wrote: `ieee80211`'s
/// vendor-specific action frame, which knows nothing of ESP-NOW, sees an
/// Action frame from the node to the peer with Espressif's OUI and, after
/// it, the random octets and the element.
#[test]
fn ieee80211_reads_it_as_a_vendor_action_frame() {
    let body = [0xa5u8; 64];
    let frame = laid(&PEER, &body);
    let read = frame
        .pread_with::<RawVendorSpecificActionFrame>(0, false)
        .expect("a vendor-specific action frame");
    assert_eq!(read.header.receiver_address.0, PEER);
    assert_eq!(read.header.transmitter_address.0, NODE);
    assert_eq!(read.header.bssid.0, BROADCAST);
    assert_eq!(read.body.oui, ESPRESSIF_OUI);
    let payload = read.body.payload;
    assert_eq!(&payload[..4], &RANDOM);
    assert_eq!(payload[4], 221);
    assert_eq!(usize::from(payload[5]), 5 + body.len());
    assert_eq!(&payload[6..9], &ESPRESSIF_OUI);
    assert_eq!(&payload[9..11], &[4, 1]);
    assert_eq!(&payload[11..], &body);
}

#[test]
fn anything_else_is_not_an_esp_now_frame() {
    let good = laid(&PEER, b"0123456789");
    assert!(parse(&good).is_some());
    let broken = |at: usize, value: u8| {
        let mut f = good.clone();
        f[at] = value;
        parse(&f).is_some()
    };
    assert!(!broken(0, 0x80), "a beacon");
    assert!(!broken(0, 0xd4), "a control frame of the same subtype");
    assert!(!broken(1, 0x01), "ToDS");
    assert!(!broken(1, 0x02), "FromDS");
    assert!(!broken(1, 0x40), "encrypted ESP-NOW is not read");
    assert!(broken(1, 0x08), "a retry is the same frame");
    assert!(!broken(24, 4), "another category");
    assert!(!broken(25, 0x00), "another vendor's action frame");
    assert!(!broken(32, 48), "not the vendor element");
    assert!(!broken(36, 0x35), "another vendor's element");
    assert!(!broken(37, 5), "another type of Espressif's");
    assert!(!broken(38, 0), "version 0 does not exist");
    assert!(!broken(33, 4), "an element shorter than its own header");
    assert!(!broken(33, 16), "an element running past the frame");
    // address 3 is not what makes it ESP-NOW
    let mut other_bssid = good.clone();
    other_bssid[16..22].copy_from_slice(&PEER);
    assert!(parse(&other_bssid).is_some());
    // octets after the element are left alone
    let mut longer = good.clone();
    longer.extend_from_slice(&[221, 3, 1, 2, 3]);
    assert_eq!(parse(&longer).unwrap().body, b"0123456789");
}

#[test]
fn version_2_frames_are_read() {
    let mut frame = laid(&NODE, b"from a newer radio");
    frame[38] = 0x02;
    let read = parse(&frame).unwrap();
    assert_eq!((read.version, read.more_data), (2, false));
    // "more data": the payload continues in elements this does not join
    frame[38] = 0x12;
    let read = parse(&frame).unwrap();
    assert_eq!((read.version, read.more_data), (2, true));
    assert_eq!(read.body, b"from a newer radio");
}

/// The receive path's promise: every prefix of a frame, and 200,000 frames
/// of noise and of mutated good frames, are read or refused, never a panic.
#[test]
fn no_input_panics_the_parser() {
    let good = laid(&BROADCAST, &[0x33u8; MAX_BODY]);
    for n in 0..=good.len() {
        let read = parse(&good[..n]);
        assert_eq!(read.is_some(), n == good.len(), "prefix of {n}");
    }
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut buf = vec![0u8; MAX_FRAME + 32];
    let mut read_ok = 0u32;
    for round in 0..200_000u32 {
        let len = (next() as usize) % buf.len();
        if round % 2 == 0 {
            for b in &mut buf[..len] {
                *b = next() as u8;
            }
        } else {
            // a good frame with a few octets changed
            let n = good.len().min(len.max(OVERHEAD));
            buf[..n].copy_from_slice(&good[..n]);
            for _ in 0..(next() % 4) {
                let at = (next() as usize) % n;
                buf[at] = next() as u8;
            }
            if let Some(f) = parse(&buf[..n]) {
                assert!(f.body.len() <= MAX_BODY);
                read_ok += 1;
            }
            continue;
        }
        if let Some(f) = parse(&buf[..len]) {
            assert!(f.body.len() <= MAX_BODY);
        }
    }
    assert!(read_ok > 0, "some mutated frames still read");
}

/// A frame from `from` with `sequence` in its sequence control, the Retry
/// bit set or clear.
fn sequenced(from: &[u8; 6], sequence: u16, retry: bool) -> Vec<u8> {
    let mut out = vec![0u8; MAX_FRAME];
    let n = write(&mut out, &NODE, from, RANDOM, b"x").expect("fits");
    out.truncate(n);
    if retry {
        out[1] |= 0x08;
    }
    out[22..24].copy_from_slice(&sequence.to_le_bytes());
    out
}

#[test]
fn a_retransmission_already_taken_is_a_duplicate_and_nothing_else_is() {
    use espnow_frame::{DUPLICATE_CACHE, Duplicates};
    let mut seen = Duplicates::new();
    // the first copy, then its retry: the acknowledgement was lost
    assert!(!seen.is_duplicate(&sequenced(&PEER, 0x0120, false)));
    assert!(seen.is_duplicate(&sequenced(&PEER, 0x0120, true)));
    assert!(seen.is_duplicate(&sequenced(&PEER, 0x0120, true)));
    // the next frame, sent twice because the first copy was lost on the
    // way here: its retry is the first this receiver has seen
    assert!(!seen.is_duplicate(&sequenced(&PEER, 0x0130, true)));
    assert!(seen.is_duplicate(&sequenced(&PEER, 0x0130, true)));
    // the same sequence control without the Retry bit is a new frame (a
    // counter that wrapped, a transmitter that restarted)
    assert!(!seen.is_duplicate(&sequenced(&PEER, 0x0130, false)));
    // another transmitter's numbers are its own
    let other = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x02];
    assert!(!seen.is_duplicate(&sequenced(&other, 0x0130, true)));
    assert!(seen.is_duplicate(&sequenced(&other, 0x0130, true)));
    assert!(seen.is_duplicate(&sequenced(&PEER, 0x0130, true)));
    // more transmitters than the cache holds: the oldest is forgotten, and
    // forgetting only ever lets a copy through, never drops a new frame
    for i in 0..DUPLICATE_CACHE as u8 {
        assert!(!seen.is_duplicate(&sequenced(&[2, 0, 0, 0, 0, i], 7, true)));
    }
    assert!(!seen.is_duplicate(&sequenced(&PEER, 0x0130, true)));
    // too short to carry a sequence control
    assert!(!seen.is_duplicate(&[0xd0, 0x08, 0, 0]));
    assert!(!seen.is_duplicate(&[]));
}

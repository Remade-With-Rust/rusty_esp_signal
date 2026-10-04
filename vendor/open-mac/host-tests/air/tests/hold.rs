//! E3's P5: the frames held for dozing stations (`ap_core::hold`), oldest
//! first per station, the group frames apart, a full pool refusing.

use ap_core::hold::{Full, HELD_FRAME_BYTES, HELD_FRAMES, Held};

const A: [u8; 6] = [2, 0, 0, 0, 0, 0xa];
const B: [u8; 6] = [2, 0, 0, 0, 0, 0xb];
const AP: [u8; 6] = [2, 0, 0, 0, 0, 1];
const BROADCAST: [u8; 6] = [0xff; 6];

fn eth(to: [u8; 6], tag: u8, payload_len: usize) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&to);
    f.extend_from_slice(&AP);
    f.extend_from_slice(&[0x08, 0x00]);
    f.extend(core::iter::repeat_n(tag, payload_len));
    f
}

#[test]
fn oldest_first_per_station_and_the_more_data_bit() {
    let mut held = Held::new();
    held.push(&eth(A, 1, 10), false).unwrap();
    held.push(&eth(B, 9, 10), false).unwrap();
    held.push(&eth(A, 2, 20), false).unwrap();
    assert_eq!(held.count(&A), 2);
    assert_eq!(held.count(&B), 1);
    assert_eq!(held.group_count(), 0);

    let (taken, more) = held.pop(&A).unwrap();
    assert_eq!(taken.frame, eth(A, 1, 10).as_slice());
    assert!(more, "one more waits for A");
    let (taken, more) = held.pop(&A).unwrap();
    assert_eq!(taken.frame, eth(A, 2, 20).as_slice());
    assert!(!more);
    assert!(held.pop(&A).is_none());
    // B's frame was never touched
    let (taken, more) = held.pop(&B).unwrap();
    assert_eq!(taken.frame[14], 9);
    assert!(!more);
    assert_eq!(held.free(), HELD_FRAMES);
}

#[test]
fn group_frames_are_kept_apart() {
    let mut held = Held::new();
    held.push(&eth(BROADCAST, 7, 40), true).unwrap();
    held.push(&eth(A, 1, 10), false).unwrap();
    held.push(&eth([1, 0, 0x5e, 0, 0, 1], 8, 40), true).unwrap();
    assert_eq!(held.group_count(), 2);
    assert_eq!(held.count(&A), 1);
    // a station's pop never hands out a group frame, nor the other way
    assert!(held.pop(&BROADCAST).is_none());
    let (g1, more) = held.pop_group().unwrap();
    assert_eq!(g1.frame[14], 7);
    assert!(more);
    let (g2, more) = held.pop_group().unwrap();
    assert_eq!(g2.frame[14], 8);
    assert!(!more);
    assert!(held.pop_group().is_none());
    assert_eq!(held.count(&A), 1);
}

#[test]
fn a_full_pool_refuses_and_a_leaving_station_frees_its_frames() {
    let mut held = Held::new();
    for i in 0..HELD_FRAMES {
        held.push(&eth(if i % 2 == 0 { A } else { B }, i as u8, 100), false)
            .unwrap();
    }
    assert_eq!(held.free(), 0);
    assert_eq!(held.push(&eth(A, 0xee, 10), false), Err(Full));
    assert_eq!(held.clear(&A), (HELD_FRAMES / 2) as u16);
    assert_eq!(held.count(&A), 0);
    assert_eq!(held.count(&B), (HELD_FRAMES / 2) as u16);
    assert_eq!(held.free(), HELD_FRAMES / 2);
    held.push(&eth(A, 0xee, 10), false).unwrap();
    // B's order survived A's clearing
    let (b, _) = held.pop(&B).unwrap();
    assert_eq!(b.frame[14], 1);
}

#[test]
fn frame_sizes_are_bounded() {
    let mut held = Held::new();
    assert_eq!(
        held.push(&[0u8; 13], false),
        Err(Full),
        "shorter than an Ethernet header"
    );
    assert_eq!(
        held.push(&vec![0u8; HELD_FRAME_BYTES + 1], false),
        Err(Full)
    );
    held.push(&vec![0u8; HELD_FRAME_BYTES], true).unwrap();
    assert_eq!(held.pop_group().unwrap().0.frame.len(), HELD_FRAME_BYTES);
}

#[test]
fn the_sequence_survives_wrapping() {
    // 0 marks an empty slot: the counter must never hand it out
    let mut held = Held::new();
    for _ in 0..3 * HELD_FRAMES {
        held.push(&eth(A, 1, 1), false).unwrap();
        held.pop(&A).unwrap();
    }
    held.push(&eth(A, 5, 1), false).unwrap();
    assert_eq!(held.count(&A), 1);
}

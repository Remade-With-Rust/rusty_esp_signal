//! E2's F15: the station's group keys by key ID, through an access point's
//! rekey. FoA held one group key and overwrote it, so group frames still
//! under the old key ID were lost until the access point switched over.

use sta_handshake::{GroupKey, GroupKeys, Install, Refusal};

fn gtk(key_id: u8, byte: u8, rsc: u64) -> GroupKey {
    GroupKey {
        key: [byte; 16],
        key_id,
        rsc,
        replay_counter: 0,
    }
}

#[test]
fn frames_under_the_old_and_the_new_key_both_pass_through_a_rekey() {
    let mut keys = GroupKeys::new();
    assert_eq!(keys.install(&gtk(1, 0xa1, 10)), Ok(Install::Program(0)));
    assert!(keys.admit(1, 11));
    // the rekey: key ID 2 arrives while the access point still sends under 1
    assert_eq!(keys.install(&gtk(2, 0xa2, 0)), Ok(Install::Program(1)));
    assert!(
        keys.admit(1, 12),
        "the old key still decrypts during the switch-over"
    );
    assert!(keys.admit(2, 1), "the new key from its first frame");
    assert!(keys.admit(1, 13));
    assert!(keys.admit(2, 2));
}

#[test]
fn each_key_keeps_its_own_replay_window() {
    let mut keys = GroupKeys::new();
    keys.install(&gtk(1, 0xa1, 100)).unwrap();
    keys.install(&gtk(2, 0xa2, 0)).unwrap();
    assert!(!keys.admit(1, 100), "at the RSC is a replay");
    assert!(keys.admit(1, 101));
    assert!(!keys.admit(1, 101), "the same number again");
    assert!(
        keys.admit(2, 5),
        "key 2's window is its own, not key 1's 101"
    );
    assert!(!keys.admit(2, 4));
}

#[test]
fn a_frame_under_a_key_id_not_held_is_refused() {
    let mut keys = GroupKeys::new();
    keys.install(&gtk(1, 0xa1, 0)).unwrap();
    assert!(!keys.admit(0, 1));
    assert!(!keys.admit(3, 1));
}

#[test]
fn the_third_key_replaces_the_older_and_an_id_reused_replaces_its_own() {
    let mut keys = GroupKeys::new();
    keys.install(&gtk(1, 0xa1, 0)).unwrap();
    keys.install(&gtk(2, 0xa2, 0)).unwrap();
    // access points alternate IDs: the third rekey reuses ID 1 with a new key
    assert_eq!(keys.install(&gtk(1, 0xb1, 0)), Ok(Install::Program(0)));
    assert_eq!(keys.key_ids(), [Some(1), Some(2)]);
    assert!(
        keys.admit(1, 1),
        "ID 1 is the new key's, its window from its RSC"
    );
    // a new ID with both entries full replaces the older of the two (ID 2's)
    assert_eq!(keys.install(&gtk(3, 0xc3, 0)), Ok(Install::Program(1)));
    assert_eq!(keys.key_ids(), [Some(1), Some(3)]);
    assert!(!keys.admit(2, 9), "the oldest key is gone");
}

#[test]
fn a_retried_rekey_does_not_reprogram_or_reset_the_window() {
    let mut keys = GroupKeys::new();
    keys.install(&gtk(2, 0xa2, 0)).unwrap();
    assert!(keys.admit(2, 50));
    assert_eq!(
        keys.install(&gtk(2, 0xa2, 0)),
        Ok(Install::AlreadyInstalled)
    );
    assert!(
        !keys.admit(2, 50),
        "the window was kept, not reset to the RSC"
    );
}

#[test]
fn a_key_does_not_move_to_another_id() {
    let mut keys = GroupKeys::new();
    keys.install(&gtk(1, 0xa1, 0)).unwrap();
    assert_eq!(keys.install(&gtk(2, 0xa1, 0)), Err(Refusal::KeyMoved));
    assert_eq!(keys.key_ids(), [Some(1), None]);
}

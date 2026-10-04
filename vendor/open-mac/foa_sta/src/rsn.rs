use core::sync::atomic::Ordering;

use foa::{
    KeySlot,
    esp_wifi_hal::prelude::{AesCipherParameters, CipherParameters, KeyType, MultiLengthKey},
};
use ieee80211::{
    crypto::partition_ptk,
    elements::rsn::{IEEE80211AkmType, IEEE80211CipherSuiteSelector},
};
use portable_atomic::AtomicU64;


/// The length of a Pairwise Master Key.
///
/// This is different for two AKMs, which we're luckily very far from implementing.
pub const PMK_LENGTH: usize = 32;
pub const WPA2_PSK_AKM: IEEE80211AkmType = IEEE80211AkmType::Psk;
pub const PTK_LENGTH: usize = WPA2_PSK_AKM.kck_len().unwrap()
    + WPA2_PSK_AKM.kek_len().unwrap()
    + IEEE80211CipherSuiteSelector::Ccmp128.tk_len().unwrap();

#[derive(Debug)]
/// A transient key security association.
///
/// Currently this is only meant for GTKSA's and PTKSA's
pub(crate) struct TransientKeySecurityAssociation<const N: usize, const IS_PAIRWISE: bool> {
    /// The cryptographic key of this TKSA.
    pub key: [u8; N],
    /// The ID of the key.
    pub key_id: u8,
    /// The replay counter tracks the last packet number received from the STA, with which this
    /// TKSA is established. It's updated with the PN of any received frame, where the PN is larger
    /// than the current value.
    replay_counter: AtomicU64,
    /// The TX packet number is incremented by one for every transmitted encapsulated MPDU.
    packet_number: AtomicU64,
}
impl<const N: usize, const IS_PAIRWISE: bool> TransientKeySecurityAssociation<N, IS_PAIRWISE> {
    /// Create a new TKSA with all counters initialized to zero.
    pub const fn new(key: [u8; N], key_id: u8) -> Self {
        Self {
            key,
            key_id,
            replay_counter: AtomicU64::new(0),
            packet_number: AtomicU64::new(1),
        }
    }
    /// Get the temporal key for this TKSA.
    pub fn tk(
        &self,
        akm_suite: IEEE80211AkmType,
        cipher_suite: IEEE80211CipherSuiteSelector,
    ) -> &[u8] {
        if IS_PAIRWISE {
            partition_ptk(&self.key, akm_suite, cipher_suite).unwrap().2
        } else {
            self.key.as_slice()
        }
    }
    /// Get the next TX packet number for this TKSA.
    pub fn next_packet_number(&self) -> u64 {
        self.packet_number.fetch_add(1, Ordering::Relaxed)
    }
    /// Check if the PN is valid and update the replay counter.
    ///
    /// This will only update the replay counter, if the PN is larger than the current value.
    pub fn update_and_validate_replay_counter(&self, packet_number: u64) -> bool {
        let replay_counter = self.replay_counter.load(Ordering::Relaxed);
        let valid = replay_counter < packet_number;
        if valid {
            self.replay_counter.store(packet_number, Ordering::Relaxed);
        } else {
            debug!(
                "Packet number not greater than replay counter. {} <= {}",
                replay_counter, packet_number
            );
        }
        valid
    }
}
#[derive(Debug)]
/// All security associations used in a WPA2 network.
pub(crate) struct SecurityAssociations {
    /// The pairwise transient key.
    pub ptksa: TransientKeySecurityAssociation<PTK_LENGTH, true>,
    /// The group key message 3 brought; from then on the group keys are
    /// [`CryptoState::group_keys`]'s (E2's F15).
    pub initial_gtk: sta_handshake::GroupKey,
    /// The Authentication and Key Management Suite.
    pub akm_suite: IEEE80211AkmType,
    /// The cipher suite.
    pub cipher_suite: IEEE80211CipherSuiteSelector,
    /// The replay counter of the last MIC-verified EAPOL-Key frame (message
    /// 3's, then each group message's): the next must be above it (E2's F3).
    pub eapol_replay_counter: u64,
}
impl SecurityAssociations {
    pub fn pairwise_temporal_key(&self) -> &[u8] {
        self.ptksa.tk(self.akm_suite, self.cipher_suite)
    }
    /*
    pub fn kck(&self) -> &[u8] {
        partition_ptk(&self.ptksa.key, self.akm_suite, self.cipher_suite)
            .unwrap()
            .0
    }
    pub fn kek(&self) -> &[u8] {
        partition_ptk(&self.ptksa.key, self.akm_suite, self.cipher_suite)
            .unwrap()
            .1
    }
    */
}
/// State of cryptographic management.
pub(crate) struct CryptoState<'foa> {
    /// Key slots for the group keys, one per [`sta_handshake::GroupKeys`]
    /// entry: the current group key and the one a rekey brings (E2's F15).
    pub gtk_key_slots: [KeySlot<'foa>; sta_handshake::GROUP_KEY_SLOTS],
    /// The group keys held, by key ID, with their replay windows.
    pub group_keys: sta_handshake::GroupKeys,
    /// Key slot used for the PTK.
    pub ptk_key_slot: KeySlot<'foa>,
    /// All security associations.
    pub security_associations: SecurityAssociations,
}
impl<'foa> CryptoState<'foa> {
    pub fn new(
        gtk_key_slots: [KeySlot<'foa>; sta_handshake::GROUP_KEY_SLOTS],
        ptk_key_slot: KeySlot<'foa>,
        bssid: [u8; 6],
        security_associations: SecurityAssociations,
    ) -> Self {
        let initial_gtk = security_associations.initial_gtk;
        let mut temp = Self {
            gtk_key_slots,
            group_keys: sta_handshake::GroupKeys::new(),
            ptk_key_slot,
            security_associations,
        };
        let ptk_key_id = temp.security_associations.ptksa.key_id;
        let tk: [u8; 16] = temp
            .security_associations
            .pairwise_temporal_key()
            .try_into()
            .unwrap();
        Self::program(&mut temp.ptk_key_slot, ptk_key_id, &tk, KeyType::Pairwise, bssid);
        // the first group key: an empty set takes any key, so this cannot fail
        let _ = temp.update_gtksa(&initial_gtk, bssid);
        temp
    }
    /// Take a group key (message 3's, or a group-key handshake's: E2's F2):
    /// held by its key ID beside the one before it, so frames under either
    /// decrypt through the access point's switch-over (F15), its replay
    /// window from its RSC (F11). A retry of a key held already programs
    /// nothing; a key offered under a second ID is refused.
    pub fn update_gtksa(
        &mut self,
        gtk: &sta_handshake::GroupKey,
        bssid: [u8; 6],
    ) -> Result<(), sta_handshake::Refusal> {
        if let sta_handshake::Install::Program(entry) = self.group_keys.install(gtk)? {
            Self::program(&mut self.gtk_key_slots[entry], gtk.key_id, &gtk.key, KeyType::Group, bssid);
        }
        self.security_associations.eapol_replay_counter = gtk.replay_counter;
        Ok(())
    }
    fn program(key_slot: &mut KeySlot<'_>, key_id: u8, key: &[u8; 16], key_type: KeyType, bssid: [u8; 6]) {
        key_slot
            .set_key(
                key_id,
                bssid,
                CipherParameters::Ccmp(AesCipherParameters {
                    key: MultiLengthKey::Short(key),
                    key_type,
                    mfp_enabled: false,
                    spp_enabled: false,
                }),
            )
            .unwrap();
    }
}

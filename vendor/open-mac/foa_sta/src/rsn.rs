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
pub const GTK_LENGTH: usize = IEEE80211CipherSuiteSelector::Ccmp128.tk_len().unwrap();

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
    /// Start the replay window at `packet_number`: frames at or below it
    /// are replays (E2's F11: a group key's starting RSC from the
    /// handshake, where FoA started every window at 0).
    pub fn set_replay_counter(&self, packet_number: u64) {
        self.replay_counter.store(packet_number, Ordering::Relaxed);
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
    /// The group transient key.
    pub gtksa: TransientKeySecurityAssociation<GTK_LENGTH, false>,
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
    pub fn group_temporal_key(&self) -> &[u8] {
        self.gtksa.tk(self.akm_suite, self.cipher_suite)
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
    /// Key slot used for the GTK.
    pub gtk_key_slot: KeySlot<'foa>,
    /// Key slot used for the PTK.
    pub ptk_key_slot: KeySlot<'foa>,
    /// All security associations.
    pub security_associations: SecurityAssociations,
}
impl<'foa> CryptoState<'foa> {
    pub fn new(
        gtk_key_slot: KeySlot<'foa>,
        ptk_key_slot: KeySlot<'foa>,
        bssid: [u8; 6],
        security_associations: SecurityAssociations,
    ) -> Self {
        let mut temp = Self {
            gtk_key_slot,
            ptk_key_slot,
            security_associations,
        };
        temp.update_key_slot(false, bssid);
        temp.update_key_slot(true, bssid);
        temp
    }
    /// Install a new group key from a group-key handshake (E2's F2: FoA
    /// had this commented out, and no handshake to call it).
    pub fn update_gtksa(&mut self, gtk: &sta_handshake::GroupKey, bssid: [u8; 6]) {
        self.security_associations.gtksa.key.copy_from_slice(&gtk.key);
        self.security_associations.gtksa.key_id = gtk.key_id;
        self.security_associations.gtksa.set_replay_counter(gtk.rsc);
        self.security_associations.eapol_replay_counter = gtk.replay_counter;
        self.update_key_slot(true, bssid);
    }
    fn update_key_slot(&mut self, group: bool, bssid: [u8; 6]) {
        let (key_slot, tk, key_id, key_type) = if group {
            (
                &mut self.gtk_key_slot,
                self.security_associations.group_temporal_key(),
                self.security_associations.gtksa.key_id,
                KeyType::Group,
            )
        } else {
            (
                &mut self.ptk_key_slot,
                self.security_associations.pairwise_temporal_key(),
                self.security_associations.ptksa.key_id,
                KeyType::Pairwise,
            )
        };
        key_slot
            .set_key(
                key_id,
                bssid,
                CipherParameters::Ccmp(AesCipherParameters {
                    key: MultiLengthKey::Short(tk.try_into().unwrap()),
                    key_type,
                    mfp_enabled: false,
                    spp_enabled: false,
                }),
            )
            .unwrap();
    }
}

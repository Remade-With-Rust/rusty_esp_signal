//! The station's half of WPA2-PSK's handshakes, as pure functions (Janus
//! E2, the family's addition to FoA). FoA's station drives them over the
//! air; `host-tests/air` drives them against a simulated access point. No
//! hardware, no clock, no randomness in here: the caller brings the
//! supplicant nonce, the buffers and the frames.
//!
//! What a received frame must be to be taken, beyond what `ieee80211`'s
//! deserialiser checks (the MIC, the key unwrap):
//!
//! - message 1: AES/HMAC-SHA1, pairwise, Key Ack; nothing else is trusted
//!   (it has no MIC), so its replay counter is only echoed;
//! - message 3: as message 1, plus MIC, Secure, Install and encrypted key
//!   data, a GTK KDE of exactly 16 bytes (E2's F1: FoA panicked on any
//!   other length), and a replay counter above the last MIC-verified frame's
//!   when there was one;
//! - group message 1 (E2's F2: FoA had no group-key handshake): group (not
//!   pairwise), Key Ack, MIC, Secure, encrypted key data, a 16-byte GTK, and
//!   a replay counter above the last MIC-verified frame's (E2's F3: a
//!   replayed group message would reinstall an old group key).
//!
//! The group key's starting packet number (`key_rsc`) comes back with it
//! (E2's F11: FoA started the group replay window at 0). Nothing here logs,
//! and no key leaves except as a return value (E2's F4).

#![no_std]

use core::marker::PhantomData;

use ieee80211::common::{DataFrameSubtype, FCFFlags, SequenceControl};
use ieee80211::crypto::eapol::{EapolKeyFrame, KeyDescriptorVersion, KeyInformation};
use ieee80211::crypto::{
    CryptoHeader, EapolSerdeError, derive_ptk, deserialize_eapol_data_frame,
    serialize_eapol_data_frame,
};
use ieee80211::data_frame::DataFrame;
use ieee80211::data_frame::header::DataFrameHeader;
use ieee80211::element_chain;
use ieee80211::elements::kde::GtkKde;
use ieee80211::elements::rsn::{IEEE80211AkmType, RsnElement};
use ieee80211::mac_parser::MACAddress;
use ieee80211::scroll::Pwrite;
use llc_rs::{EtherType, SnapLlcFrame};

/// WPA2-PSK.
pub const AKM: IEEE80211AkmType = IEEE80211AkmType::Psk;
/// The group key: CCMP-128's.
pub const GTK_LENGTH: usize = 16;
/// KCK, KEK and TK for WPA2-PSK with CCMP-128.
pub const PTK_LENGTH: usize = 48;
/// The MIC of an EAPOL-Key frame under WPA2-PSK.
const MIC_LENGTH: usize = 16;

/// Why a frame was not taken. The caller drops it and waits for the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not an EAPOL-Key frame this deserialiser reads, or too short.
    Frame,
    /// The MIC did not match, or the key data did not unwrap.
    Mic,
    /// The key information is not this message's.
    KeyInformation,
    /// The replay counter is not above the last MIC-verified frame's.
    Replay,
    /// No GTK KDE in the key data.
    NoGtk,
    /// A GTK of this many bytes, not 16.
    GtkLength(usize),
    /// An output or scratch buffer was too small (ours, not the sender's).
    Buffer,
}

impl From<EapolSerdeError> for Refusal {
    fn from(e: EapolSerdeError) -> Self {
        match e {
            EapolSerdeError::InvalidMic | EapolSerdeError::TemporaryBufferToShort => Refusal::Mic,
            _ => Refusal::Frame,
        }
    }
}

/// The pairwise transient key: KCK, KEK and TK in that order.
#[derive(Clone)]
pub struct PairwiseKeys {
    /// All 48 bytes.
    pub ptk: [u8; PTK_LENGTH],
}

impl PairwiseKeys {
    /// Derive from the PMK, both addresses and both nonces.
    #[must_use]
    pub fn derive(
        pmk: &[u8; 32],
        authenticator: &[u8; 6],
        supplicant: &[u8; 6],
        anonce: &[u8; 32],
        snonce: &[u8; 32],
    ) -> Self {
        let mut ptk = [0u8; PTK_LENGTH];
        derive_ptk(pmk, authenticator, supplicant, anonce, snonce, &mut ptk);
        Self { ptk }
    }
    /// The key confirmation key: the MIC's.
    #[must_use]
    pub fn kck(&self) -> &[u8; 16] {
        self.ptk[..16].try_into().expect("16 of 48")
    }
    /// The key encryption key: the key data's.
    #[must_use]
    pub fn kek(&self) -> &[u8; 16] {
        self.ptk[16..32].try_into().expect("16 of 48")
    }
    /// The temporal key: the data frames'.
    #[must_use]
    pub fn tk(&self) -> &[u8; 16] {
        self.ptk[32..48].try_into().expect("16 of 48")
    }
}

/// What message 1 brings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message1 {
    /// The authenticator's nonce.
    pub anonce: [u8; 32],
    /// Echoed in message 2.
    pub replay_counter: u64,
}

/// A group key, from message 3 or a group message 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroupKey {
    /// The GTK.
    pub key: [u8; GTK_LENGTH],
    /// Its key ID (0..=3).
    pub key_id: u8,
    /// The group's receive sequence counter as the authenticator gave it:
    /// group frames at or below it are replays.
    pub rsc: u64,
    /// The frame's replay counter: echoed in the reply, and the floor for
    /// the next frame.
    pub replay_counter: u64,
}

fn is_message_1(k: KeyInformation) -> bool {
    k.key_descriptor_version() == KeyDescriptorVersion::AesHmacSha1
        && k.is_pairwise()
        && k.key_ack()
        && !k.key_mic()
        && !k.install()
        && !k.encrypted_key_data()
}

fn is_message_3(k: KeyInformation) -> bool {
    k.key_descriptor_version() == KeyDescriptorVersion::AesHmacSha1
        && k.is_pairwise()
        && k.key_ack()
        && k.key_mic()
        && k.secure()
        && k.install()
        && k.encrypted_key_data()
}

fn is_group_message_1(k: KeyInformation) -> bool {
    k.key_descriptor_version() == KeyDescriptorVersion::AesHmacSha1
        && !k.is_pairwise()
        && k.key_ack()
        && k.key_mic()
        && k.secure()
        && !k.install()
        && k.encrypted_key_data()
}

/// Read message 1 of the 4-way handshake from a data frame.
pub fn read_message_1(mpdu: &mut [u8]) -> Result<Message1, Refusal> {
    let frame = deserialize_eapol_data_frame(None, None, mpdu, &mut [], AKM, false)?;
    if !is_message_1(frame.key_information) {
        return Err(Refusal::KeyInformation);
    }
    Ok(Message1 {
        anonce: frame.key_nonce,
        replay_counter: frame.key_replay_counter,
    })
}

/// The GTK out of verified key data, and the frame's counters.
fn group_key(frame: &EapolKeyFrame<'_>) -> Result<GroupKey, Refusal> {
    let gtk = frame
        .key_data
        .get_first_element::<GtkKde>()
        .ok_or(Refusal::NoGtk)?;
    let key: [u8; GTK_LENGTH] = gtk
        .gtk
        .try_into()
        .map_err(|_| Refusal::GtkLength(gtk.gtk.len()))?;
    Ok(GroupKey {
        key,
        key_id: gtk.gtk_info.key_id(),
        rsc: frame.key_rsc,
        replay_counter: frame.key_replay_counter,
    })
}

fn above(counter: u64, floor: Option<u64>) -> Result<(), Refusal> {
    match floor {
        Some(floor) if counter <= floor => Err(Refusal::Replay),
        _ => Ok(()),
    }
}

/// Read message 3. `floor`: the replay counter of the last MIC-verified
/// EAPOL-Key frame of this association, if there was one.
pub fn read_message_3(
    mpdu: &mut [u8],
    keys: &PairwiseKeys,
    scratch: &mut [u8],
    floor: Option<u64>,
) -> Result<GroupKey, Refusal> {
    let frame = deserialize_eapol_data_frame(
        Some(keys.kck()),
        Some(keys.kek()),
        mpdu,
        scratch,
        AKM,
        false,
    )?;
    if !is_message_3(frame.key_information) {
        return Err(Refusal::KeyInformation);
    }
    above(frame.key_replay_counter, floor)?;
    group_key(&frame)
}

/// Read a group-key handshake's message 1 (a rekey after the join).
/// `floor`: the replay counter of the last MIC-verified EAPOL-Key frame
/// (message 3's, then each group message's).
pub fn read_group_message_1(
    mpdu: &mut [u8],
    keys: &PairwiseKeys,
    scratch: &mut [u8],
    floor: u64,
) -> Result<GroupKey, Refusal> {
    let frame = deserialize_eapol_data_frame(
        Some(keys.kck()),
        Some(keys.kek()),
        mpdu,
        scratch,
        AKM,
        false,
    )?;
    if !is_group_message_1(frame.key_information) {
        return Err(Refusal::KeyInformation);
    }
    above(frame.key_replay_counter, Some(floor))?;
    group_key(&frame)
}

/// An EAPOL-Key frame from the station to the access point, MIC'd with the
/// KCK; returns its length in `out`. `scratch` holds the MIC's work.
#[allow(clippy::too_many_arguments)]
fn write_key_frame<E: ieee80211::scroll::ctx::TryIntoCtx<(), Error = ieee80211::scroll::Error>>(
    out: &mut [u8],
    scratch: &mut [u8],
    bssid: MACAddress,
    own: MACAddress,
    key_information: KeyInformation,
    replay_counter: u64,
    nonce: [u8; 32],
    key_data: E,
    kck: &[u8; 16],
) -> Result<usize, Refusal> {
    let frame = DataFrame {
        header: DataFrameHeader {
            subtype: DataFrameSubtype::Data,
            fcf_flags: FCFFlags::new().with_to_ds(true),
            address_1: bssid,
            address_2: own,
            address_3: bssid,
            sequence_control: SequenceControl::new(),
            ..Default::default()
        },
        payload: Some(SnapLlcFrame {
            oui: [0u8; 3],
            ether_type: EtherType::Eapol,
            payload: EapolKeyFrame {
                key_information,
                key_length: 16,
                key_replay_counter: replay_counter,
                key_nonce: nonce,
                key_iv: 0,
                key_rsc: 0,
                key_mic: [0u8; MIC_LENGTH].as_slice(),
                key_data,
                _phantom: PhantomData,
            },
            _phantom: PhantomData,
        }),
        _phantom: PhantomData,
    };
    serialize_eapol_data_frame(Some(kck), None, frame, out, scratch).map_err(|_| Refusal::Buffer)
}

/// Message 2: the station's nonce and its RSN element, MIC'd.
pub fn write_message_2(
    out: &mut [u8],
    scratch: &mut [u8],
    bssid: MACAddress,
    own: MACAddress,
    keys: &PairwiseKeys,
    snonce: &[u8; 32],
    replay_counter: u64,
) -> Result<usize, Refusal> {
    write_key_frame(
        out,
        scratch,
        bssid,
        own,
        KeyInformation::new()
            .with_is_pairwise(true)
            .with_key_mic(true)
            .with_key_descriptor_version(KeyDescriptorVersion::AesHmacSha1),
        replay_counter,
        *snonce,
        element_chain! { RsnElement::WPA2_PERSONAL },
        keys.kck(),
    )
}

/// Message 4: the acknowledgement, MIC'd, Secure.
pub fn write_message_4(
    out: &mut [u8],
    scratch: &mut [u8],
    bssid: MACAddress,
    own: MACAddress,
    keys: &PairwiseKeys,
    replay_counter: u64,
) -> Result<usize, Refusal> {
    write_key_frame(
        out,
        scratch,
        bssid,
        own,
        KeyInformation::new()
            .with_is_pairwise(true)
            .with_key_mic(true)
            .with_secure(true)
            .with_key_descriptor_version(KeyDescriptorVersion::AesHmacSha1),
        replay_counter,
        [0u8; 32],
        element_chain! {},
        keys.kck(),
    )
}

/// A group-key handshake's message 2, MIC'd, Secure, group, and protected
/// under the pairwise key (802.11-2020 12.7.7: after the 4-way handshake
/// the EAPOL-Key frames travel under the PTKSA): the frame is laid out with
/// its CCMP header (`packet_number`, `key_id`) and room for the MIC, the
/// Protected bit set, for the hardware to encrypt with the PTK's key slot.
#[allow(clippy::too_many_arguments)]
pub fn write_group_message_2(
    out: &mut [u8],
    scratch: &mut [u8],
    bssid: MACAddress,
    own: MACAddress,
    keys: &PairwiseKeys,
    replay_counter: u64,
    packet_number: u64,
    key_id: u8,
) -> Result<usize, Refusal> {
    // the EAPOL frame as if unprotected, MIC'd, at the end of `out`...
    const HEADER: usize = 24;
    const CCMP: usize = 8;
    const CCMP_MIC: usize = 8;
    let (front, back) = out
        .len()
        .checked_sub(256)
        .map(|at| out.split_at_mut(at))
        .ok_or(Refusal::Buffer)?;
    let plain = write_key_frame(
        back,
        scratch,
        bssid,
        own,
        KeyInformation::new()
            .with_key_mic(true)
            .with_secure(true)
            .with_key_descriptor_version(KeyDescriptorVersion::AesHmacSha1),
        replay_counter,
        [0u8; 32],
        element_chain! {},
        keys.kck(),
    )?;
    // ...then the protected layout at the front: header, CCMP header, the
    // LLC and EAPOL bytes, room for CCMP's MIC
    let total = plain + CCMP + CCMP_MIC;
    let protected = front.get_mut(..total).ok_or(Refusal::Buffer)?;
    protected[..HEADER].copy_from_slice(&back[..HEADER]);
    protected[1] |= 0x40;
    let header = CryptoHeader::new(packet_number, key_id).ok_or(Refusal::Buffer)?;
    protected
        .pwrite(header, HEADER)
        .map_err(|_| Refusal::Buffer)?;
    protected[HEADER + CCMP..HEADER + CCMP + plain - HEADER].copy_from_slice(&back[HEADER..plain]);
    protected[total - CCMP_MIC..].fill(0);
    Ok(total)
}

/// A received frame the hardware decrypted, as the EAPOL deserialiser reads
/// one: the hardware leaves the Protected bit and the 8-byte CCMP header in
/// place (it strips only the MIC), so the header is copied with the bit
/// cleared and the payload after the CCMP header follows it, in `out`.
/// `None` if the frame is not protected or too short; the CCMP packet
/// number's replay check is the caller's, as for any protected frame.
pub fn unprotect(mpdu: &[u8], out: &mut [u8]) -> Option<usize> {
    use ieee80211::scroll::Pread;
    let header = mpdu.pread::<DataFrameHeader>(0).ok()?;
    if !header.fcf_flags.protected() {
        return None;
    }
    let header_length = header.length_in_bytes();
    let payload = mpdu.get(header_length + 8..)?;
    let length = header_length + payload.len();
    let out = out.get_mut(..length)?;
    out[..header_length].copy_from_slice(&mpdu[..header_length]);
    out[1] &= !0x40;
    out[header_length..].copy_from_slice(payload);
    Some(length)
}

/// Whether a received data frame with a payload may go up to the network
/// stack (Null frames carry none and are never protected; the caller sets
/// them aside first): once the
/// station holds keys, only frames that came protected (E2's F6: FoA passed
/// unprotected frames up after the join, so anyone in range could inject
/// them). EAPOL-Key frames are taken apart before this, by the handshakes.
#[must_use]
pub const fn data_frame_admitted(keys_installed: bool, protected: bool) -> bool {
    protected || !keys_installed
}

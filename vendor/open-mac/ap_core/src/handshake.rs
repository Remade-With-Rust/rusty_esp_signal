//! WPA2-PSK's authenticator (802.11-2020 12.7.6, 12.7.7): the access
//! point's half of the 4-way and group-key handshakes, the mirror of
//! `sta_handshake`. The access point numbers every EAPOL-Key frame it sends
//! with a replay counter one above the last; a station's reply must echo
//! the counter of the frame it answers.
//!
//! What a station's frame must be to be taken, beyond its MIC:
//! - message 2: pairwise, MIC, not Ack, Install, Secure or encrypted key
//!   data; and its key data's RSN element the very bytes the station's
//!   association request carried (12.7.6.3: the downgrade check);
//! - message 4: pairwise, MIC, Secure, not Ack or Install;
//! - group message 2: group, MIC, Secure, not Ack.
//!
//! Message 3 carries the access point's RSN element byte for byte as its
//! beacons do (a station compares the two and leaves on a difference) and
//! the GTK in a GTK KDE, the key data wrapped under the KEK.

use core::marker::PhantomData;

use ieee80211::common::{DataFrameSubtype, FCFFlags, SequenceControl};
use ieee80211::crypto::eapol::{EapolKeyFrame, KeyDescriptorVersion, KeyInformation};
use ieee80211::crypto::{
    CryptoHeader, EapolSerdeError, deserialize_eapol_data_frame_mic, serialize_eapol_data_frame_mic,
};
use ieee80211::data_frame::DataFrame;
use ieee80211::data_frame::header::DataFrameHeader;
use ieee80211::mac_parser::MACAddress;
use ieee80211::scroll::{Pread, Pwrite};
use llc_rs::{EtherType, SnapLlcFrame};
use sta_handshake::{AKM, GroupKey, PairwiseKeys};

use crate::Address;
use crate::elements::{Elements, id};
use crate::frames::RSN_ELEMENT;

/// Why a station's frame was not taken. The access point drops it; its
/// retransmission timer decides the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not an EAPOL-Key frame, or too short.
    Frame,
    /// The MIC did not match.
    Mic,
    /// The key information is not this message's.
    KeyInformation,
    /// The replay counter is not the one of the frame it answers.
    Replay,
    /// Message 2's RSN element is not the association request's.
    RsnMismatch,
    /// An output or scratch buffer was too small (ours, not the sender's).
    Buffer,
}

impl From<EapolSerdeError> for Refusal {
    fn from(e: EapolSerdeError) -> Self {
        match e {
            EapolSerdeError::InvalidMic => Refusal::Mic,
            _ => Refusal::Frame,
        }
    }
}

/// A station's 4-way handshake as the access point keeps it.
#[derive(Clone)]
pub struct Authenticator {
    /// The access point's nonce for this handshake.
    pub anonce: [u8; 32],
    /// The replay counter of the last EAPOL-Key frame sent.
    pub replay_counter: u64,
    /// The PTK, once message 2 has given the station's nonce.
    pub keys: Option<PairwiseKeys>,
}

impl Authenticator {
    /// A handshake about to begin, with a fresh nonce.
    #[must_use]
    pub const fn new(anonce: [u8; 32]) -> Self {
        Self {
            anonce,
            replay_counter: 0,
            keys: None,
        }
    }
    /// The counter for the next frame sent.
    pub fn next_replay_counter(&mut self) -> u64 {
        self.replay_counter += 1;
        self.replay_counter
    }
}

/// The GTK KDE (802.11-2020 Figure 12-35): key ID (Tx clear), a reserved
/// octet, the GTK.
fn gtk_kde(gtk: &GroupKey) -> [u8; 24] {
    let mut kde = [0u8; 24];
    kde[..6].copy_from_slice(&[0xdd, 22, 0x00, 0x0f, 0xac, 0x01]);
    kde[6] = gtk.key_id & 0b11;
    kde[8..].copy_from_slice(&gtk.key);
    kde
}

/// An EAPOL-Key frame from the access point to a station, MIC'd under the
/// KCK when `kck` is given, key data wrapped under the KEK when the key
/// information says so.
#[allow(clippy::too_many_arguments)]
fn write_key_frame(
    out: &mut [u8],
    scratch: &mut [u8],
    bssid: Address,
    station: Address,
    key_information: KeyInformation,
    replay_counter: u64,
    nonce: [u8; 32],
    rsc: u64,
    key_data: &[u8],
    keys: Option<&PairwiseKeys>,
) -> Result<usize, Refusal> {
    let frame = DataFrame {
        header: DataFrameHeader {
            subtype: DataFrameSubtype::Data,
            fcf_flags: FCFFlags::new().with_from_ds(true),
            address_1: MACAddress::new(station),
            address_2: MACAddress::new(bssid),
            address_3: MACAddress::new(bssid),
            sequence_control: SequenceControl::new(),
            ..Default::default()
        },
        payload: Some(SnapLlcFrame {
            oui: [0u8; 3],
            ether_type: EtherType::Eapol,
            payload: EapolKeyFrame {
                key_information: key_information
                    .with_key_descriptor_version(KeyDescriptorVersion::AesHmacSha1),
                key_length: 16,
                key_replay_counter: replay_counter,
                key_nonce: nonce,
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
    serialize_eapol_data_frame_mic(
        keys.map(PairwiseKeys::mic),
        keys.map(PairwiseKeys::kek),
        frame,
        out,
        scratch,
    )
    .map_err(|_| Refusal::Buffer)
}

/// Message 1: the access point's nonce, Ack, no MIC.
pub fn write_message_1(
    out: &mut [u8],
    scratch: &mut [u8],
    bssid: Address,
    station: Address,
    anonce: &[u8; 32],
    replay_counter: u64,
) -> Result<usize, Refusal> {
    write_key_frame(
        out,
        scratch,
        bssid,
        station,
        KeyInformation::new()
            .with_is_pairwise(true)
            .with_key_ack(true),
        replay_counter,
        *anonce,
        0,
        &[],
        None,
    )
}

/// The EAPOL-Key frame in a data frame from a station, read without its
/// MIC checked: what message 2 needs before the PTK exists.
fn peek(mpdu: &[u8]) -> Result<EapolKeyFrame<'_>, Refusal> {
    let header = mpdu
        .pread::<DataFrameHeader>(0)
        .map_err(|_| Refusal::Frame)?;
    let at = header.length_in_bytes() + 8;
    let ether_type = mpdu.get(at - 2..at).ok_or(Refusal::Frame)?;
    if ether_type != [0x88, 0x8e] {
        return Err(Refusal::Frame);
    }
    mpdu.get(at..)
        .ok_or(Refusal::Frame)?
        .pread_with::<EapolKeyFrame>(0, AKM)
        .map_err(|_| Refusal::Frame)
}

/// Read message 2: the station's nonce gives the PTK, under which the MIC
/// must verify; the replay counter must be message 1's; the RSN element in
/// its key data must be `station_rsn_element`, the association request's.
#[allow(clippy::too_many_arguments)]
pub fn read_message_2(
    mpdu: &mut [u8],
    pmk: &[u8; 32],
    bssid: &Address,
    station: &Address,
    anonce: &[u8; 32],
    replay_counter: u64,
    station_rsn_element: &[u8],
) -> Result<PairwiseKeys, Refusal> {
    let (snonce, information, replay) = {
        let frame = peek(mpdu)?;
        (
            frame.key_nonce,
            frame.key_information,
            frame.key_replay_counter,
        )
    };
    if !(information.key_descriptor_version() == KeyDescriptorVersion::AesHmacSha1
        && information.is_pairwise()
        && information.key_mic()
        && !information.key_ack()
        && !information.install()
        && !information.secure()
        && !information.encrypted_key_data())
    {
        return Err(Refusal::KeyInformation);
    }
    if replay != replay_counter {
        return Err(Refusal::Replay);
    }
    let keys = PairwiseKeys::derive(pmk, bssid, station, anonce, &snonce);
    let frame =
        deserialize_eapol_data_frame_mic(Some(keys.mic()), None, mpdu, &mut [], AKM, false)?;
    let offered = Elements::new(frame.key_data.bytes).first_whole(id::RSN);
    if offered != Some(station_rsn_element) {
        return Err(Refusal::RsnMismatch);
    }
    Ok(keys)
}

/// Message 3: Install, the GTK, the access point's RSN element; MIC'd under
/// the KCK, key data wrapped under the KEK.
#[allow(clippy::too_many_arguments)]
pub fn write_message_3(
    out: &mut [u8],
    scratch: &mut [u8],
    bssid: Address,
    station: Address,
    keys: &PairwiseKeys,
    anonce: &[u8; 32],
    replay_counter: u64,
    gtk: &GroupKey,
) -> Result<usize, Refusal> {
    let mut key_data = [0u8; RSN_ELEMENT.len() + 24];
    key_data[..RSN_ELEMENT.len()].copy_from_slice(&RSN_ELEMENT);
    key_data[RSN_ELEMENT.len()..].copy_from_slice(&gtk_kde(gtk));
    write_key_frame(
        out,
        scratch,
        bssid,
        station,
        KeyInformation::new()
            .with_is_pairwise(true)
            .with_key_ack(true)
            .with_key_mic(true)
            .with_secure(true)
            .with_install(true)
            .with_encrypted_key_data(true),
        replay_counter,
        *anonce,
        gtk.rsc,
        &key_data,
        Some(keys),
    )
}

/// Read message 4: its MIC under the KCK, message 3's replay counter.
pub fn read_message_4(
    mpdu: &mut [u8],
    keys: &PairwiseKeys,
    replay_counter: u64,
) -> Result<(), Refusal> {
    let frame =
        deserialize_eapol_data_frame_mic(Some(keys.mic()), None, mpdu, &mut [], AKM, false)?;
    let information = frame.key_information;
    if !(information.key_descriptor_version() == KeyDescriptorVersion::AesHmacSha1
        && information.is_pairwise()
        && information.key_mic()
        && information.secure()
        && !information.key_ack()
        && !information.install())
    {
        return Err(Refusal::KeyInformation);
    }
    if frame.key_replay_counter != replay_counter {
        return Err(Refusal::Replay);
    }
    Ok(())
}

/// A group-key handshake's message 1, laid out protected under the PTK (its
/// CCMP header with `packet_number` and the PTK's `key_id`, the Protected
/// bit, room for CCMP's MIC) for the hardware to encrypt with the station's
/// key slot.
#[allow(clippy::too_many_arguments)]
pub fn write_group_message_1(
    out: &mut [u8],
    scratch: &mut [u8],
    bssid: Address,
    station: Address,
    keys: &PairwiseKeys,
    replay_counter: u64,
    gtk: &GroupKey,
    packet_number: u64,
    key_id: u8,
) -> Result<usize, Refusal> {
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
        station,
        KeyInformation::new()
            .with_key_ack(true)
            .with_key_mic(true)
            .with_secure(true)
            .with_encrypted_key_data(true),
        replay_counter,
        [0u8; 32],
        gtk.rsc,
        &gtk_kde(gtk),
        Some(keys),
    )?;
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

/// Read a group-key handshake's message 2, as `sta_handshake::unprotect`
/// leaves a decrypted frame: its MIC under the KCK, group message 1's
/// replay counter.
pub fn read_group_message_2(
    mpdu: &mut [u8],
    keys: &PairwiseKeys,
    replay_counter: u64,
) -> Result<(), Refusal> {
    let frame =
        deserialize_eapol_data_frame_mic(Some(keys.mic()), None, mpdu, &mut [], AKM, false)?;
    let information = frame.key_information;
    if !(information.key_descriptor_version() == KeyDescriptorVersion::AesHmacSha1
        && !information.is_pairwise()
        && information.key_mic()
        && information.secure()
        && !information.key_ack())
    {
        return Err(Refusal::KeyInformation);
    }
    if frame.key_replay_counter != replay_counter {
        return Err(Refusal::Replay);
    }
    Ok(())
}

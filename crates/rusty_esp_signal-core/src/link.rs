//! The authenticated link every ESP-NOW and LoRa frame travels in.
//!
//! **Sign the session, MAC the frames.** A 64-byte signature per frame is
//! airtime nobody has on LoRa and a third of an ESP-NOW datagram, so the
//! expensive public-key work happens once per session and every frame after
//! that carries a 16-byte HMAC-SHA256 tag.
//!
//! The session is a three-message handshake between two `did:mata` device
//! keys (`rusty_esp_mid`), in the shape of Noise `KK`: both static keys are
//! known up front (the responder decides from the initiator's DID whether to
//! talk at all — the owner pin, the adoption roster), each side adds an
//! ephemeral P-256 key, and the session key is derived from **both** ECDH
//! results, so a stolen device key after the fact does not open past traffic
//! (forward secrecy) and only the two DIDs can compute it (mutual
//! authentication). Two 16-byte nonces salt the derivation so a replayed
//! `Hello` yields a different key. Key confirmation is explicit: `Accept`
//! and `Confirm` each carry a MAC over the whole transcript.
//!
//! ```text
//! Hello   I→R  ver | 0x01 | static_pub_I (33) | eph_pub_I (33) | nonce_I (16)             84 B
//! Accept  R→I  ver | 0x02 | static_pub_R (33) | eph_pub_R (33) | nonce_R (16) | tag (16)  100 B
//! Confirm I→R  ver | 0x03 | tag (16)                                                       18 B
//!
//! ikm  = ECDH(static_I, static_R) || ECDH(eph_I, eph_R)
//! salt = nonce_I || nonce_R
//! HKDF-SHA256(salt, ikm, "janus-link-v1") → k_I→R (32) | k_R→I (32) | k_confirm (32) | id (2)
//! tag_accept  = HMAC(k_confirm, "accept"  || Hello || Accept[..84])[..16]
//! tag_confirm = HMAC(k_confirm, "confirm" || Hello || Accept[..84])[..16]
//! ```
//!
//! Data frames are an [`Envelope`]: `ver | session id (2) | seq (4) | payload
//! | tag (16)`, big-endian, 23 bytes of overhead, so an ESP-NOW datagram
//! (250 B) carries up to [`MAX_PAYLOAD`] bytes. The tag is HMAC-SHA256 under
//! the **direction's** key over everything before it, truncated to 16 bytes,
//! and is verified in constant time **before** any other check touches the
//! frame — a bad tag cannot move the replay window. Replay protection is a
//! 64-frame sliding bitmap window per direction (the IPsec/DTLS shape):
//! frames may arrive out of order within the window, never twice, never older
//! than it.
//!
//! What this module deliberately does not do: encrypt. Presence verdicts,
//! telemetry and control frames are authenticated, not confidential; a
//! payload that needs secrecy (credentials) travels over BLE pairing or the
//! iroh mesh (`rusty_esp_iroh`, TLS). Encryption is a `v2` kind byte away
//! if a product needs it.

use core::fmt;

use hmac::{Hmac, Mac};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rusty_esp_core::error::Result;
use rusty_esp_core::{Error, Micros, Rng};
use rusty_esp_mid_core::did::Did;
use rusty_esp_mid_core::key::DeviceKey;
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

/// Wire version of the envelope and the handshake.
pub const VERSION: u8 = 1;
/// Bytes of HMAC-SHA256 kept per frame and per handshake message.
pub const TAG_LEN: usize = 16;
/// `ver | session (2) | seq (4)`.
pub const HEADER_LEN: usize = 7;
/// An ESP-NOW datagram: the smallest MTU a link here has. ESP-IDF's ESP-NOW
/// documentation: a v1.0 vendor-specific action frame carries at most 250
/// bytes of payload (v2.0 on newer chips allows 1470, which v1 peers cannot
/// receive), and a device keeps at most 20 paired peers.
pub const MAX_FRAME: usize = 250;
/// ESP-NOW's paired-peer table size (ESP-IDF `ESP_NOW_MAX_TOTAL_PEER_NUM`).
pub const ESP_NOW_MAX_PEERS: usize = 20;
/// Payload that fits an ESP-NOW datagram after the envelope's 23 bytes.
pub const MAX_PAYLOAD: usize = MAX_FRAME - HEADER_LEN - TAG_LEN;
/// Bytes of nonce each side contributes.
pub const NONCE_LEN: usize = 16;
/// A SEC1-compressed P-256 public key.
pub const PUBKEY_LEN: usize = 33;
/// `Hello` on the wire.
pub const HELLO_LEN: usize = 2 + PUBKEY_LEN + PUBKEY_LEN + NONCE_LEN;
/// `Accept` on the wire.
pub const ACCEPT_LEN: usize = HELLO_LEN + TAG_LEN;
/// `Confirm` on the wire.
pub const CONFIRM_LEN: usize = 2 + TAG_LEN;
/// HKDF context string; bump with [`VERSION`].
pub const INFO: &[u8] = b"janus-link-v1";
/// Default session lifetime after which [`Session::expired`] is true.
pub const DEFAULT_LIFETIME: Micros = Micros::from_secs(24 * 60 * 60);

const KIND_HELLO: u8 = 0x01;
const KIND_ACCEPT: u8 = 0x02;
const KIND_CONFIRM: u8 = 0x03;
const KEY_LEN: usize = 32;
const OKM_LEN: usize = 3 * KEY_LEN + 2;
const WINDOW: u32 = 64;

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

/// A parsed data frame: the header fields, a borrowed payload and the tag.
///
/// [`Envelope::parse`] checks structure only; authenticity is
/// [`Session::open`]'s job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Envelope<'a> {
    /// Wire version ([`VERSION`]).
    pub ver: u8,
    /// Session id, the last two bytes of the HKDF output.
    pub session: u16,
    /// Per-direction sequence number, starts at 0, never reused.
    pub seq: u32,
    /// The application bytes.
    pub payload: &'a [u8],
    /// HMAC-SHA256 under the direction key, truncated.
    pub tag: [u8; TAG_LEN],
}

impl<'a> Envelope<'a> {
    /// Total wire size of a frame carrying `payload_len` bytes.
    #[must_use]
    pub const fn wire_len(payload_len: usize) -> usize {
        HEADER_LEN + payload_len + TAG_LEN
    }

    /// Split a frame into its fields. Fails on a wrong version or a frame
    /// shorter than header + tag.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::InvalidFormat);
        }
        let ver = bytes[0];
        if ver != VERSION {
            return Err(Error::InvalidFormat);
        }
        let session = u16::from_be_bytes([bytes[1], bytes[2]]);
        let seq = u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]);
        let tag_at = bytes.len() - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[tag_at..]);
        Ok(Envelope {
            ver,
            session,
            seq,
            payload: &bytes[HEADER_LEN..tag_at],
            tag,
        })
    }
}

// ---------------------------------------------------------------------------
// Replay window
// ---------------------------------------------------------------------------

/// A 64-frame sliding anti-replay window over `u32` sequence numbers.
///
/// Accepts each sequence number at most once, tolerates reordering inside
/// the window, refuses anything older than the window. Bit `0` of the bitmap
/// is the highest sequence seen.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplayWindow {
    highest: u32,
    bitmap: u64,
    primed: bool,
}

impl ReplayWindow {
    /// An empty window: the first frame of any sequence is accepted.
    #[must_use]
    pub const fn new() -> Self {
        ReplayWindow {
            highest: 0,
            bitmap: 0,
            primed: false,
        }
    }

    /// True when `seq` would be accepted, without recording it.
    #[must_use]
    pub fn would_accept(&self, seq: u32) -> bool {
        if !self.primed {
            return true;
        }
        if seq > self.highest {
            return true;
        }
        let back = self.highest - seq;
        back < WINDOW && (self.bitmap >> back) & 1 == 0
    }

    /// Record `seq`. Returns `false` (recording nothing) when it is a replay
    /// or older than the window.
    pub fn accept(&mut self, seq: u32) -> bool {
        if !self.primed {
            self.primed = true;
            self.highest = seq;
            self.bitmap = 1;
            return true;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= WINDOW {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.highest = seq;
            return true;
        }
        let back = self.highest - seq;
        if back >= WINDOW || (self.bitmap >> back) & 1 == 1 {
            return false;
        }
        self.bitmap |= 1 << back;
        true
    }

    /// The highest sequence number accepted so far, if any.
    #[must_use]
    pub const fn highest(&self) -> Option<u32> {
        if self.primed {
            Some(self.highest)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Per-session counters, for the telemetry frame and the ledger.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Frames sealed.
    pub sent: u32,
    /// Frames opened successfully.
    pub received: u32,
    /// Frames refused for a bad tag (before any other check).
    pub bad_tag: u32,
    /// Frames refused as replays or older than the window.
    pub replayed: u32,
    /// Frames for another session id or a wrong version.
    pub foreign: u32,
}

/// An established, mutually authenticated session with one peer.
///
/// Holds two direction keys and a replay window; zeroises its keys on drop.
pub struct Session {
    id: u16,
    peer: Did,
    k_send: [u8; KEY_LEN],
    k_recv: [u8; KEY_LEN],
    send_seq: u32,
    exhausted: bool,
    window: ReplayWindow,
    established: Micros,
    lifetime: Micros,
    counters: Counters,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.id)
            .field("send_seq", &self.send_seq)
            .field("window", &self.window)
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.k_send.zeroize();
        self.k_recv.zeroize();
    }
}

impl Session {
    /// The session id both sides derived.
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.id
    }

    /// The peer's DID (authenticated by the handshake).
    #[must_use]
    pub const fn peer(&self) -> &Did {
        &self.peer
    }

    /// Counters so far.
    #[must_use]
    pub const fn counters(&self) -> Counters {
        self.counters
    }

    /// True once `now` is past `established + lifetime`. A firmware
    /// re-handshakes; this module never rekeys in place.
    #[must_use]
    pub const fn expired(&self, now: Micros) -> bool {
        now.0.saturating_sub(self.established.0) >= self.lifetime.0
    }

    /// True once the send sequence space is used up; `seal` then refuses.
    #[must_use]
    pub const fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Seal `payload` into `out` as a frame for the peer. Returns the wire
    /// length. `BufferTooSmall` names the length needed; a payload over
    /// [`MAX_PAYLOAD`] is `Unsupported` (this is a datagram link, fragment
    /// above it); an exhausted sequence space is `Denied`.
    pub fn seal(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        if payload.len() > MAX_PAYLOAD {
            return Err(Error::Unsupported);
        }
        let needed = Envelope::wire_len(payload.len());
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        if self.exhausted {
            return Err(Error::Denied);
        }
        let seq = self.send_seq;
        match self.send_seq.checked_add(1) {
            Some(next) => self.send_seq = next,
            None => self.exhausted = true,
        }
        out[0] = VERSION;
        out[1..3].copy_from_slice(&self.id.to_be_bytes());
        out[3..7].copy_from_slice(&seq.to_be_bytes());
        out[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
        let tag = mac(&self.k_send, &[&out[..HEADER_LEN + payload.len()]])?;
        out[HEADER_LEN + payload.len()..needed].copy_from_slice(&tag);
        self.counters.sent = self.counters.sent.wrapping_add(1);
        Ok(needed)
    }

    /// Verify and accept a frame from the peer, returning its payload.
    ///
    /// Order of checks: structure → version and session id (`foreign`) →
    /// **tag** (`Crypto`, counted as `bad_tag`) → replay window (`Denied`,
    /// counted as `replayed`). The tag is checked before the window so an
    /// attacker cannot advance or poison the window with forged frames.
    pub fn open<'a>(&mut self, frame: &'a [u8]) -> Result<&'a [u8]> {
        let env = Envelope::parse(frame).inspect_err(|_| {
            self.counters.foreign = self.counters.foreign.wrapping_add(1);
        })?;
        if env.session != self.id {
            self.counters.foreign = self.counters.foreign.wrapping_add(1);
            return Err(Error::Denied);
        }
        let signed_len = frame.len() - TAG_LEN;
        if !verify(&self.k_recv, &[&frame[..signed_len]], &env.tag) {
            self.counters.bad_tag = self.counters.bad_tag.wrapping_add(1);
            return Err(Error::Crypto);
        }
        if !self.window.accept(env.seq) {
            self.counters.replayed = self.counters.replayed.wrapping_add(1);
            return Err(Error::Denied);
        }
        self.counters.received = self.counters.received.wrapping_add(1);
        Ok(env.payload)
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// The initiator's half-open handshake between `Hello` and `Accept`.
///
/// Holds the ephemeral secret (zeroised by `p256` on drop) and the `Hello`
/// bytes for the transcript.
pub struct Handshake {
    eph: SecretKey,
    hello: [u8; HELLO_LEN],
}

impl fmt::Debug for Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handshake").finish_non_exhaustive()
    }
}

/// The responder's half-open session between `Accept` and `Confirm`.
///
/// Nothing can be sealed or opened until [`Pending::confirm`] has verified
/// the initiator's key-confirmation MAC.
pub struct Pending {
    session: Session,
    k_confirm: ConfirmKey,
    transcript: [u8; HELLO_LEN + HELLO_LEN],
}

/// The key-confirmation key, zeroised on drop.
struct ConfirmKey([u8; KEY_LEN]);

impl Drop for ConfirmKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("id", &self.session.id)
            .finish_non_exhaustive()
    }
}

impl Handshake {
    /// Start a session: generate the ephemeral key and the nonce, write the
    /// `Hello` bytes. The device key is `me`.
    pub fn initiate(me: &DeviceKey, rng: &mut impl Rng) -> Result<(Self, [u8; HELLO_LEN])> {
        let eph = ephemeral(rng)?;
        let mut hello = [0u8; HELLO_LEN];
        hello[0] = VERSION;
        hello[1] = KIND_HELLO;
        hello[2..2 + PUBKEY_LEN].copy_from_slice(me.did().pubkey());
        hello[2 + PUBKEY_LEN..2 + 2 * PUBKEY_LEN].copy_from_slice(&compressed(&eph));
        rng.fill(&mut hello[2 + 2 * PUBKEY_LEN..])?;
        Ok((Handshake { eph, hello }, hello))
    }

    /// The initiator's `Hello` as sent, for the transcript.
    #[must_use]
    pub const fn hello(&self) -> &[u8; HELLO_LEN] {
        &self.hello
    }

    /// Answer a `Hello` as the responder. `allow` decides, from the
    /// initiator's DID, whether to talk at all (the owner pin, the adoption
    /// roster); a refused DID is `Denied` and no key material is derived.
    /// Returns the half-open session and the `Accept` bytes to send.
    pub fn respond(
        me: &DeviceKey,
        rng: &mut impl Rng,
        hello: &[u8],
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
        lifetime: Micros,
    ) -> Result<(Pending, [u8; ACCEPT_LEN])> {
        let hello: &[u8; HELLO_LEN] = hello.try_into().map_err(|_| Error::InvalidFormat)?;
        if hello[0] != VERSION || hello[1] != KIND_HELLO {
            return Err(Error::InvalidFormat);
        }
        let their_did = Did::from_pubkey(&hello[2..2 + PUBKEY_LEN])?;
        if !allow(&their_did) {
            return Err(Error::Denied);
        }
        let their_eph = PublicKey::from_sec1_bytes(&hello[2 + PUBKEY_LEN..2 + 2 * PUBKEY_LEN])
            .map_err(|_| Error::Crypto)?;
        let eph = ephemeral(rng)?;

        let mut accept = [0u8; ACCEPT_LEN];
        accept[0] = VERSION;
        accept[1] = KIND_ACCEPT;
        accept[2..2 + PUBKEY_LEN].copy_from_slice(me.did().pubkey());
        accept[2 + PUBKEY_LEN..2 + 2 * PUBKEY_LEN].copy_from_slice(&compressed(&eph));
        rng.fill(&mut accept[2 + 2 * PUBKEY_LEN..HELLO_LEN])?;

        let keys = derive(
            me,
            &their_did,
            &eph,
            &their_eph,
            &hello[2 + 2 * PUBKEY_LEN..],
            &accept[2 + 2 * PUBKEY_LEN..HELLO_LEN],
        )?;
        let mut transcript = [0u8; 2 * HELLO_LEN];
        transcript[..HELLO_LEN].copy_from_slice(hello);
        transcript[HELLO_LEN..].copy_from_slice(&accept[..HELLO_LEN]);
        let tag = mac(&keys.k_confirm, &[b"accept", &transcript])?;
        accept[HELLO_LEN..].copy_from_slice(&tag);

        let session = Session {
            id: keys.id,
            peer: their_did,
            k_send: keys.k_r2i,
            k_recv: keys.k_i2r,
            send_seq: 0,
            exhausted: false,
            window: ReplayWindow::new(),
            established: now,
            lifetime,
            counters: Counters::default(),
        };
        Ok((
            Pending {
                session,
                k_confirm: ConfirmKey(keys.k_confirm),
                transcript,
            },
            accept,
        ))
    }

    /// Finish as the initiator: verify the responder's `Accept` (its DID
    /// through `allow`, its MAC), derive the session, write `Confirm`.
    pub fn finish(
        self,
        me: &DeviceKey,
        accept: &[u8],
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
        lifetime: Micros,
    ) -> Result<(Session, [u8; CONFIRM_LEN])> {
        let accept: &[u8; ACCEPT_LEN] = accept.try_into().map_err(|_| Error::InvalidFormat)?;
        if accept[0] != VERSION || accept[1] != KIND_ACCEPT {
            return Err(Error::InvalidFormat);
        }
        let their_did = Did::from_pubkey(&accept[2..2 + PUBKEY_LEN])?;
        if !allow(&their_did) {
            return Err(Error::Denied);
        }
        let their_eph = PublicKey::from_sec1_bytes(&accept[2 + PUBKEY_LEN..2 + 2 * PUBKEY_LEN])
            .map_err(|_| Error::Crypto)?;
        let keys = derive(
            me,
            &their_did,
            &self.eph,
            &their_eph,
            &self.hello[2 + 2 * PUBKEY_LEN..],
            &accept[2 + 2 * PUBKEY_LEN..HELLO_LEN],
        )?;
        let mut transcript = [0u8; 2 * HELLO_LEN];
        transcript[..HELLO_LEN].copy_from_slice(&self.hello);
        transcript[HELLO_LEN..].copy_from_slice(&accept[..HELLO_LEN]);
        let mut expected = [0u8; TAG_LEN];
        expected.copy_from_slice(&accept[HELLO_LEN..]);
        if !verify(&keys.k_confirm, &[b"accept", &transcript], &expected) {
            return Err(Error::Crypto);
        }
        let mut confirm = [0u8; CONFIRM_LEN];
        confirm[0] = VERSION;
        confirm[1] = KIND_CONFIRM;
        confirm[2..].copy_from_slice(&mac(&keys.k_confirm, &[b"confirm", &transcript])?);

        let session = Session {
            id: keys.id,
            peer: their_did,
            k_send: keys.k_i2r,
            k_recv: keys.k_r2i,
            send_seq: 0,
            exhausted: false,
            window: ReplayWindow::new(),
            established: now,
            lifetime,
            counters: Counters::default(),
        };
        Ok((session, confirm))
    }
}

impl Pending {
    /// The session id, available before confirmation (to route the
    /// `Confirm` to the right pending session).
    #[must_use]
    pub const fn id(&self) -> u16 {
        self.session.id
    }

    /// Verify the initiator's `Confirm` and open the session.
    pub fn confirm(self, confirm: &[u8]) -> Result<Session> {
        let confirm: &[u8; CONFIRM_LEN] = confirm.try_into().map_err(|_| Error::InvalidFormat)?;
        if confirm[0] != VERSION || confirm[1] != KIND_CONFIRM {
            return Err(Error::InvalidFormat);
        }
        let mut expected = [0u8; TAG_LEN];
        expected.copy_from_slice(&confirm[2..]);
        if !verify(
            &self.k_confirm.0,
            &[b"confirm", &self.transcript],
            &expected,
        ) {
            return Err(Error::Crypto);
        }
        let Pending { session, .. } = self;
        Ok(session)
    }
}

// ---------------------------------------------------------------------------
// Key derivation and MACs
// ---------------------------------------------------------------------------

struct Keys {
    k_i2r: [u8; KEY_LEN],
    k_r2i: [u8; KEY_LEN],
    k_confirm: [u8; KEY_LEN],
    id: u16,
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.k_i2r.zeroize();
        self.k_r2i.zeroize();
        self.k_confirm.zeroize();
    }
}

/// A fresh P-256 secret from the device TRNG. A scalar outside the group
/// order (probability 2^-128) is retried, bounded.
fn ephemeral(rng: &mut impl Rng) -> Result<SecretKey> {
    let mut bytes = [0u8; 32];
    for _ in 0..8 {
        rng.fill(&mut bytes)?;
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            bytes.zeroize();
            return Ok(key);
        }
    }
    bytes.zeroize();
    Err(Error::Crypto)
}

fn compressed(key: &SecretKey) -> [u8; PUBKEY_LEN] {
    let point = key.public_key().to_encoded_point(true);
    let mut out = [0u8; PUBKEY_LEN];
    out.copy_from_slice(point.as_bytes());
    out
}

fn derive(
    me: &DeviceKey,
    their_did: &Did,
    my_eph: &SecretKey,
    their_eph: &PublicKey,
    nonce_i: &[u8],
    nonce_r: &[u8],
) -> Result<Keys> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&me.shared_secret(their_did)?);
    let shared = diffie_hellman(my_eph.to_nonzero_scalar(), their_eph.as_affine());
    ikm[32..].copy_from_slice(shared.raw_secret_bytes());
    let keys = expand_keys(&ikm, nonce_i, nonce_r);
    ikm.zeroize();
    keys
}

/// The key schedule: `HKDF-SHA256(salt = nonce_i || nonce_r, ikm, INFO)`
/// split as `k_i2r | k_r2i | k_confirm | id`. Pinned by the golden test
/// against an independent Python implementation.
fn expand_keys(ikm: &[u8; 64], nonce_i: &[u8], nonce_r: &[u8]) -> Result<Keys> {
    let mut salt = [0u8; 2 * NONCE_LEN];
    salt[..NONCE_LEN].copy_from_slice(nonce_i);
    salt[NONCE_LEN..].copy_from_slice(nonce_r);

    let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), ikm);
    let mut okm = [0u8; OKM_LEN];
    hk.expand(INFO, &mut okm).map_err(|_| Error::Crypto)?;

    let mut keys = Keys {
        k_i2r: [0u8; KEY_LEN],
        k_r2i: [0u8; KEY_LEN],
        k_confirm: [0u8; KEY_LEN],
        id: 0,
    };
    keys.k_i2r.copy_from_slice(&okm[..KEY_LEN]);
    keys.k_r2i.copy_from_slice(&okm[KEY_LEN..2 * KEY_LEN]);
    keys.k_confirm
        .copy_from_slice(&okm[2 * KEY_LEN..3 * KEY_LEN]);
    keys.id = u16::from_be_bytes([okm[3 * KEY_LEN], okm[3 * KEY_LEN + 1]]);
    okm.zeroize();
    Ok(keys)
}

/// HMAC-SHA256 over the concatenation of `parts`, truncated to [`TAG_LEN`].
/// HMAC accepts any key length, so the `Crypto` arm cannot fire; it is kept
/// rather than a panic path.
fn mac(key: &[u8; KEY_LEN], parts: &[&[u8]]) -> Result<[u8; TAG_LEN]> {
    let mut m = HmacSha256::new_from_slice(key).map_err(|_| Error::Crypto)?;
    for part in parts {
        m.update(part);
    }
    let full = m.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full[..TAG_LEN]);
    Ok(tag)
}

/// Constant-time truncated verification.
fn verify(key: &[u8; KEY_LEN], parts: &[&[u8]], tag: &[u8; TAG_LEN]) -> bool {
    let Ok(mut m) = HmacSha256::new_from_slice(key) else {
        return false;
    };
    for part in parts {
        m.update(part);
    }
    m.verify_truncated_left(tag).is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// xorshift64*: deterministic entropy for tests only.
    struct TestRng(u64);

    impl Rng for TestRng {
        fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
            for b in buf {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
            }
            Ok(())
        }
    }

    fn pair() -> (DeviceKey, DeviceKey, TestRng) {
        pair_with(0x9E37_79B9_7F4A_7C15)
    }

    fn pair_with(seed: u64) -> (DeviceKey, DeviceKey, TestRng) {
        (
            DeviceKey::from_seed_for_tests("signal-initiator", "cam-1"),
            DeviceKey::from_seed_for_tests("signal-responder", "hub"),
            TestRng(seed),
        )
    }

    fn handshake() -> (Session, Session) {
        handshake_with(0x9E37_79B9_7F4A_7C15)
    }

    fn handshake_with(seed: u64) -> (Session, Session) {
        let (i, r, mut rng) = pair_with(seed);
        let r_did = r.did();
        let i_did = i.did();
        let (hs, hello) = Handshake::initiate(&i, &mut rng).unwrap();
        let (pending, accept) = Handshake::respond(
            &r,
            &mut rng,
            &hello,
            |did| did == &i_did,
            Micros::ZERO,
            DEFAULT_LIFETIME,
        )
        .unwrap();
        let (si, confirm) = hs
            .finish(
                &i,
                &accept,
                |did| did == &r_did,
                Micros::ZERO,
                DEFAULT_LIFETIME,
            )
            .unwrap();
        let sr = pending.confirm(&confirm).unwrap();
        (si, sr)
    }

    #[test]
    fn wire_sizes_fit_esp_now() {
        assert_eq!(HELLO_LEN, 84);
        assert_eq!(ACCEPT_LEN, 100);
        assert_eq!(CONFIRM_LEN, 18);
        assert_eq!(MAX_PAYLOAD, 227);
        assert_eq!(Envelope::wire_len(MAX_PAYLOAD), MAX_FRAME);
    }

    #[test]
    fn both_sides_agree_and_frames_flow_both_ways() {
        let (mut si, mut sr) = handshake();
        assert_eq!(si.id(), sr.id());
        assert_eq!(
            si.peer(),
            &DeviceKey::from_seed_for_tests("signal-responder", "hub").did()
        );
        assert_eq!(
            sr.peer(),
            &DeviceKey::from_seed_for_tests("signal-initiator", "cam-1").did()
        );

        let mut buf = [0u8; MAX_FRAME];
        let n = si.seal(b"presence:1", &mut buf).unwrap();
        assert_eq!(n, Envelope::wire_len(10));
        assert_eq!(sr.open(&buf[..n]).unwrap(), b"presence:1");

        let n = sr.seal(b"ack", &mut buf).unwrap();
        assert_eq!(si.open(&buf[..n]).unwrap(), b"ack");
        assert_eq!(si.counters().sent, 1);
        assert_eq!(si.counters().received, 1);
        assert_eq!(sr.counters().received, 1);
    }

    #[test]
    fn replay_is_refused_and_counted() {
        let (mut si, mut sr) = handshake();
        let mut buf = [0u8; MAX_FRAME];
        let n = si.seal(b"once", &mut buf).unwrap();
        assert!(sr.open(&buf[..n]).is_ok());
        assert_eq!(sr.open(&buf[..n]), Err(Error::Denied));
        assert_eq!(sr.counters().replayed, 1);
        assert_eq!(sr.counters().received, 1);
    }

    #[test]
    fn bad_tag_is_refused_before_the_window_moves() {
        let (mut si, mut sr) = handshake();
        let mut buf = [0u8; MAX_FRAME];
        let n = si.seal(b"hello", &mut buf).unwrap();
        let mut forged = buf;
        forged[HEADER_LEN] ^= 0x01; // payload bit flip
        assert_eq!(sr.open(&forged[..n]), Err(Error::Crypto));
        assert_eq!(sr.counters().bad_tag, 1);
        // The genuine frame with the same seq still opens: the window did not move.
        assert_eq!(sr.open(&buf[..n]).unwrap(), b"hello");
        // A flipped tag bit too.
        let n2 = si.seal(b"again", &mut buf).unwrap();
        buf[n2 - 1] ^= 0x80;
        assert_eq!(sr.open(&buf[..n2]), Err(Error::Crypto));
    }

    #[test]
    fn reflection_is_refused() {
        let (mut si, _sr) = handshake();
        let mut buf = [0u8; MAX_FRAME];
        let n = si.seal(b"mine", &mut buf).unwrap();
        // The sender opening its own frame: the direction keys differ.
        assert_eq!(si.open(&buf[..n]), Err(Error::Crypto));
    }

    #[test]
    fn foreign_session_and_version_are_refused() {
        let (mut si, mut sr) = handshake();
        let mut buf = [0u8; MAX_FRAME];
        let n = si.seal(b"x", &mut buf).unwrap();
        let mut other = buf;
        other[1] ^= 0xFF;
        assert_eq!(sr.open(&other[..n]), Err(Error::Denied));
        let mut ver = buf;
        ver[0] = 2;
        assert_eq!(sr.open(&ver[..n]), Err(Error::InvalidFormat));
        assert_eq!(sr.counters().foreign, 2);
        assert_eq!(
            sr.open(&buf[..HEADER_LEN + TAG_LEN - 1]),
            Err(Error::InvalidFormat)
        );
    }

    #[test]
    fn reordering_inside_the_window_is_accepted_older_is_not() {
        let (mut si, mut sr) = handshake();
        let mut frames = [[0u8; MAX_FRAME]; 70];
        let mut lens = [0usize; 70];
        for (k, (f, l)) in frames.iter_mut().zip(lens.iter_mut()).enumerate() {
            *l = si.seal(&[k as u8], f).unwrap();
        }
        // Deliver 5 first, then 3, then 4 (reordered), then 5 again (replay).
        assert!(sr.open(&frames[5][..lens[5]]).is_ok());
        assert!(sr.open(&frames[3][..lens[3]]).is_ok());
        assert!(sr.open(&frames[4][..lens[4]]).is_ok());
        assert_eq!(sr.open(&frames[5][..lens[5]]), Err(Error::Denied));
        // Jump far ahead: 69 makes 0..=5 older than the 64-frame window.
        assert!(sr.open(&frames[69][..lens[69]]).is_ok());
        assert_eq!(sr.open(&frames[2][..lens[2]]), Err(Error::Denied));
        // 6 is exactly 63 back: still inside the window.
        assert!(sr.open(&frames[6][..lens[6]]).is_ok());
        assert_eq!(sr.counters().received, 5);
        assert_eq!(sr.counters().replayed, 2);
    }

    #[test]
    fn stranger_is_refused_by_policy_on_both_sides() {
        let (i, r, mut rng) = pair();
        let (hs, hello) = Handshake::initiate(&i, &mut rng).unwrap();
        let refused = Handshake::respond(
            &r,
            &mut rng,
            &hello,
            |_| false,
            Micros::ZERO,
            DEFAULT_LIFETIME,
        );
        assert!(matches!(refused, Err(Error::Denied)));
        // The responder accepts, the initiator does not recognise the responder.
        let i_did = i.did();
        let (_pending, accept) = Handshake::respond(
            &r,
            &mut rng,
            &hello,
            |did| did == &i_did,
            Micros::ZERO,
            DEFAULT_LIFETIME,
        )
        .unwrap();
        let refused = hs.finish(&i, &accept, |_| false, Micros::ZERO, DEFAULT_LIFETIME);
        assert!(matches!(refused, Err(Error::Denied)));
    }

    #[test]
    fn tampered_accept_and_confirm_fail_key_confirmation() {
        let (i, r, mut rng) = pair();
        let i_did = i.did();
        let r_did = r.did();
        let (hs, hello) = Handshake::initiate(&i, &mut rng).unwrap();
        let (pending, mut accept) = Handshake::respond(
            &r,
            &mut rng,
            &hello,
            |did| did == &i_did,
            Micros::ZERO,
            DEFAULT_LIFETIME,
        )
        .unwrap();
        // A flipped nonce byte: the initiator derives a different key and the
        // responder's MAC no longer verifies.
        accept[2 + 2 * PUBKEY_LEN] ^= 0x01;
        let (hs2, _) = Handshake::initiate(&i, &mut rng).unwrap();
        let _ = hs2;
        assert!(matches!(
            hs.finish(
                &i,
                &accept,
                |did| did == &r_did,
                Micros::ZERO,
                DEFAULT_LIFETIME
            ),
            Err(Error::Crypto)
        ));
        // A forged Confirm on the responder side.
        let mut bogus = [0u8; CONFIRM_LEN];
        bogus[0] = VERSION;
        bogus[1] = KIND_CONFIRM;
        assert!(matches!(pending.confirm(&bogus), Err(Error::Crypto)));
    }

    #[test]
    fn an_impostor_with_the_right_did_but_wrong_key_cannot_finish() {
        // The impostor copies the initiator's Hello but does not hold its
        // device key: the responder's Accept MAC is under a key the impostor
        // cannot derive, and its Confirm cannot be forged.
        let (i, r, mut rng) = pair();
        let i_did = i.did();
        let (_hs, hello) = Handshake::initiate(&i, &mut rng).unwrap();
        let (pending, accept) = Handshake::respond(
            &r,
            &mut rng,
            &hello,
            |did| did == &i_did,
            Micros::ZERO,
            DEFAULT_LIFETIME,
        )
        .unwrap();
        let impostor = DeviceKey::from_seed_for_tests("impostor", "cam-1");
        let (hs_imp, _) = Handshake::initiate(&impostor, &mut rng).unwrap();
        // Finishing with the impostor's ephemeral against the real transcript
        // is a Crypto failure (the ephemeral in Hello is not theirs either).
        assert!(matches!(
            hs_imp.finish(&impostor, &accept, |_| true, Micros::ZERO, DEFAULT_LIFETIME),
            Err(Error::Crypto)
        ));
        drop(pending);
    }

    #[test]
    fn sessions_expire_and_sequence_space_exhausts() {
        let (mut si, _sr) = handshake();
        assert!(!si.expired(Micros::from_secs(1)));
        assert!(si.expired(DEFAULT_LIFETIME));
        // Drive the sequence to the end.
        si.send_seq = u32::MAX;
        let mut buf = [0u8; MAX_FRAME];
        assert!(si.seal(b"last", &mut buf).is_ok());
        assert!(si.exhausted());
        assert_eq!(si.seal(b"one more", &mut buf), Err(Error::Denied));
    }

    #[test]
    fn seal_reports_buffer_and_payload_limits() {
        let (mut si, _sr) = handshake();
        let mut small = [0u8; 10];
        assert_eq!(
            si.seal(b"hello", &mut small),
            Err(Error::BufferTooSmall { needed: 28 })
        );
        let big = [0u8; MAX_PAYLOAD + 1];
        let mut buf = [0u8; MAX_FRAME + 1];
        assert_eq!(si.seal(&big, &mut buf), Err(Error::Unsupported));
        let max = [0u8; MAX_PAYLOAD];
        assert_eq!(si.seal(&max, &mut buf).unwrap(), MAX_FRAME);
    }

    #[test]
    fn fresh_entropy_makes_every_session_key_different() {
        // Same two device keys; different ephemerals and nonces → different
        // keys. The same entropy reproduces the same keys (the derivation
        // is deterministic given the transcript).
        let (a1, b1) = handshake_with(1);
        let (a2, b2) = handshake_with(2);
        let (a3, _b3) = handshake_with(1);
        assert_eq!(a1.id(), b1.id());
        assert_eq!(a2.id(), b2.id());
        assert_ne!(a1.k_send, a2.k_send);
        assert_ne!(a1.k_recv, a2.k_recv);
        assert_eq!(a1.k_send, a3.k_send);
    }

    #[test]
    fn replay_window_edges() {
        let mut w = ReplayWindow::new();
        assert!(w.accept(0));
        assert!(!w.accept(0));
        assert!(w.accept(63));
        assert!(w.accept(1));
        assert!(!w.accept(1));
        assert!(w.accept(64)); // shifts by 1: seq 0 falls out
        assert!(!w.accept(0));
        assert!(w.accept(1_000_000)); // shift ≥ 64 clears the bitmap
        assert!(!w.accept(64));
        assert!(w.accept(1_000_000 - 63));
        assert!(!w.accept(1_000_000 - 64));
        assert_eq!(w.highest(), Some(1_000_000));
        assert!(w.would_accept(999_999));
        assert!(!w.would_accept(1_000_000));
    }

    /// The wire format pinned by an independent implementation:
    /// `tools/link_golden.py` (Python `hmac` + `hashlib`, no Rust in the
    /// loop) produced these constants. If they ever change here, the wire
    /// changed and `VERSION` must bump.
    #[test]
    fn golden_envelope_tag_matches_python_hmac() {
        let key: [u8; KEY_LEN] = core::array::from_fn(|i| i as u8 + 1);
        let mut frame = [0u8; HEADER_LEN + 5];
        frame[0] = VERSION;
        frame[1..3].copy_from_slice(&0xBEEFu16.to_be_bytes());
        frame[3..7].copy_from_slice(&7u32.to_be_bytes());
        frame[7..].copy_from_slice(b"janus");
        let tag = mac(&key, &[&frame]).unwrap();
        assert_eq!(
            tag,
            [
                0xe7, 0x7f, 0x2e, 0x16, 0x0f, 0x22, 0xe1, 0x15, 0xb7, 0xc4, 0x8a, 0x9b, 0x5d, 0x68,
                0x61, 0x91
            ]
        );
        assert!(verify(&key, &[&frame], &tag));
        // And through `Session::seal` itself, so the header layout is pinned too.
        let mut s = Session {
            id: 0xBEEF,
            peer: DeviceKey::from_seed_for_tests("golden", "x").did(),
            k_send: key,
            k_recv: key,
            send_seq: 7,
            exhausted: false,
            window: ReplayWindow::new(),
            established: Micros::ZERO,
            lifetime: DEFAULT_LIFETIME,
            counters: Counters::default(),
        };
        let mut out = [0u8; MAX_FRAME];
        let n = s.seal(b"janus", &mut out).unwrap();
        assert_eq!(&out[..HEADER_LEN + 5], &frame);
        assert_eq!(&out[HEADER_LEN + 5..n], &tag);
    }

    #[test]
    fn golden_key_schedule_matches_python_hkdf() {
        let mut ikm = [0u8; 64];
        ikm[..32].fill(0x11);
        ikm[32..].fill(0x22);
        let nonce_i: [u8; NONCE_LEN] = core::array::from_fn(|i| 0xA0 + i as u8);
        let nonce_r: [u8; NONCE_LEN] = core::array::from_fn(|i| 0xB0 + i as u8);
        let keys = expand_keys(&ikm, &nonce_i, &nonce_r).unwrap();
        assert_eq!(
            keys.k_i2r,
            [
                0x75, 0x23, 0x04, 0x97, 0x03, 0xf0, 0x66, 0x7e, 0xe0, 0x91, 0xe9, 0xa4, 0xf0, 0xed,
                0xd9, 0xc3, 0x81, 0xc0, 0xcb, 0xe5, 0x4b, 0x43, 0x65, 0x00, 0x6f, 0x49, 0xf5, 0x8f,
                0xe3, 0x38, 0x80, 0x45
            ]
        );
        assert_eq!(
            keys.k_r2i,
            [
                0x8f, 0x5b, 0x39, 0xf3, 0x4b, 0x57, 0x4d, 0x7f, 0x7d, 0x60, 0x50, 0xad, 0xb4, 0xe8,
                0x2b, 0x08, 0xf8, 0x14, 0xf7, 0xd9, 0x63, 0x05, 0xee, 0x96, 0x17, 0x3b, 0x34, 0x70,
                0xf5, 0xae, 0xcf, 0x55
            ]
        );
        assert_eq!(
            keys.k_confirm,
            [
                0x85, 0xad, 0x78, 0xb3, 0x60, 0xf7, 0xf7, 0xaa, 0x03, 0xf6, 0xdc, 0xe8, 0xd9, 0xa8,
                0x40, 0xb0, 0xfc, 0xc5, 0x49, 0xa7, 0xce, 0x72, 0x4a, 0xd5, 0x93, 0xa7, 0xad, 0xcc,
                0x63, 0x31, 0x19, 0xb1
            ]
        );
        assert_eq!(keys.id, 0x1c04);
    }

    #[test]
    fn debug_never_prints_keys() {
        let (si, _) = handshake();
        let s = std::format!("{si:?}");
        assert!(s.contains("Session"));
        assert!(!s.contains("k_send"));
        assert!(!s.contains("k_recv"));
    }
}

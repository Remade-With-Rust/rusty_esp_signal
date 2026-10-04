//! SPAKE2+ over P-256 (RFC 9383, P256-SHA256-HKDF-SHA256-HMAC-SHA256), the
//! protocol's suite 1 (sections 5.2-5.4), and the device's signature over
//! the Reply.
//!
//! The browser is the prover (it knows the code), the device the verifier
//! (it stores `w0` and `L`). `idProver` and `idVerifier` are empty; the
//! device is bound by the Context and by its signature.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};
use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::Rng;
use rusty_esp_mid_core::setup as mid_setup;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::seal::{Opener, Sealer};
use super::{Context, DEVPUB_LEN, Secrets, Verifier};

/// Bytes of a share: an uncompressed P-256 point.
pub const SHARE_LEN: usize = 65;
/// Bytes of a confirmation (HMAC-SHA256).
pub const CONFIRM_LEN: usize = 32;
/// Bytes of the device's signature over the Reply (`r || s`).
pub const SIG_LEN: usize = 64;

/// RFC 9383's `M` for P-256, uncompressed.
const M_BYTES: [u8; SHARE_LEN] = hex65(
    "04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f\
     5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20",
);
/// RFC 9383's `N` for P-256, uncompressed.
const N_BYTES: [u8; SHARE_LEN] = hex65(
    "04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49\
     07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7",
);

const INFO_B2D: &[u8] = b"janus-setup-v1 b2d";
const INFO_D2B: &[u8] = b"janus-setup-v1 d2b";

/// An uncompressed SEC1 point on the curve, not the identity; anything
/// else is `InvalidFormat`.
pub(super) fn point(bytes: &[u8]) -> Result<AffinePoint> {
    if bytes.len() != SHARE_LEN || bytes[0] != 0x04 {
        return Err(Error::InvalidFormat);
    }
    let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| Error::InvalidFormat)?;
    let point = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or(Error::InvalidFormat)?;
    if bool::from(ProjectivePoint::from(point).is_identity()) {
        return Err(Error::InvalidFormat);
    }
    Ok(point)
}

/// A point as 65 uncompressed bytes. The identity has no such encoding:
/// `Crypto` (a computed `Z` or `V` that collapsed means a hostile share).
fn encode(p: &ProjectivePoint) -> Result<[u8; SHARE_LEN]> {
    if bool::from(p.is_identity()) {
        return Err(Error::Crypto);
    }
    let encoded = p.to_affine().to_encoded_point(false);
    let mut out = [0u8; SHARE_LEN];
    out.copy_from_slice(encoded.as_bytes());
    Ok(out)
}

fn m() -> ProjectivePoint {
    ProjectivePoint::from(point(&M_BYTES).expect("RFC 9383's M is a point"))
}

fn n() -> ProjectivePoint {
    ProjectivePoint::from(point(&N_BYTES).expect("RFC 9383's N is a point"))
}

/// A scalar from 32 big-endian bytes in `[1, n-1]`.
fn scalar(bytes: &[u8; 32]) -> Result<Scalar> {
    let mut repr = FieldBytes::default();
    repr.copy_from_slice(bytes);
    let s = Option::<Scalar>::from(Scalar::from_repr(repr)).ok_or(Error::InvalidFormat)?;
    repr.zeroize();
    if bool::from(s.is_zero()) {
        return Err(Error::InvalidFormat);
    }
    Ok(s)
}

/// A uniform scalar in `[1, n-1]` from `rng`, by rejection.
fn random_scalar(rng: &mut impl Rng) -> Result<Scalar> {
    let mut bytes = [0u8; 32];
    for _ in 0..16 {
        rng.fill(&mut bytes)?;
        if let Ok(s) = scalar(&bytes) {
            bytes.zeroize();
            return Ok(s);
        }
    }
    bytes.zeroize();
    Err(Error::Crypto)
}

/// RFC 9383's key schedule over one session.
struct Keys {
    confirm_p: [u8; 32],
    confirm_v: [u8; 32],
    shared: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.confirm_p.zeroize();
        self.confirm_v.zeroize();
        self.shared.zeroize();
    }
}

fn lp8(h: &mut Sha256, part: &[u8]) {
    h.update((part.len() as u64).to_le_bytes());
    h.update(part);
}

#[allow(clippy::too_many_arguments)]
fn schedule(
    context: &[u8],
    id_p: &[u8],
    id_v: &[u8],
    share_p: &[u8; SHARE_LEN],
    share_v: &[u8; SHARE_LEN],
    z: &[u8; SHARE_LEN],
    v: &[u8; SHARE_LEN],
    w0: &Scalar,
) -> Keys {
    let mut tt = Sha256::new();
    let mut w0_bytes = w0.to_bytes();
    for part in [
        context,
        id_p,
        id_v,
        &M_BYTES[..],
        &N_BYTES[..],
        share_p,
        share_v,
        z,
        v,
        &w0_bytes[..],
    ] {
        lp8(&mut tt, part);
    }
    w0_bytes.zeroize();
    let mut k_main: [u8; 32] = tt.finalize().into();
    let hk = Hkdf::<Sha256>::new(None, &k_main);
    let mut confirmation = [0u8; 64];
    hk.expand(b"ConfirmationKeys", &mut confirmation)
        .expect("64 bytes is a valid HKDF length");
    let mut keys = Keys {
        confirm_p: [0; 32],
        confirm_v: [0; 32],
        shared: [0; 32],
    };
    keys.confirm_p.copy_from_slice(&confirmation[..32]);
    keys.confirm_v.copy_from_slice(&confirmation[32..]);
    hk.expand(b"SharedKey", &mut keys.shared)
        .expect("32 bytes is a valid HKDF length");
    confirmation.zeroize();
    k_main.zeroize();
    keys
}

fn mac(key: &[u8; 32], share: &[u8; SHARE_LEN]) -> [u8; CONFIRM_LEN] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(share);
    m.finalize().into_bytes().into()
}

fn direction_key(shared: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared)
        .expand(info, &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

/// Both ends of an established session: the keys that seal what each side
/// sends and open what it receives.
pub struct Established {
    send: Sealer,
    recv: Opener,
}

impl Established {
    fn new(shared: &[u8; 32], browser: bool) -> Self {
        let mut b2d = direction_key(shared, INFO_B2D);
        let mut d2b = direction_key(shared, INFO_D2B);
        let (send, recv) = if browser { (&b2d, &d2b) } else { (&d2b, &b2d) };
        let out = Established {
            send: Sealer::new(send),
            recv: Opener::new(recv),
        };
        b2d.zeroize();
        d2b.zeroize();
        out
    }

    /// The sealer for what this side sends and the opener for what it
    /// receives.
    #[must_use]
    pub fn split(self) -> (Sealer, Opener) {
        (self.send, self.recv)
    }
}

// ---- the browser: the prover ---------------------------------------------

/// The browser's half of a session, between Start and Reply.
pub struct Prover {
    secrets: Secrets,
    x: Scalar,
    share_p: [u8; SHARE_LEN],
    context: Context,
}

impl Prover {
    /// Starts a session: draws `x` from `rng` and computes
    /// `shareP = x*G + w0*M`.
    pub fn start(secrets: Secrets, context: Context, rng: &mut impl Rng) -> Result<Self> {
        let x = random_scalar(rng)?;
        Self::with_scalar(secrets, context, x)
    }

    /// [`Prover::start`] with `x` given (32 bytes, big-endian, in
    /// `[1, n-1]`): for test vectors only.
    #[doc(hidden)]
    pub fn start_with_scalar(secrets: Secrets, context: Context, x: &[u8; 32]) -> Result<Self> {
        Self::with_scalar(secrets, context, scalar(x)?)
    }

    fn with_scalar(secrets: Secrets, context: Context, x: Scalar) -> Result<Self> {
        let share_p = encode(&(ProjectivePoint::GENERATOR * x + m() * secrets.w0))?;
        Ok(Prover {
            secrets,
            x,
            share_p,
            context,
        })
    }

    /// `shareP`, for Start.
    #[must_use]
    pub fn share_p(&self) -> &[u8; SHARE_LEN] {
        &self.share_p
    }

    /// The Context this session was started with.
    #[must_use]
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Takes the device's `shareV` and `confirmV` from Reply. `shareV` not a
    /// point is `InvalidFormat`; `confirmV` wrong (a wrong code, or not this
    /// device's verifier) is `Crypto`. On success: `confirmP` for Confirm,
    /// and the session's keys. The Reply's signature is checked separately
    /// ([`verify_reply`]) against the device the browser expects.
    pub fn finish(
        self,
        share_v: &[u8],
        confirm_v: &[u8],
    ) -> Result<([u8; CONFIRM_LEN], Established)> {
        let keys = prover_keys(
            self.context.as_bytes(),
            b"",
            b"",
            &self.secrets,
            &self.x,
            &self.share_p,
            share_v,
        )?;
        let share_v: &[u8; SHARE_LEN] = share_v.try_into().map_err(|_| Error::InvalidFormat)?;
        let mut want_v = mac(&keys.confirm_v, &self.share_p);
        let ok = bool::from(want_v.as_slice().ct_eq(confirm_v));
        want_v.zeroize();
        if !ok {
            return Err(Error::Crypto);
        }
        Ok((
            mac(&keys.confirm_p, share_v),
            Established::new(&keys.shared, true),
        ))
    }
}

impl Drop for Prover {
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

fn prover_keys(
    context: &[u8],
    id_p: &[u8],
    id_v: &[u8],
    secrets: &Secrets,
    x: &Scalar,
    share_p: &[u8; SHARE_LEN],
    share_v: &[u8],
) -> Result<Keys> {
    let y = ProjectivePoint::from(point(share_v)?);
    let share_v: &[u8; SHARE_LEN] = share_v.try_into().map_err(|_| Error::InvalidFormat)?;
    let t = y - n() * secrets.w0;
    let z = encode(&(t * x))?;
    let v = encode(&(t * secrets.w1))?;
    Ok(schedule(
        context,
        id_p,
        id_v,
        share_p,
        share_v,
        &z,
        &v,
        &secrets.w0,
    ))
}

// ---- the device: the verifier -----------------------------------------------

/// The device's half of a session, between Reply and Confirm.
pub struct Response {
    share_v: [u8; SHARE_LEN],
    confirm_v: [u8; CONFIRM_LEN],
    expect_p: [u8; CONFIRM_LEN],
    shared: [u8; 32],
}

/// Answers Start: draws `y` from `rng`, computes `shareV = y*G + w0*N`,
/// `Z = y*(X - w0*M)`, `V = y*L` and the key schedule. `shareP` not a point
/// is `InvalidFormat`.
pub fn respond(
    verifier: &Verifier,
    context: &Context,
    share_p: &[u8],
    rng: &mut impl Rng,
) -> Result<Response> {
    let y = random_scalar(rng)?;
    respond_inner(verifier, context.as_bytes(), b"", b"", share_p, y)
}

/// [`respond`] with `y` given: for test vectors only.
#[doc(hidden)]
pub fn respond_with_scalar(
    verifier: &Verifier,
    context: &Context,
    share_p: &[u8],
    y: &[u8; 32],
) -> Result<Response> {
    respond_inner(verifier, context.as_bytes(), b"", b"", share_p, scalar(y)?)
}

fn respond_inner(
    verifier: &Verifier,
    context: &[u8],
    id_p: &[u8],
    id_v: &[u8],
    share_p: &[u8],
    mut y: Scalar,
) -> Result<Response> {
    let x = ProjectivePoint::from(point(share_p)?);
    let share_p: &[u8; SHARE_LEN] = share_p.try_into().map_err(|_| Error::InvalidFormat)?;
    let share_v = encode(&(ProjectivePoint::GENERATOR * y + n() * verifier.w0))?;
    let z = encode(&((x - m() * verifier.w0) * y))?;
    let v = encode(&(ProjectivePoint::from(verifier.l) * y))?;
    y.zeroize();
    let keys = schedule(context, id_p, id_v, share_p, &share_v, &z, &v, &verifier.w0);
    Ok(Response {
        share_v,
        confirm_v: mac(&keys.confirm_v, share_p),
        expect_p: mac(&keys.confirm_p, &share_v),
        shared: keys.shared,
    })
}

impl Response {
    /// `shareV`, for Reply.
    #[must_use]
    pub fn share_v(&self) -> &[u8; SHARE_LEN] {
        &self.share_v
    }

    /// `confirmV`, for Reply.
    #[must_use]
    pub fn confirm_v(&self) -> &[u8; CONFIRM_LEN] {
        &self.confirm_v
    }

    /// Takes the browser's `confirmP` from Confirm, compared in constant
    /// time. Wrong (a wrong code) is `Crypto`, and the session's keys are
    /// gone with `self`.
    pub fn confirm(self, confirm_p: &[u8]) -> Result<Established> {
        if bool::from(self.expect_p.as_slice().ct_eq(confirm_p)) {
            Ok(Established::new(&self.shared, false))
        } else {
            Err(Error::Crypto)
        }
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        self.expect_p.zeroize();
        self.shared.zeroize();
    }
}

// ---- the device's signature over the Reply ---------------------------------

/// The prehash the device signs with its `did:mata` key (protocol 5.3):
/// mID's [`rusty_esp_mid_core::setup::reply_prehash`] over this session's
/// Context, `SHA-256("janus-setup-v1/reply\n" || u16be(len(Context)) ||
/// Context || shareP || shareV || confirmV)`.
#[must_use]
pub fn reply_prehash(
    context: &Context,
    share_p: &[u8; SHARE_LEN],
    share_v: &[u8; SHARE_LEN],
    confirm_v: &[u8; CONFIRM_LEN],
) -> [u8; 32] {
    mid_setup::reply_prehash(context.as_bytes(), share_p, share_v, confirm_v)
        .expect("a Context is at most 64 bytes")
}

/// The browser's check of the Reply's signature against the device it was
/// shown (`devpub`, the compressed key in Discover), by mID's rules: low-s
/// only. A signature of another length is `InvalidFormat`; one that does
/// not verify (another key, another session, a high-s twin) is `Crypto`.
pub fn verify_reply(devpub: &[u8; DEVPUB_LEN], prehash: &[u8; 32], sig: &[u8]) -> Result<()> {
    let sig: &[u8; SIG_LEN] = sig.try_into().map_err(|_| Error::InvalidFormat)?;
    mid_setup::verify_reply(devpub, prehash, sig)
}

const fn hex65(h: &str) -> [u8; SHARE_LEN] {
    let b = h.as_bytes();
    let mut out = [0u8; SHARE_LEN];
    let mut i = 0;
    let mut j = 0;
    while i < SHARE_LEN {
        // skip the whitespace a line continuation leaves
        while b[j] == b' ' || b[j] == b'\n' {
            j += 1;
        }
        out[i] = (nibble(b[j]) << 4) | nibble(b[j + 1]);
        i += 1;
        j += 2;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("not a hex digit"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> std::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn s32(hex: &str) -> Scalar {
        scalar(&h(hex).try_into().unwrap()).unwrap()
    }

    /// RFC 9383 Appendix C, the P256-SHA256-HKDF-SHA256-HMAC-SHA256 vector,
    /// through both roles' internals (its identities are "client" and
    /// "server"; the protocol's are empty).
    #[test]
    fn rfc_9383_vector() {
        let context = b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors";
        let secrets = Secrets {
            w0: s32("bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3"),
            w1: s32("7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba"),
        };
        let x = s32("d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539");
        let y = s32("717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3");
        let verifier = Verifier::from_secrets(&secrets, &[0; 16], 1_000);

        let share_p = encode(&(ProjectivePoint::GENERATOR * x + m() * secrets.w0)).unwrap();
        let device = respond_inner(&verifier, context, b"client", b"server", &share_p, y).unwrap();
        let browser = prover_keys(
            context,
            b"client",
            b"server",
            &secrets,
            &x,
            &share_p,
            &device.share_v,
        )
        .unwrap();

        assert_eq!(
            browser.confirm_p[..],
            h("871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a")[..]
        );
        assert_eq!(
            browser.confirm_v[..],
            h("ccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680")[..]
        );
        assert_eq!(
            browser.shared[..],
            h("0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7")[..]
        );
        assert_eq!(device.shared[..], browser.shared[..]);
        assert_eq!(
            device.confirm_v[..],
            h("9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68")[..]
        );
        assert_eq!(
            mac(&browser.confirm_p, &device.share_v)[..],
            h("926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527")[..]
        );
        assert_eq!(device.expect_p, mac(&browser.confirm_p, &device.share_v));
        assert_eq!(share_p[..3], h("04ef3b")[..]);
        assert_eq!(device.share_v[..3], h("04c0f6")[..]);
    }

    #[test]
    fn m_and_n_are_the_rfcs() {
        // the compressed forms RFC 9383 prints
        assert_eq!(
            point(&M_BYTES).unwrap().to_encoded_point(true).as_bytes(),
            &h("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")[..]
        );
        assert_eq!(
            point(&N_BYTES).unwrap().to_encoded_point(true).as_bytes(),
            &h("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")[..]
        );
    }

    #[test]
    fn points_that_are_refused() {
        let mut bad = M_BYTES;
        bad[64] ^= 1; // off the curve
        assert_eq!(point(&bad).err(), Some(Error::InvalidFormat));
        assert_eq!(point(&M_BYTES[..33]).err(), Some(Error::InvalidFormat)); // compressed length
        let mut compressed_tag = M_BYTES;
        compressed_tag[0] = 0x02;
        assert_eq!(point(&compressed_tag).err(), Some(Error::InvalidFormat));
        assert_eq!(point(&[0u8; SHARE_LEN]).err(), Some(Error::InvalidFormat));
    }
}

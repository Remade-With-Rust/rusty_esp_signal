//! The verifier (protocol sections 3.2 and 3.3): `w0`, `w1` from the code
//! by PBKDF2, and the 118-byte `setup.v` record the device stores.

use hmac::{Hmac, Mac};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::{Field, PrimeField};
use p256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar, U256};
use rusty_esp_core::error::{Error, Result};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::Code;

/// Bytes of salt in a verifier.
pub const SALT_LEN: usize = 16;

/// Bytes of a `setup.v` record.
pub const SETUP_V_LEN: usize = 1 + 32 + 65 + SALT_LEN + 4;

/// The fewest PBKDF2 iterations a verifier may name.
pub const MIN_ITERATIONS: u32 = 1_000;

/// The most PBKDF2 iterations a verifier may name: the browser runs what
/// Discover says, so a device claiming four billion would freeze the
/// person's page. Twenty times the starting count.
pub const MAX_ITERATIONS: u32 = 2_000_000;

const RECORD_VERSION: u8 = 1;

/// `2^256 mod n`: folds the top bytes of a 40-byte PBKDF2 half into a scalar.
const TWO_POW_256_MOD_N: &str = "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf";

/// The prover's secrets, `w0` and `w1`: what the browser derives from the
/// code. Zeroised on drop.
pub struct Secrets {
    pub(super) w0: Scalar,
    pub(super) w1: Scalar,
}

impl Secrets {
    /// `w0 || w1` from `code` (RFC 9383 section 3.2, protocol 3.2):
    /// `PBKDF2-HMAC-SHA256(lp8(pw) || lp8("") || lp8(""), salt, iterations,
    /// 80)`, each 40-byte half reduced mod `n`. Fewer than
    /// [`MIN_ITERATIONS`] is `InvalidFormat`; a zero `w0` or `w1` (odds
    /// 2^-256) is `Crypto`, and the caller draws another salt. More than
    /// [`MAX_ITERATIONS`] is `InvalidFormat`, refused before any work.
    pub fn derive(code: &Code, salt: &[u8; SALT_LEN], iterations: u32) -> Result<Self> {
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(Error::InvalidFormat);
        }
        let pw = code.as_bytes();
        let mut password = [0u8; 8 + super::CODE_SYMBOLS + 16];
        password[..8].copy_from_slice(&(pw.len() as u64).to_le_bytes());
        password[8..8 + pw.len()].copy_from_slice(pw);
        // lp8("") twice: sixteen zero bytes, already there
        let mut ws = [0u8; 80];
        pbkdf2_hmac_sha256(&password, salt, iterations, &mut ws);
        password.zeroize();
        let w0 = reduce_40(&ws[..40]);
        let w1 = reduce_40(&ws[40..]);
        ws.zeroize();
        if bool::from(w0.is_zero()) || bool::from(w1.is_zero()) {
            return Err(Error::Crypto);
        }
        Ok(Secrets { w0, w1 })
    }
}

impl Drop for Secrets {
    fn drop(&mut self) {
        self.w0.zeroize();
        self.w1.zeroize();
    }
}

impl core::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secrets(<redacted>)")
    }
}

/// The device's stored verifier: `w0`, `L = w1 * G`, the salt and the
/// iteration count, as the `setup.v` record. It holds no code and no `w1`.
/// `w0` is zeroised on drop.
pub struct Verifier {
    pub(super) w0: Scalar,
    pub(super) l: AffinePoint,
    salt: [u8; SALT_LEN],
    iterations: u32,
}

impl Verifier {
    /// The verifier made from the prover's secrets: what the portal writes
    /// at flash time.
    #[must_use]
    pub fn from_secrets(secrets: &Secrets, salt: &[u8; SALT_LEN], iterations: u32) -> Self {
        Verifier {
            w0: secrets.w0,
            l: (ProjectivePoint::GENERATOR * secrets.w1).to_affine(),
            salt: *salt,
            iterations,
        }
    }

    /// The salt the browser needs to derive `w0`, `w1` (in Discover).
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// The PBKDF2 iteration count (in Discover).
    #[must_use]
    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    /// The `setup.v` record: `0x01 || w0 || L (uncompressed) || salt ||
    /// u32be iterations`. Holds `w0`: the caller wipes it after storing.
    #[must_use]
    pub fn encode(&self) -> [u8; SETUP_V_LEN] {
        let mut out = [0u8; SETUP_V_LEN];
        out[0] = RECORD_VERSION;
        out[1..33].copy_from_slice(&self.w0.to_bytes());
        out[33..98].copy_from_slice(self.l.to_encoded_point(false).as_bytes());
        out[98..114].copy_from_slice(&self.salt);
        out[114..118].copy_from_slice(&self.iterations.to_be_bytes());
        out
    }

    /// Reads a `setup.v` record. Refused (`InvalidFormat`): another length or
    /// version, `w0` not in `[1, n-1]`, `L` not an uncompressed point on the
    /// curve, fewer than [`MIN_ITERATIONS`] or more than [`MAX_ITERATIONS`].
    pub fn decode(record: &[u8]) -> Result<Self> {
        if record.len() != SETUP_V_LEN || record[0] != RECORD_VERSION {
            return Err(Error::InvalidFormat);
        }
        let mut w0_bytes = FieldBytes::default();
        w0_bytes.copy_from_slice(&record[1..33]);
        let w0 = Option::<Scalar>::from(Scalar::from_repr(w0_bytes)).ok_or(Error::InvalidFormat)?;
        w0_bytes.zeroize();
        if bool::from(w0.is_zero()) {
            return Err(Error::InvalidFormat);
        }
        let l = super::spake::point(&record[33..98])?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&record[98..114]);
        let iterations = u32::from_be_bytes([record[114], record[115], record[116], record[117]]);
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(Error::InvalidFormat);
        }
        Ok(Verifier {
            w0,
            l,
            salt,
            iterations,
        })
    }

    /// Whether `secrets` are the ones this verifier was made from (constant
    /// time): the portal's check after writing, and the tests'.
    #[must_use]
    pub fn matches(&self, secrets: &Secrets) -> bool {
        let l = (ProjectivePoint::GENERATOR * secrets.w1).to_affine();
        let same_w0 = self.w0.to_bytes().ct_eq(&secrets.w0.to_bytes());
        let same_l = self
            .l
            .to_encoded_point(false)
            .as_bytes()
            .ct_eq(l.to_encoded_point(false).as_bytes());
        bool::from(same_w0 & same_l)
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        self.w0.zeroize();
    }
}

impl core::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Verifier")
            .field("iterations", &self.iterations)
            .finish_non_exhaustive()
    }
}

/// `int(bytes) mod n` for a 40-byte big-endian integer:
/// `hi * 2^256 + lo` with `hi` the first 8 bytes.
fn reduce_40(bytes: &[u8]) -> Scalar {
    let mut lo = FieldBytes::default();
    lo.copy_from_slice(&bytes[8..40]);
    let mut hi = [0u8; 8];
    hi.copy_from_slice(&bytes[..8]);
    let r = <Scalar as Reduce<U256>>::reduce(U256::from_be_hex(TWO_POW_256_MOD_N));
    let out =
        <Scalar as Reduce<U256>>::reduce_bytes(&lo) + Scalar::from(u64::from_be_bytes(hi)) * r;
    lo.zeroize();
    hi.zeroize();
    out
}

/// SHA-256's initial state (FIPS 180-4, 5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// PBKDF2 with HMAC-SHA256 (RFC 8018), filling `out`.
///
/// The browser pays this once a session and a guesser once a guess, so the
/// loop is the compression function and nothing else: the key's inner and
/// outer pads are absorbed once, and every later HMAC is one fixed block
/// each side (`U || 0x80 || 0.. || bitlen(64 + 32)`), pre-padded. Byte for
/// byte the generic HMAC loop, which the tests keep and compare it with.
// generic-array 0.14 is deprecated, but it is what sha2 0.10's compress256 takes
#[allow(deprecated)]
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    use sha2::Digest;
    use sha2::digest::generic_array::GenericArray;

    let prf = Hmac::<Sha256>::new_from_slice(password).expect("HMAC takes any key length");
    // the pads' states: a key longer than a block is hashed first (RFC 2104)
    let mut key = [0u8; 64];
    if password.len() > 64 {
        key[..32].copy_from_slice(&Sha256::digest(password));
    } else {
        key[..password.len()].copy_from_slice(password);
    }
    let mut pad = [0u8; 64];
    let mut inner = SHA256_IV;
    let mut outer = SHA256_IV;
    for (state, byte) in [(&mut inner, 0x36u8), (&mut outer, 0x5c)] {
        for (p, k) in pad.iter_mut().zip(key.iter()) {
            *p = k ^ byte;
        }
        sha2::compress256(state, core::slice::from_ref(GenericArray::from_slice(&pad)));
    }
    key.zeroize();
    pad.zeroize();
    // one block after a pad: 32 bytes of message, 96 in all, 768 bits
    let mut block = [0u8; 64];
    block[32] = 0x80;
    block[62..].copy_from_slice(&768u16.to_be_bytes());

    for (i, chunk) in out.chunks_mut(32).enumerate() {
        let mut mac = prf.clone();
        mac.update(salt);
        mac.update(&(i as u32 + 1).to_be_bytes());
        let mut first: [u8; 32] = mac.finalize().into_bytes().into();
        let mut u = [0u32; 8];
        for (w, b) in u.iter_mut().zip(first.chunks_exact(4)) {
            *w = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        }
        first.zeroize();
        let mut t = u;
        for _ in 1..iterations {
            for (b, w) in block[..32].chunks_exact_mut(4).zip(u.iter()) {
                b.copy_from_slice(&w.to_be_bytes());
            }
            let mut s = inner;
            sha2::compress256(
                &mut s,
                core::slice::from_ref(GenericArray::from_slice(&block)),
            );
            for (b, w) in block[..32].chunks_exact_mut(4).zip(s.iter()) {
                b.copy_from_slice(&w.to_be_bytes());
            }
            u = outer;
            sha2::compress256(
                &mut u,
                core::slice::from_ref(GenericArray::from_slice(&block)),
            );
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        let mut bytes = [0u8; 32];
        for (b, w) in bytes.chunks_exact_mut(4).zip(t.iter()) {
            b.copy_from_slice(&w.to_be_bytes());
        }
        chunk.copy_from_slice(&bytes[..chunk.len()]);
        bytes.zeroize();
        u.zeroize();
        t.zeroize();
    }
    block.zeroize();
    inner.zeroize();
    outer.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generic loop the fast one replaced: HMAC through `hmac`, every
    /// iteration finalised the ordinary way.
    fn pbkdf2_reference(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
        let prf = Hmac::<Sha256>::new_from_slice(password).unwrap();
        for (i, chunk) in out.chunks_mut(32).enumerate() {
            let mut mac = prf.clone();
            mac.update(salt);
            mac.update(&(i as u32 + 1).to_be_bytes());
            let mut u: [u8; 32] = mac.finalize().into_bytes().into();
            let mut t = u;
            for _ in 1..iterations {
                let mut mac = prf.clone();
                mac.update(&u);
                u = mac.finalize().into_bytes().into();
                for (a, b) in t.iter_mut().zip(u.iter()) {
                    *a ^= b;
                }
            }
            chunk.copy_from_slice(&t[..chunk.len()]);
        }
    }

    #[test]
    fn pbkdf2_is_the_generic_loop_byte_for_byte() {
        let long = [0xA5u8; 100];
        for password in [
            &b""[..],
            b"passwd",
            &[7u8; 63],
            &[7u8; 64],
            &[7u8; 65],
            &long,
        ] {
            for iterations in [1, 2, 3, 17, 1_000] {
                for len in [1, 32, 33, 80] {
                    let mut fast = [0u8; 80];
                    let mut slow = [0u8; 80];
                    pbkdf2_hmac_sha256(password, b"janus-salt", iterations, &mut fast[..len]);
                    pbkdf2_reference(password, b"janus-salt", iterations, &mut slow[..len]);
                    assert_eq!(fast, slow, "pw {} c {iterations} len {len}", password.len());
                }
            }
        }
    }

    #[test]
    fn pbkdf2_matches_rfc_7914_at_80000() {
        // RFC 7914 section 11: "Password", "NaCl", c = 80000, dkLen 64
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha256(b"Password", b"NaCl", 80_000, &mut out);
        assert_eq!(
            out[..16],
            [
                0x4d, 0xdc, 0xd8, 0xf6, 0x0b, 0x98, 0xbe, 0x21, 0x83, 0x0c, 0xee, 0x5e, 0xf2, 0x27,
                0x01, 0xf9
            ]
        );
    }

    #[test]
    fn pbkdf2_matches_rfc_7914() {
        // RFC 7914 section 11, PBKDF2-HMAC-SHA256: "passwd", "salt", c = 1, dkLen 64
        let mut out = [0u8; 64];
        pbkdf2_hmac_sha256(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            out[..16],
            [
                0x55, 0xac, 0x04, 0x6e, 0x56, 0xe3, 0x08, 0x9f, 0xec, 0x16, 0x91, 0xc2, 0x25, 0x44,
                0xb6, 0x05
            ]
        );
    }

    #[test]
    fn reduction_folds_the_top_bytes() {
        // n itself, padded to 40 bytes, is zero; n + 1 is one; 2^256 is 2^256 mod n
        let mut n40 = [0u8; 40];
        n40[8..].copy_from_slice(&hex32(
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        ));
        assert!(bool::from(reduce_40(&n40).is_zero()));
        n40[39] += 1;
        assert_eq!(reduce_40(&n40), Scalar::ONE);
        let mut two256 = [0u8; 40];
        two256[7] = 1;
        assert_eq!(
            reduce_40(&two256).to_bytes()[..],
            hex32(TWO_POW_256_MOD_N)[..]
        );
    }

    fn hex32(h: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}

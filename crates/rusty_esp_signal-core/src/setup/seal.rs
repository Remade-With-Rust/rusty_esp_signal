//! Sealing (protocol section 5.6): ChaCha20-Poly1305 (RFC 8439), one key per
//! direction, the nonce `0x00000000 || u64be(seq)` counted from 0, the
//! message's two header bytes as associated data.

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};
use rusty_esp_core::error::{Error, Result};
use zeroize::Zeroize;

/// Bytes of a seal's tag.
pub const TAG_LEN: usize = 16;

fn nonce(seq: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    Nonce::from(n)
}

/// Seals what one side sends. Each message takes the next sequence number.
pub struct Sealer {
    key: [u8; 32],
    seq: u64,
}

impl Sealer {
    pub(super) fn new(key: &[u8; 32]) -> Self {
        Sealer { key: *key, seq: 0 }
    }

    /// Seals `plaintext` under `header` (the message's version and kind)
    /// into `out` as `ciphertext || tag`; returns the bytes written.
    /// `BufferTooSmall` names the length needed.
    pub fn seal(&mut self, header: &[u8; 2], plaintext: &[u8], out: &mut [u8]) -> Result<usize> {
        let needed = plaintext.len() + TAG_LEN;
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        let next = self.seq.checked_add(1).ok_or(Error::Denied)?;
        let (body, tag_out) = out[..needed].split_at_mut(plaintext.len());
        body.copy_from_slice(plaintext);
        let tag = ChaCha20Poly1305::new(&self.key.into())
            .encrypt_in_place_detached(&nonce(self.seq), header, body)
            .map_err(|_| Error::Crypto)?;
        tag_out.copy_from_slice(&tag);
        self.seq = next;
        Ok(needed)
    }

    /// The sequence number the next message will take.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.seq
    }
}

impl Drop for Sealer {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Opens what the other side sends, in order: exactly the next sequence
/// number is accepted.
pub struct Opener {
    key: [u8; 32],
    seq: u64,
}

impl Opener {
    pub(super) fn new(key: &[u8; 32]) -> Self {
        Opener { key: *key, seq: 0 }
    }

    /// Opens `sealed` (`ciphertext || tag`) under `header` into `out`;
    /// returns the plaintext's length. Shorter than a tag is
    /// `InvalidFormat`; a seal that does not verify (another key, another
    /// header, another sequence number, a changed byte) is `Crypto`, and
    /// `out` is wiped.
    pub fn open(&mut self, header: &[u8; 2], sealed: &[u8], out: &mut [u8]) -> Result<usize> {
        let Some(len) = sealed.len().checked_sub(TAG_LEN) else {
            return Err(Error::InvalidFormat);
        };
        if out.len() < len {
            return Err(Error::BufferTooSmall { needed: len });
        }
        let next = self.seq.checked_add(1).ok_or(Error::Denied)?;
        let body = &mut out[..len];
        body.copy_from_slice(&sealed[..len]);
        let mut tag = Tag::default();
        tag.copy_from_slice(&sealed[len..]);
        if ChaCha20Poly1305::new(&self.key.into())
            .decrypt_in_place_detached(&nonce(self.seq), header, body, &tag)
            .is_err()
        {
            body.zeroize();
            return Err(Error::Crypto);
        }
        self.seq = next;
        Ok(len)
    }

    /// The sequence number the next message must carry.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.seq
    }
}

impl Drop for Opener {
    fn drop(&mut self) {
        self.key.zeroize();
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

    /// RFC 8439 section 2.8.2 through the library, with the RFC's own nonce
    /// (this module's nonces are counted; the cipher is the same).
    #[test]
    fn rfc_8439_aead_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce = Nonce::from(<[u8; 12]>::try_from(&h("070000004041424344454647")[..]).unwrap());
        let aad = h("50515253c0c1c2c3c4c5c6c7");
        let mut buf = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let tag = ChaCha20Poly1305::new(&key.into())
            .encrypt_in_place_detached(&nonce, &aad, &mut buf)
            .unwrap();
        assert_eq!(buf[..16], h("d31a8d34648e60db7b86afbc53ef7ec2")[..]);
        assert_eq!(tag[..], h("1ae10b594f09e26a7e902ecbd0600691")[..]);
    }

    #[test]
    fn a_seal_opens_once_in_order_and_nowhere_else() {
        let key = [7u8; 32];
        let (mut s, mut o) = (Sealer::new(&key), Opener::new(&key));
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        let n1 = s.seal(&[1, 4], b"first", &mut first).unwrap();
        let n2 = s.seal(&[1, 6], b"second", &mut second).unwrap();
        let mut out = [0u8; 64];
        // out of order: the second before the first
        assert_eq!(o.open(&[1, 6], &second[..n2], &mut out), Err(Error::Crypto));
        assert_eq!(&out[..6], &[0; 6]);
        let n = o.open(&[1, 4], &first[..n1], &mut out).unwrap();
        assert_eq!(&out[..n], b"first");
        // a replay of the first
        assert_eq!(o.open(&[1, 4], &first[..n1], &mut out), Err(Error::Crypto));
        // the right one, under a changed header
        assert_eq!(o.open(&[1, 5], &second[..n2], &mut out), Err(Error::Crypto));
        let n = o.open(&[1, 6], &second[..n2], &mut out).unwrap();
        assert_eq!(&out[..n], b"second");
        // a flipped byte
        let mut s = Sealer::new(&key);
        let mut o = Opener::new(&key);
        let n = s.seal(&[1, 5], b"settings", &mut first).unwrap();
        first[3] ^= 0x40;
        assert_eq!(o.open(&[1, 5], &first[..n], &mut out), Err(Error::Crypto));
        first[3] ^= 0x40;
        assert_eq!(
            o.open(&[1, 5], &first[..n - 1], &mut out),
            Err(Error::Crypto)
        ); // truncated
        assert_eq!(
            o.open(&[1, 5], &first[..15], &mut out),
            Err(Error::InvalidFormat)
        );
    }

    #[test]
    fn buffers_too_small_are_named() {
        let mut s = Sealer::new(&[1; 32]);
        assert_eq!(
            s.seal(&[1, 4], b"abc", &mut [0u8; 18]),
            Err(Error::BufferTooSmall { needed: 19 })
        );
        assert_eq!(s.next_seq(), 0);
    }
}

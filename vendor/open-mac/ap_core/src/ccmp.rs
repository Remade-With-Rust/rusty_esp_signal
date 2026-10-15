//! CCMP encapsulation in software (802.11-2020 clause 12.5.3).
//!
//! **Why this exists.** The S3's MAC has a crypto engine with key slots, and
//! the hardware encrypts a frame for us when the transmit descriptor names
//! one. On the second virtual interface it does not: an access point spliced
//! beside a station completed WPA2 handshakes and
//! decrypted the station's frames, and every *protected* frame it sent
//! failed, with the hardware's transmit error class 4 sub-error 1 -- all of
//! them on interface 1, none on interface 0, and open frames on the same
//! interface fine. So the access point encrypts
//! its own frames here and hands the radio a frame that is already
//! protected, naming no key slot.
//!
//! CCMP is AES-128 in CCM (RFC 3610) with an 8-octet MIC and a two-octet
//! length field, over a nonce and additional data that 802.11 builds from the
//! frame's own header. Everything that decides those two is read back out of
//! the frame being sent, so what is authenticated cannot drift from what goes
//! on the air.
//!
//! Not Wi-Fi certified.

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};

/// CCMP's MIC: 8 octets after the body (CCM's M).
pub const MIC_LEN: usize = 8;
/// The CCMP header between the MAC header and the body.
pub const HEADER_LEN: usize = 8;

const BLOCK: usize = 16;
/// The widest AAD: the header's fields with A4 and QoS Control both present.
const AAD_MAX: usize = 30;

/// Why a frame was not encapsulated. Each one means the frame is not sent:
/// this never falls back to sending it in the clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Shorter than a MAC header, a CCMP header and a MIC.
    Short,
    /// Not a data frame. A management frame would need the Management bit in
    /// the nonce and is not encapsulated here.
    NotData,
    /// The Protected bit is clear, so a receiver would not decrypt it: the
    /// caller built the frame wrong.
    NotProtected,
    /// The body does not fit CCM's two-octet length field.
    TooLong,
}

/// What the header says about itself, read from the frame rather than passed
/// in, so the AAD cannot disagree with the frame.
struct Layout {
    /// The MAC header's length: 24, plus A4, plus QoS Control.
    header: usize,
    qos: bool,
    addr4: bool,
    /// The traffic identifier, which is the nonce's priority. 0 without QoS.
    tid: u8,
}

fn layout(frame: &[u8]) -> Result<Layout, Refused> {
    if frame.len() < 24 {
        return Err(Refused::Short);
    }
    // type 2 is data; the subtype's top bit marks QoS; To DS and From DS
    // together mean a fourth address
    if (frame[0] >> 2) & 0b11 != 2 {
        return Err(Refused::NotData);
    }
    let qos = frame[0] & 0b1000_0000 != 0;
    let addr4 = frame[1] & 0b11 == 0b11;
    let header = 24 + if addr4 { 6 } else { 0 } + if qos { 2 } else { 0 };
    if frame.len() < header + HEADER_LEN + MIC_LEN {
        return Err(Refused::Short);
    }
    if frame[1] & 0b0100_0000 == 0 {
        return Err(Refused::NotProtected);
    }
    let tid = if qos { frame[header - 2] & 0x0f } else { 0 };
    Ok(Layout {
        header,
        qos,
        addr4,
        tid,
    })
}

/// The additional authenticated data (12.5.3.3.3): the header's fields, with
/// the ones that may legitimately change on the way masked out -- the
/// subtype's low bits, Retry, Power Management, More Data, the sequence
/// number (its fragment number kept) and Order on a QoS frame -- and the
/// Protected bit set. Returns its length.
fn additional_data(frame: &[u8], l: &Layout, out: &mut [u8; AAD_MAX]) -> usize {
    out[0] = frame[0] & 0b1000_1111;
    let mut flags = (frame[1] & !0b0011_1000) | 0b0100_0000;
    if l.qos {
        flags &= !0b1000_0000;
    }
    out[1] = flags;
    // A1, A2, A3
    out[2..20].copy_from_slice(&frame[4..22]);
    out[20] = frame[22] & 0x0f;
    out[21] = 0;
    let mut n = 22;
    if l.addr4 {
        out[n..n + 6].copy_from_slice(&frame[24..30]);
        n += 6;
    }
    if l.qos {
        out[n] = frame[l.header - 2] & 0x0f;
        out[n + 1] = 0;
        n += 2;
    }
    n
}

/// The nonce (12.5.3.3.4): the priority, the transmitter's address, and the
/// packet number most significant octet first. The Management bit stays
/// clear: this encapsulates data frames.
fn nonce(frame: &[u8], l: &Layout, packet_number: u64) -> [u8; 13] {
    let mut out = [0u8; 13];
    out[0] = l.tid;
    out[1..7].copy_from_slice(&frame[10..16]);
    out[7..13].copy_from_slice(&packet_number.to_be_bytes()[2..8]);
    out
}

/// The packet number out of the CCMP header already in the frame (12.5.3.2),
/// so the nonce and the wire carry the same one.
fn packet_number(header: &[u8]) -> u64 {
    u64::from_le_bytes([
        header[0], header[1], header[4], header[5], header[6], header[7], 0, 0,
    ])
}

fn encrypt_block(key: &Aes128, block: &mut [u8; BLOCK]) {
    key.encrypt_block(GenericArray::from_mut_slice(block));
}

/// One CBC-MAC step: the running value against a block, then encrypted.
fn chain(key: &Aes128, x: &mut [u8; BLOCK], block: &[u8; BLOCK]) {
    for (a, b) in x.iter_mut().zip(block) {
        *a ^= b;
    }
    encrypt_block(key, x);
}

/// CCM (RFC 3610) with AES-128, M = 8, L = 2: `body` encrypted in place and
/// the MIC written to `mic`.
fn ccm(key: &Aes128, nonce: &[u8; 13], aad: &[u8], body: &mut [u8], mic: &mut [u8]) {
    // B0: the flags (AAD present, M = 8, L = 2), the nonce, the body's length
    let mut x = [0u8; BLOCK];
    x[0] = 0x59;
    x[1..14].copy_from_slice(nonce);
    x[14..16].copy_from_slice(&(body.len() as u16).to_be_bytes());
    encrypt_block(key, &mut x);

    // the AAD, its length first, zero padded to a block (it is always short
    // enough for the two-octet length)
    let mut block = [0u8; BLOCK];
    block[..2].copy_from_slice(&(aad.len() as u16).to_be_bytes());
    let first = aad.len().min(BLOCK - 2);
    block[2..2 + first].copy_from_slice(&aad[..first]);
    chain(key, &mut x, &block);
    for rest in aad[first..].chunks(BLOCK) {
        block = [0u8; BLOCK];
        block[..rest.len()].copy_from_slice(rest);
        chain(key, &mut x, &block);
    }

    // the body, zero padded
    for part in body.chunks(BLOCK) {
        block = [0u8; BLOCK];
        block[..part.len()].copy_from_slice(part);
        chain(key, &mut x, &block);
    }

    // the counter blocks: the first encrypts the MIC, the rest the body
    let mut counter = [0u8; BLOCK];
    counter[0] = 0x01;
    counter[1..14].copy_from_slice(nonce);
    let mut first_block = counter;
    encrypt_block(key, &mut first_block);
    for (i, part) in body.chunks_mut(BLOCK).enumerate() {
        let mut s = counter;
        s[14..16].copy_from_slice(&(i as u16 + 1).to_be_bytes());
        encrypt_block(key, &mut s);
        for (b, k) in part.iter_mut().zip(s) {
            *b ^= k;
        }
    }
    for (i, m) in mic.iter_mut().enumerate().take(MIC_LEN) {
        *m = x[i] ^ first_block[i];
    }
}

/// Encrypt a built frame in place.
///
/// `frame` is the whole MPDU: the MAC header, the CCMP header with its packet
/// number and key id already written, the body in the clear, and [`MIC_LEN`]
/// octets of room at the end. On return the body is ciphertext and those
/// octets hold the MIC, so the frame can be transmitted naming no key slot.
pub fn encapsulate(frame: &mut [u8], temporal_key: &[u8; 16]) -> Result<(), Refused> {
    let l = layout(frame)?;
    let body_len = frame.len() - l.header - HEADER_LEN - MIC_LEN;
    if body_len > u16::MAX as usize {
        return Err(Refused::TooLong);
    }
    let mut aad = [0u8; AAD_MAX];
    let aad_len = additional_data(frame, &l, &mut aad);
    let pn = packet_number(&frame[l.header..l.header + HEADER_LEN]);
    let nonce = nonce(frame, &l, pn);
    let key = Aes128::new(GenericArray::from_slice(temporal_key));
    let (_, body_and_mic) = frame.split_at_mut(l.header + HEADER_LEN);
    let (body, mic) = body_and_mic.split_at_mut(body_len);
    ccm(&key, &nonce, &aad[..aad_len], body, mic);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: usize = 40;
    /// The widest frame these build: a QoS header, the CCMP header, the body
    /// and the MIC.
    const MAX: usize = 26 + HEADER_LEN + BODY + MIC_LEN;

    /// A frame as the access point builds one, and its length.
    fn frame(qos: bool, body: &[u8], pn: u64) -> ([u8; MAX], usize) {
        let mut f = [0u8; MAX];
        f[0] = if qos { 0x88 } else { 0x08 };
        f[1] = 0x02 | 0x40; // From DS, Protected
        f[4..10].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x51]); // A1, the station
        f[10..16].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xa1]); // A2, the access point
        f[16..22].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x03]); // A3
        f[22..24].copy_from_slice(&[0x30, 0x00]); // sequence 3, fragment 0
        let header = if qos {
            f[24..26].copy_from_slice(&[0x06, 0x00]); // TID 6
            26
        } else {
            24
        };
        let pn = pn.to_le_bytes();
        f[header..header + HEADER_LEN]
            .copy_from_slice(&[pn[0], pn[1], 0, 0x20, pn[2], pn[3], pn[4], pn[5]]);
        f[header + HEADER_LEN..header + HEADER_LEN + body.len()].copy_from_slice(body);
        (f, header + HEADER_LEN + body.len() + MIC_LEN)
    }

    fn body() -> [u8; BODY] {
        let mut b = [0u8; BODY];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        b
    }

    #[test]
    fn the_layout_is_read_from_the_frame() {
        let (f, n) = frame(false, &body(), 1);
        let l = layout(&f[..n]).unwrap();
        assert_eq!((l.header, l.qos, l.addr4, l.tid), (24, false, false, 0));
        let (f, n) = frame(true, &body(), 1);
        let l = layout(&f[..n]).unwrap();
        assert_eq!((l.header, l.qos, l.addr4, l.tid), (26, true, false, 6));
    }

    #[test]
    fn a_frame_that_would_not_be_decrypted_is_refused() {
        let (mut f, n) = frame(false, &body(), 1);
        f[1] &= !0x40; // the Protected bit clear
        assert_eq!(
            encapsulate(&mut f[..n], &[0; 16]),
            Err(Refused::NotProtected)
        );
        let (mut f, n) = frame(false, &body(), 1);
        f[0] = 0x00; // a management frame
        assert_eq!(encapsulate(&mut f[..n], &[0; 16]), Err(Refused::NotData));
        let (mut f, _) = frame(false, &body(), 1);
        assert_eq!(encapsulate(&mut f[..30], &[0; 16]), Err(Refused::Short));
    }

    /// The masks of 12.5.3.3.3: a field the standard says to mask must not
    /// change the AAD, and one it does not must change it.
    #[test]
    fn the_aad_masks_what_may_change_on_the_way() {
        let (base, n) = frame(true, &body(), 1);
        let aad_of = |f: &[u8]| {
            let l = layout(f).unwrap();
            let mut out = [0u8; AAD_MAX];
            let len = additional_data(f, &l, &mut out);
            (out, len)
        };
        let (want, want_len) = aad_of(&base[..n]);
        assert_eq!(want_len, 24); // 22 and the QoS Control
        for (byte, mask, masked) in [
            (1usize, 0b0000_1000u8, true), // Retry
            (1, 0b0001_0000, true),        // Power Management
            (1, 0b0010_0000, true),        // More Data
            (1, 0b1000_0000, true),        // Order, on a QoS frame
            (0, 0b0001_0000, true),        // a subtype bit
            (22, 0xf0, true),              // the sequence number
            (1, 0b0000_0010, false),       // From DS
            (22, 0x0f, false),             // the fragment number
        ] {
            let mut f = base;
            f[byte] ^= mask;
            let (got, got_len) = aad_of(&f[..n]);
            assert_eq!(
                got[..got_len] == want[..want_len],
                masked,
                "byte {byte} mask {mask:#010b} should {} the AAD",
                if masked { "not change" } else { "change" }
            );
        }
    }

    /// The body is encrypted (it does not go out in the clear), the MIC is
    /// written, and both answer to the key, the packet number and the header.
    #[test]
    fn encapsulation_hides_the_body_and_answers_to_what_is_authenticated() {
        let key = [0x42u8; 16];
        let out = |k: &[u8; 16], pn: u64, mangle: fn(&mut [u8; MAX])| {
            let (mut f, n) = frame(false, &body(), pn);
            mangle(&mut f);
            encapsulate(&mut f[..n], k).unwrap();
            (f, n)
        };
        let (base, n) = out(&key, 1, |_| {});
        assert_eq!(n, 80);
        assert_ne!(
            base[32..72],
            body(),
            "the body must not go out in the clear"
        );
        assert_ne!(base[72..80], [0u8; MIC_LEN], "the MIC must be written");
        assert_ne!(base, out(&[0x43; 16], 1, |_| {}).0, "another key");
        assert_ne!(base, out(&key, 2, |_| {}).0, "another packet number");
        // A1 is authenticated, so the MIC must answer to it
        let other = out(&key, 1, |f| f[4] = 0x06).0;
        assert_ne!(base[72..80], other[72..80], "the MIC covers A1");
    }

    /// The IEEE 802.11-2012 M.6.4 CCMP test vector (also hostap's
    /// `wlantest/test_vectors.c`): a non-QoS data frame, its 24-byte header,
    /// its CCMP header carrying PN `0x0CE77697 03B5` and key id 0, and the
    /// plaintext body. The whole MPDU is built the way the access point
    /// builds one, then encapsulated. Its nonce and additional data were read
    /// field by field against hostap's `ccmp_aad_nonce` and match exactly
    /// (FC masks, seq-number masking with the fragment kept, the PN byte
    /// order in both the header and the nonce); the interop test
    /// (`host-tests/air/tests/ccmp.rs`) checks the ciphertext itself against
    /// OpenSSL. Here: the standard's own frame encapsulates without refusal,
    /// the body is hidden and a MIC is written.
    #[test]
    fn the_standard_test_vector_encapsulates() {
        let tk = [
            0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85, 0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd,
            0xd5, 0x2f,
        ];
        // the header, the CCMP header (PN0=0xB5,PN1=0x03, key id 0 + Ext IV,
        // PN2..PN5 = 0x97,0x76,0xE7,0x0C), the plaintext, and room for the MIC
        let header = [
            0x08, 0x48, 0xc3, 0x2c, 0x0f, 0xd2, 0xe1, 0x28, 0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84,
            0x44, 0x08, 0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0x80, 0x33,
        ];
        let ccmp = [0xB5, 0x03, 0x00, 0x20, 0x97, 0x76, 0xE7, 0x0C];
        let body = [
            0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f, 0x85, 0xae, 0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd,
            0xa8, 0xeb, 0x7e, 0x78, 0xa0, 0x50,
        ];
        let mut f = [0u8; 24 + 8 + 20 + MIC_LEN];
        f[..24].copy_from_slice(&header);
        f[24..32].copy_from_slice(&ccmp);
        f[32..52].copy_from_slice(&body);
        encapsulate(&mut f, &tk).expect("the standard's frame encapsulates");
        assert_ne!(f[32..52], body, "the body is hidden");
        assert_ne!(f[52..], [0u8; MIC_LEN], "a MIC is written");
        // the header and CCMP header are left as they were
        assert_eq!(f[..24], header);
        assert_eq!(f[24..32], ccmp);
    }
}

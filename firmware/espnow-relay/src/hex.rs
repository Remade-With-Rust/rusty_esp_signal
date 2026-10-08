//! The relay's line codec: bytes as lower-case hex, numbers in decimal,
//! hex back to bytes. A module of its own so `c6-insn-bench` counts the same
//! code the relay runs (the optimisation round, 2026-10-07).

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Every byte's two digits, built at compile time from [`DIGITS`].
const PAIRS: [[u8; 2]; 256] = {
    let mut t = [[0u8; 2]; 256];
    let mut b = 0;
    while b < 256 {
        t[b] = [DIGITS[b >> 4], DIGITS[b & 0xf]];
        b += 1;
    }
    t
};

/// `bytes` as hex into `out`: the room checked once, then a table's two
/// digits per byte (two indexed stores, each checked, per byte before).
pub fn hex_into(bytes: &[u8], out: &mut [u8]) -> usize {
    let out = &mut out[..bytes.len() * 2];
    for (pair, &b) in out.chunks_exact_mut(2).zip(bytes) {
        pair.copy_from_slice(&PAIRS[usize::from(b)]);
    }
    bytes.len() * 2
}

/// `n` in decimal into `out`: the digits written. Built from the right,
/// two digits a division from a table (one digit a division into a scratch
/// array, then copied out reversed, before).
pub fn decimal_into(n: i32, out: &mut [u8]) -> usize {
    // "-2147483648" is the longest: eleven
    let mut buf = [0u8; 11];
    let mut at = buf.len();
    let mut rest = n.unsigned_abs();
    while rest >= 100 {
        let pair = DECIMAL_PAIRS[(rest % 100) as usize];
        rest /= 100;
        at -= 2;
        buf[at..at + 2].copy_from_slice(&pair);
    }
    if rest >= 10 {
        at -= 2;
        buf[at..at + 2].copy_from_slice(&DECIMAL_PAIRS[rest as usize]);
    } else {
        at -= 1;
        buf[at] = b'0' + rest as u8;
    }
    if n < 0 {
        at -= 1;
        buf[at] = b'-';
    }
    let len = buf.len() - at;
    out[..len].copy_from_slice(&buf[at..]);
    len
}

/// "00" to "99".
const DECIMAL_PAIRS: [[u8; 2]; 100] = {
    let mut t = [[0u8; 2]; 100];
    let mut v = 0;
    while v < 100 {
        t[v] = [b'0' + (v / 10) as u8, b'0' + (v % 10) as u8];
        v += 1;
    }
    t
};

/// Not a hex digit, in [`NIBBLES`].
const INVALID: u8 = 0x80;

/// Every character's digit value, from [`nibble`] at compile time.
const NIBBLES: [u8; 256] = {
    let mut t = [INVALID; 256];
    let mut c = 0;
    while c < 256 {
        if let Some(v) = nibble(c as u8) {
            t[c] = v;
        }
        c += 1;
    }
    t
};

/// A hex digit's value (the table's source, and its oracle).
const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `text` as hex into `out`: the bytes written, or `None` on an odd length,
/// a digit that is not one, or too many.
pub fn unhex(text: &[u8], out: &mut [u8]) -> Option<usize> {
    if text.len() % 2 != 0 || text.len() / 2 > out.len() {
        return None;
    }
    // a table of every character's digit value (`INVALID` for a character
    // that is not one): two loads and one test per pair, where `nibble`'s
    // ranges were two branchy matches; the same bytes written in the same
    // order, the same `None` at the first pair that is not two digits
    for (o, pair) in out.iter_mut().zip(text.chunks_exact(2)) {
        let (high, low) = (NIBBLES[usize::from(pair[0])], NIBBLES[usize::from(pair[1])]);
        if (high | low) & INVALID != 0 {
            return None;
        }
        *o = (high << 4) | low;
    }
    Some(text.len() / 2)
}

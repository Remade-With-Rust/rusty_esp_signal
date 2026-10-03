//! The setup code (protocol section 3.1): ten symbols of Crockford base32,
//! 50 bits, shown as `XXXXX-XXXXX`.

use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::Rng;
use zeroize::Zeroize;

/// Symbols in a code.
pub const CODE_SYMBOLS: usize = 10;

/// The code's display form, `XXXXX-XXXXX`, in bytes.
pub const DISPLAY_LEN: usize = CODE_SYMBOLS + 1;

/// Crockford's base32 alphabet: no `I`, `L`, `O` or `U`.
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A setup code, normalised: the ten ASCII symbols the protocol calls `pw`.
/// Never printed by `Debug`; zeroised on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    pw: [u8; CODE_SYMBOLS],
}

impl Code {
    /// A code as a person typed it. Hyphens and spaces are dropped, letters
    /// uppercased, `O` read as `0` and `I`, `L` as `1`; anything else
    /// outside the alphabet, or a count other than ten symbols, is
    /// `InvalidFormat`.
    pub fn parse(typed: &str) -> Result<Self> {
        let mut pw = [0u8; CODE_SYMBOLS];
        let mut count = 0;
        for &byte in typed.as_bytes() {
            if byte == b'-' || byte == b' ' {
                continue;
            }
            let symbol = match byte.to_ascii_uppercase() {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                other => other,
            };
            if !ALPHABET.contains(&symbol) {
                pw.zeroize();
                return Err(Error::InvalidFormat);
            }
            if count == CODE_SYMBOLS {
                pw.zeroize();
                return Err(Error::InvalidFormat);
            }
            pw[count] = symbol;
            count += 1;
        }
        if count != CODE_SYMBOLS {
            pw.zeroize();
            return Err(Error::InvalidFormat);
        }
        Ok(Code { pw })
    }

    /// The code whose 50 bits are the low 50 of `bits`, most significant
    /// symbol first.
    #[must_use]
    pub fn from_bits(bits: u64) -> Self {
        let mut pw = [0u8; CODE_SYMBOLS];
        for (i, slot) in pw.iter_mut().enumerate() {
            let shift = 5 * (CODE_SYMBOLS - 1 - i);
            *slot = ALPHABET[((bits >> shift) & 0x1F) as usize];
        }
        Code { pw }
    }

    /// A fresh code: 50 bits from `rng`, every value valid.
    pub fn generate(rng: &mut impl Rng) -> Result<Self> {
        let mut raw = [0u8; 8];
        rng.fill(&mut raw)?;
        let bits = u64::from_le_bytes(raw);
        raw.zeroize();
        Ok(Self::from_bits(bits))
    }

    /// The normalised symbols, the protocol's `pw`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CODE_SYMBOLS] {
        &self.pw
    }

    /// The display form, `XXXXX-XXXXX`, as ASCII.
    #[must_use]
    pub fn display(&self) -> [u8; DISPLAY_LEN] {
        let mut out = [b'-'; DISPLAY_LEN];
        out[..5].copy_from_slice(&self.pw[..5]);
        out[6..].copy_from_slice(&self.pw[5..]);
        out
    }
}

impl core::fmt::Debug for Code {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Code(<redacted>)")
    }
}

impl Drop for Code {
    fn drop(&mut self) {
        self.pw.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_reads_what_people_type() {
        let want = Code::parse("7KXQ3M9PRT").unwrap();
        for typed in [
            "7kxq3-m9prt",
            "7KXQ3 M9PRT",
            " 7kxq3m9prt ",
            "7-K-X-Q-3-M-9-P-R-T",
        ] {
            assert_eq!(Code::parse(typed).unwrap(), want, "{typed}");
        }
        // the look-alikes Crockford leaves out
        assert_eq!(
            Code::parse("O0IL1-ABCDE").unwrap(),
            Code::parse("00111-ABCDE").unwrap()
        );
        assert_eq!(
            Code::parse("oil11-abcde").unwrap(),
            Code::parse("01111-ABCDE").unwrap()
        );
    }

    #[test]
    fn refusals() {
        for bad in [
            "",
            "7KXQ3",
            "7KXQ3-M9PR",
            "7KXQ3-M9PRTX",
            "7KXQ3-M9PRU",
            "7KXQ3_M9PRT",
            "7KXQ3-M9PR\u{e9}",
        ] {
            assert_eq!(Code::parse(bad), Err(Error::InvalidFormat), "{bad:?}");
        }
    }

    #[test]
    fn display_and_bits_round_trip() {
        for bits in [0u64, 1, (1 << 50) - 1, 0x2A5_5AA5_5AA5, u64::MAX] {
            let code = Code::from_bits(bits);
            let shown = code.display();
            let again = Code::parse(core::str::from_utf8(&shown).unwrap()).unwrap();
            assert_eq!(again, code);
            assert_eq!(shown[5], b'-');
        }
        assert_eq!(&Code::from_bits(0).display(), b"00000-00000");
        assert_eq!(&Code::from_bits((1 << 50) - 1).display(), b"ZZZZZ-ZZZZZ");
    }

    #[test]
    fn debug_never_shows_the_code() {
        let code = Code::parse("7KXQ3-M9PRT").unwrap();
        let shown = std::format!("{code:?}");
        assert!(!shown.contains("7KXQ3"));
    }
}

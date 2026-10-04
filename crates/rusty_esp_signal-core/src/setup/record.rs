//! The settings record (protocol section 7): `u8 tag || u16be len || value`,
//! the fields `espino_nvs::janus` writes over USB plus a new verifier and an
//! adoption. Decoded borrowed, validated whole before anything is applied.

use rusty_esp_core::error::{Error, Result};
use rusty_esp_mid_core::adoption::Adoption;
use rusty_esp_mid_core::did::Did;

use super::message::ResultCode;
use super::{SETUP_V_LEN, Verifier};
use crate::wifi::{Credentials, TAG_PSK, TAG_SSID};

/// The record's tags.
pub mod tag {
    /// The network's name (`wifi.ssid`), 1-32 bytes.
    pub const SSID: u8 = super::TAG_SSID;
    /// Its passphrase (`wifi.psk`), 8-63 bytes.
    pub const PSK: u8 = super::TAG_PSK;
    /// The device's name (`name`), UTF-8, 1-64 bytes.
    pub const NAME: u8 = 0x03;
    /// The maker (`maker`), a `did:mata`.
    pub const MAKER: u8 = 0x04;
    /// `blink_ms`, `u32be`.
    pub const BLINK_MS: u8 = 0x05;
    /// `fps`, one byte.
    pub const FPS: u8 = 0x06;
    /// A new verifier (`setup.v`, 118 bytes): rotates the code.
    pub const SETUP_V: u8 = 0x10;
    /// An adoption, mID's wire bytes.
    pub const ADOPTION: u8 = 0x11;
}

/// The longest device name.
pub const NAME_MAX_LEN: usize = 64;

/// The longest passphrase the record carries (WPA2 passphrases; a 64-digit
/// raw key is not offered here).
pub const PSK_MAX_LEN: usize = 63;

/// A settings record, borrowed from the opened Settings message, each
/// field checked on its own. What needs the device's state (an adoption
/// against the pinned owner) is the device session's check.
#[derive(Debug, Default)]
pub struct Record<'a> {
    /// The network to join.
    pub network: Option<Credentials>,
    /// The device's name.
    pub name: Option<&'a str>,
    /// The maker's `did:mata`.
    pub maker: Option<&'a str>,
    /// `blink_ms`.
    pub blink_ms: Option<u32>,
    /// `fps`.
    pub fps: Option<u8>,
    /// A new verifier, its 118 bytes.
    pub setup_v: Option<&'a [u8]>,
    /// An adoption, its wire bytes.
    pub adoption: Option<&'a [u8]>,
}

impl<'a> Record<'a> {
    /// Decodes and checks a record; a refusal is the code Result carries.
    /// Nothing is applied by decoding.
    pub fn decode(bytes: &'a [u8]) -> core::result::Result<Self, ResultCode> {
        let mut record = Record::default();
        let mut seen = 0u32;
        let (mut ssid, mut psk): (Option<&[u8]>, Option<&[u8]>) = (None, None);
        let mut rest = bytes;
        while !rest.is_empty() {
            if rest.len() < 3 {
                return Err(ResultCode::Malformed);
            }
            let t = rest[0];
            let len = usize::from(u16::from_be_bytes([rest[1], rest[2]]));
            let Some(value) = rest.get(3..3 + len) else {
                return Err(ResultCode::Malformed);
            };
            rest = &rest[3 + len..];
            let bit = match t {
                tag::SSID => 0,
                tag::PSK => 1,
                tag::NAME => 2,
                tag::MAKER => 3,
                tag::BLINK_MS => 4,
                tag::FPS => 5,
                tag::SETUP_V => 6,
                tag::ADOPTION => 7,
                _ => return Err(ResultCode::UnknownTag),
            };
            if seen & (1 << bit) != 0 {
                return Err(ResultCode::UnknownTag);
            }
            seen |= 1 << bit;
            match t {
                tag::SSID => ssid = Some(value),
                tag::PSK => psk = Some(value),
                tag::NAME => {
                    let name = core::str::from_utf8(value).map_err(|_| ResultCode::BadName)?;
                    if name.is_empty()
                        || name.len() > NAME_MAX_LEN
                        || name.chars().any(char::is_control)
                    {
                        return Err(ResultCode::BadName);
                    }
                    record.name = Some(name);
                }
                tag::MAKER => {
                    let maker = core::str::from_utf8(value).map_err(|_| ResultCode::BadMaker)?;
                    Did::parse(maker).map_err(|_| ResultCode::BadMaker)?;
                    record.maker = Some(maker);
                }
                tag::BLINK_MS => {
                    let v: [u8; 4] = value.try_into().map_err(|_| ResultCode::Malformed)?;
                    record.blink_ms = Some(u32::from_be_bytes(v));
                }
                tag::FPS => {
                    let [v] = value else {
                        return Err(ResultCode::Malformed);
                    };
                    record.fps = Some(*v);
                }
                tag::SETUP_V => {
                    if value.len() != SETUP_V_LEN || Verifier::decode(value).is_err() {
                        return Err(ResultCode::BadVerifier);
                    }
                    record.setup_v = Some(value);
                }
                _ => {
                    Adoption::decode(value).map_err(|_| ResultCode::BadAdoption)?;
                    record.adoption = Some(value);
                }
            }
        }
        match (ssid, psk) {
            (None, None) => {}
            (Some(s), Some(p)) => {
                if p.len() > PSK_MAX_LEN {
                    return Err(ResultCode::BadNetwork);
                }
                record.network = Some(Credentials::new(s, p).map_err(|_| ResultCode::BadNetwork)?);
            }
            _ => return Err(ResultCode::BadNetwork),
        }
        Ok(record)
    }
}

/// Builds a settings record into a buffer: the browser's half.
pub struct RecordWriter<'b> {
    buf: &'b mut [u8],
    len: usize,
}

impl<'b> RecordWriter<'b> {
    /// A writer over `buf`.
    pub fn new(buf: &'b mut [u8]) -> Self {
        RecordWriter { buf, len: 0 }
    }

    fn push(&mut self, t: u8, value: &[u8]) -> Result<&mut Self> {
        let len = u16::try_from(value.len()).map_err(|_| Error::InvalidFormat)?;
        let needed = self.len + 3 + value.len();
        if needed > self.buf.len() {
            return Err(Error::BufferTooSmall { needed });
        }
        self.buf[self.len] = t;
        self.buf[self.len + 1..self.len + 3].copy_from_slice(&len.to_be_bytes());
        self.buf[self.len + 3..needed].copy_from_slice(value);
        self.len = needed;
        Ok(self)
    }

    /// The network: its name and passphrase together.
    pub fn network(&mut self, ssid: &[u8], psk: &[u8]) -> Result<&mut Self> {
        self.push(tag::SSID, ssid)?.push(tag::PSK, psk)
    }

    /// The device's name.
    pub fn name(&mut self, name: &str) -> Result<&mut Self> {
        self.push(tag::NAME, name.as_bytes())
    }

    /// The maker's `did:mata`.
    pub fn maker(&mut self, did: &str) -> Result<&mut Self> {
        self.push(tag::MAKER, did.as_bytes())
    }

    /// `blink_ms`.
    pub fn blink_ms(&mut self, ms: u32) -> Result<&mut Self> {
        self.push(tag::BLINK_MS, &ms.to_be_bytes())
    }

    /// `fps`.
    pub fn fps(&mut self, fps: u8) -> Result<&mut Self> {
        self.push(tag::FPS, &[fps])
    }

    /// A new verifier: the next session takes the new code.
    pub fn setup_v(&mut self, record: &[u8; SETUP_V_LEN]) -> Result<&mut Self> {
        self.push(tag::SETUP_V, record)
    }

    /// An adoption, mID's wire bytes.
    pub fn adoption(&mut self, bytes: &[u8]) -> Result<&mut Self> {
        self.push(tag::ADOPTION, bytes)
    }

    /// The record's length so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

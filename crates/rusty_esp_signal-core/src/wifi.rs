//! Wi-Fi station credentials that never print, the TLV they travel in over
//! BLE provisioning, the station reconnect policy and RSSI statistics.
//!
//! No driver here: a backend feeds [`StationPolicy::on`] the events its
//! Wi-Fi stack raises and executes the [`Action`] it gets back. The
//! credential rules are IEEE 802.11-2020 Annex J (WPA passphrase and raw
//! PSK) and §9.4.2.2 (SSID length).

use core::fmt;

use rusty_esp_core::Micros;
use rusty_esp_core::error::{Error, Result};
use zeroize::Zeroize;

/// Longest SSID, bytes (IEEE 802.11-2020 §9.4.2.2: 0..=32 octets; the empty
/// wildcard is not a network you can join, so Janus requires at least one).
pub const SSID_MAX_LEN: usize = 32;
/// Shortest WPA passphrase, characters (802.11-2020 Annex J.4.1).
pub const PASSPHRASE_MIN_LEN: usize = 8;
/// Longest WPA passphrase, characters (Annex J.4.1).
pub const PASSPHRASE_MAX_LEN: usize = 63;
/// A raw 256-bit PSK as hex: exactly 64 characters.
pub const RAW_PSK_HEX_LEN: usize = 64;

/// TLV tag of the SSID in the provisioning write.
pub const TAG_SSID: u8 = 1;
/// TLV tag of the passphrase or raw PSK in the provisioning write.
pub const TAG_PSK: u8 = 2;
/// Longest [`Credentials::encode`] output: `2 + 32 + 2 + 64` — the size of
/// the BLE `credentials` characteristic.
pub const MAX_ENCODED_LEN: usize = 2 + SSID_MAX_LEN + 2 + RAW_PSK_HEX_LEN;

/// What the `psk` field of a [`Credentials`] holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PskKind {
    /// No key: an open network.
    Open,
    /// 8..=63 printable ASCII characters (0x20..=0x7E), to be run through
    /// PBKDF2-HMAC-SHA1 with the SSID as salt (Annex J.4.1).
    Passphrase,
    /// The 256-bit PSK itself, as 64 hexadecimal characters.
    RawPsk,
}

/// A station's network name and secret, in fixed storage.
///
/// The secret is wiped on drop and never appears in [`fmt::Debug`] output.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    ssid: [u8; SSID_MAX_LEN],
    ssid_len: u8,
    psk: [u8; RAW_PSK_HEX_LEN],
    psk_len: u8,
}

impl Credentials {
    /// Validate and store.
    ///
    /// `ssid` must be 1..=32 bytes. `psk` must be empty (open network),
    /// 8..=63 bytes of printable ASCII (a passphrase), or exactly 64 hex
    /// digits (a raw PSK). Anything else is `InvalidFormat`.
    pub fn new(ssid: &[u8], psk: &[u8]) -> Result<Self> {
        if ssid.is_empty() || ssid.len() > SSID_MAX_LEN {
            return Err(Error::InvalidFormat);
        }
        Self::classify(psk)?;
        let mut creds = Credentials {
            ssid: [0; SSID_MAX_LEN],
            ssid_len: u8::try_from(ssid.len()).map_err(|_| Error::InvalidFormat)?,
            psk: [0; RAW_PSK_HEX_LEN],
            psk_len: u8::try_from(psk.len()).map_err(|_| Error::InvalidFormat)?,
        };
        if let Some(dst) = creds.ssid.get_mut(..ssid.len()) {
            dst.copy_from_slice(ssid);
        }
        if let Some(dst) = creds.psk.get_mut(..psk.len()) {
            dst.copy_from_slice(psk);
        }
        Ok(creds)
    }

    /// The [`PskKind`] of a candidate secret, or `InvalidFormat`.
    fn classify(psk: &[u8]) -> Result<PskKind> {
        match psk.len() {
            0 => Ok(PskKind::Open),
            PASSPHRASE_MIN_LEN..=PASSPHRASE_MAX_LEN => {
                if psk.iter().all(|b| (0x20..=0x7E).contains(b)) {
                    Ok(PskKind::Passphrase)
                } else {
                    Err(Error::InvalidFormat)
                }
            }
            RAW_PSK_HEX_LEN => {
                if psk.iter().all(u8::is_ascii_hexdigit) {
                    Ok(PskKind::RawPsk)
                } else {
                    Err(Error::InvalidFormat)
                }
            }
            _ => Err(Error::InvalidFormat),
        }
    }

    /// The network name, 1..=32 bytes (not necessarily UTF-8).
    #[must_use]
    pub fn ssid(&self) -> &[u8] {
        self.ssid.get(..usize::from(self.ssid_len)).unwrap_or(&[])
    }

    /// The secret: empty, the passphrase, or 64 hex digits.
    #[must_use]
    pub fn psk(&self) -> &[u8] {
        self.psk.get(..usize::from(self.psk_len)).unwrap_or(&[])
    }

    /// What [`Self::psk`] holds.
    #[must_use]
    pub fn kind(&self) -> PskKind {
        match usize::from(self.psk_len) {
            0 => PskKind::Open,
            RAW_PSK_HEX_LEN => PskKind::RawPsk,
            _ => PskKind::Passphrase,
        }
    }

    /// `true` when there is no secret.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.psk_len == 0
    }

    /// Bytes [`Self::encode`] will write: `4 + ssid + psk`.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        4 + usize::from(self.ssid_len) + usize::from(self.psk_len)
    }

    /// Write the provisioning TLV: `01 len ssid  02 len psk` (the PSK
    /// entry is present with length 0 for an open network). Returns the
    /// bytes written, at most [`MAX_ENCODED_LEN`].
    ///
    /// `BufferTooSmall { needed }` when `out` is shorter.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let needed = self.encoded_len();
        let Some(out) = out.get_mut(..needed) else {
            return Err(Error::BufferTooSmall { needed });
        };
        let (ssid_tlv, psk_tlv) = out.split_at_mut(2 + usize::from(self.ssid_len));
        write_tlv(ssid_tlv, TAG_SSID, self.ssid());
        write_tlv(psk_tlv, TAG_PSK, self.psk());
        Ok(needed)
    }

    /// Parse a provisioning TLV write.
    ///
    /// Entries are `tag(1) len(1) value(len)`. Unknown tags are skipped.
    /// `InvalidFormat` for a truncated entry, a repeated SSID or PSK tag, a
    /// missing SSID, or values that fail [`Self::new`]. A missing PSK tag
    /// means an open network.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut ssid: Option<&[u8]> = None;
        let mut psk: Option<&[u8]> = None;
        let mut rest = bytes;
        while let Some((&tag, after_tag)) = rest.split_first() {
            let Some((&len, after_len)) = after_tag.split_first() else {
                return Err(Error::InvalidFormat);
            };
            let Some((value, tail)) = after_len.split_at_checked(usize::from(len)) else {
                return Err(Error::InvalidFormat);
            };
            rest = tail;
            let slot = match tag {
                TAG_SSID => &mut ssid,
                TAG_PSK => &mut psk,
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(Error::InvalidFormat);
            }
        }
        let ssid = ssid.ok_or(Error::InvalidFormat)?;
        Self::new(ssid, psk.unwrap_or(&[]))
    }
}

/// Write one `tag len value` entry; `out` must be exactly `2 + value.len()`.
fn write_tlv(out: &mut [u8], tag: u8, value: &[u8]) {
    let Some((t, rest)) = out.split_first_mut() else {
        return;
    };
    let Some((l, body)) = rest.split_first_mut() else {
        return;
    };
    *t = tag;
    *l = u8::try_from(value.len()).unwrap_or(u8::MAX);
    if let Some(dst) = body.get_mut(..value.len()) {
        dst.copy_from_slice(value);
    }
}

impl Drop for Credentials {
    /// The passphrase (and, for good measure, the SSID) leave memory with
    /// the value: `zeroize` writes are not optimised away.
    fn drop(&mut self) {
        self.psk.zeroize();
        self.psk_len.zeroize();
        self.ssid.zeroize();
        self.ssid_len.zeroize();
    }
}

/// Prints `<redacted>` in place of a secret.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Debug for Credentials {
    /// `Credentials { ssid: "...", psk: <redacted> }` — the secret is never
    /// formatted, whatever the flags.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Credentials");
        match core::str::from_utf8(self.ssid()) {
            Ok(text) => d.field("ssid", &text),
            Err(_) => d.field("ssid", &self.ssid()),
        };
        d.field("psk", &Redacted).finish()
    }
}

/// Where the station is. The discriminant is what the BLE `status`
/// characteristic carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Phase {
    /// No credentials yet.
    #[default]
    Unprovisioned = 0,
    /// A join is in flight.
    Connecting = 1,
    /// Associated and authenticated.
    Connected = 2,
    /// Waiting out an exponential delay before the next attempt.
    Backoff = 3,
    /// Gave up after [`PolicyConfig::max_failures`]; provisioning is open
    /// again until new credentials arrive.
    Fallback = 4,
}

impl Phase {
    /// The wire value (the discriminant).
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The phase with wire value `v`, if any.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Phase::Unprovisioned),
            1 => Some(Phase::Connecting),
            2 => Some(Phase::Connected),
            3 => Some(Phase::Backoff),
            4 => Some(Phase::Fallback),
            _ => None,
        }
    }
}

/// What the Wi-Fi stack (or the clock) tells the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Event {
    /// Credentials arrived (BLE write, NVS restore, a new set while joined).
    Provisioned,
    /// The join succeeded.
    Connected,
    /// The join failed or the link dropped.
    Disconnected,
    /// Time passed; only [`Phase::Backoff`] cares.
    Tick,
}

/// What the backend must do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    /// Start a join with the stored credentials.
    Connect,
    /// Do nothing for this long, then send [`Event::Tick`].
    Wait(Micros),
    /// Open the BLE provisioning service.
    StartProvisioning,
    /// Nothing.
    None,
}

/// Tunables for [`StationPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyConfig {
    /// Delay after the first failure; doubles per failure. Default 1 s.
    pub min_backoff: Micros,
    /// Ceiling on the delay. Default 60 s.
    pub max_backoff: Micros,
    /// Consecutive failures that trigger [`Phase::Fallback`]. Default 10.
    /// Zero means the very first failure falls back.
    pub max_failures: u8,
}

impl PolicyConfig {
    /// 1 s, 60 s, 10 failures.
    pub const DEFAULT: PolicyConfig = PolicyConfig {
        min_backoff: Micros::from_secs(1),
        max_backoff: Micros::from_secs(60),
        max_failures: 10,
    };
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig::DEFAULT
    }
}

/// The station's reconnect and fallback state machine.
///
/// | phase        | event        | next        | action              |
/// |--------------|--------------|-------------|---------------------|
/// | any          | Provisioned  | Connecting  | Connect (failures = 0) |
/// | any          | Connected    | Connected   | None (failures = 0) |
/// | Connecting / Connected | Disconnected, failures < max | Backoff | Wait(min * 2^(failures-1), capped at max) |
/// | Connecting / Connected | Disconnected, failures >= max | Fallback | StartProvisioning |
/// | Backoff      | Tick, elapsed | Connecting | Connect             |
/// | Backoff      | Tick, early  | Backoff     | Wait(remaining)     |
/// | other        | other        | unchanged   | None                |
#[derive(Debug, Clone)]
pub struct StationPolicy {
    cfg: PolicyConfig,
    phase: Phase,
    failures: u8,
    reconnects: u32,
    wait_until: Micros,
}

impl Default for StationPolicy {
    fn default() -> Self {
        StationPolicy::new(PolicyConfig::DEFAULT)
    }
}

impl StationPolicy {
    /// A policy in [`Phase::Unprovisioned`].
    #[must_use]
    pub const fn new(cfg: PolicyConfig) -> Self {
        StationPolicy {
            cfg,
            phase: Phase::Unprovisioned,
            failures: 0,
            reconnects: 0,
            wait_until: Micros::ZERO,
        }
    }

    /// The tunables.
    #[must_use]
    pub const fn config(&self) -> PolicyConfig {
        self.cfg
    }

    /// Current phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Consecutive failures since the last successful join.
    #[must_use]
    pub const fn failures(&self) -> u8 {
        self.failures
    }

    /// Lifetime count of `Connect` actions issued from [`Phase::Backoff`],
    /// i.e. reconnection attempts.
    #[must_use]
    pub const fn reconnects(&self) -> u32 {
        self.reconnects
    }

    /// The delay for the `failures`-th consecutive failure:
    /// `min_backoff * 2^(failures - 1)`, saturating, capped at `max_backoff`.
    #[must_use]
    pub const fn backoff_for(&self, failures: u8) -> Micros {
        let shift = failures.saturating_sub(1) as u32;
        let raw = if shift >= u64::BITS {
            u64::MAX
        } else {
            self.cfg.min_backoff.0.saturating_mul(1u64 << shift)
        };
        let capped = if raw > self.cfg.max_backoff.0 {
            self.cfg.max_backoff.0
        } else {
            raw
        };
        Micros(capped)
    }

    /// Feed one event at time `now`; returns what to do.
    pub fn on(&mut self, event: Event, now: Micros) -> Action {
        match (self.phase, event) {
            (_, Event::Provisioned) => {
                self.failures = 0;
                self.phase = Phase::Connecting;
                Action::Connect
            }
            (_, Event::Connected) => {
                self.failures = 0;
                self.phase = Phase::Connected;
                Action::None
            }
            (Phase::Connecting | Phase::Connected, Event::Disconnected) => {
                self.failures = self.failures.saturating_add(1);
                if self.failures >= self.cfg.max_failures {
                    self.phase = Phase::Fallback;
                    Action::StartProvisioning
                } else {
                    let wait = self.backoff_for(self.failures);
                    self.wait_until = now.add_micros(wait.0);
                    self.phase = Phase::Backoff;
                    Action::Wait(wait)
                }
            }
            (Phase::Backoff, Event::Tick) => {
                let remaining = self.wait_until.since(now);
                if remaining == 0 {
                    self.reconnects = self.reconnects.saturating_add(1);
                    self.phase = Phase::Connecting;
                    Action::Connect
                } else {
                    Action::Wait(Micros(remaining))
                }
            }
            _ => Action::None,
        }
    }
}

/// Integer running statistics over `i8` dBm samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RssiStats {
    count: u32,
    sum: i64,
    min: i8,
    max: i8,
}

impl RssiStats {
    /// No samples yet.
    #[must_use]
    pub const fn new() -> Self {
        RssiStats {
            count: 0,
            sum: 0,
            min: 0,
            max: 0,
        }
    }

    /// Add a sample. The count saturates at `u32::MAX`, after which the
    /// mean stops moving.
    pub fn push(&mut self, rssi_dbm: i8) {
        if self.count == 0 {
            self.min = rssi_dbm;
            self.max = rssi_dbm;
        } else {
            self.min = self.min.min(rssi_dbm);
            self.max = self.max.max(rssi_dbm);
        }
        if self.count < u32::MAX {
            self.count += 1;
            self.sum = self.sum.saturating_add(i64::from(rssi_dbm));
        }
    }

    /// Samples seen.
    #[must_use]
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Weakest sample, `None` before the first.
    #[must_use]
    pub const fn min(&self) -> Option<i8> {
        if self.count == 0 {
            None
        } else {
            Some(self.min)
        }
    }

    /// Strongest sample, `None` before the first.
    #[must_use]
    pub const fn max(&self) -> Option<i8> {
        if self.count == 0 {
            None
        } else {
            Some(self.max)
        }
    }

    /// Mean, rounded toward negative infinity (the pessimistic dBm), `None`
    /// before the first sample.
    #[must_use]
    pub fn mean(&self) -> Option<i8> {
        if self.count == 0 {
            return None;
        }
        let floor = self.sum.div_euclid(i64::from(self.count));
        i8::try_from(floor).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    /// A fixed-capacity `fmt::Write` sink, so the tests need no allocator.
    struct Sink {
        buf: [u8; 256],
        len: usize,
    }

    impl Sink {
        fn new() -> Self {
            Sink {
                buf: [0; 256],
                len: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<not utf-8>")
        }
    }

    impl Write for Sink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.len + s.len();
            let Some(dst) = self.buf.get_mut(self.len..end) else {
                return Err(fmt::Error);
            };
            dst.copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    const HEX64: &[u8; 64] = b"0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF";

    #[test]
    fn credentials_accept_the_three_shapes() {
        let open = Credentials::new(b"cafe", b"").unwrap_or_else(|_| unreachable!());
        assert!(open.is_open());
        assert_eq!(open.kind(), PskKind::Open);
        assert_eq!(open.ssid(), b"cafe");
        assert_eq!(open.psk(), b"");

        let pass = Credentials::new(b"home", b"correct horse").unwrap_or_else(|_| unreachable!());
        assert!(!pass.is_open());
        assert_eq!(pass.kind(), PskKind::Passphrase);
        assert_eq!(pass.psk(), b"correct horse");

        let raw = Credentials::new(&[0xff; 32], HEX64).unwrap_or_else(|_| unreachable!());
        assert_eq!(raw.kind(), PskKind::RawPsk);
        assert_eq!(raw.ssid().len(), 32);
        assert_eq!(raw.psk(), HEX64);
    }

    #[test]
    fn credentials_reject_the_rest() {
        let bad = |ssid: &[u8], psk: &[u8]| Credentials::new(ssid, psk).map(|_| ());
        assert_eq!(bad(b"", b""), Err(Error::InvalidFormat));
        assert_eq!(bad(&[b'x'; 33], b""), Err(Error::InvalidFormat));
        assert_eq!(bad(b"home", b"seven77"), Err(Error::InvalidFormat));
        assert_eq!(bad(b"home", &[b'p'; 64]), Err(Error::InvalidFormat));
        assert_eq!(bad(b"home", &[b'a'; 65]), Err(Error::InvalidFormat));
        assert_eq!(bad(b"home", b"tab\there!"), Err(Error::InvalidFormat));
        assert_eq!(
            bad(b"home", "pässwörd".as_bytes()),
            Err(Error::InvalidFormat)
        );
        // The boundaries themselves are legal.
        assert_eq!(bad(b"x", &[b'z'; 8]), Ok(()));
        assert_eq!(bad(b"x", &[b'z'; 63]), Ok(()));
        assert_eq!(bad(b"x", &[b' '; 8]), Ok(()));
        assert_eq!(bad(b"x", &[b'~'; 8]), Ok(()));
    }

    #[test]
    fn debug_never_shows_the_passphrase() {
        let creds = Credentials::new(b"home", b"hunter2hunter2").unwrap_or_else(|_| unreachable!());
        let mut sink = Sink::new();
        assert!(write!(sink, "{creds:?}").is_ok());
        let text = sink.as_str();
        assert_eq!(text, "Credentials { ssid: \"home\", psk: <redacted> }");
        assert!(!text.contains("hunter2"));
        let mut sink = Sink::new();
        assert!(write!(sink, "{creds:#?}").is_ok());
        assert!(!sink.as_str().contains("hunter2"));

        // A non-UTF-8 SSID is still printable.
        let raw = Credentials::new(&[0xff, 0x00], b"").unwrap_or_else(|_| unreachable!());
        let mut sink = Sink::new();
        assert!(write!(sink, "{raw:?}").is_ok());
        assert_eq!(
            sink.as_str(),
            "Credentials { ssid: [255, 0], psk: <redacted> }"
        );
    }

    #[test]
    fn tlv_round_trips_and_matches_the_vector() {
        let creds = Credentials::new(b"home", b"password").unwrap_or_else(|_| unreachable!());
        let mut out = [0u8; MAX_ENCODED_LEN];
        assert_eq!(creds.encoded_len(), 16);
        assert_eq!(creds.encode(&mut out), Ok(16));
        assert_eq!(&out[..16], b"\x01\x04home\x02\x08password");
        assert_eq!(Credentials::decode(&out[..16]), Ok(creds.clone()));
        assert_eq!(
            creds.encode(&mut out[..15]),
            Err(Error::BufferTooSmall { needed: 16 })
        );

        let open = Credentials::new(b"cafe", b"").unwrap_or_else(|_| unreachable!());
        assert_eq!(open.encode(&mut out), Ok(8));
        assert_eq!(&out[..8], b"\x01\x04cafe\x02\x00");
        assert_eq!(Credentials::decode(&out[..8]), Ok(open.clone()));
        // A missing PSK entry also means open.
        assert_eq!(Credentials::decode(b"\x01\x04cafe"), Ok(open));

        // The longest legal write fits the characteristic exactly.
        let big = Credentials::new(&[b's'; 32], HEX64).unwrap_or_else(|_| unreachable!());
        assert_eq!(big.encoded_len(), MAX_ENCODED_LEN);
        assert_eq!(big.encode(&mut out), Ok(100));
    }

    #[test]
    fn tlv_skips_unknown_tags_and_rejects_bad_input() {
        let with_extra = b"\x07\x03abc\x01\x04home\xff\x00\x02\x08password";
        let creds = Credentials::decode(with_extra).unwrap_or_else(|_| unreachable!());
        assert_eq!(creds.ssid(), b"home");
        assert_eq!(creds.psk(), b"password");

        let dup_ssid = b"\x01\x04home\x01\x04work";
        assert_eq!(Credentials::decode(dup_ssid), Err(Error::InvalidFormat));
        let dup_psk = b"\x01\x04home\x02\x08password\x02\x08password";
        assert_eq!(Credentials::decode(dup_psk), Err(Error::InvalidFormat));
        assert_eq!(
            Credentials::decode(b"\x02\x08password"),
            Err(Error::InvalidFormat)
        );
        assert_eq!(
            Credentials::decode(b"\x01\x04hom"),
            Err(Error::InvalidFormat)
        );
        assert_eq!(Credentials::decode(b"\x01"), Err(Error::InvalidFormat));
        assert_eq!(Credentials::decode(b""), Err(Error::InvalidFormat));
        assert_eq!(Credentials::decode(b"\x01\x00"), Err(Error::InvalidFormat));
        assert_eq!(
            Credentials::decode(b"\x01\x04home\x02\x03abc"),
            Err(Error::InvalidFormat)
        );
    }

    #[test]
    fn phase_wire_values() {
        for phase in [
            Phase::Unprovisioned,
            Phase::Connecting,
            Phase::Connected,
            Phase::Backoff,
            Phase::Fallback,
        ] {
            assert_eq!(Phase::from_u8(phase.as_u8()), Some(phase));
        }
        assert_eq!(Phase::from_u8(5), None);
        assert_eq!(Phase::Fallback.as_u8(), 4);
    }

    #[test]
    fn backoff_doubles_from_one_second_to_sixty() {
        let mut policy = StationPolicy::default();
        assert_eq!(policy.phase(), Phase::Unprovisioned);
        assert_eq!(policy.on(Event::Provisioned, Micros::ZERO), Action::Connect);
        assert_eq!(policy.phase(), Phase::Connecting);

        let expected_secs = [1u64, 2, 4, 8, 16, 32, 60, 60, 60];
        let mut now = Micros::ZERO;
        for (i, secs) in expected_secs.iter().enumerate() {
            let action = policy.on(Event::Disconnected, now);
            assert_eq!(
                action,
                Action::Wait(Micros::from_secs(*secs)),
                "failure {}",
                i + 1
            );
            assert_eq!(policy.phase(), Phase::Backoff);
            assert_eq!(usize::from(policy.failures()), i + 1);
            now = now.add_micros(Micros::from_secs(*secs).0);
            assert_eq!(policy.on(Event::Tick, now), Action::Connect);
            assert_eq!(policy.phase(), Phase::Connecting);
        }
        assert_eq!(policy.reconnects(), 9);
        // The tenth failure falls back to provisioning.
        assert_eq!(
            policy.on(Event::Disconnected, now),
            Action::StartProvisioning
        );
        assert_eq!(policy.phase(), Phase::Fallback);
        assert_eq!(policy.failures(), 10);
        // Nothing to do while provisioning is open...
        assert_eq!(policy.on(Event::Tick, now), Action::None);
        assert_eq!(policy.on(Event::Disconnected, now), Action::None);
        // ... until new credentials arrive.
        assert_eq!(policy.on(Event::Provisioned, now), Action::Connect);
        assert_eq!(policy.phase(), Phase::Connecting);
        assert_eq!(policy.failures(), 0);
    }

    #[test]
    fn a_connection_resets_the_failure_count() {
        let mut policy = StationPolicy::default();
        policy.on(Event::Provisioned, Micros::ZERO);
        let mut now = Micros::ZERO;
        for secs in [1u64, 2, 4] {
            assert_eq!(
                policy.on(Event::Disconnected, now),
                Action::Wait(Micros::from_secs(secs))
            );
            now = now.add_micros(Micros::from_secs(secs).0);
            assert_eq!(policy.on(Event::Tick, now), Action::Connect);
        }
        assert_eq!(policy.failures(), 3);
        assert_eq!(policy.on(Event::Connected, now), Action::None);
        assert_eq!(policy.phase(), Phase::Connected);
        assert_eq!(policy.failures(), 0);
        assert_eq!(policy.on(Event::Tick, now), Action::None);
        // The next drop starts the ladder over at 1 s.
        assert_eq!(
            policy.on(Event::Disconnected, now),
            Action::Wait(Micros::from_secs(1))
        );
        assert_eq!(policy.failures(), 1);
    }

    #[test]
    fn early_ticks_report_the_remaining_wait() {
        let mut policy = StationPolicy::default();
        policy.on(Event::Provisioned, Micros::ZERO);
        let t0 = Micros::from_secs(100);
        assert_eq!(
            policy.on(Event::Disconnected, t0),
            Action::Wait(Micros::from_secs(1))
        );
        assert_eq!(
            policy.on(Event::Tick, t0.add_micros(300_000)),
            Action::Wait(Micros::from_millis(700))
        );
        assert_eq!(policy.phase(), Phase::Backoff);
        assert_eq!(policy.reconnects(), 0);
        assert_eq!(
            policy.on(Event::Tick, t0.add_micros(1_000_000)),
            Action::Connect
        );
        assert_eq!(policy.reconnects(), 1);
        // Ticks outside Backoff are ignored.
        assert_eq!(
            policy.on(Event::Tick, t0.add_micros(2_000_000)),
            Action::None
        );
    }

    #[test]
    fn custom_config_caps_and_zero_failures() {
        let cfg = PolicyConfig {
            min_backoff: Micros::from_millis(500),
            max_backoff: Micros::from_millis(1_500),
            max_failures: 3,
        };
        let mut policy = StationPolicy::new(cfg);
        assert_eq!(policy.config(), cfg);
        assert_eq!(policy.backoff_for(1), Micros::from_millis(500));
        assert_eq!(policy.backoff_for(2), Micros::from_millis(1_000));
        assert_eq!(policy.backoff_for(3), Micros::from_millis(1_500));
        assert_eq!(policy.backoff_for(200), Micros::from_millis(1_500));
        policy.on(Event::Provisioned, Micros::ZERO);
        assert_eq!(
            policy.on(Event::Disconnected, Micros::ZERO),
            Action::Wait(Micros::from_millis(500))
        );
        assert_eq!(
            policy.on(Event::Tick, Micros::from_secs(1)),
            Action::Connect
        );
        assert_eq!(
            policy.on(Event::Disconnected, Micros::ZERO),
            Action::Wait(Micros::from_millis(1_000))
        );
        assert_eq!(
            policy.on(Event::Tick, Micros::from_secs(2)),
            Action::Connect
        );
        assert_eq!(
            policy.on(Event::Disconnected, Micros::ZERO),
            Action::StartProvisioning
        );

        let mut instant = StationPolicy::new(PolicyConfig {
            max_failures: 0,
            ..PolicyConfig::DEFAULT
        });
        instant.on(Event::Provisioned, Micros::ZERO);
        assert_eq!(
            instant.on(Event::Disconnected, Micros::ZERO),
            Action::StartProvisioning
        );
    }

    #[test]
    fn rssi_stats() {
        let mut stats = RssiStats::new();
        assert_eq!(stats.count(), 0);
        assert_eq!(stats.min(), None);
        assert_eq!(stats.max(), None);
        assert_eq!(stats.mean(), None);
        for rssi in [-70i8, -71, -65, -90] {
            stats.push(rssi);
        }
        assert_eq!(stats.count(), 4);
        assert_eq!(stats.min(), Some(-90));
        assert_eq!(stats.max(), Some(-65));
        // (-70 - 71 - 65 - 90) / 4 = -296 / 4 = -74 exactly.
        assert_eq!(stats.mean(), Some(-74));
        stats.push(-71);
        // -367 / 5 = -73.4 -> floor -74.
        assert_eq!(stats.mean(), Some(-74));
        let mut edge = RssiStats::default();
        edge.push(i8::MIN);
        edge.push(i8::MAX);
        assert_eq!(edge.min(), Some(-128));
        assert_eq!(edge.max(), Some(127));
        // -1 / 2 = -0.5 -> floor -1.
        assert_eq!(edge.mean(), Some(-1));
    }
}

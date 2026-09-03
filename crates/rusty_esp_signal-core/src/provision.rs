//! BLE provisioning, the session: what a device does with the writes and
//! reads that arrive on the provisioning service, and what it hands back
//! to its Wi-Fi stack.
//!
//! The page a phone opens is `docs/provision.html` — Web Bluetooth, no app.
//! It reads the DID and the scan list, writes one [`Credentials`] TLV to the
//! `credentials` characteristic, and watches the `status` characteristic
//! turn from `Connecting` to `Connected`. This module is the other end:
//!
//! - a write to `credentials` is decoded, stored (the previous secret wiped
//!   on replacement, both never printable), and turned into the
//!   [`StationPolicy`]'s `Provisioned` event, whose [`Action`] the backend
//!   executes;
//! - a read of `status` is the policy's [`Phase`] as one byte, and every
//!   phase change is a `status` notification the backend sends;
//! - a read of `scan` is the [`ScanList`] the backend filled from its last
//!   Wi-Fi scan, strongest first, as TLV;
//! - a write anywhere else on the service is refused (`Denied`), a read of
//!   `credentials` likewise — the secret goes in, never out.
//!
//! No BLE stack and no Wi-Fi stack: a backend routes attribute writes and
//! reads here by UUID and feeds the policy its link events. Everything is
//! fixed-size and `no_std`.

use core::fmt;

use rusty_esp_core::Micros;
use rusty_esp_core::error::{Error, Result};

use crate::ble::{CHAR_CREDENTIALS, CHAR_SCAN, CHAR_STATUS, GATT_TABLE, Uuid128};
use crate::wifi::{Action, Credentials, Event, Phase, SSID_MAX_LEN, StationPolicy};

/// TLV tag of a network name in the `scan` value (the same tag the
/// credentials write uses for its SSID).
pub const TAG_SSID: u8 = crate::wifi::TAG_SSID;
/// TLV tag of the RSSI that follows a scan entry's SSID: one `i8` dBm.
pub const TAG_RSSI: u8 = 3;
/// TLV tag of the security flag that follows: one byte, `0` open, `1` secured.
pub const TAG_SECURED: u8 = 4;
/// The `scan` characteristic's value size (the GATT table's `max_len`).
pub const SCAN_MAX_LEN: usize = 240;
/// Networks a [`ScanList`] holds by default: eight of 2 + 32 + 3 + 3 bytes
/// fill the characteristic almost exactly.
pub const SCAN_ENTRIES: usize = 8;

/// One network from a Wi-Fi scan, as the phone sees it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ScanEntry {
    ssid: [u8; SSID_MAX_LEN],
    ssid_len: u8,
    /// Signal strength, dBm.
    pub rssi_dbm: i8,
    /// `true` when the network wants a passphrase.
    pub secured: bool,
}

impl ScanEntry {
    /// A network with a 1..=32-byte name.
    pub fn new(ssid: &[u8], rssi_dbm: i8, secured: bool) -> Result<Self> {
        if ssid.is_empty() || ssid.len() > SSID_MAX_LEN {
            return Err(Error::InvalidFormat);
        }
        let mut e = ScanEntry {
            ssid: [0; SSID_MAX_LEN],
            ssid_len: ssid.len() as u8,
            rssi_dbm,
            secured,
        };
        e.ssid[..ssid.len()].copy_from_slice(ssid);
        Ok(e)
    }

    /// The network name.
    #[must_use]
    pub fn ssid(&self) -> &[u8] {
        &self.ssid[..usize::from(self.ssid_len)]
    }

    /// Bytes [`Self::encode`] writes: `2 + ssid`, `3` for the RSSI, `3` for
    /// the flag.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        2 + self.ssid_len as usize + 3 + 3
    }

    /// `01 len ssid  03 01 rssi  04 01 secured`.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let needed = self.encoded_len();
        let Some(out) = out.get_mut(..needed) else {
            return Err(Error::BufferTooSmall { needed });
        };
        let n = usize::from(self.ssid_len);
        out[0] = TAG_SSID;
        out[1] = self.ssid_len;
        out[2..2 + n].copy_from_slice(self.ssid());
        out[2 + n..2 + n + 3].copy_from_slice(&[TAG_RSSI, 1, self.rssi_dbm as u8]);
        out[5 + n..8 + n].copy_from_slice(&[TAG_SECURED, 1, u8::from(self.secured)]);
        Ok(needed)
    }

    /// Parse one entry from the front of `bytes`: an SSID entry, then any
    /// RSSI / secured entries up to the next SSID. Returns the entry and
    /// the bytes consumed. Unknown tags are skipped.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        let mut rest = bytes;
        let mut ssid: Option<&[u8]> = None;
        let mut rssi = 0i8;
        let mut secured = false;
        let mut consumed = 0;
        while let Some((&tag, after_tag)) = rest.split_first() {
            if tag == TAG_SSID && ssid.is_some() {
                break; // the next network
            }
            let Some((&len, after_len)) = after_tag.split_first() else {
                return Err(Error::InvalidFormat);
            };
            let Some((value, tail)) = after_len.split_at_checked(usize::from(len)) else {
                return Err(Error::InvalidFormat);
            };
            match tag {
                TAG_SSID => ssid = Some(value),
                TAG_RSSI if len == 1 => rssi = value[0] as i8,
                TAG_SECURED if len == 1 => secured = value[0] != 0,
                _ => {}
            }
            consumed += 2 + usize::from(len);
            rest = tail;
        }
        let ssid = ssid.ok_or(Error::InvalidFormat)?;
        Ok((ScanEntry::new(ssid, rssi, secured)?, consumed))
    }
}

impl fmt::Debug for ScanEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanEntry")
            .field("ssid", &self.ssid())
            .field("rssi_dbm", &self.rssi_dbm)
            .field("secured", &self.secured)
            .finish()
    }
}

/// The networks a scan found, strongest first, in fixed storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanList<const N: usize = SCAN_ENTRIES> {
    entries: [ScanEntry; N],
    len: usize,
}

impl<const N: usize> Default for ScanList<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ScanList<N> {
    const EMPTY: ScanEntry = ScanEntry {
        ssid: [0; SSID_MAX_LEN],
        ssid_len: 0,
        rssi_dbm: i8::MIN,
        secured: false,
    };

    /// No networks.
    #[must_use]
    pub const fn new() -> Self {
        ScanList {
            entries: [Self::EMPTY; N],
            len: 0,
        }
    }

    /// Insert by signal strength. When the list is full, a network weaker
    /// than every entry is dropped and the weakest entry makes room for a
    /// stronger one; the caller never has to sort.
    pub fn push(&mut self, entry: ScanEntry) {
        if self.len == N {
            if entry.rssi_dbm <= self.entries[N - 1].rssi_dbm {
                return;
            }
            self.len -= 1;
        }
        let mut i = self.len;
        while i > 0 && self.entries[i - 1].rssi_dbm < entry.rssi_dbm {
            self.entries[i] = self.entries[i - 1];
            i -= 1;
        }
        self.entries[i] = entry;
        self.len += 1;
    }

    /// Forget every network.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// The networks, strongest first.
    #[must_use]
    pub fn entries(&self) -> &[ScanEntry] {
        &self.entries[..self.len]
    }

    /// How many networks.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` when no network is listed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The `scan` value: entries in order until one no longer fits `out`
    /// (or [`SCAN_MAX_LEN`], whichever is shorter). Returns the bytes
    /// written; a list that is empty writes nothing.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let cap = out.len().min(SCAN_MAX_LEN);
        let mut written = 0;
        for e in self.entries() {
            let n = e.encoded_len();
            if written + n > cap {
                break;
            }
            e.encode(&mut out[written..written + n])?;
            written += n;
        }
        Ok(written)
    }

    /// Every entry of a `scan` value, in order.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut list = Self::new();
        let mut rest = bytes;
        while !rest.is_empty() {
            let (e, n) = ScanEntry::decode(rest)?;
            list.push(e);
            rest = &rest[n..];
        }
        Ok(list)
    }
}

/// What the backend does after a write or an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// The policy's instruction (connect, wait, open provisioning, nothing).
    pub action: Action,
    /// `Some(phase byte)` when the `status` characteristic changed and its
    /// subscribers must be notified.
    pub status: Option<u8>,
}

/// The provisioning session over the GATT table.
pub struct Provisioner<const N: usize = SCAN_ENTRIES> {
    policy: StationPolicy,
    credentials: Option<Credentials>,
    scan: ScanList<N>,
}

impl<const N: usize> Provisioner<N> {
    /// An unprovisioned device with `policy`'s tunables.
    #[must_use]
    pub const fn new(policy: StationPolicy) -> Self {
        Provisioner {
            policy,
            credentials: None,
            scan: ScanList::new(),
        }
    }

    /// The station policy.
    #[must_use]
    pub const fn policy(&self) -> &StationPolicy {
        &self.policy
    }

    /// The current phase (what a `status` read returns).
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.policy.phase()
    }

    /// The stored credentials, if any. What the Wi-Fi stack joins with.
    #[must_use]
    pub const fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }

    /// The scan list the phone reads.
    #[must_use]
    pub const fn scan(&self) -> &ScanList<N> {
        &self.scan
    }

    /// Replace the scan list after a Wi-Fi scan.
    pub fn set_scan(&mut self, scan: ScanList<N>) {
        self.scan = scan;
    }

    /// Credentials restored from storage at boot: the same path a BLE
    /// write takes, without the bus.
    pub fn restore(&mut self, credentials: Credentials, now: Micros) -> Outcome {
        self.adopt(credentials, now)
    }

    /// Drop the credentials (wiped) and return to provisioning — the
    /// factory-reset button.
    pub fn forget(&mut self, _now: Micros) -> Outcome {
        let before = self.phase();
        self.credentials = None;
        self.policy = StationPolicy::new(self.policy.config());
        Outcome {
            action: Action::StartProvisioning,
            status: status_if_changed(before, self.phase()),
        }
    }

    fn adopt(&mut self, credentials: Credentials, now: Micros) -> Outcome {
        let before = self.phase();
        // the old secret is wiped by `Credentials`' drop
        self.credentials = Some(credentials);
        let action = self.policy.on(Event::Provisioned, now);
        Outcome {
            action,
            status: status_if_changed(before, self.phase()),
        }
    }

    /// A GATT write of `value` to the characteristic `uuid`.
    ///
    /// `credentials`: the TLV is decoded ([`Credentials::decode`]) and
    /// adopted; a malformed write is `InvalidFormat` and changes nothing.
    /// `status` and `scan` are read-only: `Denied`. A UUID outside the
    /// provisioning service is `Unsupported` — it is someone else's.
    pub fn on_write(&mut self, uuid: Uuid128, value: &[u8], now: Micros) -> Result<Outcome> {
        if uuid == CHAR_CREDENTIALS {
            let creds = Credentials::decode(value)?;
            return Ok(self.adopt(creds, now));
        }
        if uuid == CHAR_STATUS || uuid == CHAR_SCAN {
            return Err(Error::Denied);
        }
        Err(if GATT_TABLE.find(uuid).is_some() {
            Error::Denied
        } else {
            Error::Unsupported
        })
    }

    /// A GATT read of the characteristic `uuid` into `out`; returns the
    /// value length.
    ///
    /// `status`: one byte, the [`Phase`]. `scan`: the list as TLV.
    /// `credentials`: `Denied`, always. Anything else: `Unsupported`.
    pub fn read(&self, uuid: Uuid128, out: &mut [u8]) -> Result<usize> {
        if uuid == CHAR_STATUS {
            let Some(slot) = out.first_mut() else {
                return Err(Error::BufferTooSmall { needed: 1 });
            };
            *slot = self.phase().as_u8();
            return Ok(1);
        }
        if uuid == CHAR_SCAN {
            return self.scan.encode(out);
        }
        if uuid == CHAR_CREDENTIALS {
            return Err(Error::Denied);
        }
        Err(Error::Unsupported)
    }

    /// A Wi-Fi link event (or a tick) for the policy.
    pub fn on_event(&mut self, event: Event, now: Micros) -> Outcome {
        let before = self.phase();
        let action = self.policy.on(event, now);
        Outcome {
            action,
            status: status_if_changed(before, self.phase()),
        }
    }
}

impl<const N: usize> fmt::Debug for Provisioner<N> {
    /// Never the credentials.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provisioner")
            .field("phase", &self.phase())
            .field("has_credentials", &self.credentials.is_some())
            .field("scan_len", &self.scan.len())
            .finish()
    }
}

fn status_if_changed(before: Phase, after: Phase) -> Option<u8> {
    (before != after).then_some(after.as_u8())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble::{CHAR_DID, CHAR_MANIFEST, SERVICE_PROVISIONING};
    use crate::wifi::PolicyConfig;

    fn creds_tlv(ssid: &[u8], psk: &[u8]) -> ([u8; 128], usize) {
        let c = Credentials::new(ssid, psk).unwrap();
        let mut buf = [0u8; 128];
        let n = c.encode(&mut buf).unwrap();
        (buf, n)
    }

    #[test]
    fn a_credentials_write_connects_and_status_moves() {
        let mut p: Provisioner = Provisioner::new(StationPolicy::new(PolicyConfig::DEFAULT));
        assert_eq!(p.phase(), Phase::Unprovisioned);
        let (tlv, n) = creds_tlv(b"home-net", b"correct horse battery");
        let out = p.on_write(CHAR_CREDENTIALS, &tlv[..n], Micros(0)).unwrap();
        assert_eq!(out.action, Action::Connect);
        assert_eq!(out.status, Some(Phase::Connecting.as_u8()));
        assert_eq!(p.credentials().unwrap().ssid(), b"home-net");
        let mut b = [0u8; 4];
        assert_eq!(p.read(CHAR_STATUS, &mut b).unwrap(), 1);
        assert_eq!(b[0], Phase::Connecting.as_u8());
        let joined = p.on_event(Event::Connected, Micros(1_000));
        assert_eq!(joined.action, Action::None);
        assert_eq!(joined.status, Some(Phase::Connected.as_u8()));
        // a second identical event is no phase change and no notification
        assert_eq!(p.on_event(Event::Connected, Micros(2_000)).status, None);
        assert!(!format!("{p:?}").contains("correct horse"));
        assert!(format!("{p:?}").contains("has_credentials: true"));
    }

    #[test]
    fn bad_writes_change_nothing_and_the_secret_never_reads_back() {
        let mut p: Provisioner = Provisioner::new(StationPolicy::default());
        assert_eq!(
            p.on_write(CHAR_CREDENTIALS, &[1, 3, b'a'], Micros(0)),
            Err(Error::InvalidFormat)
        );
        assert_eq!(p.phase(), Phase::Unprovisioned);
        assert!(p.credentials().is_none());
        assert_eq!(p.on_write(CHAR_STATUS, &[2], Micros(0)), Err(Error::Denied));
        assert_eq!(p.on_write(CHAR_SCAN, &[], Micros(0)), Err(Error::Denied));
        assert_eq!(
            p.on_write(CHAR_DID, b"did:mata:x", Micros(0)),
            Err(Error::Denied)
        );
        assert_eq!(
            p.on_write(crate::ble::janus_uuid(0x7777), &[], Micros(0)),
            Err(Error::Unsupported)
        );
        let (tlv, n) = creds_tlv(b"net", b"passphrase1");
        p.on_write(CHAR_CREDENTIALS, &tlv[..n], Micros(0)).unwrap();
        let mut out = [0u8; 128];
        assert_eq!(p.read(CHAR_CREDENTIALS, &mut out), Err(Error::Denied));
        assert_eq!(p.read(CHAR_MANIFEST, &mut out), Err(Error::Unsupported));
        assert_eq!(
            p.read(SERVICE_PROVISIONING, &mut out),
            Err(Error::Unsupported)
        );
        assert_eq!(
            p.read(CHAR_STATUS, &mut []),
            Err(Error::BufferTooSmall { needed: 1 })
        );
    }

    #[test]
    fn restore_forget_and_replace() {
        let mut p: Provisioner = Provisioner::new(StationPolicy::default());
        let out = p.restore(Credentials::new(b"stored", b"").unwrap(), Micros(5));
        assert_eq!(out.action, Action::Connect);
        assert_eq!(p.phase(), Phase::Connecting);
        p.on_event(Event::Connected, Micros(6));
        // new credentials while joined: adopt and reconnect
        let (tlv, n) = creds_tlv(
            b"other",
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let out = p.on_write(CHAR_CREDENTIALS, &tlv[..n], Micros(7)).unwrap();
        assert_eq!(out.action, Action::Connect);
        assert_eq!(p.credentials().unwrap().ssid(), b"other");
        let out = p.forget(Micros(8));
        assert_eq!(out.action, Action::StartProvisioning);
        assert_eq!(out.status, Some(Phase::Unprovisioned.as_u8()));
        assert!(p.credentials().is_none());
        assert_eq!(p.policy().failures(), 0);
    }

    #[test]
    fn scan_list_orders_by_strength_caps_and_round_trips() {
        let mut list: ScanList<3> = ScanList::new();
        list.push(ScanEntry::new(b"weak", -80, true).unwrap());
        list.push(ScanEntry::new(b"strong", -40, true).unwrap());
        list.push(ScanEntry::new(b"open", -60, false).unwrap());
        list.push(ScanEntry::new(b"weakest", -90, true).unwrap()); // dropped
        list.push(ScanEntry::new(b"best", -30, true).unwrap()); // evicts weak
        let names: std::vec::Vec<&[u8]> = list.entries().iter().map(|e| e.ssid()).collect();
        assert_eq!(names, [b"best".as_slice(), b"strong", b"open"]);
        let mut buf = [0u8; SCAN_MAX_LEN];
        let n = list.encode(&mut buf).unwrap();
        assert_eq!(n, (2 + 4 + 6) + (2 + 6 + 6) + (2 + 4 + 6));
        assert_eq!(
            &buf[..12],
            &[1, 4, b'b', b'e', b's', b't', 3, 1, (-30i8) as u8, 4, 1, 1]
        );
        let back: ScanList<3> = ScanList::decode(&buf[..n]).unwrap();
        assert_eq!(back, list);
        // a short buffer takes whole entries only
        let mut small = [0u8; 20];
        assert_eq!(list.encode(&mut small).unwrap(), 12);
        assert!(ScanEntry::new(b"", -1, false).is_err());
        assert!(ScanEntry::new(&[b'x'; 33], -1, false).is_err());
        assert_eq!(ScanEntry::decode(&[3, 1, 0]), Err(Error::InvalidFormat));
        assert_eq!(ScanEntry::decode(&[1, 5, b'a']), Err(Error::InvalidFormat));
    }

    #[test]
    fn a_full_scan_of_eight_long_names_fits_the_characteristic() {
        let mut p: Provisioner = Provisioner::new(StationPolicy::default());
        let mut list = ScanList::new();
        for i in 0..8u8 {
            list.push(ScanEntry::new(&[b'a' + i; 32], -50 - i as i8, i % 2 == 0).unwrap());
        }
        p.set_scan(list);
        let mut out = [0u8; SCAN_MAX_LEN];
        let n = p.read(CHAR_SCAN, &mut out).unwrap();
        assert_eq!(n, 6 * 40, "six of eight 40-byte entries fit in 240");
        assert_eq!(ScanList::<8>::decode(&out[..n]).unwrap().len(), 6);
    }

    /// The Web Bluetooth page names the same UUIDs and tags this crate does.
    #[test]
    fn the_provisioning_page_agrees_with_the_table() {
        let page = include_str!("../../../docs/provision.html");
        let mut buf = [0u8; 36];
        for (uuid, name) in [
            (SERVICE_PROVISIONING, "provisioning service"),
            (CHAR_CREDENTIALS, "credentials"),
            (CHAR_STATUS, "status"),
            (CHAR_SCAN, "scan"),
            (crate::ble::SERVICE_MANIFEST, "manifest service"),
            (CHAR_DID, "did"),
            (crate::ble::CHAR_TICKET, "ticket"),
        ] {
            let s = uuid.write_hyphenated(&mut buf).unwrap();
            assert!(page.contains(s), "the page must name the {name} UUID {s}");
        }
        for (tag, name) in [
            (TAG_SSID, "TAG_SSID"),
            (crate::wifi::TAG_PSK, "TAG_PSK"),
            (TAG_RSSI, "TAG_RSSI"),
            (TAG_SECURED, "TAG_SECURED"),
        ] {
            assert!(page.contains(&format!("{name} = {tag}")), "{name}");
        }
        for phase in [
            "Unprovisioned",
            "Connecting",
            "Connected",
            "Backoff",
            "Fallback",
        ] {
            assert!(page.contains(phase), "{phase}");
        }
        assert!(
            !page.contains("console.log(psk"),
            "the page never logs the secret"
        );
    }
}

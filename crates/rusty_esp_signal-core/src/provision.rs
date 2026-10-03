//! BLE provisioning: the provisioning service carries the setup session.
//!
//! The page a phone opens is `docs/provision.html`, Web Bluetooth and no
//! app, running the session's browser half in wasm. It reads `discover`,
//! subscribes to `setup`, writes the session's messages to `setup` and reads
//! each answer when its header is notified, and watches `status` turn from
//! `Connecting` to `Connected`. This module is the other end
//! ([`Provisioner`]):
//!
//! - a write to `setup` is one message of the setup session (the Janus
//!   umbrella's `docs/setup-protocol.md`; [`crate::setup::Device`]); the
//!   answer, an `Error` included, is left in the `setup` value and its two
//!   header bytes are what the backend notifies. A Settings that is applied
//!   with a network is adopted and turned into the [`StationPolicy`]'s
//!   `Provisioned` event, whose [`Action`] the backend executes;
//! - a read of `discover` is the session's Discover, a read of `status` the
//!   policy's [`Phase`] as one byte, and every phase change is a `status`
//!   notification the backend sends;
//! - the scan list ([`ScanList`]) the backend fills from its last Wi-Fi scan
//!   goes out sealed in the session's Ready, never in the clear;
//! - the service is advertised only while the setup window is open, and the
//!   connection is the carrier session: the backend calls
//!   [`Provisioner::carrier_closed`] when the peer leaves.
//!
//! `credentials` (plaintext Wi-Fi in) and the public `scan` are retired.
//!
//! No BLE stack and no Wi-Fi stack: a backend routes attribute writes and
//! reads here by UUID and feeds the policy its link events. Everything is
//! fixed-size and `no_std`.

use core::fmt;

use rusty_esp_core::Micros;
use rusty_esp_core::error::{Error, Result};
use rusty_esp_core::hal::{Kv, Rng};
use rusty_esp_mid_core::signer::DeviceSigner;
use zeroize::Zeroize;

use crate::ble::{CHAR_DISCOVER, CHAR_SETUP, CHAR_STATUS, GATT_TABLE, Uuid128};
use crate::setup::device::key;
use crate::setup::{DEVPUB_LEN, Device, MAX_MESSAGE, Reset, Status, Window, label};
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
    /// stronger one; the caller never has to sort. A name already listed
    /// keeps its strongest entry (a mesh answers from several access points).
    pub fn push(&mut self, entry: ScanEntry) {
        // one line per network name: a mesh or a dual-band router answers a
        // scan from several access points, and the strongest one is the
        // one to show
        if let Some(at) = self.entries[..self.len]
            .iter()
            .position(|e| e.ssid() == entry.ssid())
        {
            if entry.rssi_dbm <= self.entries[at].rssi_dbm {
                return;
            }
            for j in at..self.len - 1 {
                self.entries[j] = self.entries[j + 1];
            }
            self.len -= 1;
        }
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
    /// `Some(header)` when a `setup` write left an answer in the `setup`
    /// value: notify these two bytes (`VERSION || kind`) to the peer, which
    /// then reads the value.
    pub answer: Option<[u8; 2]>,
}

impl Outcome {
    const fn nothing() -> Self {
        Outcome {
            action: Action::None,
            status: None,
            answer: None,
        }
    }
}

/// What a platform lends the setup session: the owner's settings (NVS
/// namespace `janus`), the identity store, randomness and the device key.
pub trait SetupEnv {
    /// The owner's settings.
    type Settings: Kv;
    /// The identity store (adoption, owner pin).
    type Identity: Kv;
    /// Randomness for the session's shares.
    type Rng: Rng;
    /// The device's `did:mata` key.
    type Signer: DeviceSigner;
    /// All four at once, as the session takes them.
    fn parts(
        &mut self,
    ) -> (
        &mut Self::Settings,
        &mut Self::Identity,
        &mut Self::Rng,
        &Self::Signer,
    );
    /// The settings alone, to read.
    fn settings(&self) -> &Self::Settings;
}

/// The four parts as one value: the [`SetupEnv`] a firmware usually holds.
pub struct Env<S, I, R, K> {
    /// The owner's settings.
    pub settings: S,
    /// The identity store.
    pub identity: I,
    /// Randomness.
    pub rng: R,
    /// The device key.
    pub signer: K,
}

impl<S: Kv, I: Kv, R: Rng, K: DeviceSigner> SetupEnv for Env<S, I, R, K> {
    type Settings = S;
    type Identity = I;
    type Rng = R;
    type Signer = K;

    fn parts(&mut self) -> (&mut S, &mut I, &mut R, &K) {
        (
            &mut self.settings,
            &mut self.identity,
            &mut self.rng,
            &self.signer,
        )
    }

    fn settings(&self) -> &S {
        &self.settings
    }
}

/// The provisioning service over the GATT table: the setup session on
/// `setup` and `discover`, the station's phase on `status`.
///
/// A backend routes attribute writes and reads here by UUID, notifies what
/// an [`Outcome`] says to, calls [`Provisioner::carrier_closed`] when the
/// peer leaves, and advertises only while [`Provisioner::advertising`].
pub struct Provisioner<E: SetupEnv, const N: usize = SCAN_ENTRIES> {
    policy: StationPolicy,
    session: Device,
    env: E,
    credentials: Option<Credentials>,
    /// The network came from a session and has not joined yet.
    trial: bool,
    scan: ScanList<N>,
    answer: [u8; MAX_MESSAGE],
    answer_len: usize,
}

impl<E: SetupEnv, const N: usize> Provisioner<E, N> {
    /// The session for the device whose compressed key is `devpub`, on the
    /// BLE carrier, after a `reset` at `now`. Reads nothing but the window's
    /// state; [`Provisioner::boot`] restores a stored network.
    pub fn new(
        policy: StationPolicy,
        devpub: [u8; DEVPUB_LEN],
        reset: Reset,
        now: Micros,
        mut env: E,
    ) -> Result<Self> {
        let session = Device::new(label::BLE, devpub, reset, now, env.parts().0)?;
        Ok(Provisioner {
            policy,
            session,
            env,
            credentials: None,
            trial: false,
            scan: ScanList::new(),
            answer: [0; MAX_MESSAGE],
            answer_len: 0,
        })
    }

    /// The stored network, if the settings hold one: adopted, and the
    /// policy asked to join it ([`Action::Connect`]). Without one,
    /// [`Action::StartProvisioning`].
    pub fn boot(&mut self, now: Micros) -> Outcome {
        match stored_network(self.env.settings()) {
            Some(credentials) => self.adopt(credentials, now),
            None => Outcome {
                action: Action::StartProvisioning,
                ..Outcome::nothing()
            },
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

    /// The network to join, if any. What the Wi-Fi stack joins with.
    #[must_use]
    pub const fn credentials(&self) -> Option<&Credentials> {
        self.credentials.as_ref()
    }

    /// The scan list the session sends, sealed, in its Ready.
    #[must_use]
    pub const fn scan(&self) -> &ScanList<N> {
        &self.scan
    }

    /// Replace the scan list after a Wi-Fi scan.
    pub fn set_scan(&mut self, scan: ScanList<N>) {
        self.scan = scan;
    }

    /// The platform's parts, for what else the firmware keeps in them.
    pub fn env(&mut self) -> &mut E {
        &mut self.env
    }

    /// Whether the service should be advertised now: only while the
    /// setup window is open (protocol section 9).
    pub fn advertising(&self, now: Micros) -> bool {
        self.session.advertising(now, self.env.settings())
    }

    /// The window as Discover reports it: open or not, its seconds left
    /// (`0xFFFF` while unprovisioned), the attempts left. A backend times its
    /// advertising by it.
    pub fn window(&self, now: Micros) -> Window {
        self.session.window(now, self.env.settings())
    }

    /// The button: the window opens for its 600 s.
    pub fn button(&mut self, now: Micros) {
        self.session.button(now);
    }

    /// Time passed: a session idle past its timeout is dropped.
    pub fn tick(&mut self, now: Micros) {
        self.session.tick(now);
    }

    /// The peer left (the BLE connection is the carrier session): the
    /// session in flight is dropped and the answer wiped.
    pub fn carrier_closed(&mut self) {
        self.session.carrier_closed();
        self.answer.zeroize();
        self.answer_len = 0;
    }

    /// Drop the network (wiped from memory and the settings) and return to
    /// provisioning: the factory-reset button. The window is open again,
    /// since the device is unprovisioned.
    pub fn forget(&mut self, _now: Micros) -> Result<Outcome> {
        let before = self.phase();
        let (settings, ..) = self.env.parts();
        settings.remove(key::SSID)?;
        settings.remove(key::PSK)?;
        self.credentials = None;
        self.policy = StationPolicy::new(self.policy.config());
        Ok(Outcome {
            action: Action::StartProvisioning,
            status: status_if_changed(before, self.phase()),
            answer: None,
        })
    }

    fn adopt(&mut self, credentials: Credentials, now: Micros) -> Outcome {
        let before = self.phase();
        // the old secret is wiped by `Credentials`' drop
        self.credentials = Some(credentials);
        let action = self.policy.on(Event::Provisioned, now);
        Outcome {
            action,
            status: status_if_changed(before, self.phase()),
            answer: None,
        }
    }

    /// A GATT write of `value` to the characteristic `uuid`.
    ///
    /// `setup`: one session message. The answer (an `Error` included) is
    /// left in the `setup` value and its header comes back to notify; a
    /// Settings that was applied with a network also adopts it, and the
    /// policy asks to join. `status` and `discover` are read-only:
    /// `Denied`. A UUID outside the provisioning service, or a retired one,
    /// is `Unsupported`.
    pub fn on_write(&mut self, uuid: Uuid128, value: &[u8], now: Micros) -> Result<Outcome> {
        if uuid == CHAR_SETUP {
            let mut scan = [0u8; SCAN_MAX_LEN];
            let scan_len = self.scan.encode(&mut scan)?;
            let status = Status {
                phase: self.phase().as_u8(),
                scan: &scan[..scan_len],
            };
            let (settings, identity, rng, signer) = self.env.parts();
            self.answer.zeroize();
            let answer = self.session.on_message(
                value,
                now,
                settings,
                identity,
                rng,
                signer,
                &status,
                &mut self.answer,
            );
            let answer = match answer {
                Ok(a) => a,
                Err(e) => {
                    self.answer_len = 0;
                    return Err(e);
                }
            };
            self.answer_len = answer.len;
            let header = [self.answer[0], self.answer[1]];
            let mut out = match answer.applied.and_then(|a| a.network) {
                Some(network) => {
                    self.trial = true;
                    self.adopt(network, now)
                }
                None => Outcome::nothing(),
            };
            out.answer = Some(header);
            return Ok(out);
        }
        if uuid == CHAR_STATUS || uuid == CHAR_DISCOVER {
            return Err(Error::Denied);
        }
        Err(if GATT_TABLE.find(uuid).is_some() {
            Error::Denied
        } else {
            Error::Unsupported
        })
    }

    /// A GATT read of the characteristic `uuid` into `out`; returns the
    /// value length. A backend serving a long read takes its slice of this.
    ///
    /// `status`: one byte, the [`Phase`]. `discover`: the session's
    /// Discover, as of `now`. `setup`: the last answer (empty before the
    /// first write and after the peer leaves). Anything else:
    /// `Unsupported`.
    pub fn read(&self, uuid: Uuid128, now: Micros, out: &mut [u8]) -> Result<usize> {
        if uuid == CHAR_STATUS {
            let Some(slot) = out.first_mut() else {
                return Err(Error::BufferTooSmall { needed: 1 });
            };
            *slot = self.phase().as_u8();
            return Ok(1);
        }
        if uuid == CHAR_DISCOVER {
            return self.session.discover(now, self.env.settings(), out);
        }
        if uuid == CHAR_SETUP {
            let n = self.answer_len;
            if out.len() < n {
                return Err(Error::BufferTooSmall { needed: n });
            }
            out[..n].copy_from_slice(&self.answer[..n]);
            return Ok(n);
        }
        Err(Error::Unsupported)
    }

    /// A Wi-Fi link event (or a tick) for the policy.
    ///
    /// When the policy gives up on the stored network ([`Phase::Fallback`],
    /// [`Action::StartProvisioning`]) the setup window opens, as the button
    /// opens it: a network that never joins must not leave the device
    /// unreachable until someone cuts its power.
    ///
    /// So does the first failed join of a network a session just applied:
    /// the person who typed it is still at the page, and a mistyped
    /// passphrase is corrected with a new session, not a power cycle. The
    /// window then runs its 600 s; a network that has joined once no longer
    /// reopens it this way.
    pub fn on_event(&mut self, event: Event, now: Micros) -> Outcome {
        let before = self.phase();
        let action = self.policy.on(event, now);
        match event {
            Event::Connected => self.trial = false,
            Event::Disconnected if self.trial => {
                self.trial = false;
                self.session.button(now);
            }
            _ => {}
        }
        if action == Action::StartProvisioning {
            self.session.button(now);
        }
        Outcome {
            action,
            status: status_if_changed(before, self.phase()),
            answer: None,
        }
    }
}

impl<E: SetupEnv, const N: usize> fmt::Debug for Provisioner<E, N> {
    /// Never the credentials, never the answer.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provisioner")
            .field("phase", &self.phase())
            .field("has_credentials", &self.credentials.is_some())
            .field("in_session", &self.session.in_session())
            .field("scan_len", &self.scan.len())
            .finish()
    }
}

/// `wifi.ssid` and `wifi.psk` from the settings, when both are there and
/// make a network.
fn stored_network(settings: &impl Kv) -> Option<Credentials> {
    let mut ssid = [0u8; SSID_MAX_LEN];
    let mut psk = [0u8; 64];
    let n = settings.get(key::SSID, &mut ssid).ok()??;
    let m = settings.get(key::PSK, &mut psk).ok()??;
    let credentials = Credentials::new(&ssid[..n], &psk[..m]).ok();
    psk.zeroize();
    credentials
}

fn status_if_changed(before: Phase, after: Phase) -> Option<u8> {
    (before != after).then_some(after.as_u8())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::{Browser, Code, RecordWriter, ResultCode, Secrets, Verifier};
    use crate::wifi::PolicyConfig;
    use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};
    use rusty_esp_mid_core::key::DeviceKey;
    use std::vec::Vec;

    const CODE: &str = "7KXQ3-M9PRT";

    type Bench = Provisioner<Env<MemoryKv, MemoryKv, InsecureTestRng, DeviceKey>>;

    fn bench(provisioned: bool) -> (Bench, [u8; DEVPUB_LEN]) {
        let salt = [5u8; 16];
        let secrets = Secrets::derive(&Code::parse(CODE).unwrap(), &salt, 1_000).unwrap();
        let mut settings = MemoryKv::new();
        settings
            .put(
                key::SETUP_V,
                &Verifier::from_secrets(&secrets, &salt, 1_000).encode(),
            )
            .unwrap();
        if provisioned {
            settings.put(key::SSID, b"old-net").unwrap();
            settings.put(key::PSK, b"old-pass-123").unwrap();
        }
        let signer = DeviceKey::from_secret(&[0x21; 32], "gatt").unwrap();
        let devpub = *signer.did().pubkey();
        let env = Env {
            settings,
            identity: MemoryKv::new(),
            rng: InsecureTestRng::seeded(3),
            signer,
        };
        let p = Provisioner::new(
            StationPolicy::new(PolicyConfig::DEFAULT),
            devpub,
            Reset::PowerOn,
            Micros::from_secs(1),
            env,
        )
        .unwrap();
        (p, devpub)
    }

    fn discover(p: &Bench, now: Micros) -> Vec<u8> {
        let mut v = [0u8; 64];
        let n = p.read(CHAR_DISCOVER, now, &mut v).unwrap();
        v[..n].to_vec()
    }

    /// What the page does on `setup`: write a message, then, on the
    /// notification, read the value.
    fn exchange(p: &mut Bench, message: &[u8], now: Micros) -> (Outcome, Vec<u8>) {
        let out = p.on_write(CHAR_SETUP, message, now).unwrap();
        let mut v = [0u8; MAX_MESSAGE];
        let n = p.read(CHAR_SETUP, now, &mut v).unwrap();
        assert_eq!(
            out.answer,
            Some([v[0], v[1]]),
            "the notification is the answer's header"
        );
        (out, v[..n].to_vec())
    }

    fn start(p: &mut Bench, devpub: &[u8; 33], code: &str, now: Micros) -> (Browser, Vec<u8>) {
        let mut buf = [0u8; MAX_MESSAGE];
        let (b, n) = Browser::start(
            &discover(p, now),
            &Code::parse(code).unwrap(),
            Some(devpub),
            crate::setup::label::BLE,
            &mut InsecureTestRng::seeded(9),
            &mut buf,
        )
        .unwrap();
        let (_, reply) = exchange(p, &buf[..n], now);
        (b, reply)
    }

    #[test]
    fn a_session_over_the_gatt_table_provisions_and_joins() {
        let (mut p, devpub) = bench(false);
        let now = Micros::from_secs(2);
        assert_eq!(p.boot(now).action, Action::StartProvisioning);
        assert!(p.advertising(now), "unprovisioned: the window is open");
        let mut scan = ScanList::new();
        scan.push(ScanEntry::new(b"home", -48, true).unwrap());
        p.set_scan(scan);

        let (mut b, reply) = start(&mut p, &devpub, CODE, now);
        let mut buf = [0u8; MAX_MESSAGE];
        let n = b.on_reply(&reply, &mut buf).unwrap();
        let (_, ready) = exchange(&mut p, &buf[..n], now);
        let mut seen = [0u8; MAX_MESSAGE];
        let r = b.on_ready(&ready, &mut seen).unwrap();
        assert_eq!(r.phase, Phase::Unprovisioned.as_u8());
        let list: ScanList<8> = ScanList::decode(&seen[..r.scan_len]).unwrap();
        assert_eq!(list.entries()[0].ssid(), b"home", "the scan list went out sealed");

        let mut rec = [0u8; 256];
        let mut w = RecordWriter::new(&mut rec);
        w.network(b"home", b"a-home-passphrase").unwrap();
        let rl = w.len();
        let n = b.send_settings(&rec[..rl], &mut buf).unwrap();
        let (out, result) = exchange(&mut p, &buf[..n], now);
        assert_eq!(out.action, Action::Connect);
        assert_eq!(out.status, Some(Phase::Connecting.as_u8()));
        assert_eq!(b.on_result(&result).unwrap().0, ResultCode::Applied);
        let c = p.credentials().unwrap();
        assert_eq!((c.ssid(), c.psk()), (&b"home"[..], &b"a-home-passphrase"[..]));
        let joined = p.on_event(Event::Connected, now);
        assert_eq!(joined.status, Some(Phase::Connected.as_u8()));

        // the window that a power-on opened closes; so does the advertising
        assert!(p.advertising(Micros::from_secs(500)));
        assert!(!p.advertising(Micros::from_secs(700)));
    }

    #[test]
    fn the_table_refuses_what_is_not_the_session() {
        let (mut p, _) = bench(false);
        let now = Micros::from_secs(2);
        assert_eq!(p.on_write(CHAR_STATUS, &[1], now), Err(Error::Denied));
        assert_eq!(p.on_write(CHAR_DISCOVER, &[0; 59], now), Err(Error::Denied));
        // the retired characteristics are no one's now
        let retired = crate::ble::janus_uuid(0x0101);
        assert_eq!(p.on_write(retired, &[1, 1, b'x'], now), Err(Error::Unsupported));
        let mut v = [0u8; 300];
        assert_eq!(
            p.read(crate::ble::janus_uuid(0x0103), now, &mut v),
            Err(Error::Unsupported)
        );
        assert_eq!(
            p.on_write(crate::ble::CHAR_DID, &[1], now),
            Err(Error::Denied),
            "someone else's characteristic"
        );
        // nothing to read before the first write
        assert_eq!(p.read(CHAR_SETUP, now, &mut v), Ok(0));
        // a malformed message is answered, not dropped: an Error in the value
        let (_, answer) = exchange(&mut p, &[1, 1, 0], now);
        assert_eq!(answer[1], crate::setup::message::kind::ERROR);
    }

    #[test]
    fn a_wrong_code_then_the_peer_leaves_and_the_device_is_free_again() {
        let (mut p, devpub) = bench(false);
        let now = Micros::from_secs(2);
        let (mut b, reply) = start(&mut p, &devpub, "AAAAA-AAAAA", now);
        let mut buf = [0u8; MAX_MESSAGE];
        assert!(b.on_reply(&reply, &mut buf).is_err(), "the browser refuses at Reply");
        // the session is still in flight until the carrier closes: Busy
        let (_, busy) = start(&mut p, &devpub, CODE, now);
        assert_eq!(busy[1], crate::setup::message::kind::ERROR);
        assert_eq!(ResultCode::from_u8(busy[2]), Some(ResultCode::Busy));
        p.carrier_closed();
        let mut v = [0u8; MAX_MESSAGE];
        assert_eq!(p.read(CHAR_SETUP, now, &mut v), Ok(0), "the answer is wiped");
        // after the backoff a new connection gets a session
        let later = now.add_micros(2_000_000);
        let (mut b, reply) = start(&mut p, &devpub, CODE, later);
        assert!(b.on_reply(&reply, &mut buf).is_ok());
    }

    #[test]
    fn boot_restores_the_stored_network_and_forget_wipes_it() {
        let (mut p, _) = bench(true);
        let now = Micros::from_secs(1);
        let out = p.boot(now);
        assert_eq!(out.action, Action::Connect);
        assert_eq!(p.credentials().unwrap().ssid(), b"old-net");
        let out = p.forget(now).unwrap();
        assert_eq!(out.action, Action::StartProvisioning);
        assert!(p.credentials().is_none());
        let mut v = [0u8; 64];
        assert_eq!(p.env().settings.get(key::SSID, &mut v), Ok(None));
        assert_eq!(p.env().settings.get(key::PSK, &mut v), Ok(None));
        assert!(p.advertising(Micros::from_secs(5_000)), "unprovisioned again");
    }

    #[test]
    fn a_network_that_never_joins_reopens_the_window() {
        let (mut p, _) = bench(true);
        let now = Micros::from_secs(1);
        assert_eq!(p.boot(now).action, Action::Connect);
        // long after the power-on's window: closed, and provisioned
        let mut later = Micros::from_secs(5_000);
        assert!(!p.advertising(later));
        // the join fails, the policy waits, retries, fails again...
        let mut out = p.on_event(Event::Disconnected, later);
        let mut n = 1;
        while out.action != Action::StartProvisioning {
            assert!(n < 64, "the policy never fell back");
            if let Action::Wait(us) = out.action {
                later = later.add_micros(us.0);
                out = p.on_event(Event::Tick, later);
                assert_eq!(out.action, Action::Connect, "the retry");
            }
            assert!(!p.advertising(later), "still closed while it retries");
            out = p.on_event(Event::Disconnected, later);
            n += 1;
        }
        assert_eq!(p.phase(), Phase::Fallback);
        assert!(p.advertising(later), "falling back opens the window");
        assert!(p.advertising(later.add_micros(599_000_000)));
        assert!(!p.advertising(later.add_micros(601_000_000)), "for the button's 600 s");
    }

    #[test]
    fn a_fresh_network_that_fails_its_first_join_reopens_the_window() {
        // a board reset by its flashing (not a power-on): open only while
        // unprovisioned
        let (mut p, devpub) = bench(false);
        let late = Micros::from_secs(4_000);
        let mut s = ScanList::new();
        s.push(ScanEntry::new(b"home", -50, true).unwrap());
        p.set_scan(s);
        let (mut b, reply) = start(&mut p, &devpub, CODE, late);
        let mut buf = [0u8; MAX_MESSAGE];
        let n = b.on_reply(&reply, &mut buf).unwrap();
        exchange(&mut p, &buf[..n], late);
        let mut rec = [0u8; 128];
        let mut w = RecordWriter::new(&mut rec);
        w.network(b"home", b"a-mistyped-pass").unwrap();
        let rl = w.len();
        let n = b.send_settings(&rec[..rl], &mut buf).unwrap();
        let (out, _) = exchange(&mut p, &buf[..n], late);
        assert_eq!(out.action, Action::Connect);
        p.carrier_closed();
        assert!(!p.advertising(late), "provisioned now: the window closed");
        // the join fails: the window opens for the correction
        p.on_event(Event::Disconnected, late);
        assert!(p.advertising(late));
        assert!(!p.advertising(late.add_micros(601_000_000)));
        // a network that joined once does not reopen it on a drop
        let (mut p, _) = bench(true);
        p.boot(late);
        p.on_event(Event::Connected, late);
        p.on_event(Event::Disconnected, late);
        assert!(!p.advertising(late));
    }

    #[test]
    fn debug_shows_neither_the_network_nor_the_answer() {
        let (mut p, _) = bench(true);
        p.boot(Micros::from_secs(1));
        let s = format!("{p:?}");
        assert!(!s.contains("old-pass"), "{s}");
        assert!(s.contains("has_credentials: true"), "{s}");
    }

    /// The Web Bluetooth page names the table this router serves, the
    /// scan list's tags and the phases, and none of the retired
    /// characteristics. (`tools/provision-page-check.mjs` runs the page's
    /// session against this router.)
    #[test]
    fn the_provisioning_page_agrees_with_the_table() {
        let page = include_str!("../../../docs/provision.html");
        let mut buf = [0u8; 36];
        for (uuid, name) in [
            (crate::ble::SERVICE_PROVISIONING, "provisioning service"),
            (CHAR_STATUS, "status"),
            (CHAR_SETUP, "setup"),
            (CHAR_DISCOVER, "discover"),
        ] {
            let s = uuid.write_hyphenated(&mut buf).unwrap();
            assert!(page.contains(s), "the page must name the {name} UUID {s}");
        }
        for retired in [0x0101, 0x0103] {
            let s = crate::ble::janus_uuid(retired)
                .write_hyphenated(&mut buf)
                .unwrap();
            assert!(!page.contains(s), "the page names a retired UUID {s}");
        }
        for (tag, name) in [
            (TAG_SSID, "TAG_SSID"),
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
            page.contains("const PAGE_WASM = \""),
            "the page carries its wasm: run tools/build-provision-page.py"
        );
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
    fn a_network_seen_through_several_access_points_is_listed_once() {
        let mut list: ScanList<4> = ScanList::new();
        list.push(ScanEntry::new(b"home", -70, true).unwrap());
        list.push(ScanEntry::new(b"cafe", -60, false).unwrap());
        list.push(ScanEntry::new(b"home", -45, true).unwrap()); // the mesh's nearer node
        list.push(ScanEntry::new(b"home", -80, true).unwrap()); // a farther one
        let seen: std::vec::Vec<(&[u8], i8)> =
            list.entries().iter().map(|e| (e.ssid(), e.rssi_dbm)).collect();
        assert_eq!(seen, [(&b"home"[..], -45), (&b"cafe"[..], -60)]);
    }

    #[test]
    fn a_full_scan_of_eight_long_names_fits_one_ready() {
        let mut list: ScanList<8> = ScanList::new();
        for i in 0..8u8 {
            list.push(ScanEntry::new(&[b'a' + i; 32], -50 - i as i8, i % 2 == 0).unwrap());
        }
        let mut out = [0u8; SCAN_MAX_LEN];
        let n = list.encode(&mut out).unwrap();
        assert_eq!(n, 6 * 40, "six of eight 40-byte entries fit in 240");
        // Ready: header, then sealed (phase || scan) and its tag
        assert!(2 + 1 + n + crate::setup::TAG_LEN <= MAX_MESSAGE);
    }
}

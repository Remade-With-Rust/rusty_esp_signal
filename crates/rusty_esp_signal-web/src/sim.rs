//! The device half for the page's host test: the firmware's own GATT router
//! ([`Provisioner`]) over in-memory stores, addressed by characteristic
//! UUID the way Web Bluetooth addresses it. Never in the page's build.

use alloc::string::String;
use alloc::vec::Vec;

use rusty_esp_core::Micros;
use rusty_esp_core::hal::Kv;
use rusty_esp_core::hal::host::{InsecureTestRng, MemoryKv};
use rusty_esp_signal_core::ble::{CHAR_DISCOVER, CHAR_SETUP, CHAR_STATUS, Uuid128};
use rusty_esp_signal_core::mid::key::DeviceKey;
use rusty_esp_signal_core::provision::{Env, Provisioner, ScanEntry, ScanList};
use rusty_esp_signal_core::setup::device::key;
use rusty_esp_signal_core::setup::{Code, Reset, Secrets, Verifier};
use rusty_esp_signal_core::wifi::{Action, StationPolicy};
use wasm_bindgen::prelude::*;

type Router = Provisioner<Env<MemoryKv, MemoryKv, InsecureTestRng, DeviceKey>>;

/// A device with a setup code, as the portal flashed it, behind the GATT
/// router.
#[wasm_bindgen]
pub struct SimDevice {
    router: Router,
    now: Micros,
    did: String,
    action: Option<Action>,
}

#[wasm_bindgen]
impl SimDevice {
    /// A device whose setup code is `code` (verifier at `iterations`), that
    /// sees the networks `scan` names (comma-separated), at power-on.
    #[wasm_bindgen(constructor)]
    pub fn new(code: &str, iterations: u32, scan: &str) -> Result<SimDevice, JsError> {
        let salt = [0x5A; 16];
        let code = Code::parse(code).map_err(|e| JsError::new(&alloc::format!("{e:?}")))?;
        let secrets = Secrets::derive(&code, &salt, iterations)
            .map_err(|e| JsError::new(&alloc::format!("{e:?}")))?;
        let mut settings = MemoryKv::new();
        settings
            .put(
                key::SETUP_V,
                &Verifier::from_secrets(&secrets, &salt, iterations).encode(),
            )
            .map_err(|e| JsError::new(&alloc::format!("{e:?}")))?;
        let signer = DeviceKey::from_secret(&[0x42; 32], "sim").expect("a key");
        let devpub = *signer.did().pubkey();
        let did = alloc::string::ToString::to_string(&signer.did());
        let env = Env {
            settings,
            identity: MemoryKv::new(),
            rng: InsecureTestRng::seeded(11),
            signer,
        };
        let now = Micros::from_secs(1);
        let mut router = Router::new(StationPolicy::default(), devpub, Reset::PowerOn, now, env)
            .map_err(|e| JsError::new(&alloc::format!("{e:?}")))?;
        let mut list = ScanList::new();
        for (i, name) in scan.split(',').filter(|s| !s.is_empty()).enumerate() {
            let rssi = -40 - 7 * i8::try_from(i).unwrap_or(10);
            if let Ok(e) = ScanEntry::new(name.as_bytes(), rssi, true) {
                list.push(e);
            }
        }
        router.set_scan(list);
        router.boot(now);
        Ok(SimDevice {
            router,
            now,
            did,
            action: None,
        })
    }

    /// The device's `did:mata`.
    #[wasm_bindgen(getter)]
    pub fn did(&self) -> String {
        self.did.clone()
    }

    /// Moves the clock on.
    pub fn advance_ms(&mut self, ms: u32) {
        self.now = self.now.add_micros(u64::from(ms) * 1_000);
    }

    /// A read of the characteristic `uuid` (hyphenated, lower case).
    pub fn read(&mut self, uuid: &str) -> Result<Vec<u8>, JsError> {
        let mut out = [0u8; 512];
        let n = self
            .router
            .read(parse(uuid)?, self.now, &mut out)
            .map_err(|e| JsError::new(&alloc::format!("read refused: {e:?}")))?;
        Ok(out[..n].to_vec())
    }

    /// A write to `uuid`: the notification to send for it (the answer's
    /// header), empty when there is none.
    pub fn write(&mut self, uuid: &str, value: &[u8]) -> Result<Vec<u8>, JsError> {
        let outcome = self
            .router
            .on_write(parse(uuid)?, value, self.now)
            .map_err(|e| JsError::new(&alloc::format!("write refused: {e:?}")))?;
        if outcome.action != Action::None {
            self.action = Some(outcome.action);
        }
        Ok(outcome.answer.map(|h| h.to_vec()).unwrap_or_default())
    }

    /// The peer left.
    pub fn disconnect(&mut self) {
        self.router.carrier_closed();
    }

    /// What the policy last asked for (`"Connect"`, ...), if anything.
    pub fn action(&self) -> Option<String> {
        self.action.map(|a| alloc::format!("{a:?}"))
    }

    /// The network the device would join, as `ssid` (never the passphrase).
    pub fn network(&self) -> Option<String> {
        self.router
            .credentials()
            .map(|c| String::from_utf8_lossy(c.ssid()).into_owned())
    }

    /// Whether the stored passphrase is `psk` (compared here, never handed
    /// out).
    pub fn passphrase_is(&self, psk: &str) -> bool {
        self.router
            .credentials()
            .is_some_and(|c| c.psk() == psk.as_bytes())
    }

    /// The `status` characteristic's UUID, the `setup` one's and the
    /// `discover` one's, for the test's fake GATT.
    pub fn uuids() -> Vec<String> {
        [CHAR_STATUS, CHAR_SETUP, CHAR_DISCOVER]
            .iter()
            .map(|u| {
                let mut b = [0u8; Uuid128::HYPHENATED_LEN];
                String::from(u.write_hyphenated(&mut b).unwrap_or(""))
            })
            .collect()
    }
}

fn parse(uuid: &str) -> Result<Uuid128, JsError> {
    let hex: Vec<u8> = uuid
        .bytes()
        .filter(|b| *b != b'-')
        .collect::<Vec<u8>>()
        .chunks(2)
        .map(|p| {
            let s = core::str::from_utf8(p).unwrap_or("zz");
            u8::from_str_radix(s, 16).unwrap_or(0)
        })
        .collect();
    let bytes: [u8; 16] = hex
        .try_into()
        .map_err(|_| JsError::new("not a 128-bit UUID"))?;
    Ok(Uuid128::new(bytes))
}

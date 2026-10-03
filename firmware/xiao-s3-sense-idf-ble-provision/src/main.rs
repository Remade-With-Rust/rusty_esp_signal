//! Janus S3 on Track A: the XIAO ESP32-S3 Sense provisioned over BLE.
//!
//! Boot → the settings and the device key from NVS → Bluedroid → the core's
//! provisioning service, advertised as `janus-s3` while the setup window is
//! open → a phone carries the encrypted setup session (SPAKE2+, the Janus
//! umbrella's `docs/setup-protocol.md`, 11.1) over `setup` and `discover` →
//! the Settings it seals are applied to the owner's settings, the network
//! among them → the station policy says `Connect` → Wi-Fi joins with that
//! network → the phase goes back over BLE as a `status` notification. Every
//! decision is the core's (`Provisioner`, `StationPolicy`, the session);
//! this file wires the radio, the stores and the clock. `credentials` (a
//! plaintext TLV) and the public `scan` are retired.
//!
//! A device takes a session only once a setup code's verifier (`setup.v`)
//! is in its settings, which the portal (espino) writes at flash time;
//! without one, Discover offers no code and every Start is `NoVerifier`.
//!
//! The settings are the `janus` namespace of the default `nvs` partition.
//! The device key lives in the `identity` partition, minted on the first
//! boot and loaded on every other; this firmware's table has no such
//! partition, so it falls back to `nvs`, where a re-provision re-mints the
//! DID. A stored network is joined at boot. The service is advertised only
//! while the setup window is open (until a network is stored, and for ten
//! minutes after a power-on once one is); the main loop ticks it every
//! second so the advertising follows the window.
//!
//! The kill test (package ledger S3) is a phone provisioning from a Web
//! Bluetooth page with no app-store app; that needs the board. This builds.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use esp_idf_svc::bt::BtDriver;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::hal::reset::ResetReason;
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, NvsCustom};
use esp_idf_svc::sys::link_patches;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use rusty_esp_core::hal::Kv;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_mid_esp::idf::{EspNvsKv, EspRng, IDENTITY_PARTITION};
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::provision::{Env, Provisioner};
use rusty_esp_signal_core::setup::Reset;
use rusty_esp_signal_core::wifi::{Action, Event, StationPolicy};
use rusty_esp_signal_esp::idf::ble::BleProvisioning;

const NAME: &str = "janus-s3";
/// The namespace the settings and the identity live in, on every track.
const NAMESPACE: &str = "janus";
/// This board, in the key store's terms; the DID depends on the key alone.
const DEVICE_ID: &str = "janus";
/// How often the provisioning service is ticked: the advertising follows
/// the setup window, and an idle session is dropped.
const TICK: Duration = Duration::from_secs(1);

/// The identity store: the `identity` partition, or the owner's `nvs` when
/// the partition table has none.
enum Identity {
    Own(EspNvsKv<NvsCustom>),
    Shared(EspNvsKv),
}

impl Kv for Identity {
    fn get(&self, key: &str, out: &mut [u8]) -> rusty_esp_core::error::Result<Option<usize>> {
        match self {
            Identity::Own(kv) => kv.get(key, out),
            Identity::Shared(kv) => kv.get(key, out),
        }
    }

    fn put(&mut self, key: &str, value: &[u8]) -> rusty_esp_core::error::Result<()> {
        match self {
            Identity::Own(kv) => kv.put(key, value),
            Identity::Shared(kv) => kv.put(key, value),
        }
    }

    fn remove(&mut self, key: &str) -> rusty_esp_core::error::Result<bool> {
        match self {
            Identity::Own(kv) => kv.remove(key),
            Identity::Shared(kv) => kv.remove(key),
        }
    }
}

fn main() -> Result<()> {
    link_patches();
    EspLogger::initialize_default();

    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;
    // Only a power-on opens the setup window on a provisioned device; a
    // software or watchdog reset does not (protocol section 9).
    let reset = match ResetReason::get() {
        ResetReason::PowerOn => Reset::PowerOn,
        _ => Reset::Other,
    };

    // Wi-Fi and BLE share the S3's modem; the HAL splits it in two.
    let (wifi_modem, bt_modem) = peripherals.modem.split();
    let bt = Arc::new(BtDriver::new(bt_modem, Some(nvs.clone()))?);

    // The owner's settings: the verifier, the failure count, and what a
    // session applies.
    let settings =
        EspNvsKv::open_unchecked(nvs.clone(), NAMESPACE).context("the settings namespace")?;
    // The identity: its own partition, never the owner's `nvs`, which a
    // re-provision rewrites whole; a table without one falls back to `nvs`.
    let mut identity = match EspNvsKv::open_custom_unchecked(IDENTITY_PARTITION, NAMESPACE) {
        Ok(kv) => Identity::Own(kv),
        Err(e) => {
            log::warn!(
                "no {IDENTITY_PARTITION:?} partition ({e:?}): the device key shares the owner's nvs and a re-provision re-mints the DID"
            );
            Identity::Shared(
                EspNvsKv::open_unchecked(nvs.clone(), NAMESPACE)
                    .context("the identity namespace")?,
            )
        }
    };
    // The Bluetooth controller is up, so the chip's RNG is a true one.
    let mut rng = EspRng::after_radio_start();
    let key = DeviceKey::load_or_generate(&mut identity, &mut rng, DEVICE_ID)
        .context("the device key")?;
    let devpub = *key.did().pubkey();
    log::info!("device {}", key.did());

    let boot = Instant::now();
    let now = move || Micros(u64::try_from(boot.elapsed().as_micros()).unwrap_or(u64::MAX));
    let env = Env {
        settings,
        identity,
        rng,
        signer: key,
    };
    let mut provisioner: Provisioner<_> =
        Provisioner::new(StationPolicy::default(), devpub, reset, now(), env)
            .context("the setup session")?;
    // A stored network is joined now; without one the policy waits for a
    // session to apply one.
    let booted = provisioner.boot(now());
    log::info!("boot reset={reset:?} -> {:?}", booted.action);
    let (ble, actions) = BleProvisioning::start(bt, NAME, provisioner, now)?;
    log::info!("{NAME}: the provisioning service carries the setup session while the window is open");

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(wifi_modem, sysloop.clone(), Some(nvs))?,
        sysloop,
    )?;

    let mut pending: VecDeque<Action> = VecDeque::from([booted.action]);
    // The policy's backoff: when to tell it time has passed.
    let mut retry_at: Option<Instant> = None;
    loop {
        let action = match pending.pop_front() {
            Some(a) => a,
            None => match actions.recv_timeout(TICK) {
                Ok(a) => a,
                Err(RecvTimeoutError::Timeout) => {
                    if let Err(e) = ble.tick() {
                        log::warn!("ble tick: {e:?}");
                    }
                    if retry_at.is_some_and(|at| Instant::now() >= at) {
                        retry_at = None;
                        pending.push_back(ble.on_event(Event::Tick)?);
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(anyhow!("the provisioning service went away"));
                }
            },
        };
        match action {
            Action::Connect => {
                let creds = ble.with_provisioner(|p| {
                    p.credentials()
                        .map(|c| (c.ssid().to_vec(), c.psk().to_vec()))
                });
                let Some((ssid, psk)) = creds else {
                    continue;
                };
                log::info!(
                    "joining {:?} ({} bytes of passphrase, not shown)",
                    String::from_utf8_lossy(&ssid),
                    psk.len()
                );
                let joined = join(&mut wifi, &ssid, &psk);
                if let Err(e) = &joined {
                    log::warn!("join failed: {e}");
                }
                let event = if joined.is_ok() {
                    Event::Connected
                } else {
                    Event::Disconnected
                };
                pending.push_back(ble.on_event(event)?);
            }
            // Timed by the tick loop above, so the advertising keeps
            // following the window through a backoff.
            Action::Wait(us) => retry_at = Some(Instant::now() + Duration::from_micros(us.0)),
            Action::StartProvisioning | Action::None => {}
        }
    }
}

fn join(wifi: &mut BlockingWifi<EspWifi<'static>>, ssid: &[u8], psk: &[u8]) -> Result<()> {
    let ssid = core::str::from_utf8(ssid).context("ssid is not UTF-8")?;
    let psk = core::str::from_utf8(psk).context("passphrase is not UTF-8")?;
    let client = ClientConfiguration {
        ssid: ssid.try_into().map_err(|_| anyhow!("ssid longer than 32 bytes"))?,
        password: psk
            .try_into()
            .map_err(|_| anyhow!("passphrase longer than 64 bytes"))?,
        ..Default::default()
    };
    wifi.set_configuration(&Configuration::Client(client))?;
    if !wifi.is_started()? {
        wifi.start()?;
    }
    wifi.connect()?;
    wifi.wait_netif_up()?;
    log::info!("joined; ip {:?}", wifi.wifi().sta_netif().get_ip_info()?.ip);
    Ok(())
}

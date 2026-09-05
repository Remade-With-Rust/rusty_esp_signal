//! Janus S3 on Track A: the XIAO ESP32-S3 Sense provisioned over BLE.
//!
//! Boot → Bluedroid → the core's provisioning service advertises as
//! `janus-s3` → a phone writes the Wi-Fi credential TLV → the station policy
//! says `Connect` → Wi-Fi joins with those credentials → the phase goes back
//! over BLE as a `status` notification. Every decision is the core's
//! (`Provisioner`, `StationPolicy`); this file wires the radio and the clock.
//!
//! The kill test (package ledger S3) is a phone provisioning from a Web
//! Bluetooth page with no app-store app; that needs the board. This builds.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use esp_idf_svc::bt::BtDriver;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::hal::peripherals::Peripherals;
use esp_idf_svc::log::EspLogger;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::link_patches;
use esp_idf_svc::wifi::{BlockingWifi, ClientConfiguration, Configuration, EspWifi};
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::provision::Provisioner;
use rusty_esp_signal_core::wifi::{Action, Event, StationPolicy};
use rusty_esp_signal_esp::idf::ble::BleProvisioning;

const NAME: &str = "janus-s3";

fn main() -> Result<()> {
    link_patches();
    EspLogger::initialize_default();

    let peripherals = Peripherals::take()?;
    let sysloop = EspSystemEventLoop::take()?;
    let nvs = EspDefaultNvsPartition::take()?;

    // Wi-Fi and BLE share the S3's modem; the HAL splits it in two.
    let (wifi_modem, bt_modem) = peripherals.modem.split();
    let bt = Arc::new(BtDriver::new(bt_modem, Some(nvs.clone()))?);

    let boot = Instant::now();
    let now = move || Micros(u64::try_from(boot.elapsed().as_micros()).unwrap_or(u64::MAX));
    let provisioner: Provisioner = Provisioner::new(StationPolicy::default());
    let (ble, actions) = BleProvisioning::start(bt, NAME, provisioner, now)?;
    log::info!("advertising as {NAME}: write the credential TLV to the provisioning service");

    let mut wifi = BlockingWifi::wrap(
        EspWifi::new(wifi_modem, sysloop.clone(), Some(nvs))?,
        sysloop,
    )?;

    let mut pending: VecDeque<Action> = VecDeque::new();
    loop {
        let action = match pending.pop_front() {
            Some(a) => a,
            None => actions.recv().context("the provisioning service went away")?,
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
            Action::Wait(us) => {
                std::thread::sleep(Duration::from_micros(us.0));
                pending.push_back(ble.on_event(Event::Tick)?);
            }
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

//! The Janus BLE GATT server, built with `trouble-host`.
//!
//! The core defines the contract as data — [`GATT_TABLE`]: three services
//! (provisioning, manifest, telemetry) under the Janus base UUID, with the
//! characteristic sizes and property bits the ledger records. This module is
//! the same table expressed in `trouble-host`'s macros, plus the serve loop
//! that hands a credential write to the core's [`Provisioner`].
//!
//! It touches no esp crate: the server is generic over `bt-hci`'s
//! [`Controller`], so it runs over esp-radio's `BleConnector` on the chip and
//! over any other HCI transport on a host. The packet pool is
//! `trouble-host`'s [`DefaultPacketPool`], which is what the `gatt_server`
//! macro builds the attribute server around. The firmware builds the controller
//! and the [`Stack`], then calls [`serve`].
//!
//! ## The UUIDs
//!
//! The literals below are the core's `janus_uuid(short)` values written out,
//! because the macro needs a literal. [`assert_uuids`] checks the two agree,
//! so a change to the core's base cannot silently diverge from the server.
//!
//! ## What the characteristics carry
//!
//! | characteristic | direction | payload |
//! |---|---|---|
//! | `credentials` | write | the core's Wi-Fi credential TLV (tag 1 SSID, tag 2 PSK) |
//! | `status` | read, notify | the `wifi::Phase` as one byte |
//! | `scan` | read | the networks seen, strongest first (`provision` TLV) |
//! | `manifest` | read | the signed capability manifest |
//! | `did` | read | the `did:mata:` string |
//! | `ticket` | read | the `janus1…` ticket string |
//! | `rssi` / `presence` | read, notify | telemetry bytes |
//!
//! The session behind the provisioning service is the core's
//! [`Provisioner`]: [`serve`] hands it every credentials write and publishes
//! its phase and scan list, so the firmware holds one object that knows the
//! credentials, the policy and what to do next.
//!
//! Arrays longer than 32 bytes have no `Default` impl in Rust, so those
//! characteristics carry an explicit `value = [0u8; N]` for the macro.
//!
//! Credentials are written, never read back: the value characteristic is
//! write-only so a paired phone cannot pull the passphrase out again, and the
//! core's `wifi::Credentials` zeroises on drop.

use bt_hci::controller::ControllerCmdSync;
use trouble_host::prelude::*;

use rusty_esp_signal_core::ble as core_ble;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::esp_core::error::Result as CoreResult;
use rusty_esp_signal_core::provision::Provisioner;
use rusty_esp_signal_core::wifi::Action;

/// Provisioning: take Wi-Fi credentials in, report the connection phase.
/// The services and the server, as `trouble-host` macros.
///
/// The macros generate helper items (attribute handles, constructors) they do
/// not document, so `missing_docs` is allowed for the module; every service,
/// characteristic and public function is documented on its own. The
/// expansion also borrows each field value for a generic argument, which
/// clippy flags as needless — that code is the macro's, not ours.
#[allow(missing_docs, clippy::needless_borrows_for_generic_args)]
pub mod gatt {
    use super::*;

    #[gatt_service(uuid = "4a616e75-7300-4d41-5441-000000000100")]
    pub struct ProvisioningService {
        /// The core's credential TLV, written by the provisioner.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000101", write, value = [0u8; 100])]
        pub credentials: [u8; 100],
        /// `wifi::Phase` as a byte.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000102", read, notify)]
        pub status: u8,
        /// The networks the device can see, strongest first, as the core's
        /// `provision` TLV.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000103", read, value = [0u8; 240])]
        pub scan: [u8; 240],
    }

    /// Identity: who this device is, and what it can do.
    #[gatt_service(uuid = "4a616e75-7300-4d41-5441-000000000200")]
    pub struct ManifestService {
        /// The signed capability manifest bytes.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000201", read, value = [0u8; 128])]
        pub manifest: [u8; 128],
        /// The `did:mata:` string.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000202", read, value = [0u8; 56])]
        pub did: [u8; 56],
        /// The `janus1…` ticket string.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000203", read, value = [0u8; 128])]
        pub ticket: [u8; 128],
    }

    /// Telemetry: what the radios are seeing.
    #[gatt_service(uuid = "4a616e75-7300-4d41-5441-000000000300")]
    pub struct TelemetryService {
        /// Station RSSI, dBm as a signed byte.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000301", read, notify)]
        pub rssi: u8,
        /// Uptime in seconds, big-endian.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000302", read)]
        pub uptime: u32,
        /// The presence verdict: tag byte then motion level.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000303", read, notify)]
        pub presence: [u8; 2],
    }

    /// The Janus GATT server: the core's three services.
    #[gatt_server]
    pub struct JanusServer {
        /// Wi-Fi provisioning.
        pub provisioning: ProvisioningService,
        /// Device identity and capability manifest.
        pub manifest: ManifestService,
        /// Radio telemetry.
        pub telemetry: TelemetryService,
    }
}

pub use gatt::{JanusServer, ManifestService, ProvisioningService, TelemetryService};

/// What [`serve`] reports back to the firmware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The peer disconnected.
    Disconnected,
    /// Credentials were written, decoded and adopted by the session; the
    /// station policy asks for this (normally [`Action::Connect`]), and the
    /// credentials themselves are in [`Provisioner::credentials`].
    Provisioned(Action),
}

/// Advertise as a connectable peripheral and serve one connection through
/// the core's provisioning session.
///
/// `name` is the advertised local name. Before advertising, the `status`
/// and `scan` values are set from `provisioner` so a phone reads the phase
/// and the networks the device saw. A write to `credentials` goes to
/// [`Provisioner::on_write`]: accepted, the new phase is written to `status`
/// and notified to the peer and the function returns
/// [`Served::Provisioned`]; refused (a malformed TLV), the write is rejected
/// with an ATT error and the connection stays up. `now` is the device
/// clock the policy timestamps with.
///
/// The caller runs the stack's `Runner` concurrently (`runner.run()`), as
/// `trouble-host` requires.
pub async fn serve<'a, C, const N: usize>(
    peripheral: &mut Peripheral<'a, C, DefaultPacketPool>,
    server: &JanusServer<'_>,
    name: &str,
    provisioner: &mut Provisioner<N>,
    mut now: impl FnMut() -> Micros,
) -> core::result::Result<Served, BleHostError<C::Error>>
where
    C: Controller
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvData>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvParams>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvEnable>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetScanResponseData>,
{
    // What the phone reads first: the phase, and the networks seen.
    let mut scan = [0u8; 240];
    let _ = provisioner.read(core_ble::CHAR_SCAN, &mut scan);
    server.set(&server.provisioning.scan, &scan)?;
    server.set(&server.provisioning.status, &provisioner.phase().as_u8())?;

    let mut adv_data = [0u8; 31];
    let len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteLocalName(name.as_bytes()),
        ],
        &mut adv_data[..],
    )?;

    let advertiser = peripheral
        .advertise(
            &AdvertisementParameters::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..len],
                scan_data: &[],
            },
        )
        .await?;
    let conn = advertiser.accept().await?;
    let conn = conn
        .with_attribute_server(&server.server)
        .map_err(BleHostError::from)?;

    loop {
        match conn.next().await {
            GattConnectionEvent::Disconnected { .. } => return Ok(Served::Disconnected),
            GattConnectionEvent::Gatt { event } => {
                let mut provisioned = None;
                if let GattEvent::Write(ref write) = event {
                    if write.handle() == server.provisioning.credentials.handle {
                        match provisioner.on_write(core_ble::CHAR_CREDENTIALS, write.data(), now())
                        {
                            Ok(outcome) => provisioned = Some(outcome),
                            Err(_) => {
                                // A malformed TLV is the peer's error, not ours;
                                // the session is unchanged.
                                let reply = event.reject(AttErrorCode::VALUE_NOT_ALLOWED)?;
                                reply.send().await;
                                continue;
                            }
                        }
                    }
                }
                let reply = event.accept()?;
                reply.send().await;
                if let Some(outcome) = provisioned {
                    if let Some(phase) = outcome.status {
                        server.set(&server.provisioning.status, &phase)?;
                        // A peer that did not subscribe simply does not get it.
                        let _ = server.provisioning.status.notify(&conn, &phase).await;
                    }
                    return Ok(Served::Provisioned(outcome.action));
                }
            }
            _ => {}
        }
    }
}

/// Check that the literal UUIDs above still match the core's table, so a
/// change to the core's base UUID cannot silently diverge from the server.
///
/// Returns `Err(Error::InvalidFormat)` on a mismatch.
pub fn assert_uuids() -> CoreResult<()> {
    use rusty_esp_signal_core::esp_core::Error;

    const PAIRS: [(&str, core_ble::Uuid128); 3] = [
        (
            "4a616e75-7300-4d41-5441-000000000100",
            core_ble::SERVICE_PROVISIONING,
        ),
        (
            "4a616e75-7300-4d41-5441-000000000200",
            core_ble::SERVICE_MANIFEST,
        ),
        (
            "4a616e75-7300-4d41-5441-000000000300",
            core_ble::SERVICE_TELEMETRY,
        ),
    ];
    let mut buf = [0u8; core_ble::Uuid128::HYPHENATED_LEN];
    for (literal, uuid) in PAIRS {
        let text = uuid.write_hyphenated(&mut buf)?;
        if text != literal {
            return Err(Error::InvalidFormat);
        }
    }
    Ok(())
}

//! The Janus BLE GATT server, built with `trouble-host`.
//!
//! The core defines the contract as data — [`GATT_TABLE`]: three services
//! (provisioning, manifest, telemetry) under the Janus base UUID, with the
//! characteristic sizes and property bits the ledger records. This module is
//! the same table expressed in `trouble-host`'s macros, plus the serve loop
//! that carries the setup session to the core's [`Provisioner`].
//!
//! It touches no esp crate: the server is generic over `bt-hci`'s
//! [`Controller`], so it runs over esp-radio's `BleConnector` on the chip and
//! over any other HCI transport on a host. The packet pool is
//! `trouble-host`'s [`DefaultPacketPool`], which is what the `gatt_server`
//! macro builds the attribute server around. The firmware builds the controller
//! and the [`Stack`], then calls [`accept`] and [`Session::serve`].
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
//! | `status` | read, notify | the `wifi::Phase` as one byte |
//! | `setup` | write, read, notify | the setup session's messages (the Janus umbrella's `docs/setup-protocol.md`, 11.1) |
//! | `discover` | read | the session's Discover, fresh on every read |
//! | `manifest` | read | the signed capability manifest |
//! | `did` | read | the `did:mata:` string |
//! | `ticket` | read | the `janus1…` ticket string |
//! | `rssi` / `presence` | read, notify | telemetry bytes |
//!
//! `credentials` (plaintext Wi-Fi in) and the public `scan` are retired:
//! the settings arrive sealed in the session, the scan list leaves sealed in
//! its Ready.
//!
//! ## The setup binding
//!
//! The browser subscribes to `setup`, then writes one message. The write is
//! handed to [`Provisioner::on_write`] whole: a message longer than one ATT
//! packet arrives as a prepared write, which `trouble-host` assembles
//! (`att-queued-writes`, a 512-byte buffer) and hands over at offset 0. The
//! write is acknowledged, the answer is stored as `setup`'s value, and its
//! two header bytes are notified without touching the stored value; the
//! browser reads the value (a long read when it needs one, served from the
//! table). `setup` and `discover` are `heapless::Vec`s, so a read returns
//! the value at its own length.
//!
//! The connection is the carrier session: when the peer leaves, the
//! session in flight is dropped and the stored answer cleared. The service
//! is advertised only while the setup window is open, and for no longer
//! than it has left ([`accept`]).
//!
//! The advertisement is the flags and the provisioning service UUID; the
//! name rides in the scan response. A legacy advertisement holds 31 bytes,
//! the UUID alone takes 18, and a page filtering on the service must see it
//! whole.
//!
//! Arrays longer than 32 bytes have no `Default` impl in Rust, so those
//! characteristics carry an explicit `value = [0u8; N]` for the macro.

use core::future::Future;

use bt_hci::controller::ControllerCmdSync;
use embassy_futures::select::{Either, select};
use embassy_time::{Duration, Timer};
use heapless::Vec;
use trouble_host::prelude::*;

use rusty_esp_signal_core::ble as core_ble;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::esp_core::error::{Error as CoreError, Result as CoreResult};
use rusty_esp_signal_core::provision::{Outcome, Provisioner, SetupEnv};
use rusty_esp_signal_core::setup::MAX_MESSAGE;
use rusty_esp_signal_core::setup::message::WINDOW_UNTIL_PROVISIONED;
use rusty_esp_signal_core::wifi::{Action, Event};

/// Bytes of the `setup` value.
const SETUP_LEN: usize = core_ble::SETUP_VALUE_LEN as usize;
/// Bytes of the `discover` value.
const DISCOVER_LEN: usize = core_ble::DISCOVER_VALUE_LEN as usize;

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
        /// `wifi::Phase` as a byte.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000102", read, notify)]
        pub status: u8,
        /// The setup session's messages: the browser's in, the device's
        /// answer out.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000104", write, read, notify, value = Vec::new())]
        pub setup: Vec<u8, SETUP_LEN>,
        /// The session's Discover.
        #[characteristic(uuid = "4a616e75-7300-4d41-5441-000000000105", read, value = Vec::new())]
        pub discover: Vec<u8, DISCOVER_LEN>,
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

/// What [`Session::serve`] (and the one-shot [`serve`]) reports back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The peer disconnected; the session in flight was dropped.
    Disconnected,
    /// A session applied settings with a network; the station policy asks
    /// for this (normally [`Action::Connect`]), and the network itself is in
    /// [`Provisioner::credentials`].
    Provisioned(Action),
}

/// A connected peer with the attribute server attached: the phone.
///
/// [`accept`] returns one. [`Session::serve`] carries the setup session
/// until settings with a network are applied or the peer leaves;
/// [`Session::attend`] keeps answering the peer while the firmware does the
/// join, so a read or a write during those seconds is not left hanging
/// until the ATT timeout drops the link; [`Session::report`] tells it how
/// the join went. Dropping the session drops the link.
pub struct Session<'stack, 'server> {
    conn: GattConnection<'stack, 'server, DefaultPacketPool>,
}

impl<'stack, 'server> Session<'stack, 'server> {
    /// Carry the setup session until it applies a network or the peer
    /// leaves.
    ///
    /// A read of `discover` is answered with a fresh Discover. A write to
    /// `setup` goes to [`Provisioner::on_write`] whole, is acknowledged, and
    /// its answer is stored as `setup`'s value and its header notified; a
    /// write the core could not take at all (a stored record that failed,
    /// a partial prepared write) is refused with an ATT error and the
    /// connection stays up. A phase change is written to `status` and
    /// notified. When the peer leaves, [`Provisioner::carrier_closed`].
    /// `now` is the device clock.
    pub async fn serve<E: SetupEnv, const N: usize>(
        &self,
        server: &JanusServer<'_>,
        provisioner: &mut Provisioner<E, N>,
        now: impl FnMut() -> Micros,
    ) -> core::result::Result<Served, Error> {
        self.serve_observed(server, provisioner, now, |_, _| {}).await
    }

    /// [`Session::serve`], and `observe(kind, took)` for every `setup`
    /// message the session answered: the message's kind byte (Start
    /// `0x01`, Confirm `0x03`, Settings `0x05`) and the device's time on it,
    /// from the write's arrival to its answer.
    pub async fn serve_observed<E: SetupEnv, const N: usize>(
        &self,
        server: &JanusServer<'_>,
        provisioner: &mut Provisioner<E, N>,
        mut now: impl FnMut() -> Micros,
        mut observe: impl FnMut(u8, Micros),
    ) -> core::result::Result<Served, Error> {
        loop {
            match self.conn.next().await {
                GattConnectionEvent::Disconnected { .. } => {
                    provisioner.carrier_closed();
                    server.set(&server.provisioning.setup, &Vec::new())?;
                    return Ok(Served::Disconnected);
                }
                GattConnectionEvent::Gatt { event } => {
                    let mut answered = None;
                    match event {
                        GattEvent::Read(ref read)
                            if read.handle() == server.provisioning.discover.handle =>
                        {
                            let mut d = [0u8; DISCOVER_LEN];
                            if let Ok(n) = provisioner.read(core_ble::CHAR_DISCOVER, now(), &mut d) {
                                let value = Vec::from_slice(&d[..n]).unwrap_or_default();
                                server.set(&server.provisioning.discover, &value)?;
                            }
                        }
                        GattEvent::Write(ref write)
                            if write.handle() == server.provisioning.setup.handle =>
                        {
                            let stamp = now();
                            // a plain write is the whole message at 0, and a
                            // queued long write arrives assembled, also at 0
                            let mut kind = 0;
                            match write.with_data(|offset, data| {
                                if offset != 0 {
                                    return Err(CoreError::InvalidFormat);
                                }
                                kind = data.get(1).copied().unwrap_or(0);
                                provisioner.on_write(core_ble::CHAR_SETUP, data, stamp)
                            }) {
                                Ok(outcome) => {
                                    observe(kind, Micros(now().0.saturating_sub(stamp.0)));
                                    answered = Some(outcome);
                                }
                                Err(_) => {
                                    let reply = event.reject(AttErrorCode::UNLIKELY_ERROR)?;
                                    reply.send().await;
                                    continue;
                                }
                            }
                        }
                        _ => {}
                    }
                    // accepting stores what was written; the answer goes in after
                    let reply = event.accept()?;
                    reply.send().await;
                    if let Some(outcome) = answered {
                        if let Some(served) = self.answer(server, provisioner, outcome, now()).await? {
                            return Ok(served);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// The answer into `setup`, its header out, and the phase if it moved.
    async fn answer<E: SetupEnv, const N: usize>(
        &self,
        server: &JanusServer<'_>,
        provisioner: &Provisioner<E, N>,
        outcome: Outcome,
        now: Micros,
    ) -> core::result::Result<Option<Served>, Error> {
        let mut buf = [0u8; MAX_MESSAGE];
        let n = provisioner
            .read(core_ble::CHAR_SETUP, now, &mut buf)
            .unwrap_or(0);
        let value = Vec::from_slice(&buf[..n]).unwrap_or_default();
        server.set(&server.provisioning.setup, &value)?;
        if let Some(header) = outcome.answer {
            // `false`: notify the header without overwriting the stored answer
            let _ = server
                .provisioning
                .setup
                .notify_raw(&self.conn, &header, false)
                .await;
        }
        if let Some(phase) = outcome.status {
            publish(server, &self.conn, phase).await?;
        }
        Ok(match outcome.action {
            Action::None => None,
            action => Some(Served::Provisioned(action)),
        })
    }

    /// Run `fut` to completion while answering the peer's requests (every
    /// one accepted as written). `None` if the peer left first; the caller
    /// then calls [`Provisioner::carrier_closed`].
    pub async fn attend<F: Future>(&self, fut: F) -> Option<F::Output> {
        match select(fut, self.answer_all()).await {
            Either::First(value) => Some(value),
            Either::Second(()) => None,
        }
    }

    /// Accept everything until the peer leaves.
    async fn answer_all(&self) {
        loop {
            match self.conn.next().await {
                GattConnectionEvent::Disconnected { .. } => return,
                GattConnectionEvent::Gatt { event } => {
                    if let Ok(reply) = event.accept() {
                        reply.send().await;
                    }
                }
                _ => {}
            }
        }
    }

    /// Feed `event` (the join's outcome) to the session and publish the
    /// phase it moves to: written to `status` and notified to the peer.
    pub async fn report<E: SetupEnv, const N: usize>(
        &self,
        server: &JanusServer<'_>,
        provisioner: &mut Provisioner<E, N>,
        event: Event,
        now: Micros,
    ) -> core::result::Result<Outcome, Error> {
        let outcome = provisioner.on_event(event, now);
        if let Some(phase) = outcome.status {
            publish(server, &self.conn, phase).await?;
        }
        Ok(outcome)
    }
}

/// The phase into `status`, and out to the peer.
async fn publish(
    server: &JanusServer<'_>,
    conn: &GattConnection<'_, '_, DefaultPacketPool>,
    phase: u8,
) -> core::result::Result<(), Error> {
    server.set(&server.provisioning.status, &phase)?;
    // A peer that did not subscribe simply does not get it. The value was
    // stored by `set` above; `false` keeps trouble-host from storing it twice.
    let _ = server.provisioning.status.notify(conn, &phase, false).await;
    Ok(())
}

/// Advertise as a connectable peripheral and accept one peer, while the
/// setup window is open.
///
/// `Ok(None)` when the window is closed at `now`, or closes before anyone
/// connects: the advertising runs for no longer than the window has left
/// (until provisioned, it has no end). The firmware waits for the button or
/// the next power-on and asks again.
///
/// The advertisement carries the flags and the 128-bit provisioning service
/// UUID (21 of its 31 bytes), which is what a Web Bluetooth page filters
/// on; `name` goes in the scan response, where it is not competing with the
/// UUID for the budget. Before advertising, `status` and `discover` are set
/// from `provisioner`.
///
/// The caller runs the stack's `Runner` concurrently (`runner.run()`), as
/// `trouble-host` requires.
pub async fn accept<'stack, 'server, C, E: SetupEnv, const N: usize>(
    peripheral: &mut Peripheral<'stack, C, DefaultPacketPool>,
    server: &'server JanusServer<'_>,
    name: &str,
    provisioner: &Provisioner<E, N>,
    now: Micros,
) -> core::result::Result<Option<Session<'stack, 'server>>, BleHostError<C::Error>>
where
    C: Controller
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvData>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvParams>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvEnable>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetScanResponseData>,
{
    let window = provisioner.window(now);
    if !provisioner.advertising(now) {
        return Ok(None);
    }
    let mut d = [0u8; DISCOVER_LEN];
    if let Ok(n) = provisioner.read(core_ble::CHAR_DISCOVER, now, &mut d) {
        server.set(
            &server.provisioning.discover,
            &Vec::from_slice(&d[..n]).unwrap_or_default(),
        )?;
    }
    server.set(&server.provisioning.setup, &Vec::new())?;
    server.set(&server.provisioning.status, &provisioner.phase().as_u8())?;

    // On the air a 128-bit UUID is little-endian; the core keeps the
    // written-out order.
    let mut service = core_ble::SERVICE_PROVISIONING.to_bytes();
    service.reverse();
    let mut adv_data = [0u8; 31];
    let adv_len = AdStructure::encode_slice(
        &[
            AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED),
            AdStructure::CompleteServiceUuids128(&[service]),
        ],
        &mut adv_data[..],
    )?;
    let mut scan_data = [0u8; 31];
    let scan_len = AdStructure::encode_slice(
        &[AdStructure::CompleteLocalName(core_ble::advertised_name(name).as_bytes())],
        &mut scan_data[..],
    )?;

    let advertiser = peripheral
        .advertise(
            &AdvertisementParameters::default(),
            Advertisement::ConnectableScannableUndirected {
                adv_data: &adv_data[..adv_len],
                scan_data: &scan_data[..scan_len],
            },
        )
        .await?;
    // A legacy advertisement has no duration of its own (trouble-host keeps
    // `timeout` for extended sets), so the window's end is a timer raced
    // against the connection; dropping the advertiser stops it.
    let accepted = if window.window_s == WINDOW_UNTIL_PROVISIONED {
        Either::First(advertiser.accept().await)
    } else {
        let left = Duration::from_secs(u64::from(window.window_s));
        select(advertiser.accept(), Timer::after(left)).await
    };
    let conn = match accepted {
        Either::First(conn) => conn?,
        // the window closed while advertising
        Either::Second(()) => return Ok(None),
    };
    let conn = conn
        .with_attribute_server(&server.server)
        .map_err(BleHostError::from)?;
    Ok(Some(Session { conn }))
}

/// [`accept`] one peer and [`Session::serve`] it: one connection, served
/// until it provisions or leaves, then dropped. `Ok(None)` when the window
/// is closed. For a firmware with nothing to join (the C6 has no Wi-Fi
/// stack); one that joins keeps the [`Session`] and reports through it.
pub async fn serve<'stack, C, E: SetupEnv, const N: usize>(
    peripheral: &mut Peripheral<'stack, C, DefaultPacketPool>,
    server: &JanusServer<'_>,
    name: &str,
    provisioner: &mut Provisioner<E, N>,
    mut now: impl FnMut() -> Micros,
) -> core::result::Result<Option<Served>, BleHostError<C::Error>>
where
    C: Controller
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvData>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvParams>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetAdvEnable>
        + ControllerCmdSync<bt_hci::cmd::le::LeSetScanResponseData>,
{
    let Some(session) = accept(peripheral, server, name, provisioner, now()).await? else {
        return Ok(None);
    };
    session
        .serve(server, provisioner, now)
        .await
        .map(Some)
        .map_err(BleHostError::from)
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

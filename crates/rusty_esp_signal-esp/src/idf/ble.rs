//! The Janus provisioning GATT service on ESP-IDF's Bluedroid host (Track A).
//!
//! The same contract as [`crate::ble`] (Track B, `trouble-host`): the core's
//! provisioning service — `status` READ | NOTIFY, `setup` WRITE | READ |
//! NOTIFY, `discover` READ — served through `esp-idf-svc`'s [`EspGatts`]
//! and [`EspBleGap`], with the core's [`Provisioner`] as the one object that
//! carries the setup session (the Janus umbrella's `docs/setup-protocol.md`,
//! 11.1), knows the network, the policy and what to do next.
//!
//! Bluedroid answers reads of `status` itself from the attribute value this
//! module sets ([`AutoResponse::ByGatt`]). `setup` and `discover` are
//! answered by the app ([`AutoResponse::ByApp`]): a read is served from the
//! session at the offset asked for (a long read takes its slices), and a
//! write is assembled here when it arrives as a prepared (long) write —
//! Bluedroid hands each part over with its offset and then an execute — so
//! a message longer than one ATT packet reaches the session whole. Nothing
//! of the session rests in the stack's attribute store.
//!
//! The answer to a `setup` write is acknowledged, then its two header bytes
//! are notified; the browser reads the value. The connection is the carrier
//! session: one peer at a time, and when it leaves the session in flight is
//! dropped. The service is advertised only while the setup window is open
//! and nobody is connected; [`BleProvisioning::tick`] (call it every second
//! or so) starts and stops the advertising as the window moves.
//!
//! The firmware owns the modem and builds the [`BtDriver`]; it calls
//! [`BleProvisioning::start`] and waits on the returned receiver for what the
//! station policy asks (normally [`Action::Connect`], the network then in
//! the provisioner). Wi-Fi events go back in through
//! [`BleProvisioning::on_event`], and the phase reaches a subscribed phone
//! as a notification.
//!
//! No `unsafe`: the FFI boundary is `esp-idf-svc`'s.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};

use enumset::enum_set;
use esp_idf_svc::bt::ble::gap::{AdvConfiguration, BleGapEvent, EspBleGap};
use esp_idf_svc::bt::ble::gatt::server::{ConnectionId, EspGatts, GattsEvent, TransferId};
use esp_idf_svc::bt::ble::gatt::{
    AutoResponse, GattCharacteristic, GattDescriptor, GattId, GattInterface, GattResponse,
    GattServiceId, GattStatus, Handle, Permission, Property,
};
use esp_idf_svc::bt::{BdAddr, Ble, BtDriver, BtStatus, BtUuid};
use esp_idf_svc::sys::{ESP_FAIL, EspError};
use rusty_esp_signal_core::ble as core_ble;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::provision::{Outcome, Provisioner, SCAN_ENTRIES, ScanList, SetupEnv};
use rusty_esp_signal_core::setup::MAX_MESSAGE;
use rusty_esp_signal_core::wifi::{Action, Event};

/// The Bluetooth driver the firmware builds (it owns the modem).
pub type Driver = Arc<BtDriver<'static, Ble>>;
type Gap = Arc<EspBleGap<'static, Ble, Driver>>;
type Gatts = Arc<EspGatts<'static, Ble, Driver>>;

/// The GATTS application id this service registers under.
pub const APP_ID: u16 = 0x4a4e;
/// The Client Characteristic Configuration descriptor.
const CCCD: u16 = 0x2902;
/// Handles the service needs: itself, three characteristics (declaration and
/// value each) and two descriptors, with room.
const SERVICE_HANDLES: u16 = 12;
/// The core table's sizes for `setup` and `discover`.
const SETUP_MAX: usize = core_ble::SETUP_VALUE_LEN as usize;
const DISCOVER_MAX: usize = core_ble::DISCOVER_VALUE_LEN as usize;

fn bt_uuid(u: core_ble::Uuid128) -> BtUuid {
    BtUuid::uuid128(u128::from_be_bytes(u.to_bytes()))
}

/// The peer: the carrier session.
struct Connection {
    conn_id: ConnectionId,
    peer: BdAddr,
    status_subscribed: bool,
    setup_subscribed: bool,
    /// A prepared write to `setup` being assembled.
    prepared: Vec<u8>,
}

/// Which attribute follows the one whose event just arrived. The table is
/// built one attribute at a time so each descriptor lands behind its own
/// characteristic.
enum Next {
    StatusCccd,
    Setup,
    SetupCccd,
    Discover,
    Done,
}

struct State<E: SetupEnv, const N: usize> {
    gatt_if: Option<GattInterface>,
    /// The phase byte the table is started with.
    phase_byte: u8,
    service: Option<Handle>,
    status: Option<Handle>,
    status_cccd: Option<Handle>,
    setup: Option<Handle>,
    setup_cccd: Option<Handle>,
    discover: Option<Handle>,
    connection: Option<Connection>,
    /// The radio is advertising (or was asked to start).
    advertising: bool,
    provisioner: Provisioner<E, N>,
}

/// The provisioning service, running. Clones share the one session.
pub struct BleProvisioning<E: SetupEnv, const N: usize = SCAN_ENTRIES> {
    gap: Gap,
    gatts: Gatts,
    name: String,
    state: Arc<Mutex<State<E, N>>>,
    actions: Sender<Action>,
    now: Arc<dyn Fn() -> Micros + Send + Sync>,
}

impl<E: SetupEnv, const N: usize> Clone for BleProvisioning<E, N> {
    fn clone(&self) -> Self {
        Self {
            gap: Arc::clone(&self.gap),
            gatts: Arc::clone(&self.gatts),
            name: self.name.clone(),
            state: Arc::clone(&self.state),
            actions: self.actions.clone(),
            now: Arc::clone(&self.now),
        }
    }
}

impl<E: SetupEnv, const N: usize> core::fmt::Debug for BleProvisioning<E, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BleProvisioning")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<E: SetupEnv + Send + 'static, const N: usize> BleProvisioning<E, N> {
    /// Start: register the application (Bluedroid confirms, then the service
    /// is created and started, and advertised as `name` while the setup
    /// window is open), and hand every policy instruction to the returned
    /// receiver. `now` is the firmware's monotonic clock, the one the
    /// session's window and the policy's backoff run on.
    pub fn start(
        driver: Driver,
        name: &str,
        provisioner: Provisioner<E, N>,
        now: impl Fn() -> Micros + Send + Sync + 'static,
    ) -> Result<(Self, Receiver<Action>), EspError> {
        let gap = Arc::new(EspBleGap::new(Arc::clone(&driver))?);
        let gatts = Arc::new(EspGatts::new(driver)?);
        let (tx, rx) = mpsc::channel();
        let this = Self {
            gap,
            gatts,
            // what a scan response carries: Bluedroid refuses a longer name
            // and the service is never created
            name: core_ble::advertised_name(name).to_owned(),
            state: Arc::new(Mutex::new(State {
                gatt_if: None,
                phase_byte: 0,
                service: None,
                status: None,
                status_cccd: None,
                setup: None,
                setup_cccd: None,
                discover: None,
                connection: None,
                advertising: false,
                provisioner,
            })),
            actions: tx,
            now: Arc::new(now),
        };
        let gap_cb = this.clone();
        this.gap
            .subscribe(move |event| gap_cb.report(gap_cb.on_gap(event)))?;
        let gatts_cb = this.clone();
        this.gatts.subscribe(move |(gatt_if, event)| {
            gatts_cb.report(gatts_cb.on_gatts(gatt_if, event));
        })?;
        this.gatts.register_app(APP_ID)?;
        Ok((this, rx))
    }

    fn lock(&self) -> MutexGuard<'_, State<E, N>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Run `f` over the session: the network, the policy, the phase.
    pub fn with_provisioner<R>(&self, f: impl FnOnce(&mut Provisioner<E, N>) -> R) -> R {
        f(&mut self.lock().provisioner)
    }

    /// The networks the device saw, strongest first: sent, sealed, in the
    /// next session's Ready.
    pub fn set_scan(&self, scan: ScanList<N>) {
        self.lock().provisioner.set_scan(scan);
    }

    /// A station event from the Wi-Fi driver: the policy answers, and a
    /// changed phase reaches a subscribed phone.
    pub fn on_event(&self, event: Event) -> Result<Action, EspError> {
        let now = (self.now)();
        let mut st = self.lock();
        let outcome = st.provisioner.on_event(event, now);
        self.publish_status(&mut st, outcome.status)?;
        Ok(outcome.action)
    }

    /// The button: the setup window opens for its 600 s, and the service is
    /// advertised.
    pub fn button(&self) -> Result<(), EspError> {
        let now = (self.now)();
        self.lock().provisioner.button(now);
        self.tick()
    }

    /// Time passed: an idle session is dropped, and the advertising follows
    /// the window (on while it is open and nobody is connected, off
    /// otherwise). Call it every second or so.
    pub fn tick(&self) -> Result<(), EspError> {
        let now = (self.now)();
        let (want, have) = {
            let mut st = self.lock();
            st.provisioner.tick(now);
            let want =
                st.service.is_some() && st.connection.is_none() && st.provisioner.advertising(now);
            (want, st.advertising)
        };
        match (want, have) {
            (true, false) => self.advertise(),
            (false, true) => {
                self.lock().advertising = false;
                self.gap.stop_advertising()
            }
            _ => Ok(()),
        }
    }

    fn publish_status(&self, st: &mut State<E, N>, status: Option<u8>) -> Result<(), EspError> {
        let Some(byte) = status else {
            return Ok(());
        };
        let (Some(gatt_if), Some(handle)) = (st.gatt_if, st.status) else {
            return Ok(());
        };
        self.gatts.set_attr(handle, &[byte])?;
        if let Some(c) = st.connection.as_ref().filter(|c| c.status_subscribed) {
            self.gatts.notify(gatt_if, c.conn_id, handle, &[byte])?;
        }
        Ok(())
    }

    /// The advertisement carries the flags and the 128-bit provisioning
    /// service UUID and nothing else: that is 21 of the 31 bytes a legacy
    /// advertisement holds (`core_ble::provisioning_adv_len`), and a device
    /// name never fits in the 8 that remain. Asking for it anyway costs the
    /// UUID — Bluedroid logs `BTM_BleWriteAdvData, Partial data write into
    /// ADV` and a browser filtering on the service then never sees the
    /// device. The name goes in the scan response instead, which a scanner
    /// reads before it shows anything to a person.
    fn advertise(&self) -> Result<(), EspError> {
        self.lock().advertising = true;
        self.gap.set_adv_conf(&AdvConfiguration {
            include_name: false,
            flag: 2,
            service_uuid: Some(bt_uuid(core_ble::SERVICE_PROVISIONING)),
            ..Default::default()
        })
    }

    /// The device's name, in the scan response an active scanner asks for.
    fn scan_response(&self) -> Result<(), EspError> {
        self.gap.set_adv_conf(&AdvConfiguration {
            set_scan_rsp: true,
            include_name: true,
            ..Default::default()
        })
    }

    fn on_gap(&self, event: BleGapEvent) -> Result<(), EspError> {
        match event {
            // configured in order: advertisement, then scan response, then
            // the radio starts — a scanner that sees one sees both.
            BleGapEvent::AdvertisingConfigured(status) => {
                self.check_bt(status)?;
                self.scan_response()?;
            }
            BleGapEvent::ScanResponseConfigured(status) => {
                self.check_bt(status)?;
                // the window may have closed, or a peer arrived, meanwhile
                if self.lock().advertising {
                    self.gap.start_advertising()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn on_gatts(&self, gatt_if: GattInterface, event: GattsEvent) -> Result<(), EspError> {
        match event {
            GattsEvent::ServiceRegistered { status, app_id } => {
                self.check_gatt(status)?;
                if app_id == APP_ID {
                    self.create_service(gatt_if)?;
                }
            }
            GattsEvent::ServiceCreated {
                status,
                service_handle,
                ..
            } => {
                self.check_gatt(status)?;
                self.start_service(service_handle)?;
            }
            GattsEvent::CharacteristicAdded {
                status,
                attr_handle,
                service_handle,
                char_uuid,
            } => {
                self.check_gatt(status)?;
                self.characteristic_added(service_handle, attr_handle, char_uuid)?;
            }
            GattsEvent::DescriptorAdded {
                status,
                attr_handle,
                service_handle,
                descr_uuid,
            } => {
                self.check_gatt(status)?;
                if descr_uuid == BtUuid::uuid16(CCCD) {
                    self.cccd_added(service_handle, attr_handle)?;
                }
            }
            GattsEvent::PeerConnected { conn_id, addr, .. } => self.connected(conn_id, addr)?,
            GattsEvent::PeerDisconnected { addr, .. } => self.disconnected(addr)?,
            GattsEvent::Read {
                conn_id,
                trans_id,
                handle,
                offset,
                need_rsp,
                ..
            } => self.read(gatt_if, conn_id, trans_id, handle, offset, need_rsp)?,
            GattsEvent::Write {
                conn_id,
                trans_id,
                handle,
                offset,
                need_rsp,
                is_prep,
                value,
                ..
            } => self.written(
                gatt_if, conn_id, trans_id, handle, offset, need_rsp, is_prep, value,
            )?,
            GattsEvent::ExecWrite {
                conn_id,
                trans_id,
                canceled,
                ..
            } => self.executed(gatt_if, conn_id, trans_id, canceled)?,
            _ => {}
        }
        Ok(())
    }

    fn create_service(&self, gatt_if: GattInterface) -> Result<(), EspError> {
        self.lock().gatt_if = Some(gatt_if);
        self.gap.set_device_name(&self.name)?;
        self.gatts.create_service(
            gatt_if,
            &GattServiceId {
                id: GattId {
                    uuid: bt_uuid(core_ble::SERVICE_PROVISIONING),
                    inst_id: 0,
                },
                is_primary: true,
            },
            SERVICE_HANDLES,
        )
    }

    fn start_service(&self, service: Handle) -> Result<(), EspError> {
        {
            let mut st = self.lock();
            st.service = Some(service);
            st.phase_byte = st.provisioner.phase().as_u8();
        }
        self.gatts.start_service(service)?;
        // One attribute at a time, each added when the last one's event
        // arrives: a descriptor belongs to whichever characteristic precedes
        // it in the attribute table, so queueing the characteristics first
        // would put a CCCD behind the wrong one and leave its characteristic
        // unsubscribable ("GATT Error: Not supported" in a browser).
        self.add_status(service)
    }

    /// `status`: the phase byte, readable and notified. Its CCCD follows it.
    fn add_status(&self, service: Handle) -> Result<(), EspError> {
        let phase = self.lock().phase_byte;
        self.gatts.add_characteristic(
            service,
            &GattCharacteristic {
                uuid: bt_uuid(core_ble::CHAR_STATUS),
                permissions: enum_set!(Permission::Read),
                properties: enum_set!(Property::Read | Property::Notify),
                max_len: 1,
                auto_rsp: AutoResponse::ByGatt,
            },
            &[phase],
        )
    }

    /// `setup`: the session's messages, answered by the app. Its CCCD
    /// follows it.
    fn add_setup(&self, service: Handle) -> Result<(), EspError> {
        self.gatts.add_characteristic(
            service,
            &GattCharacteristic {
                uuid: bt_uuid(core_ble::CHAR_SETUP),
                permissions: enum_set!(Permission::Read | Permission::Write),
                properties: enum_set!(Property::Read | Property::Write | Property::Notify),
                max_len: SETUP_MAX,
                auto_rsp: AutoResponse::ByApp,
            },
            &[],
        )
    }

    /// `discover`: the session's Discover, made fresh for every read. Last.
    fn add_discover(&self, service: Handle) -> Result<(), EspError> {
        self.gatts.add_characteristic(
            service,
            &GattCharacteristic {
                uuid: bt_uuid(core_ble::CHAR_DISCOVER),
                permissions: enum_set!(Permission::Read),
                properties: enum_set!(Property::Read),
                max_len: DISCOVER_MAX,
                auto_rsp: AutoResponse::ByApp,
            },
            &[],
        )
    }

    fn add_cccd(&self, service: Handle) -> Result<(), EspError> {
        self.gatts.add_descriptor(
            service,
            &GattDescriptor {
                uuid: BtUuid::uuid16(CCCD),
                permissions: enum_set!(Permission::Read | Permission::Write),
            },
        )
    }

    fn characteristic_added(
        &self,
        service: Handle,
        attr: Handle,
        uuid: BtUuid,
    ) -> Result<(), EspError> {
        let next = {
            let mut st = self.lock();
            if st.service != Some(service) {
                return Ok(());
            }
            if uuid == bt_uuid(core_ble::CHAR_STATUS) {
                st.status = Some(attr);
                Next::StatusCccd
            } else if uuid == bt_uuid(core_ble::CHAR_SETUP) {
                st.setup = Some(attr);
                Next::SetupCccd
            } else if uuid == bt_uuid(core_ble::CHAR_DISCOVER) {
                st.discover = Some(attr);
                Next::Done
            } else {
                Next::Done
            }
        };
        self.add(service, next)
    }

    fn cccd_added(&self, service: Handle, attr: Handle) -> Result<(), EspError> {
        let next = {
            let mut st = self.lock();
            if st.service != Some(service) {
                return Ok(());
            }
            // the CCCDs arrive in table order: `status`'s, then `setup`'s
            if st.status_cccd.is_none() {
                st.status_cccd = Some(attr);
                Next::Setup
            } else {
                st.setup_cccd = Some(attr);
                Next::Discover
            }
        };
        self.add(service, next)
    }

    fn add(&self, service: Handle, next: Next) -> Result<(), EspError> {
        match next {
            Next::StatusCccd | Next::SetupCccd => self.add_cccd(service),
            Next::Setup => self.add_setup(service),
            Next::Discover => self.add_discover(service),
            // the table is whole: advertise if the window is open
            Next::Done => self.tick(),
        }
    }

    fn connected(&self, conn_id: ConnectionId, peer: BdAddr) -> Result<(), EspError> {
        let mut st = self.lock();
        if st.connection.is_none() {
            st.connection = Some(Connection {
                conn_id,
                peer,
                status_subscribed: false,
                setup_subscribed: false,
                prepared: Vec::new(),
            });
        }
        // a connection stops the advertising; one peer is the carrier session
        st.advertising = false;
        Ok(())
    }

    fn disconnected(&self, peer: BdAddr) -> Result<(), EspError> {
        {
            let mut st = self.lock();
            if st.connection.as_ref().is_some_and(|c| c.peer == peer) {
                st.connection = None;
                st.provisioner.carrier_closed();
            }
        }
        self.tick()
    }

    /// A read the app answers: `setup` or `discover`, from `offset`.
    fn read(
        &self,
        gatt_if: GattInterface,
        conn_id: ConnectionId,
        trans_id: TransferId,
        handle: Handle,
        offset: u16,
        need_rsp: bool,
    ) -> Result<(), EspError> {
        if !need_rsp {
            return Ok(());
        }
        let now = (self.now)();
        let mut buf = [0u8; SETUP_MAX];
        let (status, n) = {
            let st = self.lock();
            let uuid = if Some(handle) == st.setup {
                Some(core_ble::CHAR_SETUP)
            } else if Some(handle) == st.discover {
                Some(core_ble::CHAR_DISCOVER)
            } else {
                None
            };
            match uuid.map(|u| st.provisioner.read(u, now, &mut buf)) {
                Some(Ok(n)) if usize::from(offset) <= n => (GattStatus::Ok, n),
                Some(Ok(_)) => (GattStatus::InvalidOffset, 0),
                Some(Err(_)) => (GattStatus::ErrUnlikely, 0),
                None => (GattStatus::InvalidHandle, 0),
            }
        };
        let mut rsp = GattResponse::new();
        if matches!(status, GattStatus::Ok) {
            // Bluedroid sends as much of it as the MTU takes; a long read
            // asks again at the next offset
            rsp.attr_handle(handle)
                .offset(offset)
                .value(&buf[usize::from(offset)..n])?;
        }
        self.gatts
            .send_response(gatt_if, conn_id, trans_id, status, Some(&rsp))
    }

    #[allow(clippy::too_many_arguments)]
    fn written(
        &self,
        gatt_if: GattInterface,
        conn_id: ConnectionId,
        trans_id: TransferId,
        handle: Handle,
        offset: u16,
        need_rsp: bool,
        is_prep: bool,
        value: &[u8],
    ) -> Result<(), EspError> {
        let mut answered = None;
        let status = {
            let mut st = self.lock();
            let (status_cccd, setup_cccd, setup) = (st.status_cccd, st.setup_cccd, st.setup);
            let Some(c) = st.connection.as_mut().filter(|c| c.conn_id == conn_id) else {
                drop(st);
                return self.respond(gatt_if, conn_id, trans_id, need_rsp, GattStatus::WrongState);
            };
            if Some(handle) == status_cccd || Some(handle) == setup_cccd {
                if offset == 0 && value.len() == 2 {
                    let on = value[0] & 0x01 == 0x01;
                    if Some(handle) == status_cccd {
                        c.status_subscribed = on;
                    } else {
                        c.setup_subscribed = on;
                    }
                }
                GattStatus::Ok
            } else if Some(handle) == setup && is_prep {
                // one part of a long write: kept until the execute, and
                // echoed back as the prepare-write response must be
                if usize::from(offset) != c.prepared.len() {
                    GattStatus::InvalidOffset
                } else if c.prepared.len() + value.len() > SETUP_MAX {
                    c.prepared.clear();
                    GattStatus::PrepareQueueFull
                } else {
                    c.prepared.extend_from_slice(value);
                    drop(st);
                    if need_rsp {
                        let mut rsp = GattResponse::new();
                        rsp.attr_handle(handle).offset(offset).value(value)?;
                        self.gatts.send_response(
                            gatt_if,
                            conn_id,
                            trans_id,
                            GattStatus::Ok,
                            Some(&rsp),
                        )?;
                    }
                    return Ok(());
                }
            } else if Some(handle) == setup {
                if offset != 0 {
                    GattStatus::InvalidOffset
                } else {
                    let (status, outcome) = self.session(&mut st, value);
                    answered = outcome;
                    status
                }
            } else {
                GattStatus::InvalidHandle
            }
        };
        self.respond(gatt_if, conn_id, trans_id, need_rsp, status)?;
        if let Some(outcome) = answered {
            self.answered(gatt_if, outcome)?;
        }
        Ok(())
    }

    /// The execute that ends a long write: the assembled message goes to
    /// the session (or, cancelled, is dropped).
    fn executed(
        &self,
        gatt_if: GattInterface,
        conn_id: ConnectionId,
        trans_id: TransferId,
        canceled: bool,
    ) -> Result<(), EspError> {
        let mut answered = None;
        let status = {
            let mut st = self.lock();
            let message = match st.connection.as_mut().filter(|c| c.conn_id == conn_id) {
                Some(c) => core::mem::take(&mut c.prepared),
                None => Vec::new(),
            };
            if canceled || message.is_empty() {
                GattStatus::Ok
            } else {
                let (status, outcome) = self.session(&mut st, &message);
                answered = outcome;
                status
            }
        };
        self.respond(gatt_if, conn_id, trans_id, true, status)?;
        if let Some(outcome) = answered {
            self.answered(gatt_if, outcome)?;
        }
        Ok(())
    }

    /// One whole message to the session, its time on the device logged as
    /// the Track B backend's `serve_observed` reports it
    /// (`setup msg=<kind> took_us=<n>`).
    fn session(&self, st: &mut State<E, N>, message: &[u8]) -> (GattStatus, Option<Outcome>) {
        let now = (self.now)();
        let result = st.provisioner.on_write(core_ble::CHAR_SETUP, message, now);
        let took = (self.now)().0.saturating_sub(now.0);
        let kind = match message.get(1) {
            Some(0x01) => "Start",
            Some(0x03) => "Confirm",
            Some(0x05) => "Settings",
            _ => "other",
        };
        log::info!("setup msg={kind} took_us={took}");
        match result {
            Ok(outcome) => (GattStatus::Ok, Some(outcome)),
            // not an answer: the device could not take it at all
            Err(_) => (GattStatus::ErrUnlikely, None),
        }
    }

    /// After the write is acknowledged: the answer's header notified, the
    /// phase published, the policy's instruction handed on.
    fn answered(&self, gatt_if: GattInterface, outcome: Outcome) -> Result<(), EspError> {
        let mut st = self.lock();
        if let (Some(header), Some(handle)) = (outcome.answer, st.setup) {
            if let Some(c) = st.connection.as_ref().filter(|c| c.setup_subscribed) {
                self.gatts.notify(gatt_if, c.conn_id, handle, &header)?;
            }
        }
        self.publish_status(&mut st, outcome.status)?;
        if outcome.action != Action::None {
            let _ = self.actions.send(outcome.action);
        }
        Ok(())
    }

    fn respond(
        &self,
        gatt_if: GattInterface,
        conn_id: ConnectionId,
        trans_id: TransferId,
        need_rsp: bool,
        status: GattStatus,
    ) -> Result<(), EspError> {
        if need_rsp {
            self.gatts
                .send_response(gatt_if, conn_id, trans_id, status, None)?;
        }
        Ok(())
    }

    fn report(&self, r: Result<(), EspError>) {
        if let Err(e) = r {
            log::warn!("ble provisioning: {e:?}");
        }
    }

    fn check_bt(&self, s: BtStatus) -> Result<(), EspError> {
        if matches!(s, BtStatus::Success) {
            Ok(())
        } else {
            log::warn!("gap: {s:?}");
            Err(EspError::from_infallible::<ESP_FAIL>())
        }
    }

    fn check_gatt(&self, s: GattStatus) -> Result<(), EspError> {
        if matches!(s, GattStatus::Ok) {
            Ok(())
        } else {
            log::warn!("gatts: {s:?}");
            Err(EspError::from_infallible::<ESP_FAIL>())
        }
    }
}

/// The message never exceeds the attribute the table declares.
const _: () = assert!(MAX_MESSAGE == SETUP_MAX);

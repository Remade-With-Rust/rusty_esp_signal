//! The Janus provisioning GATT service on ESP-IDF's Bluedroid host (Track A).
//!
//! The same contract as [`crate::ble`] (Track B, `trouble-host`): the core's
//! provisioning service — `credentials` WRITE, `status` READ | NOTIFY,
//! `scan` READ — served through `esp-idf-svc`'s [`EspGatts`] and
//! [`EspBleGap`], with the core's [`Provisioner`] as the one object that
//! knows the credentials, the policy and what to do next. Bluedroid answers
//! reads of `status` and `scan` itself from attribute values this module
//! sets ([`AutoResponse::ByGatt`]); `credentials` is answered by the app, so
//! the passphrase never rests in the stack's attribute store — it goes from
//! the write event into the core's `Credentials`, which redacts in `Debug`
//! and zeroises on drop.
//!
//! The firmware owns the modem and builds the [`BtDriver`]; it calls
//! [`BleProvisioning::start`] and waits on the returned receiver for what the
//! station policy asks (normally [`Action::Connect`], the credentials then in
//! the provisioner). Wi-Fi events go back in through
//! [`BleProvisioning::on_event`], and the phase reaches every subscribed
//! phone as a notification.
//!
//! No `unsafe`: the FFI boundary is `esp-idf-svc`'s.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};

use enumset::enum_set;
use esp_idf_svc::bt::ble::gap::{AdvConfiguration, BleGapEvent, EspBleGap};
use esp_idf_svc::bt::ble::gatt::server::{ConnectionId, EspGatts, GattsEvent, TransferId};
use esp_idf_svc::bt::ble::gatt::{
    AutoResponse, GattCharacteristic, GattDescriptor, GattId, GattInterface, GattServiceId,
    GattStatus, Handle, Permission, Property,
};
use esp_idf_svc::bt::{BdAddr, Ble, BtDriver, BtStatus, BtUuid};
use esp_idf_svc::sys::{ESP_FAIL, EspError};
use rusty_esp_signal_core::ble as core_ble;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::provision::{Provisioner, SCAN_ENTRIES, ScanList};
use rusty_esp_signal_core::wifi::{Action, Event};

/// The Bluetooth driver the firmware builds (it owns the modem).
pub type Driver = Arc<BtDriver<'static, Ble>>;
type Gap = Arc<EspBleGap<'static, Ble, Driver>>;
type Gatts = Arc<EspGatts<'static, Ble, Driver>>;

/// The GATTS application id this service registers under.
pub const APP_ID: u16 = 0x4a4e;
/// Peers served at once.
pub const MAX_CONNECTIONS: usize = 2;
/// The Client Characteristic Configuration descriptor.
const CCCD: u16 = 0x2902;
/// Handles the service needs: itself, three characteristics (declaration and
/// value each) and one descriptor, with room.
const SERVICE_HANDLES: u16 = 10;
/// The core table's sizes for `credentials` and `scan`.
const CREDENTIALS_MAX: usize = 100;
const SCAN_MAX: usize = 240;

fn bt_uuid(u: core_ble::Uuid128) -> BtUuid {
    BtUuid::uuid128(u128::from_be_bytes(u.to_bytes()))
}

#[derive(Debug, Clone)]
struct Connection {
    conn_id: ConnectionId,
    peer: BdAddr,
    subscribed: bool,
}

struct State<const N: usize> {
    gatt_if: Option<GattInterface>,
    service: Option<Handle>,
    credentials: Option<Handle>,
    status: Option<Handle>,
    status_cccd: Option<Handle>,
    scan: Option<Handle>,
    connections: Vec<Connection>,
    provisioner: Provisioner<N>,
}

/// The provisioning service, running. Clones share the one session.
pub struct BleProvisioning<const N: usize = SCAN_ENTRIES> {
    gap: Gap,
    gatts: Gatts,
    name: String,
    state: Arc<Mutex<State<N>>>,
    actions: Sender<Action>,
    now: Arc<dyn Fn() -> Micros + Send + Sync>,
}

impl<const N: usize> Clone for BleProvisioning<N> {
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

impl<const N: usize> core::fmt::Debug for BleProvisioning<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BleProvisioning")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl<const N: usize> BleProvisioning<N> {
    /// Start: register the application (Bluedroid confirms, then the service
    /// is created, started and advertised as `name`), and hand every policy
    /// instruction to the returned receiver. `now` is the firmware's
    /// monotonic clock for the policy's backoff.
    pub fn start(
        driver: Driver,
        name: &str,
        provisioner: Provisioner<N>,
        now: impl Fn() -> Micros + Send + Sync + 'static,
    ) -> Result<(Self, Receiver<Action>), EspError> {
        let gap = Arc::new(EspBleGap::new(Arc::clone(&driver))?);
        let gatts = Arc::new(EspGatts::new(driver)?);
        let (tx, rx) = mpsc::channel();
        let this = Self {
            gap,
            gatts,
            name: name.to_owned(),
            state: Arc::new(Mutex::new(State {
                gatt_if: None,
                service: None,
                credentials: None,
                status: None,
                status_cccd: None,
                scan: None,
                connections: Vec::new(),
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

    fn lock(&self) -> MutexGuard<'_, State<N>> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Run `f` over the session: the credentials, the policy, the phase.
    pub fn with_provisioner<R>(&self, f: impl FnOnce(&mut Provisioner<N>) -> R) -> R {
        f(&mut self.lock().provisioner)
    }

    /// Publish the networks the device saw, strongest first.
    pub fn set_scan(&self, scan: ScanList<N>) -> Result<(), EspError> {
        let mut st = self.lock();
        st.provisioner.set_scan(scan);
        let mut buf = [0u8; SCAN_MAX];
        let n = st
            .provisioner
            .read(core_ble::CHAR_SCAN, &mut buf)
            .unwrap_or(0);
        if let Some(handle) = st.scan {
            self.gatts.set_attr(handle, &buf[..n])?;
        }
        Ok(())
    }

    /// A station event from the Wi-Fi driver: the policy answers, and a
    /// changed phase reaches every subscribed phone.
    pub fn on_event(&self, event: Event) -> Result<Action, EspError> {
        let now = (self.now)();
        let mut st = self.lock();
        let outcome = st.provisioner.on_event(event, now);
        self.publish_status(&mut st, outcome.status)?;
        Ok(outcome.action)
    }

    fn publish_status(&self, st: &mut State<N>, status: Option<u8>) -> Result<(), EspError> {
        let Some(byte) = status else {
            return Ok(());
        };
        let (Some(gatt_if), Some(handle)) = (st.gatt_if, st.status) else {
            return Ok(());
        };
        self.gatts.set_attr(handle, &[byte])?;
        for c in st.connections.iter().filter(|c| c.subscribed) {
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
                self.gap.start_advertising()?;
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
                    let mut st = self.lock();
                    if st.service == Some(service_handle) {
                        st.status_cccd = Some(attr_handle);
                    }
                }
            }
            GattsEvent::PeerConnected { conn_id, addr, .. } => self.connected(conn_id, addr)?,
            GattsEvent::PeerDisconnected { addr, .. } => self.disconnected(addr)?,
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
            _ => {}
        }
        Ok(())
    }

    fn create_service(&self, gatt_if: GattInterface) -> Result<(), EspError> {
        self.lock().gatt_if = Some(gatt_if);
        self.gap.set_device_name(&self.name)?;
        self.advertise()?;
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
        let (status, scan) = {
            let mut st = self.lock();
            st.service = Some(service);
            let mut buf = [0u8; SCAN_MAX];
            let n = st
                .provisioner
                .read(core_ble::CHAR_SCAN, &mut buf)
                .unwrap_or(0);
            (st.provisioner.phase().as_u8(), buf[..n].to_vec())
        };
        self.gatts.start_service(service)?;
        // credentials: written by the phone, answered by the app, never readable
        self.gatts.add_characteristic(
            service,
            &GattCharacteristic {
                uuid: bt_uuid(core_ble::CHAR_CREDENTIALS),
                permissions: enum_set!(Permission::Write),
                properties: enum_set!(Property::Write),
                max_len: CREDENTIALS_MAX,
                auto_rsp: AutoResponse::ByApp,
            },
            &[],
        )?;
        // status: the phase byte, readable and notified
        self.gatts.add_characteristic(
            service,
            &GattCharacteristic {
                uuid: bt_uuid(core_ble::CHAR_STATUS),
                permissions: enum_set!(Permission::Read),
                properties: enum_set!(Property::Read | Property::Notify),
                max_len: 1,
                auto_rsp: AutoResponse::ByGatt,
            },
            &[status],
        )?;
        // scan: the networks seen, strongest first
        self.gatts.add_characteristic(
            service,
            &GattCharacteristic {
                uuid: bt_uuid(core_ble::CHAR_SCAN),
                permissions: enum_set!(Permission::Read),
                properties: enum_set!(Property::Read),
                max_len: SCAN_MAX,
                auto_rsp: AutoResponse::ByGatt,
            },
            &scan,
        )?;
        Ok(())
    }

    fn characteristic_added(
        &self,
        service: Handle,
        attr: Handle,
        uuid: BtUuid,
    ) -> Result<(), EspError> {
        let add_cccd = {
            let mut st = self.lock();
            if st.service != Some(service) {
                return Ok(());
            }
            if uuid == bt_uuid(core_ble::CHAR_CREDENTIALS) {
                st.credentials = Some(attr);
                false
            } else if uuid == bt_uuid(core_ble::CHAR_STATUS) {
                st.status = Some(attr);
                true
            } else if uuid == bt_uuid(core_ble::CHAR_SCAN) {
                st.scan = Some(attr);
                false
            } else {
                false
            }
        };
        if add_cccd {
            self.gatts.add_descriptor(
                service,
                &GattDescriptor {
                    uuid: BtUuid::uuid16(CCCD),
                    permissions: enum_set!(Permission::Read | Permission::Write),
                },
            )?;
        }
        Ok(())
    }

    fn connected(&self, conn_id: ConnectionId, peer: BdAddr) -> Result<(), EspError> {
        let accepted = {
            let mut st = self.lock();
            if st.connections.len() < MAX_CONNECTIONS {
                st.connections.push(Connection {
                    conn_id,
                    peer,
                    subscribed: false,
                });
                true
            } else {
                false
            }
        };
        if accepted {
            // keep advertising so a second phone can find the device
            self.advertise()?;
        }
        Ok(())
    }

    fn disconnected(&self, peer: BdAddr) -> Result<(), EspError> {
        let removed = {
            let mut st = self.lock();
            match st.connections.iter().position(|c| c.peer == peer) {
                Some(i) => {
                    st.connections.swap_remove(i);
                    true
                }
                None => false,
            }
        };
        if removed {
            self.advertise()?;
        }
        Ok(())
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
        let status = {
            let mut st = self.lock();
            if Some(handle) == st.status_cccd {
                if offset == 0 && value.len() == 2 {
                    if let Some(c) = st.connections.iter_mut().find(|c| c.conn_id == conn_id) {
                        c.subscribed = value[0] & 0x01 == 0x01;
                    }
                }
                GattStatus::Ok
            } else if Some(handle) == st.credentials {
                if is_prep || offset != 0 {
                    // one write carries the whole TLV; long writes are not part of the contract
                    GattStatus::ReqNotSupported
                } else {
                    let now = (self.now)();
                    match st
                        .provisioner
                        .on_write(core_ble::CHAR_CREDENTIALS, value, now)
                    {
                        Ok(outcome) => {
                            self.publish_status(&mut st, outcome.status)?;
                            let _ = self.actions.send(outcome.action);
                            GattStatus::Ok
                        }
                        // the TLV did not decode; nothing was kept
                        Err(_) => GattStatus::InvalidAttrLen,
                    }
                }
            } else {
                GattStatus::InvalidHandle
            }
        };
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

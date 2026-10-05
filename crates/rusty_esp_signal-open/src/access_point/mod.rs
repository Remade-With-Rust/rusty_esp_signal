//! The access point on the open lower MAC (the umbrella's experiments
//! plan, row E3; P2-P7 on the bench XIAO). **Not Wi-Fi certified.**
//!
//! The same shape as the station half and `rusty_esp_signal-esp`'s
//! `hal::netstack` hosting: [`hosted_stack`] brings the MAC up as an access
//! point and gives the embassy-net [`Stack`] at a fixed address plus the
//! runners to spawn ([`mac_task`], [`ap_task`], [`net_task`],
//! [`dhcp_server_task`]). The access point's decisions and frames are
//! `ap_core`'s (host-tested, checked by an independent Python); this module
//! is the runner: beacons at each TBTT from the S3's soft-AP TSF, the
//! station table, WPA2-PSK as authenticator with the hardware's key slots
//! (CCMP header, packet numbers and replay checks ours), the group key
//! rotated on a schedule and when a station leaves, frames held for dozing
//! stations (TIM, PS-Poll, the wake, the DTIM), WMM and HT with a rate
//! ladder per station, re-association, class-3 frames from strangers
//! answered, stations gone quiet dropped. The PHY is Espressif's `libphy`,
//! untouched. Counters for the firmware's watch line: [`stats`].
//!
//! WPA2-PSK (a passphrase of 8 to 63 bytes) or, for a device's setup
//! network, an open one ([`AccessPointConfig::open`]).

mod tsf;

use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::raw_link::{RawLink, RawRunner};
use ap_core::frames::{self, Bss};
use ap_core::handshake::{self, Authenticator};
use ap_core::hold::Held;
use ap_core::qos::{self, HtCapabilities};
use ap_core::request::{self, Request};
use ap_core::stations::{MAX_STATIONS, State, Stations};
use ap_core::{Address, reason, status};
use embassy_futures::select::{Either3, select3};
use embassy_net::{Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4};
use embassy_net_driver::{HardwareAddress, LinkState};
use embassy_net_driver_channel as ch;
use embassy_time::{Duration, Instant, Timer};
use esp_hal::rng::Rng;
use foa::LMacInterfaceControl;
use foa::RxEndpoint;
use foa::esp_wifi_hal::ll::EdcaAccessCategory;
use foa::esp_wifi_hal::prelude::{
    AesCipherParameters, CipherParameters, ControlFrameFilterConfig, KeyType, MultiLengthKey,
    RxFilterBank, TxMacParameters, TxPlcpParameters,
};
use foa::esp_wifi_hal::rates::{HrDsssRate, HtRate, OfdmRate, TxPhyRate};
use foa::{FoAResources, FoARunner, KeySlot, RetryBehaviour, TxEndpoint, VirtualInterface};

/// The library says nothing; the counters say it.
macro_rules! note {
    ($($t:tt)*) => {};
}
use sta_handshake::GroupKey;
use static_cell::{ConstStaticCell, StaticCell};

/// An EAPOL-Key frame not answered within this is sent again (802.11's
/// dot11RSNAConfigPairwiseUpdateTimeOut is 100 ms; a laptop's supplicant
/// may take longer, so 1 s), at most this many times, then the station is
/// deauthenticated (reason 15).
const HANDSHAKE_RESEND_US: u64 = 1_000_000;
const HANDSHAKE_RESENDS: u8 = 3;
const GTK_KEY_ID: u8 = 1;
const BEACON_INTERVAL_TU: u16 = 100;
const DTIM_PERIOD: u8 = 2;
/// The Ethernet frames between the stack and the air.
pub const MTU: usize = 1514;

const SNAP: [u8; 6] = [0xaa, 0xaa, 0x03, 0, 0, 0];
const EAPOL: [u8; 2] = [0x88, 0x8e];

static BEACONS: AtomicU32 = AtomicU32::new(0);
static BEACON_FAILURES: AtomicU32 = AtomicU32::new(0);
static MANAGEMENT_REPLIES: AtomicU32 = AtomicU32::new(0);
static MANAGEMENT_UNACKED: AtomicU32 = AtomicU32::new(0);
static UP_FRAMES: AtomicU32 = AtomicU32::new(0);
static DOWN_FRAMES: AtomicU32 = AtomicU32::new(0);
static FORWARDED: AtomicU32 = AtomicU32::new(0);
static HELD: AtomicU32 = AtomicU32::new(0);
static HELD_DROPPED: AtomicU32 = AtomicU32::new(0);
static RELEASED: AtomicU32 = AtomicU32::new(0);
static GROUP_HELD: AtomicU32 = AtomicU32::new(0);
static PS_POLLS: AtomicU32 = AtomicU32::new(0);
static WAKES: AtomicU32 = AtomicU32::new(0);
static STATIONS_NOW: AtomicU32 = AtomicU32::new(0);
static DOZING_NOW: AtomicU32 = AtomicU32::new(0);
static JOINS: AtomicU32 = AtomicU32::new(0);
static LEAVES: AtomicU32 = AtomicU32::new(0);
static DROPPED_INACTIVE: AtomicU32 = AtomicU32::new(0);
/// Frames for the stack dropped because its receive channel was full.
static UP_DROPPED: AtomicU32 = AtomicU32::new(0);
static REKEYS: AtomicU32 = AtomicU32::new(0);
static REKEY_MESSAGES: AtomicU32 = AtomicU32::new(0);
static REKEY_UNACKED: AtomicU32 = AtomicU32::new(0);
static REKEY_CONFIRMED: AtomicU32 = AtomicU32::new(0);
static REKEY_TIMEOUTS: AtomicU32 = AtomicU32::new(0);
/// ARP frames from stations: each one answers a group-addressed request of
/// ours, so they say the station decrypts under the group key in use.
static ARP_UP: AtomicU32 = AtomicU32::new(0);
/// Data frames sent as QoS Data, and at HT rates (E3's P7).
static QOS_DATA_SENT: AtomicU32 = AtomicU32::new(0);
static HT_SENT: AtomicU32 = AtomicU32::new(0);
static DATA_UNACKED: AtomicU32 = AtomicU32::new(0);
static LADDER_UP: AtomicU32 = AtomicU32::new(0);
static LADDER_DOWN: AtomicU32 = AtomicU32::new(0);
static STRANGERS: AtomicU32 = AtomicU32::new(0);
static HANDSHAKE_RESENT: AtomicU32 = AtomicU32::new(0);
static HANDSHAKE_REFUSED: AtomicU32 = AtomicU32::new(0);
static HANDSHAKE_TIMEOUTS: AtomicU32 = AtomicU32::new(0);
static PLAINTEXT_DROPPED: AtomicU32 = AtomicU32::new(0);
static REPLAYS: AtomicU32 = AtomicU32::new(0);

macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static CELL: StaticCell<$t> = StaticCell::new();
        CELL.init_with(|| $val)
    }};
}

/// FoA's lower-MAC runner, for the life of the firmware.
#[embassy_executor::task]
pub async fn mac_task(mut runner: FoARunner<'static>) {
    runner.run().await
}

/// The IP stack's engine, for the life of the firmware.
#[embassy_executor::task]
pub async fn net_task(mut runner: Runner<'static, ch::Device<'static, MTU>>) -> ! {
    runner.run().await
}

/// The DHCP server of the hosted network, for the life of the firmware
/// (edge-dhcp over embassy-net's UDP): leases from `.50` of the board's
/// subnet, the board as gateway. `address` is what [`hosted_stack`] took.
#[embassy_executor::task]
pub async fn dhcp_server_task(stack: Stack<'static>, address: Ipv4Cidr) -> ! {
    use core::net::{SocketAddr, SocketAddrV4};
    use edge_dhcp::io::{self, DEFAULT_SERVER_PORT};
    use edge_dhcp::server::{Server, ServerOptions};
    use edge_nal::UdpBind as _;
    use edge_nal_embassy::{Udp, UdpBuffers};

    let ip: Ipv4Addr = address.address();
    let now = || Instant::now().as_secs();
    let mut server = Server::<_, 8>::new(now, ip);
    let mut gateway = [ip];
    let options = ServerOptions::new(ip, Some(&mut gateway));
    let buffers = UdpBuffers::<1, 1500, 1500, 2>::new();
    let mut packet = [0u8; 1500];
    loop {
        let udp = Udp::new(stack, &buffers);
        if let Ok(mut socket) = udp
            .bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                DEFAULT_SERVER_PORT,
            )))
            .await
        {
            let _ = io::server::run(&mut server, &options, &mut socket, &mut packet).await;
        }
        Timer::after(Duration::from_millis(500)).await;
    }
}

fn plcp(rate: TxPhyRate) -> TxPlcpParameters {
    TxPlcpParameters {
        rate,
        ..Default::default()
    }
}

fn one_mbit() -> TxPhyRate {
    TxPhyRate::HrDsss(HrDsssRate::new(0, false).expect("1 Mbit/s, long preamble"))
}

fn is_group(a: &[u8]) -> bool {
    a.first().is_some_and(|b| b & 1 == 1)
}

fn ccmp(key: &[u8; 16], key_type: KeyType) -> CipherParameters<'_> {
    CipherParameters::Ccmp(AesCipherParameters {
        key: MultiLengthKey::Short(key),
        key_type,
        mfp_enabled: false,
        spp_enabled: false,
    })
}

/// The CCMP header (802.11-2020 12.5.3.2): PN0, PN1, reserved, the key ID
/// byte with Ext IV, PN2 to PN5.
fn ccmp_header(packet_number: u64, key_id: u8) -> [u8; 8] {
    let pn = packet_number.to_le_bytes();
    [
        pn[0],
        pn[1],
        0,
        0x20 | (key_id << 6),
        pn[2],
        pn[3],
        pn[4],
        pn[5],
    ]
}

fn ccmp_packet_number(header: &[u8]) -> u64 {
    u64::from_le_bytes([
        header[0], header[1], header[4], header[5], header[6], header[7], 0, 0,
    ])
}

/// A station's place on the rate ladder: 6, 12, 24, 36, 54 Mbit/s, then
/// MCS 0-7 as far as the station receives (the short guard interval if it
/// does). Down one on a frame it never acknowledged, up one after eight
/// acknowledged in a row.
#[derive(Clone, Copy, Debug)]
struct Ladder {
    rung: u8,
    top: u8,
    short_gi: bool,
    streak: u8,
}

impl Ladder {
    const LEGACY: [OfdmRate; 5] = [
        OfdmRate::Mbits6,
        OfdmRate::Mbits12,
        OfdmRate::Mbits24,
        OfdmRate::Mbits36,
        OfdmRate::Mbits54,
    ];
    const START: u8 = 2; // 24 Mbit/s, as before P7

    fn new(ht: Option<HtCapabilities>) -> Self {
        let (top, short_gi) = match ht.and_then(|h| h.highest_mcs().map(|m| (m, h.short_gi_20))) {
            Some((mcs, sgi)) => (Self::LEGACY.len() as u8 + mcs, sgi),
            None => (Self::LEGACY.len() as u8 - 1, false),
        };
        Self {
            rung: Self::START.min(top),
            top,
            short_gi,
            streak: 0,
        }
    }

    fn rate(&self) -> TxPhyRate {
        let legacy = Self::LEGACY.len() as u8;
        if self.rung < legacy {
            TxPhyRate::Ofdm(Self::LEGACY[usize::from(self.rung)])
        } else {
            match HtRate::new(self.rung - legacy, self.short_gi, false) {
                Some(ht) => TxPhyRate::Ht(ht),
                None => TxPhyRate::Ofdm(OfdmRate::Mbits24),
            }
        }
    }

    fn acknowledged(&mut self) {
        self.streak = self.streak.saturating_add(1);
        if self.streak >= 8 && self.rung < self.top {
            self.rung += 1;
            self.streak = 0;
            LADDER_UP.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn lost(&mut self) {
        self.streak = 0;
        if self.rung > 0 {
            self.rung -= 1;
            LADDER_DOWN.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    SentMessage1,
    SentMessage3,
    Done,
    /// A group-key handshake's message 1 sent; message 2 awaited.
    SentGroupMessage1,
}

/// A station's security association as the access point keeps it.
struct Peer {
    address: Address,
    authenticator: Authenticator,
    stage: Stage,
    sent_at_us: u64,
    resends: u8,
    key_slot: Option<KeySlot<'static>>,
    tx_packet_number: u64,
    rx_packet_number: u64,
    /// A group-key handshake's message 1 waits for this dozing station to
    /// wake (its AID is in the TIM meanwhile).
    group_key_wanted: bool,
    /// It takes QoS data frames.
    qos: bool,
    /// Its rate ladder.
    ladder: Ladder,
}

struct AccessPoint {
    tx: &'static mut TxEndpoint<'static>,
    control: &'static LMacInterfaceControl<'static>,
    bss: Bss<'static>,
    stations: Stations,
    peers: [Option<Peer>; MAX_STATIONS],
    pmk: [u8; 32],
    /// The group key group frames go out under.
    gtk: GroupKey,
    /// The next group key, while stations are being handed it.
    pending_gtk: Option<GroupKey>,
    /// Two key slots: the key in use and the one about to be.
    gtk_slots: [KeySlot<'static>; 2],
    gtk_slot_in_use: usize,
    group_packet_number: u64,
    rekey_at_us: u64,
    rekey_due: bool,
    rekey_interval_us: u64,
    inactivity_us: u64,
    held: &'static mut Held,
}

impl AccessPoint {
    fn peer(&mut self, address: &Address) -> Option<&mut Peer> {
        self.peers
            .iter_mut()
            .flatten()
            .find(|p| p.address == *address)
    }

    fn forget(&mut self, address: &Address) {
        for slot in self.peers.iter_mut() {
            if slot.as_ref().is_some_and(|p| p.address == *address) {
                // a station that held the group key is gone: the key goes too
                if slot.as_ref().is_some_and(|p| p.key_slot.is_some()) {
                    self.rekey_due = true;
                }
                // its key slot is released (FoA deletes the key) as it drops
                *slot = None;
            }
        }
        self.held.clear(address);
        self.stations.remove(address);
    }

    /// The TIM's count for a station: frames held for it, and a group-key
    /// message waiting for its wake.
    fn refresh_queued(&mut self, station: &Address) {
        let waiting = self.peer(station).is_some_and(|p| p.group_key_wanted);
        let n = self.held.count(station) + u16::from(waiting);
        self.stations.set_queued(station, n);
    }

    fn anyone_dozing(&self) -> bool {
        self.stations.iter().any(|s| s.power_save)
    }

    /// An Ethernet frame for the air: held if its station dozes (or, for a
    /// group frame, if anyone does), else sent now.
    async fn deliver(&mut self, eth: &[u8]) {
        let Some(to): Option<Address> = eth.get(..6).and_then(|a| a.try_into().ok()) else {
            return;
        };
        let group = is_group(&to);
        let dozing = if group {
            self.anyone_dozing()
        } else {
            self.stations.get(&to).is_some_and(|s| s.power_save)
        };
        if !dozing {
            self.transmit(eth, false).await;
            return;
        }
        match self.held.push(eth, group) {
            Ok(()) => {
                if group {
                    GROUP_HELD.fetch_add(1, Ordering::Relaxed);
                } else {
                    HELD.fetch_add(1, Ordering::Relaxed);
                    self.refresh_queued(&to);
                }
            }
            Err(_) => {
                HELD_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// One held frame to a station that asked (PS-Poll), More Data set
    /// while more wait.
    async fn release_one(&mut self, station: Address) {
        if self.peer(&station).is_some_and(|p| p.group_key_wanted) {
            if let Some(p) = self.peer(&station) {
                p.group_key_wanted = false;
            }
            self.refresh_queued(&station);
            self.transmit_group_message_1(station).await;
            return;
        }
        let mut copy = [0u8; ap_core::hold::HELD_FRAME_BYTES];
        let Some((taken, more)) = self.held.pop(&station) else {
            return;
        };
        let n = taken.frame.len();
        copy[..n].copy_from_slice(taken.frame);
        RELEASED.fetch_add(1, Ordering::Relaxed);
        self.refresh_queued(&station);
        self.transmit(&copy[..n], more).await;
    }

    /// Every held frame to a station that woke (the Power Management bit
    /// clear).
    async fn release_all(&mut self, station: Address) {
        while self.held.count(&station) > 0
            || self.peer(&station).is_some_and(|p| p.group_key_wanted)
        {
            self.release_one(station).await;
        }
    }

    fn new_group_key(key_id: u8) -> GroupKey {
        let mut key = [0u8; 16];
        Rng::new().read(&mut key);
        GroupKey {
            key,
            key_id,
            rsc: 0,
            replay_counter: 0,
        }
    }

    /// A new group key: into the spare key slot, then to every connected
    /// station by a group-key handshake; group frames switch to it once all
    /// have answered (`finish_rekey_if_done`).
    async fn begin_rekey(&mut self, now: u64) {
        self.rekey_due = false;
        self.rekey_at_us = now + self.rekey_interval_us;
        if !self.bss.protected || self.pending_gtk.is_some() {
            return;
        }
        let key_id = if self.gtk.key_id == 1 { 2 } else { 1 };
        let gtk = Self::new_group_key(key_id);
        let spare = 1 - self.gtk_slot_in_use;
        if self.gtk_slots[spare]
            .set_key(key_id, self.bss.bssid, ccmp(&gtk.key, KeyType::Group))
            .is_err()
        {
            note!("open-ap: the spare key slot refused the group key");
            return;
        }
        self.pending_gtk = Some(gtk);
        let connected: [Option<Address>; MAX_STATIONS] = core::array::from_fn(|i| {
            self.peers[i]
                .as_ref()
                .filter(|p| p.stage == Stage::Done)
                .map(|p| p.address)
        });
        for station in connected.into_iter().flatten() {
            if let Some(p) = self.peer(&station) {
                p.resends = 0;
            }
            self.send_group_message_1(station).await;
        }
        self.finish_rekey_if_done();
    }

    /// Every station has the pending key (or is gone): group frames go
    /// out under it from here.
    fn finish_rekey_if_done(&mut self) {
        let Some(gtk) = self.pending_gtk else {
            return;
        };
        if self
            .peers
            .iter()
            .flatten()
            .any(|p| p.stage == Stage::SentGroupMessage1)
        {
            return;
        }
        self.pending_gtk = None;
        self.gtk = gtk;
        self.gtk_slot_in_use = 1 - self.gtk_slot_in_use;
        self.group_packet_number = 0;
        REKEYS.fetch_add(1, Ordering::Relaxed);
        note!("open-ap: group key rotated to key id {}", gtk.key_id);
    }

    /// A group-key handshake's message 1 to a station: now if it is awake;
    /// for a dozing one it waits, its AID in the TIM, and goes when the
    /// station wakes or polls (like any frame for it: P5), with no resend
    /// timer running meanwhile.
    async fn send_group_message_1(&mut self, station: Address) {
        if self.stations.get(&station).is_some_and(|s| s.power_save) {
            if let Some(p) = self.peer(&station) {
                p.stage = Stage::SentGroupMessage1;
                p.group_key_wanted = true;
                p.sent_at_us = u64::MAX;
            }
            self.refresh_queued(&station);
            return;
        }
        self.transmit_group_message_1(station).await;
    }

    /// The group-key handshake's message 1 on the air: the pending key,
    /// protected under the station's pairwise key.
    async fn transmit_group_message_1(&mut self, station: Address) {
        let bssid = self.bss.bssid;
        let Some(gtk) = self.pending_gtk else {
            if let Some(p) = self.peer(&station) {
                // the rotation finished without this station (it was dropped
                // and came back): nothing to hand it
                if p.stage == Stage::SentGroupMessage1 {
                    p.stage = Stage::Done;
                }
            }
            return;
        };
        let Some(peer) = self.peer(&station) else {
            return;
        };
        let Some(keys) = peer.authenticator.keys.clone() else {
            return;
        };
        let Some(slot) = peer.key_slot.as_ref().map(KeySlot::key_slot) else {
            return;
        };
        let replay = peer.authenticator.next_replay_counter();
        peer.tx_packet_number += 1;
        let packet_number = peer.tx_packet_number;
        peer.stage = Stage::SentGroupMessage1;
        peer.sent_at_us = Instant::now().as_micros();
        let mut buf = self.tx.alloc_tx_buf().await;
        let mut scratch = [0u8; 512];
        let Ok(n) = handshake::write_group_message_1(
            &mut buf[..],
            &mut scratch,
            bssid,
            station,
            &keys,
            replay,
            &gtk,
            packet_number,
            0,
        ) else {
            return;
        };
        let done = self
            .tx
            .transmit_edca(
                EdcaAccessCategory::default(),
                buf,
                n,
                plcp(TxPhyRate::Ofdm(OfdmRate::Mbits24)),
                TxMacParameters {
                    key_slot_index: Some(slot as u8),
                    wait_for_ack: true,
                    override_seq_num: true,
                    ..Default::default()
                },
                RetryBehaviour::RetryUntil(4),
            )
            .wait_for_completion()
            .await;
        REKEY_MESSAGES.fetch_add(1, Ordering::Relaxed);
        if !matches!(done, Some(d) if d.result.is_ok()) {
            REKEY_UNACKED.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A protected EAPOL-Key frame from a station, decrypted by the
    /// hardware and unwrapped: a group-key handshake's message 2.
    async fn group_eapol(&mut self, station: Address, plain: &mut [u8]) {
        let confirmed = {
            let Some(peer) = self.peer(&station) else {
                return;
            };
            if peer.stage != Stage::SentGroupMessage1 {
                return;
            }
            let replay = peer.authenticator.replay_counter;
            let Some(keys) = peer.authenticator.keys.clone() else {
                return;
            };
            match handshake::read_group_message_2(plain, &keys, replay) {
                Ok(()) => {
                    peer.stage = Stage::Done;
                    peer.resends = 0;
                    true
                }
                Err(_why) => {
                    HANDSHAKE_REFUSED.fetch_add(1, Ordering::Relaxed);
                    note!(
                        "open-ap: group message 2 from {:02x?} refused: {:?}",
                        station,
                        why
                    );
                    false
                }
            }
        };
        if confirmed {
            REKEY_CONFIRMED.fetch_add(1, Ordering::Relaxed);
            self.finish_rekey_if_done();
        }
    }

    /// The group frames held, after the DTIM beacon.
    async fn release_group(&mut self) {
        let mut copy = [0u8; ap_core::hold::HELD_FRAME_BYTES];
        while let Some((taken, more)) = self.held.pop_group() {
            let n = taken.frame.len();
            copy[..n].copy_from_slice(taken.frame);
            RELEASED.fetch_add(1, Ordering::Relaxed);
            self.transmit(&copy[..n], more).await;
        }
    }

    /// A frame the access point lays out with `write`, sent unprotected
    /// with ACKs and retries; counted.
    async fn reply(&mut self, write: impl FnOnce(&mut [u8], &mut [u8]) -> Option<usize>) {
        let mut buf = self.tx.alloc_tx_buf().await;
        let mut scratch = [0u8; 1024];
        let Some(n) = write(&mut buf[..], &mut scratch) else {
            return;
        };
        let done = self
            .tx
            .transmit_edca(
                EdcaAccessCategory::default(),
                buf,
                n,
                plcp(one_mbit()),
                TxMacParameters {
                    wait_for_ack: true,
                    override_seq_num: true,
                    ..Default::default()
                },
                RetryBehaviour::RetryUntil(4),
            )
            .wait_for_completion()
            .await;
        MANAGEMENT_REPLIES.fetch_add(1, Ordering::Relaxed);
        if !matches!(done, Some(d) if d.result.is_ok()) {
            MANAGEMENT_UNACKED.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn send_message_1(&mut self, station: Address) {
        let bssid = self.bss.bssid;
        let Some(peer) = self.peer(&station) else {
            return;
        };
        let replay = peer.authenticator.next_replay_counter();
        let anonce = peer.authenticator.anonce;
        peer.stage = Stage::SentMessage1;
        peer.sent_at_us = Instant::now().as_micros();
        self.reply(|out, scratch| {
            handshake::write_message_1(out, scratch, bssid, station, &anonce, replay).ok()
        })
        .await;
    }

    async fn send_message_3(&mut self, station: Address) {
        let (bssid, gtk) = (self.bss.bssid, self.pending_gtk.unwrap_or(self.gtk));
        let Some(peer) = self.peer(&station) else {
            return;
        };
        let Some(keys) = peer.authenticator.keys.clone() else {
            return;
        };
        let replay = peer.authenticator.next_replay_counter();
        let anonce = peer.authenticator.anonce;
        peer.stage = Stage::SentMessage3;
        peer.sent_at_us = Instant::now().as_micros();
        self.reply(|out, scratch| {
            handshake::write_message_3(out, scratch, bssid, station, &keys, &anonce, replay, &gtk)
                .ok()
        })
        .await;
    }

    /// A station associated: its 4-way handshake begins with a fresh ANonce;
    /// on an open network it is connected at once.
    async fn begin_handshake(&mut self, station: Address) {
        if !self.bss.protected {
            if let Some(free) = self
                .peers
                .iter_mut()
                .find(|p| p.as_ref().is_none_or(|p| p.address == station))
            {
                *free = Some(Peer {
                    address: station,
                    authenticator: Authenticator::new([0; 32]),
                    stage: Stage::Done,
                    sent_at_us: 0,
                    resends: 0,
                    key_slot: None,
                    tx_packet_number: 0,
                    rx_packet_number: 0,
                    group_key_wanted: false,
                    qos: false,
                    ladder: Ladder::new(None),
                });
            }
            self.stations.connected(&station);
            JOINS.fetch_add(1, Ordering::Relaxed);
            note!(
                "open-ap: {:02x?} associated on the open network: connected",
                station
            );
            return;
        }
        let mut anonce = [0u8; 32];
        Rng::new().read(&mut anonce);
        if let Some(free) = self
            .peers
            .iter_mut()
            .find(|p| p.as_ref().is_none_or(|p| p.address == station))
        {
            *free = Some(Peer {
                address: station,
                authenticator: Authenticator::new(anonce),
                stage: Stage::SentMessage1,
                sent_at_us: 0,
                resends: 0,
                key_slot: None,
                tx_packet_number: 1,
                rx_packet_number: 0,
                group_key_wanted: false,
                qos: false,
                ladder: Ladder::new(None),
            });
            self.send_message_1(station).await;
        }
    }

    /// An EAPOL-Key frame from a station, in the clear (messages 2 and 4).
    async fn eapol(&mut self, station: Address, frame: &mut [u8]) {
        let (bssid, pmk) = (self.bss.bssid, self.pmk);
        let rsn: heapless_rsn::Rsn = match self.stations.get(&station) {
            Some(s) => heapless_rsn::Rsn::from(s.rsn_element()),
            None => return,
        };
        let Some(peer) = self.peer(&station) else {
            return;
        };
        match peer.stage {
            Stage::SentMessage1 => {
                let replay = peer.authenticator.replay_counter;
                let anonce = peer.authenticator.anonce;
                match handshake::read_message_2(
                    frame,
                    &pmk,
                    &bssid,
                    &station,
                    &anonce,
                    replay,
                    rsn.as_slice(),
                ) {
                    Ok(keys) => {
                        peer.authenticator.keys = Some(keys);
                        peer.resends = 0;
                        self.send_message_3(station).await;
                    }
                    Err(_why) => {
                        HANDSHAKE_REFUSED.fetch_add(1, Ordering::Relaxed);
                        note!(
                            "open-ap: message 2 from {:02x?} refused: {:?}",
                            station,
                            why
                        );
                    }
                }
            }
            Stage::SentMessage3 => {
                let replay = peer.authenticator.replay_counter;
                let Some(keys) = peer.authenticator.keys.clone() else {
                    return;
                };
                if let Err(_why) = handshake::read_message_4(frame, &keys, replay) {
                    HANDSHAKE_REFUSED.fetch_add(1, Ordering::Relaxed);
                    note!(
                        "open-ap: message 4 from {:02x?} refused: {:?}",
                        station,
                        why
                    );
                    return;
                }
                // the pairwise key into a key slot of the station's own
                let Some(mut slot) = self.control.acquire_key_slot() else {
                    note!("open-ap: no key slot for {:02x?}", station);
                    return;
                };
                if slot
                    .set_key(0, station, ccmp(keys.tk(), KeyType::Pairwise))
                    .is_err()
                {
                    note!("open-ap: the key slot refused the PTK");
                    return;
                }
                let peer = self.peer(&station).expect("held above");
                peer.key_slot = Some(slot);
                peer.stage = Stage::Done;
                self.stations.connected(&station);
                JOINS.fetch_add(1, Ordering::Relaxed);
                note!("open-ap: {:02x?} keys installed: connected", station);
            }
            Stage::Done | Stage::SentGroupMessage1 => {}
        }
    }

    /// Handshakes not answered in time: sent again, or the station
    /// deauthenticated.
    async fn resend_due(&mut self) {
        let now = Instant::now().as_micros();
        let due: Option<(Address, Stage, u8)> = self.peers.iter().flatten().find_map(|p| {
            (p.stage != Stage::Done && now.saturating_sub(p.sent_at_us) > HANDSHAKE_RESEND_US)
                .then_some((p.address, p.stage, p.resends))
        });
        let Some((station, stage, resends)) = due else {
            return;
        };
        if resends >= HANDSHAKE_RESENDS {
            let group = stage == Stage::SentGroupMessage1;
            if group {
                REKEY_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            } else {
                HANDSHAKE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            }
            note!(
                "open-ap: {:02x?} {} handshake timed out",
                station,
                if group { "group-key" } else { "4-way" }
            );
            self.forget(&station);
            let b = self.bss.bssid;
            let why = if group {
                reason::GROUP_KEY_HANDSHAKE_TIMEOUT
            } else {
                reason::FOURWAY_HANDSHAKE_TIMEOUT
            };
            self.reply(|out, _| frames::deauthentication(out, b, station, why))
                .await;
            self.finish_rekey_if_done();
            return;
        }
        if let Some(p) = self.peer(&station) {
            p.resends += 1;
        }
        HANDSHAKE_RESENT.fetch_add(1, Ordering::Relaxed);
        match stage {
            Stage::SentMessage1 => self.send_message_1(station).await,
            Stage::SentMessage3 => self.send_message_3(station).await,
            Stage::SentGroupMessage1 => self.send_group_message_1(station).await,
            Stage::Done => {}
        }
    }

    /// A data frame on an open network: in the clear, to a connected
    /// station or to the group.
    async fn transmit_open(
        &mut self,
        to: Address,
        from: &[u8],
        ether_type: [u8; 2],
        payload: &[u8],
        more_data: bool,
        group: bool,
    ) {
        let (qos_station, rate) = if group {
            (false, one_mbit())
        } else {
            let Some(peer) = self.peer(&to) else {
                return;
            };
            (peer.qos, peer.ladder.rate())
        };
        let header = if qos_station { 26 } else { 24 };
        let mut buf = self.tx.alloc_tx_buf().await;
        let n = header + 8 + payload.len();
        let Some(frame) = buf.get_mut(..n) else {
            return;
        };
        let subtype = if qos_station { 0x88 } else { 0x08 };
        frame[..4].copy_from_slice(&[subtype, 0x02 | if more_data { 0x20 } else { 0 }, 0, 0]);
        frame[4..10].copy_from_slice(&to);
        frame[10..16].copy_from_slice(&self.bss.bssid);
        frame[16..22].copy_from_slice(from);
        frame[22..24].copy_from_slice(&[0, 0]);
        if qos_station {
            frame[24..26].copy_from_slice(&qos::qos_control(0));
        }
        frame[header..header + 6].copy_from_slice(&SNAP);
        frame[header + 6..header + 8].copy_from_slice(&ether_type);
        frame[header + 8..].copy_from_slice(payload);
        let retry = if group {
            RetryBehaviour::Drop
        } else {
            RetryBehaviour::RetryUntil(7)
        };
        let pending = self.tx.transmit_edca(
            EdcaAccessCategory::default(),
            buf,
            n,
            plcp(rate),
            TxMacParameters {
                wait_for_ack: !group,
                override_seq_num: true,
                ..Default::default()
            },
            retry,
        );
        DOWN_FRAMES.fetch_add(1, Ordering::Relaxed);
        if qos_station {
            QOS_DATA_SENT.fetch_add(1, Ordering::Relaxed);
        }
        if matches!(rate, TxPhyRate::Ht(_)) {
            HT_SENT.fetch_add(1, Ordering::Relaxed);
        }
        if !group {
            // the ladder learns from the acknowledgement, as on WPA2
            let done = pending.wait_for_completion().await;
            let acked = matches!(done, Some(d) if d.result.is_ok());
            if !acked {
                DATA_UNACKED.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(peer) = self.peer(&to) {
                if acked {
                    peer.ladder.acknowledged();
                } else {
                    peer.ladder.lost();
                }
            }
        }
    }

    /// A data frame from the access point, from an Ethernet frame: protected
    /// under the station's pairwise key, or the group key when
    /// group-addressed; `more_data` for a frame released to a dozing
    /// station with more behind it.
    async fn transmit(&mut self, eth: &[u8], more_data: bool) {
        if eth.len() < 14 {
            return;
        }
        let to: Address = eth[..6].try_into().unwrap_or([0; 6]);
        let from = &eth[6..12];
        let ether_type = [eth[12], eth[13]];
        let payload = &eth[14..];
        let group = is_group(&to);
        if !self.bss.protected {
            self.transmit_open(to, from, ether_type, payload, more_data, group)
                .await;
            return;
        }
        let (slot, key_id, packet_number, qos_station, rate) = if group {
            self.group_packet_number += 1;
            (
                self.gtk_slots[self.gtk_slot_in_use].key_slot(),
                self.gtk.key_id,
                self.group_packet_number,
                false,
                one_mbit(),
            )
        } else {
            let Some(peer) = self.peer(&to) else {
                return;
            };
            let Some(slot) = peer.key_slot.as_ref().map(KeySlot::key_slot) else {
                return;
            };
            peer.tx_packet_number += 1;
            (slot, 0, peer.tx_packet_number, peer.qos, peer.ladder.rate())
        };
        // a QoS station gets QoS Data (subtype 8) with the QoS Control field
        let header = if qos_station { 26 } else { 24 };
        let mut buf = self.tx.alloc_tx_buf().await;
        let n = header + 8 + 8 + payload.len() + 8;
        let Some(frame) = buf.get_mut(..n) else {
            return;
        };
        let subtype = if qos_station { 0x88 } else { 0x08 };
        frame[..4].copy_from_slice(&[
            subtype,
            0x02 | 0x40 | if more_data { 0x20 } else { 0 },
            0,
            0,
        ]);
        frame[4..10].copy_from_slice(&to);
        frame[10..16].copy_from_slice(&self.bss.bssid);
        frame[16..22].copy_from_slice(from);
        frame[22..24].copy_from_slice(&[0, 0]);
        if qos_station {
            frame[24..26].copy_from_slice(&qos::qos_control(0));
        }
        frame[header..header + 8].copy_from_slice(&ccmp_header(packet_number, key_id));
        frame[header + 8..header + 14].copy_from_slice(&SNAP);
        frame[header + 14..header + 16].copy_from_slice(&ether_type);
        frame[header + 16..header + 16 + payload.len()].copy_from_slice(payload);
        frame[n - 8..].fill(0);
        let retry = if group {
            RetryBehaviour::Drop
        } else {
            RetryBehaviour::RetryUntil(7)
        };
        let pending = self.tx.transmit_edca(
            EdcaAccessCategory::default(),
            buf,
            n,
            plcp(rate),
            TxMacParameters {
                key_slot_index: Some(slot as u8),
                wait_for_ack: !group,
                override_seq_num: true,
                ..Default::default()
            },
            retry,
        );
        DOWN_FRAMES.fetch_add(1, Ordering::Relaxed);
        if qos_station {
            QOS_DATA_SENT.fetch_add(1, Ordering::Relaxed);
        }
        if matches!(rate, TxPhyRate::Ht(_)) {
            HT_SENT.fetch_add(1, Ordering::Relaxed);
        }
        if !group {
            // the ladder learns from the acknowledgement (a frame at a time:
            // the bench's access point, not a streaming one yet)
            let done = pending.wait_for_completion().await;
            let acked = matches!(done, Some(d) if d.result.is_ok());
            if !acked {
                DATA_UNACKED.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(peer) = self.peer(&to) {
                if acked {
                    peer.ladder.acknowledged();
                } else {
                    peer.ladder.lost();
                }
            }
        }
    }

    /// A control frame: a PS-Poll (subtype 10) from a station releases one
    /// held frame.
    async fn control(&mut self, f: &[u8], fc0: u8, now: u64) {
        if fc0 >> 4 != 10 || f.len() < 16 || f[4..10] != self.bss.bssid {
            return;
        }
        let Ok(station) = <[u8; 6]>::try_from(&f[10..16]) else {
            return;
        };
        if self.stations.get(&station).map(|s| s.state) != Some(State::Connected) {
            return;
        }
        PS_POLLS.fetch_add(1, Ordering::Relaxed);
        // a poll says it is awake for this frame, still dozing after
        self.stations.heard(&station, now, true);
        self.release_one(station).await;
    }

    async fn management(&mut self, f: &[u8], now: u64) {
        let bss = self.bss;
        match request::parse(f, &bss.bssid) {
            Some(Request::Probe { from, ssid }) if ssid.is_none() || ssid == Some(bss.ssid) => {
                let ts = tsf::access_point();
                self.reply(|out, _| {
                    let n = frames::probe_response(out, &bss, from)?;
                    out[24..32].copy_from_slice(&ts.to_le_bytes());
                    Some(n)
                })
                .await;
            }
            Some(Request::Authentication {
                from,
                algorithm,
                sequence,
            }) => {
                // a station starting again: its keys go
                self.forget(&from);
                let status = self.stations.authenticate(from, algorithm, sequence);
                self.stations.heard(&from, now, false);
                note!("open-ap: authentication from {:02x?} status={status}", from);
                self.reply(|out, _| frames::authentication(out, bss.bssid, from, status))
                    .await;
            }
            Some(Request::Association {
                from,
                ssid,
                rsn_element,
                reassociation,
                qos,
                ht,
            }) => {
                let (status, aid) = match self.stations.associate(
                    from,
                    ssid == Some(bss.ssid),
                    rsn_element,
                    bss.protected,
                ) {
                    Ok(aid) => (status::SUCCESS, aid),
                    Err(status) => (status, 0),
                };
                if status == status::SUCCESS {
                    self.stations.set_capabilities(&from, qos, ht);
                }
                self.stations.heard(&from, now, false);
                note!(
                    "open-ap: {} from {:02x?} status={status} aid={aid}",
                    if reassociation {
                        "re-association"
                    } else {
                        "association"
                    },
                    from
                );
                self.reply(|out, _| {
                    frames::association_response(out, &bss, from, status, aid, reassociation)
                })
                .await;
                if status == status::SUCCESS {
                    note!(
                        "open-ap: {:02x?} qos={qos} ht={}",
                        from,
                        match ht {
                            Some(h) => h.highest_mcs().map_or(0, |m| i32::from(m) + 1),
                            None => -1,
                        }
                    );
                    self.begin_handshake(from).await;
                    if let Some(p) = self.peer(&from) {
                        p.qos = qos;
                        p.ladder = Ladder::new(ht);
                    }
                }
            }
            Some(Request::Deauthentication { from, .. } | Request::Disassociation { from, .. }) => {
                if self.stations.get(&from).is_some() {
                    LEAVES.fetch_add(1, Ordering::Relaxed);
                }
                self.forget(&from);
            }
            _ => {}
        }
    }

    async fn data(
        &mut self,
        f: &mut [u8],
        fc0: u8,
        fc1: u8,
        now: u64,
        up: &mut ch::RxRunner<'static, MTU>,
    ) {
        if fc1 & 0b11 != 0b01 || f.len() < 24 {
            return;
        }
        let (Ok(bssid), Ok(station), Ok(destination)) = (
            <[u8; 6]>::try_from(&f[4..10]),
            <[u8; 6]>::try_from(&f[10..16]),
            <[u8; 6]>::try_from(&f[16..22]),
        ) else {
            return;
        };
        if bssid != self.bss.bssid {
            return;
        }
        let power_save = fc1 & 0x10 != 0;
        let (state, was_dozing) = match self.stations.get(&station) {
            Some(s) => (Some(s.state), s.power_save),
            None => (None, false),
        };
        if !self.stations.heard(&station, now, power_save)
            || !matches!(state, Some(State::Associated | State::Connected))
        {
            STRANGERS.fetch_add(1, Ordering::Relaxed);
            let b = self.bss.bssid;
            self.reply(|out, _| {
                frames::deauthentication(out, b, station, reason::CLASS3_FROM_NONASSOC)
            })
            .await;
            return;
        }
        if was_dozing && !power_save {
            WAKES.fetch_add(1, Ordering::Relaxed);
            self.release_all(station).await;
        }
        let subtype = fc0 >> 4;
        if subtype & 0b0100 != 0 {
            return; // Null, QoS Null
        }
        let header = if subtype & 0b1000 != 0 { 26 } else { 24 };
        let protected = fc1 & 0x40 != 0;
        if !self.bss.protected {
            // an open network: data in the clear, and nothing protected can
            // be meant for it
            if protected {
                return;
            }
            self.station_data(f, header, station, destination, up).await;
            return;
        }
        if !protected {
            // in the clear only the 4-way handshake's frames (E2's F6, the
            // access point's side)
            let llc = f.get(header..header + 8);
            if llc.is_some_and(|l| l[..6] == SNAP && l[6..8] == EAPOL)
                && self
                    .peer(&station)
                    .is_some_and(|p| matches!(p.stage, Stage::SentMessage1 | Stage::SentMessage3))
            {
                self.eapol(station, f).await;
            } else {
                PLAINTEXT_DROPPED.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
        // decrypted by the hardware under the station's key: the CCMP header
        // stays, the MIC is gone; the packet number must climb
        let Some(ccmp) = f.get(header..header + 8) else {
            return;
        };
        let packet_number = ccmp_packet_number(ccmp);
        let Some(peer) = self.peer(&station) else {
            return;
        };
        if peer.key_slot.is_none() {
            return; // no keys yet: nothing protected can be from it
        }
        if packet_number <= peer.rx_packet_number {
            REPLAYS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        peer.rx_packet_number = packet_number;
        self.station_data(f, header + 8, station, destination, up)
            .await;
    }

    /// A station's data frame, its LLC header at `body` (after the CCMP
    /// header, or right after the MAC header on an open network): to the
    /// stack, to another station, or both.
    async fn station_data(
        &mut self,
        f: &mut [u8],
        body: usize,
        station: Address,
        destination: Address,
        up: &mut ch::RxRunner<'static, MTU>,
    ) {
        let Some(llc) = f.get(body..body + 8) else {
            return;
        };
        if llc[..6] != SNAP {
            return;
        }
        let ether_type = [llc[6], llc[7]];
        let payload_at = body + 8;
        if ether_type == EAPOL && self.bss.protected {
            // a group-key handshake's message 2, as the station-side
            // unprotect lays a decrypted frame out
            let mut plain = [0u8; 512];
            if let Some(n) = sta_handshake::unprotect(f, &mut plain) {
                self.group_eapol(station, &mut plain[..n]).await;
            }
            return;
        }
        if ether_type == [0x08, 0x06] {
            ARP_UP.fetch_add(1, Ordering::Relaxed);
        }
        UP_FRAMES.fetch_add(1, Ordering::Relaxed);
        let for_us = destination == self.bss.bssid;
        let group = is_group(&destination);
        if for_us || group {
            let Some(buf) = up.try_rx_buf() else {
                UP_DROPPED.fetch_add(1, Ordering::Relaxed);
                return;
            };
            {
                let payload = &f[payload_at..];
                let n = 14 + payload.len();
                if let Some(eth) = buf.get_mut(..n) {
                    eth[..6].copy_from_slice(&destination);
                    eth[6..12].copy_from_slice(&station);
                    eth[12..14].copy_from_slice(&ether_type);
                    eth[14..].copy_from_slice(payload);
                    up.rx_done(n);
                }
            }
        }
        if !for_us {
            FORWARDED.fetch_add(1, Ordering::Relaxed);
            // as an Ethernet frame: the destination, the station, the type
            let mut eth = [0u8; 1600];
            let len = f.len() - payload_at;
            eth[..6].copy_from_slice(&destination);
            eth[6..12].copy_from_slice(&station);
            eth[12..14].copy_from_slice(&ether_type);
            eth[14..14 + len].copy_from_slice(&f[payload_at..]);
            self.deliver(&eth[..14 + len]).await;
        }
    }
}

/// The RSN element a station's association carried, copied out of the
/// station table so the table can be borrowed again.
mod heapless_rsn {
    pub struct Rsn {
        bytes: [u8; ap_core::stations::MAX_RSN_ELEMENT],
        len: usize,
    }
    impl From<&[u8]> for Rsn {
        fn from(b: &[u8]) -> Self {
            let mut bytes = [0u8; ap_core::stations::MAX_RSN_ELEMENT];
            let len = b.len().min(bytes.len());
            bytes[..len].copy_from_slice(&b[..len]);
            Self { bytes, len }
        }
    }
    impl Rsn {
        pub fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }
}

/// What to host.
#[derive(Clone, Copy, Debug)]
pub struct AccessPointConfig {
    /// The network's name, up to 32 bytes.
    pub ssid: &'static str,
    /// WPA2-PSK's passphrase, 8 to 63 bytes; empty for an open network
    /// ([`AccessPointConfig::open`]).
    pub passphrase: &'static str,
    /// The 2.4 GHz channel, 1 to 13.
    pub channel: u8,
    /// The board's address and the network's prefix (leases from `.50`).
    pub address: Ipv4Cidr,
    /// How often the group key rotates (also on every station leaving).
    pub rekey_interval: Duration,
    /// A station heard nothing from for this long is dropped (reason 4).
    pub inactivity: Duration,
    /// Offer WMM and HT (802.11n rates to stations that take them).
    pub ht: bool,
    /// Where the soft-AP TSF starts: the RTC's time since power-up, so a
    /// reset does not look like a clock that ran backwards (E3's R1).
    pub tsf_seed_us: u64,
}

impl AccessPointConfig {
    /// A network at `192.168.71.1/24` on channel 6, the key rotating hourly,
    /// five minutes of silence before a drop, WMM and HT on.
    #[must_use]
    pub const fn new(ssid: &'static str, passphrase: &'static str, tsf_seed_us: u64) -> Self {
        Self {
            ssid,
            passphrase,
            channel: 6,
            address: Ipv4Cidr::new(Ipv4Addr::new(192, 168, 71, 1), 24),
            rekey_interval: Duration::from_secs(3600),
            inactivity: Duration::from_secs(300),
            ht: true,
            tsf_seed_us,
        }
    }

    /// An open network: no passphrase, no handshake, data in the clear.
    /// For a device's setup network (the experiments plan's E7): what
    /// crosses it is a setup session that authenticates and seals itself
    /// (`rusty_esp_signal-core::setup::page`), and it is hosted only while
    /// the device is unprovisioned or its setup window is open. Everything
    /// else as [`AccessPointConfig::new`].
    #[must_use]
    pub const fn open(ssid: &'static str, tsf_seed_us: u64) -> Self {
        Self::new(ssid, "", tsf_seed_us)
    }
}

/// The access point's runner: beacons, the stations' frames, the stack's
/// frames, for the life of the firmware ([`ap_task`]).
pub struct ApRunner {
    ap: AccessPoint,
    rx: RxEndpoint<'static, 'static>,
    up: ch::RxRunner<'static, MTU>,
    down: ch::TxRunner<'static, MTU>,
}

/// The open MAC as an access point and an IP stack at a fixed address over
/// it: the counterpart of `hal::netstack::hosted_stack` with esp-radio's
/// access-point interface. Once per firmware (the MAC's resources are
/// static). The BSSID is the chip's base MAC address plus one, as
/// esp-radio's soft-AP address is. `seed` salts the stack's port and ID
/// choices; take it from the hardware RNG.
///
/// # Panics
///
/// On a passphrase outside 8 to 63 bytes or an SSID over 32: the build
/// names them, so the firmware never gets past its first boot with either.
pub fn hosted_stack<const SOCK: usize>(
    wifi: esp_hal::peripherals::WIFI<'static>,
    config: AccessPointConfig,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
) -> OpenAccessPoint {
    bring_up(wifi, config, resources, seed, None).0
}

/// [`hosted_stack`], and the mID link on raw ESP-NOW frames beside it (the
/// experiments plan's E4): the access point on the radio's first virtual
/// interface, the raw link on its second, on the station's address and the
/// access point's channel -- as ESP-NOW rides beside a soft-AP on the blob.
/// `peer` is the link's other end, or `raw_link::BROADCAST` to learn it at
/// the handshake. Spawn `raw_link::rx_task` with the runner besides the
/// access point's tasks (the one [`mac_task`] serves both).
///
/// # Panics
///
/// As [`hosted_stack`].
pub fn hosted_stack_with_raw_link<const SOCK: usize>(
    wifi: esp_hal::peripherals::WIFI<'static>,
    config: AccessPointConfig,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
    peer: [u8; 6],
) -> (OpenAccessPoint, RawLink, RawRunner) {
    let (ap, raw) = bring_up(wifi, config, resources, seed, Some(peer));
    let (link, runner) = raw.expect("asked for above");
    (ap, link, runner)
}

fn bring_up<const SOCK: usize>(
    wifi: esp_hal::peripherals::WIFI<'static>,
    config: AccessPointConfig,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
    raw_peer: Option<[u8; 6]>,
) -> (OpenAccessPoint, Option<(RawLink, RawRunner)>) {
    let protected = !config.passphrase.is_empty();
    assert!(
        !protected || (8..=63).contains(&config.passphrase.len()),
        "WPA2-PSK's passphrase is 8 to 63 bytes (or empty: an open network)"
    );
    assert!(config.ssid.len() <= 32, "an SSID is up to 32 bytes");
    tsf::start_access_point_clock_at(config.tsf_seed_us);

    // the PMK, once: PBKDF2-HMAC-SHA1, 4,096 rounds (none on an open network)
    let mut pmk = [0u8; 32];
    if protected {
        ieee80211::crypto::map_passphrase_to_psk(config.passphrase, config.ssid, &mut pmk);
    }

    static FOA: StaticCell<FoAResources> = StaticCell::new();
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static VIF_RAW: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    let ([vif, vif_raw, ..], mac) = foa::init(FOA.init(FoAResources::new()), wifi);
    let vif = VIF.init(vif);
    // the raw link (E4) on the second interface, when asked for
    let raw =
        raw_peer.map(|peer| crate::raw_link::attach(VIF_RAW.init(vif_raw), config.channel, peer));
    let (control, rx, tx) = vif.split();
    let control: &'static LMacInterfaceControl<'static> = control;

    let base = esp_hal::efuse::base_mac_address();
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(base.as_bytes());
    bssid[5] = bssid[5].wrapping_add(1);
    let _ = control.lock_channel(config.channel);
    control.set_filter(RxFilterBank::ReceiverAddress, bssid);
    control.set_filter(RxFilterBank::Bssid, bssid);
    control.set_filter_bssid_check(false);
    // PS-Poll is the one control frame the access point reads (the HAL
    // passes none up by default)
    control.set_control_frame_filter(&ControlFrameFilterConfig {
        ps_poll: true,
        ..ControlFrameFilterConfig::none()
    });

    // the group key, random, in a key slot of its own; a second slot for
    // the next one
    let mut gtk_key = [0u8; 16];
    Rng::new().read(&mut gtk_key);
    let gtk = GroupKey {
        key: gtk_key,
        key_id: GTK_KEY_ID,
        rsc: 0,
        replay_counter: 0,
    };
    let mut gtk_slots = [
        control
            .acquire_key_slot()
            .expect("a key slot for the group key"),
        control
            .acquire_key_slot()
            .expect("a key slot for the next group key"),
    ];
    gtk_slots[0]
        .set_key(GTK_KEY_ID, bssid, ccmp(&gtk.key, KeyType::Group))
        .expect("the group key");

    // 8 frames each way: a bridge's 16-chunk window does not fit, and its
    // go-back-N carries the loss; 16 cost 12 KB of .bss, which on the S3 is
    // the main stack's (E3's C16, run 6: the stack guard tripped at boot)
    let state = mk_static!(ch::State<MTU, 8, 8>, ch::State::new());
    let (net_runner, device) = ch::new(state, HardwareAddress::Ethernet(bssid));
    let (state_runner, up, down) = net_runner.split();
    state_runner.set_link_state(LinkState::Up);
    let ip = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: config.address,
        gateway: Some(config.address.address()),
        dns_servers: Default::default(),
    });
    let (stack, net) = embassy_net::new(device, ip, resources, seed);

    static HELD_FRAMES: ConstStaticCell<Held> = ConstStaticCell::new(Held::new());
    static SSID: StaticCell<[u8; 32]> = StaticCell::new();
    let ssid_bytes = SSID.init([0u8; 32]);
    ssid_bytes[..config.ssid.len()].copy_from_slice(config.ssid.as_bytes());
    let ap = AccessPoint {
        tx,
        control,
        bss: Bss {
            bssid,
            ssid: &ssid_bytes[..config.ssid.len()],
            channel: config.channel,
            beacon_interval_tu: BEACON_INTERVAL_TU,
            protected,
            ht: config.ht,
        },
        stations: Stations::new(),
        peers: [const { None }; MAX_STATIONS],
        pmk,
        gtk,
        pending_gtk: None,
        gtk_slots,
        gtk_slot_in_use: 0,
        group_packet_number: 0,
        rekey_at_us: Instant::now().as_micros() + config.rekey_interval.as_micros(),
        rekey_due: false,
        rekey_interval_us: config.rekey_interval.as_micros(),
        inactivity_us: config.inactivity.as_micros(),
        held: HELD_FRAMES.take(),
    };
    (
        OpenAccessPoint {
            stack,
            bssid,
            mac,
            ap: ApRunner { ap, rx, up, down },
            net,
        },
        raw,
    )
}

/// What [`hosted_stack`] gives a firmware: the stack, the BSSID, and the
/// three runners to spawn ([`mac_task`], [`ap_task`], [`net_task`]) before
/// anything awaits the stack; [`dhcp_server_task`] serves the leases.
pub struct OpenAccessPoint {
    /// The IP stack at the configured address.
    pub stack: Stack<'static>,
    /// The network's BSSID (the base MAC plus one).
    pub bssid: [u8; 6],
    /// FoA's lower-MAC runner, for [`mac_task`].
    pub mac: FoARunner<'static>,
    /// The access point's runner, for [`ap_task`].
    pub ap: ApRunner,
    /// The IP stack's runner, for [`net_task`].
    pub net: Runner<'static, ch::Device<'static, MTU>>,
}

/// The access point, for the life of the firmware: a beacon at each TBTT
/// (its TIM from the station table), every frame from the air answered or
/// passed up, every frame from the stack sent or held.
#[embassy_executor::task]
pub async fn ap_task(runner: ApRunner) -> ! {
    let ApRunner {
        mut ap,
        mut rx,
        mut up,
        mut down,
    } = runner;
    let interval_us = u64::from(BEACON_INTERVAL_TU) * 1024;
    // the hook runs this long before the TBTT; the timestamp lands this
    // long after the hook (long preamble and PLCP, then the 24-byte header
    // at 1 Mbit/s)
    const LEAD_US: u64 = 40;
    const TO_TIMESTAMP_US: u64 = 192 + 24 * 8;
    let mut beacon_index: u32 = 0;
    let mut frame = [0u8; 1600];
    let mut sweep = Instant::now();
    loop {
        let now = tsf::access_point();
        let next_tbtt = (now / interval_us + 1) * interval_us;
        let wait = next_tbtt.saturating_sub(now).saturating_sub(LEAD_US);
        match select3(
            Timer::after(Duration::from_micros(wait)),
            rx.receive(),
            down.tx_buf(),
        )
        .await
        {
            Either3::First(()) => {
                let dtim_count = (beacon_index % u32::from(DTIM_PERIOD)) as u8;
                beacon_index = beacon_index.wrapping_add(1);
                let group_buffered = ap.held.group_count() > 0;
                let tim = ap.stations.tim(dtim_count, DTIM_PERIOD, group_buffered);
                let mut buf = ap.tx.alloc_tx_buf().await;
                let Some(beacon) = frames::beacon(&mut buf[..], &ap.bss, &tim) else {
                    continue;
                };
                let at = beacon.timestamp_at;
                let sent = ap
                    .tx
                    .transmit_beacon_with_hook(
                        &mut buf[..beacon.len],
                        plcp(one_mbit()),
                        TxMacParameters {
                            override_seq_num: true,
                            ..Default::default()
                        },
                        |f| {
                            let ts = tsf::access_point() + TO_TIMESTAMP_US;
                            f[at..at + 8].copy_from_slice(&ts.to_le_bytes());
                        },
                    )
                    .await;
                if sent.is_ok() {
                    BEACONS.fetch_add(1, Ordering::Relaxed);
                } else {
                    BEACON_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
                if dtim_count == 0 && group_buffered {
                    ap.release_group().await;
                }
                ap.resend_due().await;
                let now_us = Instant::now().as_micros();
                if ap.rekey_due || now_us >= ap.rekey_at_us {
                    ap.begin_rekey(now_us).await;
                }
            }
            Either3::Second(received) => {
                let bytes = received.mpdu_buffer();
                let n = bytes.len().min(frame.len());
                frame[..n].copy_from_slice(&bytes[..n]);
                drop(received);
                let (fc0, fc1) = (frame[0], frame[1]);
                let now = Instant::now().as_micros();
                match (fc0 >> 2) & 0b11 {
                    0 => ap.management(&frame[..n], now).await,
                    1 => ap.control(&frame[..n], fc0, now).await,
                    2 => ap.data(&mut frame[..n], fc0, fc1, now, &mut up).await,
                    _ => {}
                }
            }
            Either3::Third(eth) => {
                let n = eth.len();
                if n >= 14 {
                    frame[..n].copy_from_slice(eth);
                }
                down.tx_done();
                if n >= 14 {
                    ap.deliver(&frame[..n]).await;
                }
            }
        }
        if sweep.elapsed().as_secs() >= 10 {
            sweep = Instant::now();
            let now_us = Instant::now().as_micros();
            while let Some(gone) = ap.stations.inactive(now_us, ap.inactivity_us) {
                ap.forget(&gone);
                DROPPED_INACTIVE.fetch_add(1, Ordering::Relaxed);
                let b = ap.bss.bssid;
                ap.reply(|out, _| frames::deauthentication(out, b, gone, reason::INACTIVITY))
                    .await;
            }
            STATIONS_NOW.store(ap.stations.iter().count() as u32, Ordering::Relaxed);
            DOZING_NOW.store(
                ap.stations.iter().filter(|s| s.power_save).count() as u32,
                Ordering::Relaxed,
            );
        }
    }
}

/// The access point's counters since boot, for a firmware's watch line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Stations in the table now, and how many of them doze.
    pub stations: u32,
    /// Stations in the table now, and how many of them doze.
    pub dozing: u32,
    /// Beacons sent and beacon transmissions that failed.
    pub beacons: u32,
    /// Beacons sent and beacon transmissions that failed.
    pub beacon_failures: u32,
    /// Management replies sent, and those never acknowledged (probe
    /// responses to scanners that left the channel, mostly).
    pub replies: u32,
    /// Management replies sent, and those never acknowledged (probe
    /// responses to scanners that left the channel, mostly).
    pub replies_unacked: u32,
    /// 4-way handshakes completed (a station joined and keyed).
    pub joins: u32,
    /// Stations that said goodbye (deauthentication or disassociation).
    pub leaves: u32,
    /// Stations dropped for silence (reason 4).
    pub dropped_inactive: u32,
    /// Frames for the stack dropped because its receive channel was full.
    pub up_dropped: u32,
    /// EAPOL frames sent again, refused, and handshakes timed out.
    pub handshake_resent: u32,
    /// EAPOL frames sent again, refused, and handshakes timed out.
    pub handshake_refused: u32,
    /// EAPOL frames sent again, refused, and handshakes timed out.
    pub handshake_timeouts: u32,
    /// Data frames up from stations, down to them, and relayed between
    /// them (or to the group).
    pub up: u32,
    /// Data frames up from stations, down to them, and relayed between
    /// them (or to the group).
    pub down: u32,
    /// Data frames up from stations, down to them, and relayed between
    /// them (or to the group).
    pub forwarded: u32,
    /// Unprotected data frames dropped after a station's keys were in, and
    /// protected frames whose packet number did not climb.
    pub plaintext_dropped: u32,
    /// Unprotected data frames dropped after a station's keys were in, and
    /// protected frames whose packet number did not climb.
    pub replays: u32,
    /// Class-3 frames from stations the table does not hold (answered with
    /// reason 7).
    pub strangers: u32,
    /// Power save: frames held for dozing stations, dropped for a full
    /// pool, released; group frames held; PS-Polls; wakes.
    pub held: u32,
    /// Power save: frames held for dozing stations, dropped for a full
    /// pool, released; group frames held; PS-Polls; wakes.
    pub held_dropped: u32,
    /// Power save: frames held for dozing stations, dropped for a full
    /// pool, released; group frames held; PS-Polls; wakes.
    pub released: u32,
    /// Power save: frames held for dozing stations, dropped for a full
    /// pool, released; group frames held; PS-Polls; wakes.
    pub group_held: u32,
    /// Power save: frames held for dozing stations, dropped for a full
    /// pool, released; group frames held; PS-Polls; wakes.
    pub ps_polls: u32,
    /// Power save: frames held for dozing stations, dropped for a full
    /// pool, released; group frames held; PS-Polls; wakes.
    pub wakes: u32,
    /// Group-key rotations completed, messages sent, unacknowledged,
    /// confirmed, timed out.
    pub rekeys: u32,
    /// Group-key rotations completed, messages sent, unacknowledged,
    /// confirmed, timed out.
    pub rekey_messages: u32,
    /// Group-key rotations completed, messages sent, unacknowledged,
    /// confirmed, timed out.
    pub rekey_unacked: u32,
    /// Group-key rotations completed, messages sent, unacknowledged,
    /// confirmed, timed out.
    pub rekey_confirmed: u32,
    /// Group-key rotations completed, messages sent, unacknowledged,
    /// confirmed, timed out.
    pub rekey_timeouts: u32,
    /// ARP frames from stations (each answers a group-addressed request:
    /// the group key in use works for them).
    pub arp_up: u32,
    /// QoS Data frames sent, frames sent at HT rates, unicast data frames
    /// never acknowledged, rate-ladder steps up and down.
    pub qos_sent: u32,
    /// QoS Data frames sent, frames sent at HT rates, unicast data frames
    /// never acknowledged, rate-ladder steps up and down.
    pub ht_sent: u32,
    /// QoS Data frames sent, frames sent at HT rates, unicast data frames
    /// never acknowledged, rate-ladder steps up and down.
    pub data_unacked: u32,
    /// QoS Data frames sent, frames sent at HT rates, unicast data frames
    /// never acknowledged, rate-ladder steps up and down.
    pub ladder_up: u32,
    /// QoS Data frames sent, frames sent at HT rates, unicast data frames
    /// never acknowledged, rate-ladder steps up and down.
    pub ladder_down: u32,
}

/// The counters now.
#[must_use]
pub fn stats() -> Stats {
    let r = |a: &AtomicU32| a.load(Ordering::Relaxed);
    Stats {
        stations: r(&STATIONS_NOW),
        dozing: r(&DOZING_NOW),
        beacons: r(&BEACONS),
        beacon_failures: r(&BEACON_FAILURES),
        replies: r(&MANAGEMENT_REPLIES),
        replies_unacked: r(&MANAGEMENT_UNACKED),
        joins: r(&JOINS),
        leaves: r(&LEAVES),
        dropped_inactive: r(&DROPPED_INACTIVE),
        up_dropped: r(&UP_DROPPED),
        handshake_resent: r(&HANDSHAKE_RESENT),
        handshake_refused: r(&HANDSHAKE_REFUSED),
        handshake_timeouts: r(&HANDSHAKE_TIMEOUTS),
        up: r(&UP_FRAMES),
        down: r(&DOWN_FRAMES),
        forwarded: r(&FORWARDED),
        plaintext_dropped: r(&PLAINTEXT_DROPPED),
        replays: r(&REPLAYS),
        strangers: r(&STRANGERS),
        held: r(&HELD),
        held_dropped: r(&HELD_DROPPED),
        released: r(&RELEASED),
        group_held: r(&GROUP_HELD),
        ps_polls: r(&PS_POLLS),
        wakes: r(&WAKES),
        rekeys: r(&REKEYS),
        rekey_messages: r(&REKEY_MESSAGES),
        rekey_unacked: r(&REKEY_UNACKED),
        rekey_confirmed: r(&REKEY_CONFIRMED),
        rekey_timeouts: r(&REKEY_TIMEOUTS),
        arp_up: r(&ARP_UP),
        qos_sent: r(&QOS_DATA_SENT),
        ht_sent: r(&HT_SENT),
        data_unacked: r(&DATA_UNACKED),
        ladder_up: r(&LADDER_UP),
        ladder_down: r(&LADDER_DOWN),
    }
}

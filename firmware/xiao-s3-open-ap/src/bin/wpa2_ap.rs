//! E3's P4b (experiments plan): a WPA2-PSK access point on the open lower
//! MAC that a station joins. `janus-e3-wpa2` on channel 6, 192.168.4.1 with
//! a DHCP server, as P4a's open one, plus WPA2: the PMK from the passphrase
//! at boot, a random group key in its own key slot, the 4-way handshake as
//! authenticator (`ap_core`, which an independent implementation checks on
//! the host), each station's pairwise key in a key slot of its own once
//! message 4 is in, and CCMP on every data frame: the hardware encrypts and
//! decrypts, the frames' CCMP headers, packet numbers and replay checks are
//! ours. Power save (E3's P5): a station whose last frame carried the Power
//! Management bit dozes; its frames are held (`ap_core::hold`) and named in
//! the beacon's TIM, one released per PS-Poll with More Data set while more
//! wait, all of them when it sends with the bit clear; group frames are
//! held while anyone dozes and go after the DTIM beacon. **Not Wi-Fi
//! certified.**
//!
//! The passphrase is `JANUS_AP_PASS` at build time and nowhere else:
//! `tools/e3-p4b.py` makes a fresh one for each run, in memory, for this
//! throwaway bench network; nothing here prints it.
#![no_std]
#![no_main]

#[path = "../tsf.rs"]
mod tsf;

use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU32, Ordering};

use ap_core::frames::{self, Bss};
use ap_core::handshake::{self, Authenticator};
use ap_core::hold::Held;
use ap_core::request::{self, Request};
use ap_core::stations::{MAX_STATIONS, State, Stations};
use ap_core::{Address, reason, status};
use embassy_executor::Spawner;
use embassy_futures::select::{Either3, select3};
use embassy_net::{Ipv4Cidr, Stack, StackResources, StaticConfigV4};
use embassy_net_driver::{HardwareAddress, LinkState};
use embassy_net_driver_channel as ch;
use embassy_time::{Duration, Instant, Timer};
use esp_backtrace as _;
use esp_hal::rng::Rng;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use foa::esp_wifi_hal::ll::EdcaAccessCategory;
use foa::esp_wifi_hal::prelude::{
    AesCipherParameters, CipherParameters, ControlFrameFilterConfig, KeyType, MultiLengthKey, RxFilterBank,
    TxMacParameters, TxPlcpParameters,
};
use foa::esp_wifi_hal::rates::{HrDsssRate, OfdmRate, TxPhyRate};
use foa::LMacInterfaceControl;
use foa::{FoAResources, FoARunner, KeySlot, RetryBehaviour, TxEndpoint, VirtualInterface};
use sta_handshake::GroupKey;
use static_cell::{ConstStaticCell, StaticCell};

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &[u8] = b"janus-e3-wpa2";
const PASSPHRASE: &str = env!("JANUS_AP_PASS");
const CHANNEL: u8 = 6;
const BEACON_INTERVAL_TU: u16 = 100;
const DTIM_PERIOD: u8 = 2;
const MTU: usize = 1514;
const ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 4, 1);
const INACTIVITY_US: u64 = 300_000_000;
/// An EAPOL-Key frame not answered within this is sent again (802.11's
/// dot11RSNAConfigPairwiseUpdateTimeOut is 100 ms; a laptop's supplicant
/// may take longer, so 1 s), at most this many times, then the station is
/// deauthenticated (reason 15).
const HANDSHAKE_RESEND_US: u64 = 1_000_000;
const HANDSHAKE_RESENDS: u8 = 3;
const GTK_KEY_ID: u8 = 1;
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
static STRANGERS: AtomicU32 = AtomicU32::new(0);
static HANDSHAKES: AtomicU32 = AtomicU32::new(0);
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

#[embassy_executor::task]
async fn mac_task(mut runner: FoARunner<'static>) {
    runner.run().await
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, ch::Device<'static, MTU>>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn dhcp_task(stack: Stack<'static>) -> ! {
    use core::net::{SocketAddr, SocketAddrV4};
    use edge_dhcp::io::{self, DEFAULT_SERVER_PORT};
    use edge_dhcp::server::{Server, ServerOptions};
    use edge_nal::UdpBind as _;
    use edge_nal_embassy::{Udp, UdpBuffers};

    let now = || Instant::now().as_secs();
    let mut server = Server::<_, 8>::new(now, ADDRESS);
    let mut gateway = [ADDRESS];
    let options = ServerOptions::new(ADDRESS, Some(&mut gateway));
    let buffers = UdpBuffers::<1, 1500, 1500, 2>::new();
    let mut packet = [0u8; 1500];
    loop {
        let udp = Udp::new(stack, &buffers);
        if let Ok(mut socket) = udp
            .bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_SERVER_PORT)))
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
    [pn[0], pn[1], 0, 0x20 | (key_id << 6), pn[2], pn[3], pn[4], pn[5]]
}

fn ccmp_packet_number(header: &[u8]) -> u64 {
    u64::from_le_bytes([header[0], header[1], header[4], header[5], header[6], header[7], 0, 0])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    SentMessage1,
    SentMessage3,
    Done,
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
}

struct AccessPoint {
    tx: &'static mut TxEndpoint<'static>,
    control: &'static LMacInterfaceControl<'static>,
    bss: Bss<'static>,
    stations: Stations,
    peers: [Option<Peer>; MAX_STATIONS],
    pmk: [u8; 32],
    gtk: GroupKey,
    gtk_slot: KeySlot<'static>,
    group_packet_number: u64,
    held: &'static mut Held,
}

impl AccessPoint {
    fn peer(&mut self, address: &Address) -> Option<&mut Peer> {
        self.peers.iter_mut().flatten().find(|p| p.address == *address)
    }

    fn forget(&mut self, address: &Address) {
        for slot in self.peers.iter_mut() {
            if slot.as_ref().is_some_and(|p| p.address == *address) {
                // its key slot is released (FoA deletes the key) as it drops
                *slot = None;
            }
        }
        self.held.clear(address);
        self.stations.remove(address);
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
                    let n = self.held.count(&to);
                    self.stations.set_queued(&to, n);
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
        let mut copy = [0u8; ap_core::hold::HELD_FRAME_BYTES];
        let Some((taken, more)) = self.held.pop(&station) else {
            return;
        };
        let n = taken.frame.len();
        copy[..n].copy_from_slice(taken.frame);
        let left = self.held.count(&station);
        self.stations.set_queued(&station, left);
        RELEASED.fetch_add(1, Ordering::Relaxed);
        self.transmit(&copy[..n], more).await;
    }

    /// Every held frame to a station that woke (the Power Management bit
    /// clear).
    async fn release_all(&mut self, station: Address) {
        while self.held.count(&station) > 0 {
            self.release_one(station).await;
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
        self.reply(|out, scratch| handshake::write_message_1(out, scratch, bssid, station, &anonce, replay).ok())
            .await;
    }

    async fn send_message_3(&mut self, station: Address) {
        let (bssid, gtk) = (self.bss.bssid, self.gtk);
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
            handshake::write_message_3(out, scratch, bssid, station, &keys, &anonce, replay, &gtk).ok()
        })
        .await;
    }

    /// A station associated: its 4-way handshake begins with a fresh ANonce.
    async fn begin_handshake(&mut self, station: Address) {
        let mut anonce = [0u8; 32];
        Rng::new().read(&mut anonce);
        if let Some(free) = self.peers.iter_mut().find(|p| p.as_ref().is_none_or(|p| p.address == station)) {
            *free = Some(Peer {
                address: station,
                authenticator: Authenticator::new(anonce),
                stage: Stage::SentMessage1,
                sent_at_us: 0,
                resends: 0,
                key_slot: None,
                tx_packet_number: 1,
                rx_packet_number: 0,
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
                match handshake::read_message_2(frame, &pmk, &bssid, &station, &anonce, replay, rsn.as_slice()) {
                    Ok(keys) => {
                        peer.authenticator.keys = Some(keys);
                        peer.resends = 0;
                        self.send_message_3(station).await;
                    }
                    Err(why) => {
                        HANDSHAKE_REFUSED.fetch_add(1, Ordering::Relaxed);
                        println!("open-ap: message 2 from {:02x?} refused: {:?}", station, why);
                    }
                }
            }
            Stage::SentMessage3 => {
                let replay = peer.authenticator.replay_counter;
                let Some(keys) = peer.authenticator.keys.clone() else {
                    return;
                };
                if let Err(why) = handshake::read_message_4(frame, &keys, replay) {
                    HANDSHAKE_REFUSED.fetch_add(1, Ordering::Relaxed);
                    println!("open-ap: message 4 from {:02x?} refused: {:?}", station, why);
                    return;
                }
                // the pairwise key into a key slot of the station's own
                let Some(mut slot) = self.control.acquire_key_slot() else {
                    println!("open-ap: no key slot for {:02x?}", station);
                    return;
                };
                if slot.set_key(0, station, ccmp(keys.tk(), KeyType::Pairwise)).is_err() {
                    println!("open-ap: the key slot refused the PTK");
                    return;
                }
                let peer = self.peer(&station).expect("held above");
                peer.key_slot = Some(slot);
                peer.stage = Stage::Done;
                self.stations.connected(&station);
                HANDSHAKES.fetch_add(1, Ordering::Relaxed);
                println!("open-ap: {:02x?} keys installed: connected", station);
            }
            Stage::Done => {}
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
            HANDSHAKE_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            println!("open-ap: {:02x?} handshake timed out", station);
            self.forget(&station);
            let b = self.bss.bssid;
            self.reply(|out, _| frames::deauthentication(out, b, station, reason::FOURWAY_HANDSHAKE_TIMEOUT))
                .await;
            return;
        }
        if let Some(p) = self.peer(&station) {
            p.resends += 1;
        }
        HANDSHAKE_RESENT.fetch_add(1, Ordering::Relaxed);
        match stage {
            Stage::SentMessage1 => self.send_message_1(station).await,
            Stage::SentMessage3 => self.send_message_3(station).await,
            Stage::Done => {}
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
        let (slot, key_id, packet_number) = if group {
            self.group_packet_number += 1;
            (self.gtk_slot.key_slot(), GTK_KEY_ID, self.group_packet_number)
        } else {
            let Some(peer) = self.peer(&to) else {
                return;
            };
            let Some(slot) = peer.key_slot.as_ref().map(KeySlot::key_slot) else {
                return;
            };
            peer.tx_packet_number += 1;
            (slot, 0, peer.tx_packet_number)
        };
        let mut buf = self.tx.alloc_tx_buf().await;
        let n = 24 + 8 + 8 + payload.len() + 8;
        let Some(frame) = buf.get_mut(..n) else {
            return;
        };
        frame[..4].copy_from_slice(&[0x08, 0x02 | 0x40 | if more_data { 0x20 } else { 0 }, 0, 0]);
        frame[4..10].copy_from_slice(&to);
        frame[10..16].copy_from_slice(&self.bss.bssid);
        frame[16..22].copy_from_slice(from);
        frame[22..24].copy_from_slice(&[0, 0]);
        frame[24..32].copy_from_slice(&ccmp_header(packet_number, key_id));
        frame[32..38].copy_from_slice(&SNAP);
        frame[38..40].copy_from_slice(&ether_type);
        frame[40..40 + payload.len()].copy_from_slice(payload);
        frame[n - 8..].fill(0);
        let (rate, retry) = if group {
            (one_mbit(), RetryBehaviour::Drop)
        } else {
            (TxPhyRate::Ofdm(OfdmRate::Mbits24), RetryBehaviour::RetryUntil(7))
        };
        let _ = self.tx.transmit_edca(
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
            Some(Request::Probe { from, ssid }) if ssid.is_none() || ssid == Some(SSID) => {
                let ts = tsf::access_point();
                self.reply(|out, _| {
                    let n = frames::probe_response(out, &bss, from)?;
                    out[24..32].copy_from_slice(&ts.to_le_bytes());
                    Some(n)
                })
                .await;
            }
            Some(Request::Authentication { from, algorithm, sequence }) => {
                // a station starting again: its keys go
                self.forget(&from);
                let status = self.stations.authenticate(from, algorithm, sequence);
                self.stations.heard(&from, now, false);
                println!("open-ap: authentication from {:02x?} status={status}", from);
                self.reply(|out, _| frames::authentication(out, bss.bssid, from, status)).await;
            }
            Some(Request::Association { from, ssid, rsn_element, reassociation }) => {
                let (status, aid) = match self.stations.associate(from, ssid == Some(SSID), rsn_element, true) {
                    Ok(aid) => (status::SUCCESS, aid),
                    Err(status) => (status, 0),
                };
                self.stations.heard(&from, now, false);
                println!(
                    "open-ap: {} from {:02x?} status={status} aid={aid}",
                    if reassociation { "re-association" } else { "association" },
                    from
                );
                self.reply(|out, _| frames::association_response(out, &bss, from, status, aid, reassociation))
                    .await;
                if status == status::SUCCESS {
                    self.begin_handshake(from).await;
                }
            }
            Some(Request::Deauthentication { from, reason } | Request::Disassociation { from, reason }) => {
                if self.stations.get(&from).is_some() {
                    println!("open-ap: {:02x?} left reason={reason}", from);
                }
                self.forget(&from);
            }
            _ => {}
        }
    }

    async fn data(&mut self, f: &mut [u8], fc0: u8, fc1: u8, now: u64, up: &mut ch::RxRunner<'static, MTU>) {
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
            self.reply(|out, _| frames::deauthentication(out, b, station, reason::CLASS3_FROM_NONASSOC))
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
        if !protected {
            // in the clear only the 4-way handshake's frames (E2's F6, the
            // access point's side)
            let llc = f.get(header..header + 8);
            if llc.is_some_and(|l| l[..6] == SNAP && l[6..8] == EAPOL)
                && self.peer(&station).is_some_and(|p| p.stage != Stage::Done)
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
        if peer.stage != Stage::Done {
            return;
        }
        if packet_number <= peer.rx_packet_number {
            REPLAYS.fetch_add(1, Ordering::Relaxed);
            return;
        }
        peer.rx_packet_number = packet_number;
        let body = header + 8;
        let Some(llc) = f.get(body..body + 8) else {
            return;
        };
        if llc[..6] != SNAP {
            return;
        }
        let ether_type = [llc[6], llc[7]];
        let payload_at = body + 8;
        UP_FRAMES.fetch_add(1, Ordering::Relaxed);
        let for_us = destination == self.bss.bssid;
        let group = is_group(&destination);
        if for_us || group {
            if let Some(buf) = up.try_rx_buf() {
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

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    let peripherals =
        esp_hal::init(esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max()));
    esp_alloc::heap_allocator!(size: 96 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    println!("open-ap: boot (E3 P4b WPA2; the open MAC, NOT Wi-Fi certified)");
    let started = Instant::now();

    let rtc = esp_hal::rtc_cntl::Rtc::new(peripherals.RTC_TIMER);
    tsf::start_access_point_clock_at(rtc.time_since_power_up().as_micros());

    // the PMK, once: PBKDF2-HMAC-SHA1, 4,096 rounds
    let pmk_started = Instant::now();
    let mut pmk = [0u8; 32];
    ieee80211::crypto::map_passphrase_to_psk(PASSPHRASE, "janus-e3-wpa2", &mut pmk);
    println!("open-ap: pmk derived pmk_ms={}", pmk_started.elapsed().as_millis());

    static FOA: StaticCell<FoAResources> = StaticCell::new();
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    let ([vif, ..], runner) = foa::init(FOA.init(FoAResources::new()), peripherals.WIFI);
    spawner.spawn(mac_task(runner).expect("mac task"));
    let vif = VIF.init(vif);
    let (control, mut rx, tx) = vif.split();
    let control: &'static LMacInterfaceControl<'static> = control;

    let base = esp_hal::efuse::base_mac_address();
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(base.as_bytes());
    bssid[5] = bssid[5].wrapping_add(1);
    if control.lock_channel(CHANNEL).is_err() {
        println!("open-ap: channel {CHANNEL} refused");
    }
    control.set_filter(RxFilterBank::ReceiverAddress, bssid);
    control.set_filter(RxFilterBank::Bssid, bssid);
    control.set_filter_bssid_check(false);
    // PS-Poll is the one control frame the access point reads (the HAL
    // passes none up by default)
    control.set_control_frame_filter(&ControlFrameFilterConfig {
        ps_poll: true,
        ..ControlFrameFilterConfig::none()
    });

    // the group key, random, in a key slot of its own
    let mut gtk_key = [0u8; 16];
    Rng::new().read(&mut gtk_key);
    let gtk = GroupKey {
        key: gtk_key,
        key_id: GTK_KEY_ID,
        rsc: 0,
        replay_counter: 0,
    };
    let mut gtk_slot = control.acquire_key_slot().expect("a key slot for the group key");
    gtk_slot
        .set_key(GTK_KEY_ID, bssid, ccmp(&gtk.key, KeyType::Group))
        .expect("the group key");

    let state = mk_static!(ch::State<MTU, 8, 8>, ch::State::new());
    let (net_runner, device) = ch::new(state, HardwareAddress::Ethernet(bssid));
    let (state_runner, mut up, mut down) = net_runner.split();
    state_runner.set_link_state(LinkState::Up);
    let config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(ADDRESS, 24),
        gateway: None,
        dns_servers: Default::default(),
    });
    let seed = u64::from(Rng::new().random()) << 32 | u64::from(Rng::new().random());
    let (stack, stack_runner) =
        embassy_net::new(device, config, mk_static!(StackResources<6>, StackResources::new()), seed);
    spawner.spawn(net_task(stack_runner).expect("net task"));
    spawner.spawn(dhcp_task(stack).expect("dhcp task"));

    static HELD_FRAMES: ConstStaticCell<Held> = ConstStaticCell::new(Held::new());
    let mut ap = AccessPoint {
        tx,
        control,
        bss: Bss {
            bssid,
            ssid: SSID,
            channel: CHANNEL,
            beacon_interval_tu: BEACON_INTERVAL_TU,
            protected: true,
        },
        stations: Stations::new(),
        peers: [const { None }; MAX_STATIONS],
        pmk,
        gtk,
        gtk_slot,
        group_packet_number: 0,
        held: HELD_FRAMES.take(),
    };
    println!(
        "open-ap: hosting ssid=janus-e3-wpa2 (WPA2-PSK, CCMP) channel={CHANNEL} bssid={:02x?} address={ADDRESS} init_ms={}",
        bssid,
        started.elapsed().as_millis()
    );

    let interval_us = u64::from(BEACON_INTERVAL_TU) * 1024;
    const LEAD_US: u64 = 40;
    const TO_TIMESTAMP_US: u64 = 192 + 24 * 8;
    let mut beacon_index: u32 = 0;
    let mut frame = [0u8; 1600];
    let mut report = Instant::now();
    loop {
        let now = tsf::access_point();
        let next_tbtt = (now / interval_us + 1) * interval_us;
        let wait = next_tbtt.saturating_sub(now).saturating_sub(LEAD_US);
        match select3(Timer::after(Duration::from_micros(wait)), rx.receive(), down.tx_buf()).await {
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
        if report.elapsed().as_secs() >= 10 {
            report = Instant::now();
            let now_us = Instant::now().as_micros();
            while let Some(gone) = ap.stations.inactive(now_us, INACTIVITY_US) {
                ap.forget(&gone);
                let b = ap.bss.bssid;
                ap.reply(|out, _| frames::deauthentication(out, b, gone, reason::INACTIVITY)).await;
            }
            println!(
                "open-ap: up_s={} stations={} beacons={} beacon_failures={} replies={} unacked={} handshakes={} resent={} refused={} timeouts={} up={} down={} forwarded={} plaintext_dropped={} replays={} held={} held_dropped={} released={} group_held={} ps_polls={} wakes={} dozing_now={} strangers={}",
                started.elapsed().as_secs(),
                ap.stations.iter().count(),
                BEACONS.load(Ordering::Relaxed),
                BEACON_FAILURES.load(Ordering::Relaxed),
                MANAGEMENT_REPLIES.load(Ordering::Relaxed),
                MANAGEMENT_UNACKED.load(Ordering::Relaxed),
                HANDSHAKES.load(Ordering::Relaxed),
                HANDSHAKE_RESENT.load(Ordering::Relaxed),
                HANDSHAKE_REFUSED.load(Ordering::Relaxed),
                HANDSHAKE_TIMEOUTS.load(Ordering::Relaxed),
                UP_FRAMES.load(Ordering::Relaxed),
                DOWN_FRAMES.load(Ordering::Relaxed),
                FORWARDED.load(Ordering::Relaxed),
                PLAINTEXT_DROPPED.load(Ordering::Relaxed),
                REPLAYS.load(Ordering::Relaxed),
                HELD.load(Ordering::Relaxed),
                HELD_DROPPED.load(Ordering::Relaxed),
                RELEASED.load(Ordering::Relaxed),
                GROUP_HELD.load(Ordering::Relaxed),
                PS_POLLS.load(Ordering::Relaxed),
                WAKES.load(Ordering::Relaxed),
                ap.stations.iter().filter(|s| s.power_save).count(),
                STRANGERS.load(Ordering::Relaxed),
            );
        }
    }
}

use core::{
    future::pending,
    marker::PhantomData,
    sync::atomic::{AtomicU32, AtomicU8, Ordering},
};

use embassy_futures::{
    join::join,
    select::{Either3, select3},
};
use embassy_net_driver::{HardwareAddress, LinkState};
use embassy_net_driver_channel::{RxRunner, StateRunner, TxRunner};
use embassy_time::Ticker;
use ethernet::{Ethernet2Frame, Ethernet2Header};
use foa::{
    ReceivedFrame, RetryBehaviour, RxEndpoint,
    esp_wifi_hal::{ll::EdcaAccessCategory, prelude::*},
    util::{operations::deauthenticate, rx_router::RxRouterQueue},
};
use futures_util::FutureExt;
use ieee80211::{
    GenericFrame,
    common::{DataFrameSubtype, FCFFlags, FrameType, SequenceControl},
    crypto::{CryptoHeader, MicState},
    data_frame::{
        DataFrame, DataFrameReadPayload, PotentiallyWrappedPayload, header::DataFrameHeader,
    },
    mac_parser::MACAddress,
    match_frames,
    mgmt_frame::{BeaconFrame, DeauthenticationFrame},
    scroll::{Pread, Pwrite},
};
use llc_rs::SnapLlcFrame;

use crate::{
    MTU, StaTxRx,
    connection_state::{ConnectionInfo, ConnectionState, DisconnectionReason},
    rx_router::{StaRxRouterEndpoint, StaRxRouterInput, StaRxRouterOperation},
};
enum ConnectionRxEvent {
    Disconnected(DisconnectionReason),
    BeaconReceived,
}

pub(crate) struct ConnectionRunner<'foa, 'vif> {
    // Low level RX/TX.
    pub(crate) rx_router_endpoint: StaRxRouterEndpoint<'foa, 'vif>,
    pub(crate) sta_tx_rx: &'vif StaTxRx<'foa, 'vif>,

    // Upper layer control.
    pub(crate) state_runner: StateRunner<'vif>,
}
impl ConnectionRunner<'_, '_> {
    /// Handle a deauth frame.
    ///
    /// NOTE: Currently this immediately leads to disconnection.
    fn handle_deauth(&self, deauth: DeauthenticationFrame<'_>) -> ConnectionRxEvent {
        debug!(
            "Received deauthentication frame from {}, reason: {:?}.",
            deauth.header.transmitter_address, deauth.reason
        );
        ConnectionRxEvent::Disconnected(DisconnectionReason::Deauthenticated)
    }
    /// Handle a frame arriving on the background queue, during a connection.
    fn handle_bg_rx(&self, buffer: ReceivedFrame<'_>) -> Option<ConnectionRxEvent> {
        match_frames! {
            buffer.mpdu_buffer(),
            deauth = DeauthenticationFrame => {
                self.handle_deauth(deauth)
            }
            _beacon = BeaconFrame => {
                ConnectionRxEvent::BeaconReceived
            }
        }
        .ok()
    }
    /// Run the background task.
    ///
    /// This will return if we are deauthenticated or a beacon timeout occurs.
    async fn run_connection(
        &self,
        ConnectionInfo {
            bss,
            own_address,
            connection_config,
            ..
        }: &ConnectionInfo,
    ) -> DisconnectionReason {
        let mut beacon_timeout = connection_config.beacon_timeout.map(Ticker::every);
        loop {
            // We wait for one of three things to happen.
            // 1. An off channel request arrives, which we grant immediately and wait for its
            //    completion.
            // 2. A frame to arrive from the background queue.
            // 3. A beacon timeout to occur.
            match select3(
                self.sta_tx_rx
                    .interface_control
                    .wait_for_off_channel_request(),
                self.rx_router_endpoint.receive(),
                async {
                    if let Some(ref mut ticker) = beacon_timeout {
                        ticker.next().await
                    } else {
                        pending().await
                    }
                },
            )
            .await
            {
                Either3::First(off_channel_request) => {
                    off_channel_request.grant();
                    self.sta_tx_rx
                        .interface_control
                        .wait_for_off_channel_completion()
                        .await;
                }
                Either3::Second(buffer) => {
                    if let Some(connection_rx_event) = self.handle_bg_rx(buffer) {
                        match connection_rx_event {
                            ConnectionRxEvent::Disconnected(disconnection_reason) => {
                                return disconnection_reason;
                            }
                            ConnectionRxEvent::BeaconReceived => {
                                beacon_timeout.as_mut().map(Ticker::reset);
                            }
                        }
                    }
                }
                Either3::Third(_) => {
                    // Since we assume the network can either not or barely hear us, we use the
                    // lowest PHY rate.
                    deauthenticate(
                        self.sta_tx_rx.tx_endpoint,
                        bss.bssid,
                        *own_address,
                        true,
                        OfdmRate::Mbits6.into(),
                    )
                    .await;
                    debug!("Disconnected from BSS due to beacon timeout.");
                    return DisconnectionReason::BeaconTimeout;
                }
            }
        }
    }
    /// Handle the tranmsission of MSDUs.
    async fn run_msdu_tx(
        tx_runner: &mut TxRunner<'_, MTU>,
        sta_tx_rx: &StaTxRx<'_, '_>,
        connection_info: &ConnectionInfo,
    ) -> ! {
        loop {
            let msdu = tx_runner.tx_buf().await;

            // We don't want to accidentally transmit a MSDU, while we're not on channel.
            if sta_tx_rx.in_off_channel_operation() {
                sta_tx_rx
                    .interface_control
                    .wait_for_off_channel_completion()
                    .await;
            }
            let Ok(ethernet_frame) = msdu.pread::<Ethernet2Frame>(0) else {
                continue;
            };
            let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
            let data_frame = DataFrame {
                header: DataFrameHeader {
                    subtype: DataFrameSubtype::Data,
                    fcf_flags: FCFFlags::new().with_to_ds(true),
                    address_1: connection_info.bss.bssid,
                    address_2: connection_info.own_address,
                    address_3: ethernet_frame.header.dst,
                    sequence_control: SequenceControl::new(),
                    ..Default::default()
                },
                payload: Some(SnapLlcFrame {
                    oui: [0x00; 3],
                    ether_type: ethernet_frame.header.ether_type,
                    payload: ethernet_frame.payload,
                    _phantom: PhantomData,
                }),
                _phantom: PhantomData,
            };

            cfg_select! {
                feature = "rsn" => {
                    let tx_crypto_info = sta_tx_rx.map_crypto_state(|crypto_state| {
                        (
                            crypto_state
                                .security_associations
                                .ptksa
                                .next_packet_number(),
                            crypto_state.security_associations.ptksa.key_id,
                            crypto_state.ptk_key_slot.key_slot(),
                        )
                    });
                },
                _ => {
                    let tx_crypto_info = None::<(u64, u8, usize)>;
                }

            }
            let Some((written, key_slot)) =
                (if let Some((new_packet_number, key_id, key_slot)) = tx_crypto_info {
                    tx_buf
                        .pwrite(
                            data_frame.crypto_wrap(
                                CryptoHeader::new(new_packet_number, key_id).unwrap(),
                                MicState::Short,
                            ),
                            0,
                        )
                        .ok()
                        .map(|written| (written, Some(key_slot as u8)))
                } else {
                    tx_buf.pwrite(data_frame, 0).ok().zip(Some(None))
                })
            else {
                continue;
            };
            let rate = data_frame_rate(sta_tx_rx.phy_rate());
            let _ = sta_tx_rx.tx_endpoint.transmit_edca(
                data_access_category(),
                tx_buf,
                written,
                TxPlcpParameters {
                    rate,
                    ..Default::default()
                },
                TxMacParameters {
                    key_slot_index: key_slot,
                    wait_for_ack: true,
                    rts_strategy: data_rts_strategy(),
                    // Each newly generated MSDU needs a fresh MPDU sequence;
                    // the driver keeps it unchanged across its MAC retries.
                    override_seq_num: true,
                    ..Default::default()
                },
                data_retry_behaviour(rate),
            );
            trace!(
                "Transmitted {} bytes to {}",
                msdu.len(),
                ethernet_frame.header.dst
            );
            tx_runner.tx_done();
        }
    }
    /// Run all actual background operations.
    async fn run(&mut self, tx_runner: &mut TxRunner<'_, MTU>) -> ! {
        loop {
            let connection_info = self.sta_tx_rx.connection_state.wait_for_connection().await;
            self.state_runner
                .set_hardware_address(HardwareAddress::Ethernet(*connection_info.own_address));
            self.state_runner.set_link_state(LinkState::Up);
            debug!("Link went up.");
            // At this point, the channel will have been locked, so we'll only receive off channel
            // requests, while we're connected.

            // Run the connection, until we're disconnected.
            let disconnection_reason = match select3(
                self.sta_tx_rx.connection_state.wait_for_disconnection(),
                self.run_connection(&connection_info),
                Self::run_msdu_tx(tx_runner, self.sta_tx_rx, &connection_info),
            )
            .await
            {
                Either3::First(disconnection_reason) | Either3::Second(disconnection_reason) => {
                    disconnection_reason
                }
                Either3::Third(_) => unreachable!(),
            };
            if tx_runner.try_tx_buf().is_some() {
                tx_runner.tx_done();
            }
            // We reset all connection specific parameters here.
            // Unlocking the channel was already done, by any path leading to disconnection.
            self.sta_tx_rx.interface_control.unlock_channel();
            self.sta_tx_rx.reset_phy_rate();
            self.sta_tx_rx
                .interface_control
                .clear_filter(RxFilterBank::Bssid);
            self.sta_tx_rx
                .connection_state
                .signal_state(ConnectionState::Disconnected(disconnection_reason));
            self.state_runner.set_link_state(LinkState::Down);
            debug!("Link went down.");
        }
    }
}
pub(crate) struct RoutingRunner<'foa, 'vif> {
    // Low level RX/TX.
    pub(crate) rx_router_input: StaRxRouterInput<'foa, 'vif>,
    pub(crate) interface_rx_endpoint: RxEndpoint<'foa, 'vif>,
    pub(crate) sta_tx_rx: &'vif StaTxRx<'foa, 'vif>,

    // Upper layer control.
    pub(crate) rx_runner: RxRunner<'vif, MTU>,

    /// A group-key handshake's message 1 taken, its message 2 still to send
    /// (its replay counter): sent from `run`, which may await (E2's F2).
    pub(crate) group_reply: Option<u64>,
}
impl RoutingRunner<'_, '_> {
    #[allow(unused)]
    fn process_potentially_wrapped_payload<'a>(
        &self,
        is_group: bool,
        payload: PotentiallyWrappedPayload<DataFrameReadPayload<'a>>,
    ) -> Option<DataFrameReadPayload<'a>> {
        match payload {
            PotentiallyWrappedPayload::Unwrapped(payload) => Some(payload),
            PotentiallyWrappedPayload::CryptoWrapped(crypto_wrapper) => {
                #[cfg(feature = "rsn")]
                return self
                    .sta_tx_rx
                    .map_crypto_state(|crypto_state| {
                        let security_associations = &crypto_state.security_associations;
                        let packet_number = crypto_wrapper.crypto_header.packet_number();
                        let packet_number_valid = if is_group {
                            security_associations
                                .gtksa
                                .update_and_validate_replay_counter(packet_number)
                        } else {
                            security_associations
                                .ptksa
                                .update_and_validate_replay_counter(packet_number)
                        };
                        packet_number_valid.then_some(crypto_wrapper.payload)
                    })
                    .flatten();
                #[cfg(not(feature = "rsn"))]
                return None;
            }
        }
    }
    /// Handover a single MSDU to embassy_net.
    fn handle_downlink_msdu(
        &mut self,
        payload: &[u8],
        source_address: MACAddress,
        destination_address: MACAddress,
    ) -> Option<()> {
        // The body of every data frame contains a logical link control (LLC) frame, as specified
        // in IEEE 802.2.
        let llc_payload = payload.pread::<SnapLlcFrame>(0).ok()?;
        // We don't wait on an RX buffer becoming available here, since doing so could stall the
        // routing task.
        let Some(rx_buf) = self.rx_runner.try_rx_buf() else {
            trace!("Dropping MSDU, because no buffers are available.");
            return None;
        };
        // Here we serialize the ethernet frame.
        let Ok(written) = rx_buf.pwrite(
            Ethernet2Frame {
                header: Ethernet2Header {
                    dst: destination_address,
                    src: source_address,
                    ether_type: llc_payload.ether_type,
                },
                payload: llc_payload.payload,
            },
            0,
        ) else {
            return None;
        };
        self.rx_runner.rx_done(written);
        Some(())
    }
    /// A group-key handshake's message 1 (E2's F2): verified, its GTK
    /// installed, and the reply queued for `run`. `mpdu` is the frame as
    /// received; a protected one has passed the PTK's replay check already.
    #[cfg(feature = "rsn")]
    fn handle_group_key_frame(&mut self, mpdu: &[u8]) {
        let mut plain = [0u8; 512];
        let mut scratch = [0u8; 512];
        let length = match sta_handshake::unprotect(mpdu, &mut plain) {
            Some(length) => length,
            None => match plain.get_mut(..mpdu.len()) {
                Some(copy) => {
                    copy.copy_from_slice(mpdu);
                    mpdu.len()
                }
                None => return,
            },
        };
        let Some(bssid) = self
            .sta_tx_rx
            .connection_state
            .connection_info()
            .map(|connection_info| *connection_info.bss.bssid)
        else {
            return;
        };
        let taken = self.sta_tx_rx.map_crypto_state(|crypto_state| {
            let keys = sta_handshake::PairwiseKeys {
                ptk: crypto_state.security_associations.ptksa.key,
            };
            let floor = crypto_state.security_associations.eapol_replay_counter;
            match sta_handshake::read_group_message_1(&mut plain[..length], &keys, &mut scratch, floor) {
                Ok(gtk) => {
                    crypto_state.update_gtksa(&gtk, bssid);
                    GROUP_REKEYS.fetch_add(1, Ordering::Relaxed);
                    debug!("Group key handshake: GTK key ID {} installed.", gtk.key_id);
                    Some(gtk.replay_counter)
                }
                Err(refusal) => {
                    GROUP_REFUSED.fetch_add(1, Ordering::Relaxed);
                    debug!("Group key message refused: {:?}", defmt_or_log::Debug2Format(&refusal));
                    None
                }
            }
        });
        if let Some(Some(replay_counter)) = taken {
            self.group_reply = Some(replay_counter);
        }
    }
    /// Send a group-key handshake's message 2, protected under the PTK.
    #[cfg(feature = "rsn")]
    async fn send_group_reply(&mut self, replay_counter: u64) {
        let Some(connection_info) = self.sta_tx_rx.connection_state.connection_info() else {
            return;
        };
        let Some((keys, packet_number, key_id, key_slot)) =
            self.sta_tx_rx.map_crypto_state(|crypto_state| {
                let ptksa = &crypto_state.security_associations.ptksa;
                (
                    sta_handshake::PairwiseKeys { ptk: ptksa.key },
                    ptksa.next_packet_number(),
                    ptksa.key_id,
                    crypto_state.ptk_key_slot.key_slot(),
                )
            })
        else {
            return;
        };
        let mut tx_buf = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let mut scratch = [0u8; 512];
        let Ok(written) = sta_handshake::write_group_message_2(
            tx_buf.as_mut_slice(),
            &mut scratch,
            connection_info.bss.bssid,
            connection_info.own_address,
            &keys,
            replay_counter,
            packet_number,
            key_id,
        ) else {
            return;
        };
        let _ = self
            .sta_tx_rx
            .tx_endpoint
            .transmit_edca(
                EdcaAccessCategory::default(),
                tx_buf,
                written,
                TxPlcpParameters {
                    rate: self.sta_tx_rx.phy_rate(),
                    ..Default::default()
                },
                TxMacParameters {
                    key_slot_index: Some(key_slot as u8),
                    wait_for_ack: true,
                    override_seq_num: true,
                    ..Default::default()
                },
                RetryBehaviour::RetryUntil(7),
            )
            .wait_for_completion()
            .await;
        debug!("Group key handshake: message 2 sent.");
    }
    /// Forward a received data frame to higher layers.
    fn handle_data_rx(&mut self, data_frame: DataFrame<'_, &[u8]>, mpdu: &[u8]) -> Option<()> {
        // E2's F6: once the station holds keys, an unprotected data frame is
        // anyone's; FoA passed them up to the network stack
        #[cfg(feature = "rsn")]
        if !sta_handshake::data_frame_admitted(
            self.sta_tx_rx.rsna_activated(),
            data_frame.header.fcf_flags.protected(),
        ) {
            UNPROTECTED_DROPPED.fetch_add(1, Ordering::Relaxed);
            trace!("Dropping an unprotected data frame.");
            return None;
        }
        let destination_address = data_frame.header.destination_address()?;
        let source_address = data_frame.header.source_address()?;
        let Some(payload) = self.process_potentially_wrapped_payload(
            destination_address.is_multicast(),
            data_frame.potentially_wrapped_payload(Some(MicState::NotPresent))?,
        ) else {
            info!("Dropping MSDU.");
            return None;
        };
        // E2's F2: a protected EAPOL-Key frame (the group-key handshake
        // after the join) reaches here, its PN checked above; it is the
        // station's, not the network stack's
        #[cfg(feature = "rsn")]
        if let DataFrameReadPayload::Single(single) = &payload
            && single
                .pread::<SnapLlcFrame>(0)
                .is_ok_and(|llc| llc.ether_type == llc_rs::EtherType::Eapol)
        {
            self.handle_group_key_frame(mpdu);
            return Some(());
        }
        match payload {
            DataFrameReadPayload::Single(payload) => {
                self.handle_downlink_msdu(payload, *source_address, *destination_address)
            }
            DataFrameReadPayload::AMSDU(mut amsdu_sub_frame_iterator) => amsdu_sub_frame_iterator
                .try_for_each(|sub_frame| {
                    self.handle_downlink_msdu(
                        sub_frame.payload,
                        sub_frame.source_address,
                        sub_frame.destination_address,
                    )
                }),
        }
    }
    fn connecting_mac_address(&self) -> Option<MACAddress> {
        self.rx_router_input
            .operation(RxRouterQueue::Foreground)
            .or_else(|| self.rx_router_input.operation(RxRouterQueue::Background))
            .and_then(StaRxRouterOperation::connecting_mac_address)
    }
    /// Run the routing task.
    async fn run(&mut self) -> ! {
        loop {
            let borrowed_buffer = self.interface_rx_endpoint.receive().await;
            // We create a generic frame, to do matching.
            let Ok(generic_frame) = GenericFrame::new(borrowed_buffer.mpdu_buffer(), false) else {
                continue;
            };
            trace!(
                "RX type: {:?}",
                generic_frame.frame_control_field().frame_type()
            );
            let address_1 = generic_frame.address_1();
            // Here we toss out frames, where the first address doesn't meet one of these conditions:
            // 1. Is multicast
            // 2. Is the address, with which we're already associated with a BSS.
            // 3. Is the address, with which we're currently associating with a BSS.
            if !address_1.is_multicast()
                && let Some(own_address) = self
                    .sta_tx_rx
                    .connection_state
                    .connection_info()
                    .map(|connection_info| connection_info.own_address)
                    .or_else(|| self.connecting_mac_address())
                && own_address != address_1
            {
                continue;
            }

            // We won't process any frames, while another interface is doing an off channel
            // operation.
            if !self.sta_tx_rx.in_off_channel_operation()
                && self
                    .sta_tx_rx
                    .interface_control
                    .off_channel_operation_in_progress()
            {
                continue;
            }
            // To reduce latency, we process all data frames here directly, if we are connected.
            if self.sta_tx_rx.connection_state.connected() {
                if generic_frame.is_eapol_key_frame() {
                    // An unprotected EAPOL-Key frame after the join: a
                    // group-key handshake from an access point that sends it
                    // in the clear; its MIC still authenticates it (E2's F2)
                    if !self.sta_tx_rx.rsna_activated() {
                        debug!("Discarding EAPOL Key Frame, since RSNA isn't activated.");
                    } else {
                        #[cfg(feature = "rsn")]
                        {
                            self.handle_group_key_frame(borrowed_buffer.mpdu_buffer());
                            if let Some(replay_counter) = self.group_reply.take() {
                                self.send_group_reply(replay_counter).await;
                            }
                            continue;
                        }
                    }
                } else if let FrameType::Data(_) = generic_frame.frame_control_field().frame_type()
                {
                    let Some(Ok(data_frame)) = generic_frame.parse_to_typed() else {
                        continue;
                    };
                    // We don't want to process data frames during an off channel operation, since
                    // otherwise it would be possible to inject frames on other channels.
                    if self.sta_tx_rx.in_off_channel_operation() {
                        continue;
                    }
                    self.handle_data_rx(data_frame, borrowed_buffer.mpdu_buffer());
                    #[cfg(feature = "rsn")]
                    if let Some(replay_counter) = self.group_reply.take() {
                        self.send_group_reply(replay_counter).await;
                    }
                    continue;
                }
            }
            // We ask the RX router, where all other frames should go.
            let _ = self.rx_router_input.route_frame(borrowed_buffer);
        }
    }
}
/// Interface runner for the STA interface.
pub struct StaRunner<'foa, 'vif> {
    pub(crate) tx_runner: TxRunner<'vif, MTU>,
    pub(crate) connection_runner: ConnectionRunner<'foa, 'vif>,
    pub(crate) routing_runner: RoutingRunner<'foa, 'vif>,
}
impl StaRunner<'_, '_> {
    /// Run the station interface.
    pub fn run(&mut self) -> impl Future<Output = ()> {
        debug!("STA runner active.");
        join(
            self.connection_runner.run(&mut self.tx_runner),
            self.routing_runner.run(),
        )
        .map(|_| ())
    }
}

/// How a data MPDU is retried (E1, the family's change; upstream sent every
/// data frame at OFDM 6 Mbit/s with seven retries at that rate). From an
/// OFDM rate the frame steps down the 802.11g ladder, two attempts at the
/// first rate and one at each rate below, padded with 6 Mbit/s to eight
/// attempts: a good link sends at the station's rate, a poor one ends where
/// upstream always was, with one more try. Other rates keep upstream's
/// behaviour.
/// E2's counters: group rekeys taken and refused, unprotected data frames
/// dropped after the join (F2, F6). The board's evidence for B1.
static GROUP_REKEYS: AtomicU32 = AtomicU32::new(0);
static GROUP_REFUSED: AtomicU32 = AtomicU32::new(0);
static UNPROTECTED_DROPPED: AtomicU32 = AtomicU32::new(0);

/// Group-key handshakes taken, group-key messages refused, and unprotected
/// data frames dropped after keys were installed, since boot.
pub fn air_stats() -> (u32, u32, u32) {
    (
        GROUP_REKEYS.load(Ordering::Relaxed),
        GROUP_REFUSED.load(Ordering::Relaxed),
        UNPROTECTED_DROPPED.load(Ordering::Relaxed),
    )
}

/// The 802.11g rates, fastest first.
const LADDER: [foa::esp_wifi_hal::rates::OfdmRate; 8] = {
    use foa::esp_wifi_hal::rates::OfdmRate::*;
    [Mbits54, Mbits48, Mbits36, Mbits24, Mbits18, Mbits12, Mbits9, Mbits6]
};

/// One data frame in this many starts at the sample rate, when one is set.
pub const SAMPLE_EVERY: u32 = 16;
/// The sample rate's hardware code (`OfdmRate as u8`); 0 is none.
static SAMPLE_RATE: AtomicU8 = AtomicU8::new(0);
static DATA_FRAMES: AtomicU32 = AtomicU32::new(0);

/// Start one data frame in [`SAMPLE_EVERY`] at `rate` (E1, the family's
/// addition): the rate control learns how a rate it is not using would do
/// from a few frames, not from a second of them. `None` stops sampling.
pub fn set_data_sample_rate(rate: Option<foa::esp_wifi_hal::rates::OfdmRate>) {
    SAMPLE_RATE.store(rate.map_or(0, |r| r as u8), Ordering::Relaxed);
}

/// The rate this data frame starts at: the station's, or the sample rate's
/// for one frame in [`SAMPLE_EVERY`].
fn data_frame_rate(rate: foa::esp_wifi_hal::rates::TxPhyRate) -> foa::esp_wifi_hal::rates::TxPhyRate {
    let code = SAMPLE_RATE.load(Ordering::Relaxed);
    if code == 0 || DATA_FRAMES.fetch_add(1, Ordering::Relaxed) % SAMPLE_EVERY != SAMPLE_EVERY - 1 {
        return rate;
    }
    LADDER
        .iter()
        .find(|r| **r as u8 == code)
        .map_or(rate, |r| foa::esp_wifi_hal::rates::TxPhyRate::Ofdm(*r))
}

fn data_retry_behaviour(rate: foa::esp_wifi_hal::rates::TxPhyRate) -> RetryBehaviour {
    use foa::esp_wifi_hal::rates::{OfdmRate, TxPhyRate};
    let TxPhyRate::Ofdm(first) = rate else {
        return RetryBehaviour::RetryUntil(7);
    };
    let start = LADDER.iter().position(|r| *r == first).unwrap_or(LADDER.len() - 1);
    let mut chain = heapless::Vec::<TxPhyRate, 8>::new();
    // two at the station's rate, then one a step
    let _ = chain.push(TxPhyRate::Ofdm(first));
    let _ = chain.push(TxPhyRate::Ofdm(first));
    for r in &LADDER[start + 1..] {
        if chain.push(TxPhyRate::Ofdm(*r)).is_err() {
            break;
        }
    }
    while chain.push(TxPhyRate::Ofdm(OfdmRate::Mbits6)).is_ok() {}
    RetryBehaviour::MultiRateRetry(chain)
}

/// RTS/CTS for data frames (E1, the family's change). The driver's default
/// sends an RTS before every unicast frame; 802.11's default RTS threshold
/// (2,347 bytes) is above any MPDU here, so data frames go without one.
/// Building with `JANUS_OPEN_RTS=on` keeps upstream's behaviour (the A/B).
fn data_rts_strategy() -> foa::esp_wifi_hal::async_driver::RtsStrategy {
    if option_env!("JANUS_OPEN_RTS") == Some("on") {
        foa::esp_wifi_hal::async_driver::RtsStrategy::DriverControlled
    } else {
        foa::esp_wifi_hal::async_driver::RtsStrategy::Forced(false)
    }
}

/// The EDCA access category data frames contend in (E1, the family's
/// change). Upstream sends them as best effort: AIFSN 3, CWmin 15. These
/// are non-QoS data frames, whose 802.11 default (DCF) waits DIFS, which is
/// AIFSN 2; building with `JANUS_OPEN_AC=vi` sends them as video, AIFSN 2
/// and CWmin 7, so a frame waits less for the medium. That puts the board
/// ahead of other stations' best-effort traffic on a shared network, so it
/// is a build choice, not the default.
fn data_access_category() -> EdcaAccessCategory {
    if option_env!("JANUS_OPEN_AC") == Some("vi") {
        EdcaAccessCategory::Video
    } else {
        EdcaAccessCategory::default()
    }
}

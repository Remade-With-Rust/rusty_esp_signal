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

use foa::esp_wifi_hal::rates::{HtRate, OfdmRate, TxPhyRate};

use crate::{
    MTU, StaTxRx, ht,
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
        // E8: an HT link with A-MPDUs built in asks for a block-ack
        // agreement, and again every 2 s (at most ten times) while none is
        // made: some access points answer only once the TID carries data
        let ask = connection_info.link.ht.is_some() && crate::ampdu_built();
        let mut asked = 0u8;
        let mut last_ask = embassy_time::Instant::now();
        if ask {
            Self::request_block_ack(sta_tx_rx, connection_info).await;
            asked = 1;
        }
        loop {
            // wait for a packet; each path below takes it
            tx_runner.tx_buf().await;
            if ask
                && asked < 10
                && BA_WINDOW.load(Ordering::Relaxed) == 0
                && last_ask.elapsed() >= embassy_time::Duration::from_secs(2)
            {
                Self::request_block_ack(sta_tx_rx, connection_info).await;
                asked += 1;
                last_ask = embassy_time::Instant::now();
            }

            // We don't want to accidentally transmit a MSDU, while we're not on channel.
            if sta_tx_rx.in_off_channel_operation() {
                sta_tx_rx
                    .interface_control
                    .wait_for_off_channel_completion()
                    .await;
            }
            // E8: on a link with QoS, QoS data frames, two packets in one
            // A-MSDU when a second is already waiting on an HT link
            if connection_info.link.qos {
                Self::send_qos_data(tx_runner, sta_tx_rx, connection_info).await;
                continue;
            }
            let msdu = tx_runner.tx_buf().await;
            let Ok(ethernet_frame) = msdu.pread::<Ethernet2Frame>(0) else {
                // E8: give the buffer back; `continue` alone took the same
                // runt again, forever
                tx_runner.tx_done();
                continue;
            };
            let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
            let own = *connection_info.own_address;
            let four = bridged(msdu, own);
            let data_frame = DataFrame {
                header: DataFrameHeader {
                    subtype: DataFrameSubtype::Data,
                    fcf_flags: FCFFlags::new().with_to_ds(true).with_from_ds(four),
                    address_1: connection_info.bss.bssid,
                    address_2: connection_info.own_address,
                    address_3: ethernet_frame.header.dst,
                    sequence_control: SequenceControl::new(),
                    address_4: if four {
                        Some(ethernet_frame.header.src)
                    } else {
                        None
                    },
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

            let tx_crypto_info = Self::tx_crypto_info(sta_tx_rx);
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
                tx_runner.tx_done();
                continue;
            };
            let behind =
                background(msdu, own) || (four && RELAY_BACKGROUND.load(Ordering::Relaxed));
            let category = if behind {
                RELAYED_AS_BACKGROUND.fetch_add(1, Ordering::Relaxed);
                EdcaAccessCategory::Background
            } else {
                data_access_category()
            };
            Self::transmit_data_as(category, sta_tx_rx, tx_buf, written, key_slot, true, None);
            trace!(
                "Transmitted {} bytes to {}",
                msdu.len(),
                ethernet_frame.header.dst
            );
            tx_runner.tx_done();
        }
    }
    /// The pairwise key's next packet number, key ID and key slot, once
    /// keys are installed.
    fn tx_crypto_info(sta_tx_rx: &StaTxRx<'_, '_>) -> Option<(u64, u8, usize)> {
        cfg_select! {
            feature = "rsn" => {
                sta_tx_rx.map_crypto_state(|crypto_state| {
                    (
                        crypto_state
                            .security_associations
                            .ptksa
                            .next_packet_number(),
                        crypto_state.security_associations.ptksa.key_id,
                        crypto_state.ptk_key_slot.key_slot(),
                    )
                })
            },
            _ => {
                let _ = sta_tx_rx;
                None
            }
        }
    }
    /// Hand a data MPDU (or an A-MPDU laid out as `ampdu` says, E8) to
    /// the MAC at the station's data rate; `override_seq` has the driver
    /// number it.
    fn transmit_data(
        sta_tx_rx: &StaTxRx<'_, '_>,
        tx_buf: foa::TxBuffer<'_>,
        written: usize,
        key_slot: Option<u8>,
        override_seq: bool,
        ampdu: Option<foa::esp_wifi_hal::prelude::AmpduLayout>,
    ) {
        Self::transmit_data_as(
            data_access_category(),
            sta_tx_rx,
            tx_buf,
            written,
            key_slot,
            override_seq,
            ampdu,
        );
    }
    /// [`Self::transmit_data`] in `category`.
    fn transmit_data_as(
        category: EdcaAccessCategory,
        sta_tx_rx: &StaTxRx<'_, '_>,
        tx_buf: foa::TxBuffer<'_>,
        written: usize,
        key_slot: Option<u8>,
        override_seq: bool,
        ampdu: Option<foa::esp_wifi_hal::prelude::AmpduLayout>,
    ) {
        let rate = data_frame_rate(sta_tx_rx.phy_rate());
        let _ = sta_tx_rx.tx_endpoint.transmit_edca(
            category,
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
                override_seq_num: override_seq,
                ampdu,
                ..Default::default()
            },
            data_retry_behaviour(rate),
        );
    }
    /// One QoS data frame (E8): the waiting packet, and a second one in
    /// the same A-MSDU if it is already waiting, fits, and the link is HT
    /// with A-MSDUs built in. The first packet is never held back for a
    /// second: only what the network stack has already queued is joined.
    async fn send_qos_data(
        tx_runner: &mut TxRunner<'_, MTU>,
        sta_tx_rx: &StaTxRx<'_, '_>,
        connection_info: &ConnectionInfo,
    ) {
        if background(tx_runner.tx_buf().await, *connection_info.own_address) {
            Self::send_background(tx_runner, sta_tx_rx, connection_info).await;
            return;
        }
        if bridged(tx_runner.tx_buf().await, *connection_info.own_address) {
            Self::send_bridged(tx_runner, sta_tx_rx, connection_info).await;
            return;
        }
        if connection_info.link.ht.is_some()
            && crate::send_ampdu()
            && BA_WINDOW.load(Ordering::Relaxed) >= 2
        {
            Self::send_ampdu(tx_runner, sta_tx_rx, connection_info).await;
            return;
        }
        let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let crypto = Self::tx_crypto_info(sta_tx_rx);
        let bssid = *connection_info.bss.bssid;
        let own = *connection_info.own_address;
        let buf = tx_buf.as_mut_slice();
        let first = tx_runner.tx_buf().await;
        let frame = ht::QosData::begin(buf, bssid, own, crypto.map(|(pn, key_id, _)| (pn, key_id)), first);
        tx_runner.tx_done();
        let Ok(mut frame) = frame else {
            QOS_REFUSED.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if connection_info.link.ht.is_some()
            && crate::send_amsdu()
            && let Some(next) = tx_runner.try_tx_buf()
            && !background(next, own)
            && !bridged(next, own)
            && frame.fits(buf.len(), next.len())
            && frame.push(buf, next).is_ok()
        {
            tx_runner.tx_done();
            AMSDU_SENT.fetch_add(1, Ordering::Relaxed);
        }
        let written = frame.finish(buf);
        QOS_SENT.fetch_add(1, Ordering::Relaxed);
        // E8: TID 0's own sequence numbers when a block-ack agreement may
        // be (or become) active, so the access point's window sees no holes
        let own_sequence = connection_info.link.ht.is_some() && crate::ampdu_built();
        if own_sequence {
            set_sequence(buf, next_qos_sequence(1));
        }
        Self::transmit_data(
            sta_tx_rx,
            tx_buf,
            written,
            crypto.map(|(_, _, key_slot)| key_slot as u8),
            !own_sequence,
            None,
        );
    }
    /// A relayed packet alone, as background: one QoS data frame on TID 1
    /// (user priority 1, the background access category), numbered by the
    /// MAC -- outside TID 0's own sequence and block-ack agreement.
    async fn send_background(
        tx_runner: &mut TxRunner<'_, MTU>,
        sta_tx_rx: &StaTxRx<'_, '_>,
        connection_info: &ConnectionInfo,
    ) {
        let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let crypto = Self::tx_crypto_info(sta_tx_rx);
        let bssid = *connection_info.bss.bssid;
        let own = *connection_info.own_address;
        let buf = tx_buf.as_mut_slice();
        let first = tx_runner.tx_buf().await;
        let frame = ht::QosData::begin(buf, bssid, own, crypto.map(|(pn, key_id, _)| (pn, key_id)), first);
        tx_runner.tx_done();
        let Ok(frame) = frame else {
            QOS_REFUSED.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let written = frame.finish(buf);
        // QoS Control's TID: 1 (background); the A-MSDU bit as finish left it
        buf[24] = (buf[24] & !0x0f) | 1;
        RELAYED_AS_BACKGROUND.fetch_add(1, Ordering::Relaxed);
        Self::transmit_data_as(
            EdcaAccessCategory::Background,
            sta_tx_rx,
            tx_buf,
            written,
            crypto.map(|(_, _, key_slot)| key_slot as u8),
            true,
            None,
        );
    }
    /// A bridged station's frame: 4-address QoS data, the station's own MAC
    /// as address 4, never folded into the device's own A-MSDU or A-MPDU.
    /// Background only while relayed traffic is put behind the device's
    /// own; otherwise it takes the same access category as the
    /// station's own data.
    async fn send_bridged(
        tx_runner: &mut TxRunner<'_, MTU>,
        sta_tx_rx: &StaTxRx<'_, '_>,
        connection_info: &ConnectionInfo,
    ) {
        let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let crypto = Self::tx_crypto_info(sta_tx_rx);
        let bssid = *connection_info.bss.bssid;
        let own = *connection_info.own_address;
        let behind = RELAY_BACKGROUND.load(Ordering::Relaxed);
        let buf = tx_buf.as_mut_slice();
        let first = tx_runner.tx_buf().await;
        let written = ht::write_four_address(
            buf,
            bssid,
            own,
            crypto.map(|(pn, key_id, _)| (pn, key_id)),
            first,
            if behind { 1 } else { 0 },
        );
        tx_runner.tx_done();
        let Ok(written) = written else {
            QOS_REFUSED.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if behind {
            RELAYED_AS_BACKGROUND.fetch_add(1, Ordering::Relaxed);
        }
        QOS_SENT.fetch_add(1, Ordering::Relaxed);
        let own_sequence = !behind && connection_info.link.ht.is_some() && crate::ampdu_built();
        if own_sequence {
            set_sequence(buf, next_qos_sequence(1));
        }
        let category = if behind {
            EdcaAccessCategory::Background
        } else {
            data_access_category()
        };
        Self::transmit_data_as(
            category,
            sta_tx_rx,
            tx_buf,
            written,
            crypto.map(|(_, _, key_slot)| key_slot as u8),
            !own_sequence,
            None,
        );
    }
    /// E8: the waiting packets as one A-MPDU, as many as are queued, fit
    /// the TX buffer and the block-ack agreement allows (at most
    /// `AMPDU_MAX`); one packet goes as a single QoS data frame. Each
    /// subframe: its 8-byte prefix (`ht::ampdu_prefix`), then a QoS data
    /// MPDU with its own packet number and TID 0 sequence number.
    async fn send_ampdu(
        tx_runner: &mut TxRunner<'_, MTU>,
        sta_tx_rx: &StaTxRx<'_, '_>,
        connection_info: &ConnectionInfo,
    ) {
        use foa::esp_wifi_hal::prelude::{AMPDU_MAX, AmpduLayout};
        let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let bssid = *connection_info.bss.bssid;
        let own = *connection_info.own_address;
        let window = usize::from(BA_WINDOW.load(Ordering::Relaxed));
        let max = AMPDU_MAX.min(window);
        let buf = tx_buf.as_mut_slice();
        let mut layout = AmpduLayout::default();
        // (the layout is rebuilt for a resend below)
        let mut key_slot = None;
        let mut at = 0usize;
        while usize::from(layout.count) < max {
            let packet = if layout.count == 0 {
                tx_runner.tx_buf().await
            } else {
                match tx_runner.try_tx_buf() {
                    Some(packet) if !background(packet, own) && !bridged(packet, own) => packet,
                    _ => break,
                }
            };
            // header, CCMP header, LLC/SNAP, payload, MIC
            let need = 8 + ht::QOS_HEADER + 8 + 8 + packet.len().saturating_sub(14) + 8;
            if packet.len() < 14 || at + need > buf.len() {
                if layout.count == 0 {
                    tx_runner.tx_done();
                    QOS_REFUSED.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                break;
            }
            let crypto = Self::tx_crypto_info(sta_tx_rx);
            key_slot = crypto.map(|(_, _, slot)| slot as u8);
            let mpdu = &mut buf[at + 8..];
            let written = ht::QosData::begin(
                mpdu,
                bssid,
                own,
                crypto.map(|(pn, key_id, _)| (pn, key_id)),
                packet,
            )
            .map(|frame| frame.finish(mpdu));
            tx_runner.tx_done();
            let Ok(len) = written else {
                QOS_REFUSED.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let sequence = next_qos_sequence(1);
            set_sequence(mpdu, sequence);
            buf[at..at + 8].copy_from_slice(&ht::ampdu_prefix(len as u16 + 4, sequence));
            let i = usize::from(layout.count);
            layout.offsets[i] = at as u16;
            layout.mpdu_lens[i] = len as u16;
            if i == 0 {
                layout.ssn = sequence;
            }
            layout.count += 1;
            at = (at + 8 + len).next_multiple_of(4);
        }
        QOS_SENT.fetch_add(u32::from(layout.count), Ordering::Relaxed);
        if layout.count == 0 {
            return;
        }
        if layout.count == 1 {
            // one packet: a single QoS data frame, moved to the buffer's start
            let len = usize::from(layout.mpdu_lens[0]);
            buf.copy_within(8..8 + len, 0);
            Self::transmit_data(sta_tx_rx, tx_buf, len, key_slot, false, None);
            return;
        }
        // the first subframe carries the duration (esp-radio: 48 us, the
        // block-ack's time)
        let first = usize::from(layout.offsets[0]) + 8;
        buf[first + 2..first + 4].copy_from_slice(&48u16.to_le_bytes());
        AMPDU_SENT.fetch_add(1, Ordering::Relaxed);
        AMPDU_SUBFRAMES.fetch_add(u32::from(layout.count), Ordering::Relaxed);
        // send, read the block-ack, resend what it did not acknowledge: at
        // most two more rounds; no block-ack counts as nothing acknowledged
        let mut end = at;
        let mut rounds = 0u8;
        loop {
            let generation = BA_GENERATION.load(Ordering::Relaxed);
            BA_ARRIVED.reset();
            let rate = data_frame_rate(sta_tx_rx.phy_rate());
            let done = sta_tx_rx
                .tx_endpoint
                .transmit_edca(
                    data_access_category(),
                    tx_buf,
                    end,
                    TxPlcpParameters {
                        rate,
                        ..Default::default()
                    },
                    TxMacParameters {
                        key_slot_index: key_slot,
                        wait_for_ack: true,
                        rts_strategy: data_rts_strategy(),
                        override_seq_num: false,
                        ampdu: Some(layout),
                        ..Default::default()
                    },
                    data_retry_behaviour(rate),
                )
                .wait_for_completion()
                .await;
            let Some(done) = done else {
                return;
            };
            tx_buf = done.frame;
            // the block-ack follows the A-MPDU at once; the routing task
            // wakes this one the moment it has it (polling in 300 us sleeps
            // cost about a third of a three-subframe A-MPDU's time)
            if BA_GENERATION.load(Ordering::Relaxed) == generation {
                let _ = embassy_time::with_timeout(
                    embassy_time::Duration::from_millis(3),
                    BA_ARRIVED.wait(),
                )
                .await;
            }
            let answered = BA_GENERATION.load(Ordering::Relaxed) != generation;
            if answered {
                BA_RECEIVED.fetch_add(1, Ordering::Relaxed);
            }
            let ssn = BA_SSN.load(Ordering::Relaxed) as u16;
            let bitmap = u64::from(BA_BITMAP_LO.load(Ordering::Relaxed))
                | (u64::from(BA_BITMAP_HI.load(Ordering::Relaxed)) << 32);
            let buf = tx_buf.as_mut_slice();
            let acked = |sequence: u16| {
                let offset = sequence.wrapping_sub(ssn) & 0x0fff;
                answered && offset < 64 && bitmap & (1 << offset) != 0
            };
            // the unacknowledged subframes, packed to the front, Retry set
            let mut next = AmpduLayout::default();
            let mut write = 0usize;
            for i in 0..usize::from(layout.count) {
                let start = usize::from(layout.offsets[i]);
                let len = usize::from(layout.mpdu_lens[i]);
                let sequence = u16::from_le_bytes([buf[start + 2], buf[start + 3]]);
                if acked(sequence) {
                    continue;
                }
                buf.copy_within(start..start + 8 + len, write);
                buf[write + 8 + 1] |= 0x08;
                let j = usize::from(next.count);
                next.offsets[j] = write as u16;
                next.mpdu_lens[j] = len as u16;
                if j == 0 {
                    next.ssn = sequence;
                }
                next.count += 1;
                write = (write + 8 + len).next_multiple_of(4);
            }
            if rounds == 0 {
                foa::esp_wifi_hal::tx_stats::record_subframes(
                    &rate,
                    u32::from(layout.count),
                    u32::from(layout.count - next.count),
                );
            }
            if next.count == 0 {
                AMPDU_DELIVERED.fetch_add(u32::from(layout.count), Ordering::Relaxed);
                return;
            }
            AMPDU_DELIVERED.fetch_add(u32::from(layout.count - next.count), Ordering::Relaxed);
            rounds += 1;
            if rounds > 2 {
                AMPDU_DROPPED.fetch_add(u32::from(next.count), Ordering::Relaxed);
                // the access point holds every later frame of TID 0 until
                // the gap fills: move its window past what was given up
                drop(tx_buf);
                Self::send_block_ack_request(sta_tx_rx, connection_info).await;
                return;
            }
            AMPDU_RESENT.fetch_add(u32::from(next.count), Ordering::Relaxed);
            if next.count == 1 {
                let len = usize::from(next.mpdu_lens[0]);
                buf.copy_within(8..8 + len, 0);
                Self::transmit_data(sta_tx_rx, tx_buf, len, key_slot, false, None);
                return;
            }
            layout = next;
            end = write;
        }
    }
    /// E8: a BlockAckReq for TID 0 starting at the next sequence number to
    /// be used, so the access point stops waiting for subframes given up on.
    async fn send_block_ack_request(sta_tx_rx: &StaTxRx<'_, '_>, connection_info: &ConnectionInfo) {
        let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let ssn = QOS_SEQUENCE.load(Ordering::Relaxed) & 0x0fff;
        let Ok(written) = ht::write_block_ack_request(
            tx_buf.as_mut_slice(),
            *connection_info.own_address,
            *connection_info.bss.bssid,
            0,
            ssn,
        ) else {
            return;
        };
        BAR_SENT.fetch_add(1, Ordering::Relaxed);
        // answered with a block-ack, not an ACK: no wait here; resent a
        // few times so one lost on the air does not leave the gap
        for _ in 0..3 {
            let done = sta_tx_rx
                .tx_endpoint
                .transmit_edca(
                    EdcaAccessCategory::default(),
                    tx_buf,
                    written,
                    TxPlcpParameters {
                        rate: TxPhyRate::Ofdm(OfdmRate::Mbits24),
                        ..Default::default()
                    },
                    TxMacParameters {
                        wait_for_ack: false,
                        override_seq_num: false,
                        ..Default::default()
                    },
                    RetryBehaviour::Drop,
                )
                .wait_for_completion()
                .await;
            let Some(done) = done else {
                return;
            };
            tx_buf = done.frame;
        }
    }
    /// E8: ask the access point for a block-ack agreement on TID 0; its
    /// answer is taken by the routing task (`BA_WINDOW`).
    async fn request_block_ack(sta_tx_rx: &StaTxRx<'_, '_>, connection_info: &ConnectionInfo) {
        let mut tx_buf = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let dialog = BA_DIALOG.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let ssn = QOS_SEQUENCE.load(Ordering::Relaxed);
        let Ok(written) = ht::write_addba_request(
            tx_buf.as_mut_slice(),
            *connection_info.own_address,
            *connection_info.bss.bssid,
            dialog,
            0,
            64,
            ssn,
        ) else {
            return;
        };
        ADDBA_REQUESTED.fetch_add(1, Ordering::Relaxed);
        let _ = sta_tx_rx
            .tx_endpoint
            .transmit_edca(
                EdcaAccessCategory::default(),
                tx_buf,
                written,
                TxPlcpParameters {
                    rate: TxPhyRate::Ofdm(OfdmRate::Mbits24),
                    ..Default::default()
                },
                TxMacParameters {
                    wait_for_ack: true,
                    override_seq_num: true,
                    ..Default::default()
                },
                RetryBehaviour::RetryUntil(7),
            )
            .wait_for_completion()
            .await;
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
            // E8: an agreement ends with its association
            BA_WINDOW.store(0, Ordering::Relaxed);
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
                        let packet_number = crypto_wrapper.crypto_header.packet_number();
                        // a group frame is checked against the key its CCMP
                        // header names (E2's F15)
                        let packet_number_valid = if is_group {
                            crypto_state
                                .group_keys
                                .admit(crypto_wrapper.crypto_header.key_id(), packet_number)
                        } else {
                            crypto_state
                                .security_associations
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
        if destination_address == ieee80211::mac_parser::BROADCAST {
            BROADCAST_DELIVERED.fetch_add(1, Ordering::Relaxed);
        } else if destination_address.is_multicast() {
            MULTICAST_DELIVERED.fetch_add(1, Ordering::Relaxed);
        }
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
            let keys =
                sta_handshake::PairwiseKeys::from_ptk(crypto_state.security_associations.ptksa.key);
            let floor = crypto_state.security_associations.eapol_replay_counter;
            match sta_handshake::read_group_message_1(&mut plain[..length], &keys, &mut scratch, floor) {
                Ok(gtk) => match crypto_state.update_gtksa(&gtk, bssid) {
                    Ok(()) => {
                        GROUP_REKEYS.fetch_add(1, Ordering::Relaxed);
                        debug!("Group key handshake: GTK key ID {} installed.", gtk.key_id);
                        Some(gtk.replay_counter)
                    }
                    Err(refusal) => {
                        GROUP_REFUSED.fetch_add(1, Ordering::Relaxed);
                        debug!("Group key refused: {:?}", defmt_or_log::Debug2Format(&refusal));
                        None
                    }
                },
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
                    sta_handshake::PairwiseKeys::from_ptk(ptksa.key),
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
    /// Count an unprotected data frame dropped after the join by kind.
    #[cfg(feature = "rsn")]
    fn classify_dropped(&self, data_frame: &DataFrame<'_, &[u8]>) {
        let header = &data_frame.header;
        DROPPED_LAST_SUBTYPE.store(header.subtype.into_bits(), Ordering::Relaxed);
        let from_ap = self
            .sta_tx_rx
            .connection_state
            .connection_info()
            .is_some_and(|connection_info| *header.transmitter_address() == connection_info.bss.bssid);
        if !from_ap {
            DROPPED_NOT_AP.fetch_add(1, Ordering::Relaxed);
        }
        let ether_type = data_frame
            .payload
            .and_then(|payload| payload.pread::<SnapLlcFrame>(0).ok())
            .map_or(0, |llc| u16::from(llc.ether_type));
        DROPPED_LAST_ETHER_TYPE.store(u32::from(ether_type), Ordering::Relaxed);
        if header.address_1.is_multicast() {
            DROPPED_GROUP.fetch_add(1, Ordering::Relaxed);
        } else {
            DROPPED_UNICAST.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Forward a received data frame to higher layers.
    fn handle_data_rx(&mut self, data_frame: DataFrame<'_, &[u8]>, mpdu: &[u8]) -> Option<()> {
        // A Null or QoS Null frame carries no payload and is never protected:
        // nothing goes up, and it is no refusal. The owner's hotspot sends the
        // station one every 10 s (its keep-alive); they were all of the 348
        // "unprotected frames dropped" in B1's hour (E2, 2026-10-03)
        if !data_frame.header.subtype.has_payload() {
            NULL_FRAMES.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // E2's F6: once the station holds keys, an unprotected data frame is
        // anyone's; FoA passed them up to the network stack
        #[cfg(feature = "rsn")]
        if !sta_handshake::data_frame_admitted(
            self.sta_tx_rx.rsna_activated(),
            data_frame.header.fcf_flags.protected(),
        ) {
            UNPROTECTED_DROPPED.fetch_add(1, Ordering::Relaxed);
            self.classify_dropped(&data_frame);
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
    /// Answer an ADDBA Request with "declined" (E8): the MAC has no
    /// block-ack, so the station takes no A-MPDU.
    async fn decline_addba(&self, request: &ht::AddbaRequest, own: [u8; 6], bssid: [u8; 6]) {
        let mut tx_buf = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let Ok(written) = ht::write_addba_decline(tx_buf.as_mut_slice(), own, bssid, request) else {
            return;
        };
        ADDBA_DECLINED.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .sta_tx_rx
            .tx_endpoint
            .transmit_edca(
                EdcaAccessCategory::default(),
                tx_buf,
                written,
                TxPlcpParameters {
                    rate: TxPhyRate::Ofdm(OfdmRate::Mbits24),
                    ..Default::default()
                },
                TxMacParameters {
                    wait_for_ack: true,
                    override_seq_num: true,
                    ..Default::default()
                },
                RetryBehaviour::RetryUntil(7),
            )
            .wait_for_completion()
            .await;
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
            // E8: a compressed block-ack from the access point to us (FC
            // 0x94; RA, TA, BA Control, Starting Sequence Control, a 64-bit
            // bitmap: 802.11-2020 9.3.1.8): recorded for `send_ampdu`
            {
                let mpdu = borrowed_buffer.mpdu_buffer();
                if mpdu.len() >= 28 && mpdu[0] == 0x94 {
                    if let Some((own, bssid)) = self
                        .sta_tx_rx
                        .connection_state
                        .map_connection_info(|c| (*c.own_address, *c.bss.bssid))
                        && mpdu[4..10] == own
                        && mpdu[10..16] == bssid
                    {
                        let ssc = u16::from_le_bytes([mpdu[18], mpdu[19]]);
                        BA_SSN.store(u32::from(ssc >> 4), Ordering::Relaxed);
                        BA_BITMAP_LO.store(
                            u32::from_le_bytes([mpdu[20], mpdu[21], mpdu[22], mpdu[23]]),
                            Ordering::Relaxed,
                        );
                        BA_BITMAP_HI.store(
                            u32::from_le_bytes([mpdu[24], mpdu[25], mpdu[26], mpdu[27]]),
                            Ordering::Relaxed,
                        );
                        BA_GENERATION.fetch_add(1, Ordering::Relaxed);
                        BA_ARRIVED.signal(());
                    }
                    continue;
                }
            }
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
            // E8: a census of block-ack action frames (category 3) addressed
            // here, whoever sent them: how many, the last one's action code
            // and status word
            {
                let mpdu = borrowed_buffer.mpdu_buffer();
                if mpdu.len() >= 24 + 5 && mpdu[0] == 0xd0 && mpdu[24] == ht::BLOCK_ACK_CATEGORY {
                    BA_ACTIONS_SEEN.fetch_add(1, Ordering::Relaxed);
                    BA_LAST_ACTION.store(
                        u32::from(mpdu[25]) | (u32::from(u16::from_le_bytes([mpdu[27], mpdu[28]])) << 8),
                        Ordering::Relaxed,
                    );
                }
            }
            // E8: the access point offering a block-ack agreement to an HT
            // station; it agrees to none, so it says so
            if let Some((own, bssid)) = self
                .sta_tx_rx
                .connection_state
                .map_connection_info(|c| (*c.own_address, *c.bss.bssid))
                && let Some(request) = ht::addba_request(borrowed_buffer.mpdu_buffer(), own)
                && request.from == bssid
            {
                drop(borrowed_buffer);
                self.decline_addba(&request, own, bssid).await;
                continue;
            }
            // E8: the access point's answer to our ADDBA Request
            if let Some((own, bssid)) = self
                .sta_tx_rx
                .connection_state
                .map_connection_info(|c| (*c.own_address, *c.bss.bssid))
                && let Some(response) = ht::addba_response(borrowed_buffer.mpdu_buffer(), own)
                && response.from == bssid
            {
                if response.status == 0
                    && response.tid() == 0
                    && response.dialog_token == BA_DIALOG.load(Ordering::Relaxed)
                {
                    BA_WINDOW.store(response.buffer_size(), Ordering::Relaxed);
                    ADDBA_ACCEPTED.fetch_add(1, Ordering::Relaxed);
                } else {
                    ADDBA_REFUSED.fetch_add(1, Ordering::Relaxed);
                }
                continue;
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

/// E2's counters: group rekeys taken and refused, unprotected data frames
/// dropped after the join (F2, F6). The board's evidence for B1.
static GROUP_REKEYS: AtomicU32 = AtomicU32::new(0);
static GROUP_REFUSED: AtomicU32 = AtomicU32::new(0);
static UNPROTECTED_DROPPED: AtomicU32 = AtomicU32::new(0);
/// Null and QoS Null data frames received (no payload; not refusals).
static NULL_FRAMES: AtomicU32 = AtomicU32::new(0);
/// Group-addressed MSDUs handed to the network stack: to the broadcast
/// address, and to any other group address (IPv6 neighbour discovery's
/// solicited-node groups, mDNS).
static BROADCAST_DELIVERED: AtomicU32 = AtomicU32::new(0);
static MULTICAST_DELIVERED: AtomicU32 = AtomicU32::new(0);
/// The dropped frames, all with a payload, by kind (E2, F6): to a unicast
/// address, to a group address; sent by another transmitter than the
/// access point; and the last one's subtype (the 4-bit field) and LLC
/// ether type.
static DROPPED_UNICAST: AtomicU32 = AtomicU32::new(0);
static DROPPED_GROUP: AtomicU32 = AtomicU32::new(0);
static DROPPED_NOT_AP: AtomicU32 = AtomicU32::new(0);
static DROPPED_LAST_SUBTYPE: AtomicU8 = AtomicU8::new(0);
static DROPPED_LAST_ETHER_TYPE: AtomicU32 = AtomicU32::new(0);

/// E8: QoS data frames sent, of them A-MSDUs of two packets, packets the
/// QoS writer refused (a runt; never seen), and ADDBA requests declined.
static QOS_SENT: AtomicU32 = AtomicU32::new(0);
static AMSDU_SENT: AtomicU32 = AtomicU32::new(0);
static QOS_REFUSED: AtomicU32 = AtomicU32::new(0);
static ADDBA_DECLINED: AtomicU32 = AtomicU32::new(0);

/// E8's block-ack agreement on TID 0: the window the access point agreed
/// (0: none), the last ADDBA dialog token, and TID 0's sequence numbers.
static BA_WINDOW: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
static BA_DIALOG: AtomicU8 = AtomicU8::new(0);
static QOS_SEQUENCE: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(0);
static ADDBA_REQUESTED: AtomicU32 = AtomicU32::new(0);
static ADDBA_ACCEPTED: AtomicU32 = AtomicU32::new(0);
static ADDBA_REFUSED: AtomicU32 = AtomicU32::new(0);
static AMPDU_SENT: AtomicU32 = AtomicU32::new(0);
/// The last block-ack from the access point: its starting sequence number,
/// its bitmap, and a count that moves with each one.
static BA_SSN: AtomicU32 = AtomicU32::new(0);
static BA_BITMAP_LO: AtomicU32 = AtomicU32::new(0);
static BA_BITMAP_HI: AtomicU32 = AtomicU32::new(0);
static BA_GENERATION: AtomicU32 = AtomicU32::new(0);
/// Raised by the routing task with each block-ack, for `send_ampdu`.
static BA_ARRIVED: embassy_sync::signal::Signal<
    embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex,
    (),
> = embassy_sync::signal::Signal::new();
/// A-MPDUs answered by a block-ack; subframes acknowledged, resent, and
/// given up on after the third round.
static BA_RECEIVED: AtomicU32 = AtomicU32::new(0);
static AMPDU_DELIVERED: AtomicU32 = AtomicU32::new(0);
static AMPDU_RESENT: AtomicU32 = AtomicU32::new(0);
static AMPDU_DROPPED: AtomicU32 = AtomicU32::new(0);
/// BlockAckReqs sent after subframes were given up on.
static BAR_SENT: AtomicU32 = AtomicU32::new(0);

/// E8: (A-MPDU sends answered by a block-ack, subframes acknowledged,
/// resent, dropped, BlockAckReqs sent) since boot.
pub fn block_ack_stats() -> (u32, u32, u32, u32, u32) {
    (
        BA_RECEIVED.load(Ordering::Relaxed),
        AMPDU_DELIVERED.load(Ordering::Relaxed),
        AMPDU_RESENT.load(Ordering::Relaxed),
        AMPDU_DROPPED.load(Ordering::Relaxed),
        BAR_SENT.load(Ordering::Relaxed),
    )
}
/// Block-ack action frames received (any action), and the last one's action
/// code (bits 0-7) and the two bytes after its dialog token (bits 8-23: an
/// ADDBA Response's status, an ADDBA Request's parameters).
static BA_ACTIONS_SEEN: AtomicU32 = AtomicU32::new(0);
static BA_LAST_ACTION: AtomicU32 = AtomicU32::new(0);

/// E8: block-ack action frames received since boot, and the last one's
/// action code | status-or-parameters << 8.
pub fn ba_census() -> (u32, u32) {
    (
        BA_ACTIONS_SEEN.load(Ordering::Relaxed),
        BA_LAST_ACTION.load(Ordering::Relaxed),
    )
}
static AMPDU_SUBFRAMES: AtomicU32 = AtomicU32::new(0);

/// `n` consecutive TID 0 sequence numbers: the first.
fn next_qos_sequence(n: u16) -> u16 {
    QOS_SEQUENCE.fetch_add(n, Ordering::Relaxed) & 0x0fff
}

/// The Sequence Control field of the MPDU at `mpdu`'s start.
fn set_sequence(mpdu: &mut [u8], sequence: u16) {
    if let Some(field) = mpdu.get_mut(22..24) {
        field.copy_from_slice(&((sequence & 0x0fff) << 4).to_le_bytes());
    }
}

/// E8's A-MPDU counters since boot: (ADDBA requests sent, accepted,
/// refused, the window agreed now (0: none), A-MPDUs sent, subframes in
/// them).
pub fn ampdu_stats() -> (u32, u32, u32, u16, u32, u32) {
    (
        ADDBA_REQUESTED.load(Ordering::Relaxed),
        ADDBA_ACCEPTED.load(Ordering::Relaxed),
        ADDBA_REFUSED.load(Ordering::Relaxed),
        BA_WINDOW.load(Ordering::Relaxed),
        AMPDU_SENT.load(Ordering::Relaxed),
        AMPDU_SUBFRAMES.load(Ordering::Relaxed),
    )
}

/// E8's counters since boot: (QoS data frames sent, A-MSDUs among them,
/// packets refused, ADDBA requests declined).
pub fn qos_stats() -> (u32, u32, u32, u32) {
    (
        QOS_SENT.load(Ordering::Relaxed),
        AMSDU_SENT.load(Ordering::Relaxed),
        QOS_REFUSED.load(Ordering::Relaxed),
        ADDBA_DECLINED.load(Ordering::Relaxed),
    )
}

/// Group-addressed MSDUs handed to the network stack since boot: (to the
/// broadcast address, to another group address).
pub fn group_delivered() -> (u32, u32) {
    (
        BROADCAST_DELIVERED.load(Ordering::Relaxed),
        MULTICAST_DELIVERED.load(Ordering::Relaxed),
    )
}

/// Null and QoS Null data frames received since boot.
pub fn null_frames() -> u32 {
    NULL_FRAMES.load(Ordering::Relaxed)
}

/// The unprotected data frames with a payload dropped since boot, by kind:
/// (unicast, group-addressed, not from the access point, the last one's
/// subtype, the last one's ether type).
pub fn dropped_unprotected() -> (u32, u32, u32, u8, u16) {
    (
        DROPPED_UNICAST.load(Ordering::Relaxed),
        DROPPED_GROUP.load(Ordering::Relaxed),
        DROPPED_NOT_AP.load(Ordering::Relaxed),
        DROPPED_LAST_SUBTYPE.load(Ordering::Relaxed),
        DROPPED_LAST_ETHER_TYPE.load(Ordering::Relaxed) as u16,
    )
}

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
/// The sample rate, encoded by [`encode_rate`]; 0 is none.
static SAMPLE_RATE: AtomicU8 = AtomicU8::new(0);
static DATA_FRAMES: AtomicU32 = AtomicU32::new(0);

/// A data rate in one byte: an OFDM rate as its hardware code (nonzero),
/// an HT rate as 0x80 | short GI << 3 | MCS (E8).
fn encode_rate(rate: TxPhyRate) -> u8 {
    match rate {
        TxPhyRate::Ofdm(r) => r as u8,
        TxPhyRate::Ht(h) => 0x80 | (u8::from(h.short_gi()) << 3) | (h.mcs_index() & 7),
        TxPhyRate::HrDsss(_) => 0,
    }
}

fn decode_rate(code: u8) -> Option<TxPhyRate> {
    if code & 0x80 != 0 {
        HtRate::new(code & 7, code & 0x08 != 0, false).map(TxPhyRate::Ht)
    } else {
        LADDER.iter().find(|r| **r as u8 == code).map(|r| TxPhyRate::Ofdm(*r))
    }
}

/// Start one data frame in [`SAMPLE_EVERY`] at `rate` (E1, the family's
/// addition): the rate control learns how a rate it is not using would do
/// from a few frames, not from a second of them. `None` stops sampling.
/// OFDM or, on an HT link, HT (E8).
pub fn set_data_sample_rate(rate: Option<TxPhyRate>) {
    SAMPLE_RATE.store(rate.map_or(0, encode_rate), Ordering::Relaxed);
}

/// The rate this data frame starts at: the station's, or the sample rate's
/// for one frame in [`SAMPLE_EVERY`].
fn data_frame_rate(rate: TxPhyRate) -> TxPhyRate {
    let code = SAMPLE_RATE.load(Ordering::Relaxed);
    if code == 0 || DATA_FRAMES.fetch_add(1, Ordering::Relaxed) % SAMPLE_EVERY != SAMPLE_EVERY - 1 {
        return rate;
    }
    decode_rate(code).unwrap_or(rate)
}

/// How a data MPDU is retried (E1, the family's change; upstream sent every
/// data frame at OFDM 6 Mbit/s with seven retries at that rate). From an
/// OFDM rate the frame steps down the 802.11g ladder, two attempts at the
/// first rate and one at each rate below, padded with 6 Mbit/s to eight
/// attempts: a good link sends at the station's rate, a poor one ends where
/// upstream always was, with one more try. From an HT rate (E8) the same
/// down the MCS indices, padded with MCS 0 (6.5 Mbit/s, as robust as OFDM
/// 6). Other rates keep upstream's behaviour.
fn data_retry_behaviour(rate: TxPhyRate) -> RetryBehaviour {
    let mut chain = heapless::Vec::<TxPhyRate, 8>::new();
    match rate {
        TxPhyRate::Ofdm(first) => {
            let start = LADDER.iter().position(|r| *r == first).unwrap_or(LADDER.len() - 1);
            // two at the station's rate, then one a step
            let _ = chain.push(rate);
            let _ = chain.push(rate);
            for r in &LADDER[start + 1..] {
                if chain.push(TxPhyRate::Ofdm(*r)).is_err() {
                    break;
                }
            }
            while chain.push(TxPhyRate::Ofdm(OfdmRate::Mbits6)).is_ok() {}
        }
        TxPhyRate::Ht(first) => {
            let _ = chain.push(rate);
            let _ = chain.push(rate);
            for mcs in (0..first.mcs_index()).rev() {
                if let Some(r) = HtRate::new(mcs, first.short_gi(), false)
                    && chain.push(TxPhyRate::Ht(r)).is_err()
                {
                    break;
                }
            }
            let floor = TxPhyRate::Ht(HtRate::new(0, first.short_gi(), false).unwrap_or_default());
            while chain.push(floor).is_ok() {}
        }
        TxPhyRate::HrDsss(_) => return RetryBehaviour::RetryUntil(7),
    }
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

/// Relayed frames upstream go out as background ([`set_relay_background`]),
/// and how many have.
static RELAY_BACKGROUND: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static RELAYED_AS_BACKGROUND: AtomicU32 = AtomicU32::new(0);

/// The Ethernet source a relay's forwarding gives a frame it relays upstream
/// through NAT: the station's own address with the locally
/// administered bit flipped. NAT frames stay 3-address, so the mark is not
/// an address on the air; it tells the station which frames are relayed.
/// A bridged frame keeps the station's real MAC and goes out 4-address.
#[must_use]
pub const fn relay_mark(own: [u8; 6]) -> [u8; 6] {
    let mut m = own;
    m[0] ^= 0x02;
    m
}

/// Send relayed frames upstream as background traffic, or not: while on, a
/// frame carrying [`relay_mark`] goes alone, as background (TID 1 in a QoS
/// data frame on a QoS link), never in the TID 0 aggregates the station's
/// own traffic uses; the station's own frames are unchanged. Relayed
/// traffic behind the device's own, on the air.
pub fn set_relay_background(on: bool) {
    RELAY_BACKGROUND.store(on, Ordering::Relaxed);
}

/// Relayed frames sent as background since boot.
pub fn relayed_as_background() -> u32 {
    RELAYED_AS_BACKGROUND.load(Ordering::Relaxed)
}

/// An Ethernet frame the plane relayed, while relayed frames go as background.
fn background(eth: &[u8], own: [u8; 6]) -> bool {
    RELAY_BACKGROUND.load(Ordering::Relaxed) && eth.len() >= 12 && eth[6..12] == relay_mark(own)
}

/// A frame whose Ethernet source is a station being bridged: not this
/// device, and not the NAT relay mark. It goes on the air as address 4.
fn bridged(eth: &[u8], own: [u8; 6]) -> bool {
    if eth.len() < 12 {
        return false;
    }
    let mut src = [0u8; 6];
    src.copy_from_slice(&eth[6..12]);
    src != own && src != relay_mark(own)
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

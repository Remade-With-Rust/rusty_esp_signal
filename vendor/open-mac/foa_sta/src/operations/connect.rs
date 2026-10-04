use core::{marker::PhantomData, mem};

use embassy_futures::join::join;
use embassy_time::WithTimeout;
use foa::{
    ReceivedFrame, TxBuffer,
    esp_wifi_hal::{
        ll::EdcaAccessCategory,
        prelude::{RxFilterBank, TxMacParameters, TxPlcpParameters},
    },
};
use ieee80211::{
    common::{
        AssociationID, CapabilitiesInformation, IEEE80211AuthenticationAlgorithmNumber,
        IEEE80211StatusCode, SequenceControl,
    },
    element_chain,
    elements::{SSIDElement, rsn::RsnElement},
    mac_parser::MACAddress,
    mgmt_frame::{
        AssociationRequestFrame, AssociationResponseFrame, AuthenticationFrame,
        ManagementFrameHeader,
        body::{AssociationRequestBody, AuthenticationBody},
    },
    scroll::{Pread, Pwrite},
};

use crate::{
    ConnectionConfig, SecurityConfig, StaError, StaTxRx,
    bss::BSS,
    operations::{DEFAULT_SUPPORTED_RATES, DEFAULT_XRATES},
    rx_router::{StaRxRouterEndpoint, StaRxRouterOperation, StaRxRouterScopedOperation},
    util::HexWrapper,
};

pub struct ConnectionParameters<'a> {
    pub config: ConnectionConfig,
    pub own_address: MACAddress,
    #[allow(unused)]
    pub credentials: Option<crate::Credentials<'a>>,
}

/// Connecting to an AP.
struct ConnectionOperation<'foa, 'vif, 'params> {
    sta_tx_rx: &'params StaTxRx<'foa, 'vif>,
    connection_parameters: &'params ConnectionParameters<'params>,
}
#[cfg(feature = "rsn")]
mod private {
    use foa::{
        RetryBehaviour, TxBuffer, TxReturnData,
        esp_wifi_hal::{
            ll::EdcaAccessCategory,
            prelude::{TxMacParameters, TxPlcpParameters},
        },
    };
    use ieee80211::{elements::rsn::IEEE80211CipherSuiteSelector, mac_parser::MACAddress};
    use sta_handshake::{GroupKey, Message1, PairwiseKeys, Refusal};

    use crate::{
        BSS, StaError, StaTxRx,
        rsn::{PMK_LENGTH, SecurityAssociations, TransientKeySecurityAssociation, WPA2_PSK_AKM},
        rx_router::{StaRxRouterOperation, StaRxRouterScopedOperation},
    };

    impl<'foa, 'vif, 'params> super::ConnectionOperation<'foa, 'vif, 'params> {
        /// Transmit an EAPOL-Key frame that `write` lays out in the TX buffer
        /// (E2: the frames are `sta_handshake`'s, the host tests' too).
        pub(crate) async fn send_eapol_key_frame(
            sta_tx_rx: &StaTxRx<'_, '_>,
            write: impl FnOnce(&mut [u8], &mut [u8]) -> Result<usize, Refusal>,
        ) -> Result<(), StaError> {
            let mut tx_buffer = sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
            let (buffer, temp_buffer) = tx_buffer.split_at_mut(500);
            let Ok(written) = write(buffer, temp_buffer) else {
                debug!("4WHS frame did not fit its buffer.");
                return Err(StaError::AckTimeout);
            };
            let res = sta_tx_rx
                .tx_endpoint
                .transmit_edca(
                    EdcaAccessCategory::default(),
                    tx_buffer,
                    written,
                    TxPlcpParameters {
                        rate: sta_tx_rx.phy_rate(),
                        ..Default::default()
                    },
                    TxMacParameters {
                        // The EAPOL data header starts with a placeholder.
                        override_seq_num: true,
                        ..Default::default()
                    },
                    RetryBehaviour::RetryUntil(7),
                )
                .wait_for_completion()
                .await;
            if matches!(res, Some(TxReturnData { result: Err(_), .. })) {
                debug!("4WHS step timeout.");
                Err(StaError::AckTimeout)
            } else {
                Ok(())
            }
        }
        /// Wait for message 1 to arrive and process it accordingly.
        async fn process_message_1(
            router_operation: &StaRxRouterScopedOperation<'foa, 'vif, 'params>,
        ) -> Message1 {
            loop {
                let mut frame = router_operation.receive().await;
                match sta_handshake::read_message_1(frame.mpdu_buffer_mut()) {
                    Ok(message_1) => break message_1,
                    Err(refusal) => {
                        debug!("4WHS message 1 refused: {:?}", defmt_or_log::Debug2Format(&refusal));
                        continue;
                    }
                }
            }
        }
        /// Wait for message 3 and take its group key. A GTK of any length but
        /// 16 bytes is refused, not a panic (E2's F1).
        async fn process_message_3(
            router_operation: &StaRxRouterScopedOperation<'foa, 'vif, 'params>,
            mut scratch_buffer: TxBuffer<'_>,
            keys: &PairwiseKeys,
        ) -> GroupKey {
            loop {
                let mut frame = router_operation.receive().await;
                match sta_handshake::read_message_3(
                    frame.mpdu_buffer_mut(),
                    keys,
                    scratch_buffer.as_mut_slice(),
                    None,
                ) {
                    Ok(gtk) => break gtk,
                    Err(refusal) => {
                        debug!("4WHS message 3 refused: {:?}", defmt_or_log::Debug2Format(&refusal));
                        continue;
                    }
                }
            }
        }
        pub(super) async fn do_4whs(
            &self,
            pmk: [u8; PMK_LENGTH],
            router_operation: &mut StaRxRouterScopedOperation<'foa, 'vif, 'params>,
            bss: &'params BSS,
        ) -> Result<SecurityAssociations, StaError> {
            use esp_hal::rng::Rng;

            router_operation.transition(
            StaRxRouterOperation::CryptoHandshake{
                own_address: self.connection_parameters.own_address
            })
            .expect("This should not fail, since all three connecting operations have the same compatibility and there is no await point in the transition.");

            let mut supplicant_nonce = [0u8; 32];
            Rng::new().read(&mut supplicant_nonce);
            // E2's F4: no key material in a log line, at any level
            debug!("Starting 4WHS.");

            let message_1 = Self::process_message_1(router_operation).await;
            debug!("Processed 4WHS message 1.");

            let bssid: MACAddress = bss.bssid;
            let own: MACAddress = self.connection_parameters.own_address;
            let keys = PairwiseKeys::derive(
                &pmk,
                &bssid,
                &own,
                &message_1.anonce,
                &supplicant_nonce,
            );
            Self::send_eapol_key_frame(self.sta_tx_rx, |buffer, temp| {
                sta_handshake::write_message_2(
                    buffer,
                    temp,
                    bssid,
                    own,
                    &keys,
                    &supplicant_nonce,
                    message_1.replay_counter,
                )
            })
            .await?;
            debug!("Sent 4WHS message 2.");

            // We abuse a TX buffer as a general purpose buffer here.
            let scratch_buffer = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;

            let gtk = Self::process_message_3(router_operation, scratch_buffer, &keys).await;
            debug!("Processed 4WHS message 3. GTK key ID: {}", gtk.key_id);

            Self::send_eapol_key_frame(self.sta_tx_rx, |buffer, temp| {
                sta_handshake::write_message_4(buffer, temp, bssid, own, &keys, gtk.replay_counter)
            })
            .await?;
            debug!("Sent 4WHS message 4.");

            // the group key goes to CryptoState's group keys, its replay
            // window from its RSC (E2's F11, F15)
            Ok(SecurityAssociations {
                ptksa: TransientKeySecurityAssociation::new(keys.ptk, 0),
                initial_gtk: gtk,
                akm_suite: WPA2_PSK_AKM,
                cipher_suite: IEEE80211CipherSuiteSelector::Ccmp128,
                eapol_replay_counter: gtk.replay_counter,
            })
        }
    }
}
impl<'foa, 'vif, 'params> ConnectionOperation<'foa, 'vif, 'params> {
    fn complete(self) {
        mem::forget(self);
    }
    /// Send the specified frame and wait for a response.
    ///
    /// If no response is received in the specified timeout duration, or a transmission error
    /// occurs, the step will be retried as many times as specified. This compensates for a weird
    /// behavior of some APs, where they ACK a frame, but don't transmit a response. While this is
    /// rare, it can still occur, so this significantly stabilizes connection establishment.
    async fn do_bidirectional_connection_step(
        &self,
        router_operation: &StaRxRouterScopedOperation<'foa, 'vif, 'params>,
        mut frame: TxBuffer<'foa>,
        frame_length: usize,
    ) -> Result<ReceivedFrame<'_>, StaError> {
        for _ in 0..=self.connection_parameters.config.handshake_retries {
            let Some(res) = self
                .sta_tx_rx
                .tx_endpoint
                .transmit_edca(
                    EdcaAccessCategory::default(),
                    frame,
                    frame_length,
                    TxPlcpParameters {
                        rate: self.sta_tx_rx.phy_rate(),
                        ..Default::default()
                    },
                    TxMacParameters {
                        // Authentication and association frames are generated
                        // here; assign a new sequence for each queued request.
                        override_seq_num: true,
                        ..Default::default()
                    },
                    foa::RetryBehaviour::RetryUntil(7),
                )
                .wait_for_completion()
                .await
            else {
                warn!("Somehow the queue overran this shouldn't be possible.");
                break;
            };
            frame = res.frame;
            // Due to the user operation being set to authenticating, we'll only receive authentication
            // frames.
            if let Ok(frame) = router_operation
                .receive()
                .with_timeout(self.connection_parameters.config.handshake_timeout)
                .await
            {
                return Ok(frame);
            } else {
                trace!("Response to bidirectional connection step timed out.");
                continue;
            };
        }
        Err(StaError::ResponseTimeout)
    }
    /// Authenticate with the BSS.
    ///
    /// This currently only performs open system authentication.
    async fn do_auth(
        &self,
        router_operation: &StaRxRouterScopedOperation<'foa, 'vif, 'params>,
        bss: &BSS,
    ) -> Result<(), StaError> {
        let auth_frame = AuthenticationFrame {
            header: ManagementFrameHeader {
                receiver_address: bss.bssid,
                bssid: bss.bssid,
                transmitter_address: self.connection_parameters.own_address,
                sequence_control: SequenceControl::new(),
                duration: 0,
                ..Default::default()
            },
            body: AuthenticationBody {
                status_code: IEEE80211StatusCode::Success,
                authentication_algorithm_number: IEEE80211AuthenticationAlgorithmNumber::OpenSystem,
                authentication_transaction_sequence_number: 1,
                elements: element_chain! {},
                _phantom: PhantomData,
            },
        };
        // Allocate a TX buffer and serialize the frame.
        let mut tx_buffer = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let written = tx_buffer.pwrite(auth_frame, 0).unwrap();
        // Transmit an authentication frame and wait for the response.
        let response = self
            .do_bidirectional_connection_step(router_operation, tx_buffer, written)
            .await?;
        // Try to parse the frame or return an error.
        let Ok(auth_frame) = response.mpdu_buffer().pread::<AuthenticationFrame>(0) else {
            debug!(
                "Failed to authenticate with {}, frame deserialization failed.",
                bss.bssid
            );
            return Err(StaError::FrameDeserializationFailed);
        };
        // Check if the authentication was successful and return an authentication failure if not.
        if auth_frame.status_code == IEEE80211StatusCode::Success {
            debug!("Successfully authenticated with {}.", bss.bssid);
            Ok(())
        } else {
            debug!(
                "Failed to authenticate with {}, status: {:?}.",
                bss.bssid, auth_frame.status_code
            );
            Err(StaError::AuthenticationFailure(auth_frame.status_code))
        }
    }
    /// Associate with the BSS.
    ///
    /// Like authentication, this only performs the bare minimum with a set of predetermined
    /// supported rates.
    async fn do_assoc(
        &self,
        router_operation: &mut StaRxRouterScopedOperation<'foa, 'vif, 'params>,
        bss: &BSS,
    ) -> Result<AssociationID, StaError> {
        router_operation.transition(
            StaRxRouterOperation::Associating {
                own_address: self.connection_parameters.own_address
            })
            .expect("This should not fail, since all three connecting operations have the same compatibility and there is no await point in the transition.");

        let rsn_active = bss.security_config != SecurityConfig::Open;
        let mut tx_buffer = self.sta_tx_rx.tx_endpoint.alloc_tx_buf().await;
        let mut assoc_request_frame = AssociationRequestFrame {
            header: ManagementFrameHeader {
                receiver_address: bss.bssid,
                bssid: bss.bssid,
                transmitter_address: self.connection_parameters.own_address,
                sequence_control: SequenceControl::new(),
                duration: 60,
                ..Default::default()
            },
            body: AssociationRequestBody {
                capabilities_info: CapabilitiesInformation::new()
                    .with_is_ess(true)
                    .with_is_confidentiality_required(rsn_active),
                listen_interval: 0,
                elements: element_chain! {
                    SSIDElement::new(bss.ssid.as_str()).ok_or(StaError::InvalidBss)?,
                    DEFAULT_SUPPORTED_RATES,
                    DEFAULT_XRATES
                },
                _phantom: PhantomData,
            },
        }
        .into_dynamic(tx_buffer.as_mut())
        .unwrap();

        if rsn_active {
            assoc_request_frame
                .add_element(RsnElement::WPA2_PERSONAL)
                .unwrap();
        }

        let written = assoc_request_frame.finish(false).unwrap();
        // Transmit an association request and wait for the association response.
        let response = self
            .do_bidirectional_connection_step(router_operation, tx_buffer, written)
            .await?;
        // Try to parse the response or return an error.
        let Ok(assoc_response) = response.mpdu_buffer().pread::<AssociationResponseFrame>(0) else {
            debug!(
                "Failed to associate with {}, frame deserialization failed.",
                bss.bssid
            );
            return Err(StaError::FrameDeserializationFailed);
        };
        if let Some(aid) = assoc_response.association_id
            && assoc_response.status_code == IEEE80211StatusCode::Success
        {
            debug!(
                "Successfully associated with {}, AID: {:?}.",
                bss.bssid, aid
            );
            return Ok(aid);
        }
        debug!(
            "Failed to associate with {}, status: {:?}.",
            bss.bssid, assoc_response.status_code
        );
        debug!("Assoc frame: {}", HexWrapper(response.mpdu_buffer()));
        Err(StaError::AssociationFailure(assoc_response.status_code))
    }
    fn configure_rx_filters(&self, bss: &BSS) {
        // Here we set and enable the BSSID and RA filters.

        self.sta_tx_rx.interface_control.set_filter(
            RxFilterBank::ReceiverAddress,
            *self.connection_parameters.own_address,
        );
        self.sta_tx_rx
            .interface_control
            .set_filter(RxFilterBank::Bssid, *bss.bssid);
    }
    async fn run(
        self,
        rx_router_endpoint: &'params mut StaRxRouterEndpoint<'foa, 'vif>,
        bss: &BSS,
    ) -> Result<AssociationID, StaError> {
        debug!(
            "Connecting to {} on channel {} with MAC address {}.",
            bss.bssid, bss.channel, self.connection_parameters.own_address
        );
        // Start the bringup operation for LMAC channel lock.
        let bringup_operation = self
            .sta_tx_rx
            .interface_control
            .begin_interface_bringup_operation(bss.channel)
            .map_err(StaError::LMacError)?;

        // Start the RX router operation, so that authentication and association frames are routed
        // to us for the duration of the connection bringup.
        // NOTE: If further protocol negotiations, like RSN, TDLS, FT etc. are added in the future,
        // the match statement in the RX router will have to be expanded, to route those frames
        // too.
        let (mut router_operation, _) = join(
            rx_router_endpoint.start_operation(StaRxRouterOperation::Authenticating {
                own_address: self.connection_parameters.own_address,
            }),
            self.sta_tx_rx
                .interface_control
                .wait_for_off_channel_completion(),
        )
        .await;

        #[cfg(feature = "rsn")]
        let pmk_and_key_slots = if bss.security_config != SecurityConfig::Open
            && let Some(credentials) = self.connection_parameters.credentials
        {
            // two group key slots (the current key and a rekey's: E2's F15)
            // and the pairwise one
            let [gtk_key_slot_0, gtk_key_slot_1, ptk_key_slot] = core::array::from_fn(|_| {
                self.sta_tx_rx
                    .interface_control
                    .acquire_key_slot()
                    .ok_or(StaError::NoKeySlotsAvailable)
            });
            let mut pmk = [0u8; crate::rsn::PMK_LENGTH];
            if credentials.pmk(&mut pmk, bss.ssid.as_str()).is_err() {
                debug!("Invalid PSK length.");
                return Err(StaError::InvalidPskLength);
            }
            Some((pmk, [gtk_key_slot_0?, gtk_key_slot_1?], ptk_key_slot?))
        } else {
            None
        };

        // Configure the RX filters to the specified addresses, so that we actually receive frames
        // from the AP.
        self.configure_rx_filters(bss);

        // Try to authenticate with the AP.
        self.do_auth(&router_operation, bss).await?;

        // Try to associate with the AP.
        let aid = self.do_assoc(&mut router_operation, bss).await?;

        #[cfg(feature = "rsn")]
        if let Some((pmk, gtk_key_slots, ptk_key_slot)) = pmk_and_key_slots {
            let crypto_keys = self.do_4whs(pmk, &mut router_operation, bss).await?;
            self.sta_tx_rx.crypto_state.lock(|rc| {
                let _ = rc.borrow_mut().insert(crate::rsn::CryptoState::new(
                    gtk_key_slots,
                    ptk_key_slot,
                    *bss.bssid,
                    crypto_keys,
                ));
            })
        }

        // By marking the connection operation as completed, we forget self and therefore the drop
        // code never gets executed and the filter configuration remains in place.
        self.complete();
        router_operation.complete();
        bringup_operation.complete();

        Ok(aid)
    }
}
impl Drop for ConnectionOperation<'_, '_, '_> {
    fn drop(&mut self) {
        self.sta_tx_rx
            .interface_control
            .clear_filter(RxFilterBank::ReceiverAddress);
        self.sta_tx_rx
            .interface_control
            .clear_filter(RxFilterBank::Bssid);
    }
}
pub fn connect<'foa, 'vif, 'params>(
    sta_tx_rx: &'params StaTxRx<'foa, 'vif>,
    rx_router_endpoint: &'params mut StaRxRouterEndpoint<'foa, 'vif>,
    bss: &'params BSS,
    connection_parameters: &'params ConnectionParameters<'params>,
) -> impl Future<Output = Result<AssociationID, StaError>> {
    ConnectionOperation {
        sta_tx_rx,
        connection_parameters,
    }
    .run(rx_router_endpoint, bss)
}

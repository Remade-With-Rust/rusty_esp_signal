//! LoRa P2P over `lora-phy`, carrying the core's authenticated envelope.
//!
//! The core owns the radio parameters and their limits ([`lora::Params`]:
//! exact time-on-air, region duty cycle, the Semtech formula) and the
//! authenticated [`link::Session`]. This backend maps the core's parameters to
//! `lora-phy`'s modulation and packet parameters ([`to_modulation`],
//! [`to_tx_packet`], [`to_rx_packet`]) and drives an SX126x radio over them
//! ([`LoraLink`]).
//!
//! `lora-phy` is generic over the radio kind and the SPI/GPIO it sits on, so
//! [`LoraLink`] is too; a firmware constructs the concrete
//! `LoRa<Sx126x<SpiDevice, InterfaceVariant, Sx1262>, Delay>` and hands it in
//! with a [`lora::Params`] and a peer [`link::Session`]. The conversions and
//! the send/receive envelope handling are the shared, checkable part; the SPI
//! bring-up is the firmware's.
//!
//! Duty cycle is enforced by the core's [`lora::DutyCycle`], which a caller
//! consults before each [`LoraLink::send`]; the region's airtime budget is a
//! legal limit, not a suggestion.

use lora_phy::mod_params::{
    Bandwidth, CodingRate, ModulationParams, PacketParams, SpreadingFactor,
};
use lora_phy::mod_traits::RadioKind;
use lora_phy::{DelayNs, LoRa, RxMode};
use rusty_esp_signal_core::esp_core::Error;
use rusty_esp_signal_core::esp_core::error::Result;
use rusty_esp_signal_core::esp_core::{Micros, Rng};
use rusty_esp_signal_core::link::{DEFAULT_LIFETIME, Handshake, MAX_FRAME, Session};
use rusty_esp_signal_core::lora::{Bw, Cr, Params, Sf};
use rusty_esp_signal_core::mid::did::Did;
use rusty_esp_signal_core::mid::key::DeviceKey;

/// Map the core [`Sf`] to `lora-phy`'s [`SpreadingFactor`].
#[must_use]
pub const fn to_sf(sf: Sf) -> SpreadingFactor {
    match sf {
        Sf::Sf7 => SpreadingFactor::_7,
        Sf::Sf8 => SpreadingFactor::_8,
        Sf::Sf9 => SpreadingFactor::_9,
        Sf::Sf10 => SpreadingFactor::_10,
        Sf::Sf11 => SpreadingFactor::_11,
        Sf::Sf12 => SpreadingFactor::_12,
    }
}

/// Map the core [`Bw`] to `lora-phy`'s [`Bandwidth`].
#[must_use]
pub const fn to_bw(bw: Bw) -> Bandwidth {
    match bw {
        Bw::Khz125 => Bandwidth::_125KHz,
        Bw::Khz250 => Bandwidth::_250KHz,
        Bw::Khz500 => Bandwidth::_500KHz,
    }
}

/// Map the core [`Cr`] to `lora-phy`'s [`CodingRate`].
#[must_use]
pub const fn to_cr(cr: Cr) -> CodingRate {
    match cr {
        Cr::Cr4_5 => CodingRate::_4_5,
        Cr::Cr4_6 => CodingRate::_4_6,
        Cr::Cr4_7 => CodingRate::_4_7,
        Cr::Cr4_8 => CodingRate::_4_8,
    }
}

/// Build `lora-phy` modulation parameters from the core [`Params`].
///
/// `lora-phy` derives low-data-rate optimisation itself from the symbol time,
/// which matches the core's `Ldro::Auto`; a firmware that pins LDRO on or off
/// diverges from `lora-phy` here and should say so.
pub fn to_modulation<RK: RadioKind, DLY: DelayNs>(
    radio: &mut LoRa<RK, DLY>,
    params: &Params,
) -> Result<ModulationParams> {
    radio
        .create_modulation_params(
            to_sf(params.sf),
            to_bw(params.bw),
            to_cr(params.cr),
            params.freq_hz,
        )
        .map_err(|_| Error::Unsupported)
}

/// Build transmit packet parameters from the core [`Params`].
pub fn to_tx_packet<RK: RadioKind, DLY: DelayNs>(
    radio: &mut LoRa<RK, DLY>,
    params: &Params,
    modulation: &ModulationParams,
) -> Result<PacketParams> {
    radio
        .create_tx_packet_params(
            params.preamble_symbols,
            !params.explicit_header,
            params.crc,
            false,
            modulation,
        )
        .map_err(|_| Error::Unsupported)
}

/// Build receive packet parameters from the core [`Params`].
pub fn to_rx_packet<RK: RadioKind, DLY: DelayNs>(
    radio: &mut LoRa<RK, DLY>,
    params: &Params,
    modulation: &ModulationParams,
) -> Result<PacketParams> {
    radio
        .create_rx_packet_params(
            params.preamble_symbols,
            !params.explicit_header,
            MAX_FRAME as u8,
            params.crc,
            false,
            modulation,
        )
        .map_err(|_| Error::Unsupported)
}

/// An authenticated LoRa point-to-point link.
///
/// Owns a `lora-phy` radio and the core [`Params`]; the caller holds a
/// [`Session`] for the peer. [`LoraLink::send`] seals a payload and transmits
/// it; [`LoraLink::recv`] receives a frame and opens it. The radio parameters
/// (spreading factor, bandwidth, region) are fixed for the link's life, so the
/// modulation parameters are built once.
pub struct LoraLink<RK: RadioKind, DLY: DelayNs> {
    radio: LoRa<RK, DLY>,
    params: Params,
    modulation: ModulationParams,
    tx_packet: PacketParams,
    rx_packet: PacketParams,
}

impl<RK: RadioKind, DLY: DelayNs> LoraLink<RK, DLY> {
    /// Build a link over `radio` with the core [`Params`]. Builds the
    /// modulation and packet parameters up front.
    pub fn new(mut radio: LoRa<RK, DLY>, params: Params) -> Result<Self> {
        let modulation = to_modulation(&mut radio, &params)?;
        let tx_packet = to_tx_packet(&mut radio, &params, &modulation)?;
        let rx_packet = to_rx_packet(&mut radio, &params, &modulation)?;
        Ok(Self {
            radio,
            params,
            modulation,
            tx_packet,
            rx_packet,
        })
    }

    /// The core parameters this link uses (for airtime and duty-cycle checks).
    #[must_use]
    pub const fn params(&self) -> &Params {
        &self.params
    }

    /// Run the handshake as the **initiator** over the half-duplex modem:
    /// transmit `Hello`, receive `Accept`, transmit `Confirm`, return the
    /// [`Session`]. LoRa is one frame at a time, so this alternates tx and rx;
    /// the peer must be in its responder receive window when each message is
    /// sent. `allow` vets the responder's DID.
    pub async fn handshake_initiator(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
    ) -> Result<Session> {
        let (hs, hello) = Handshake::initiate(me, rng)?;
        self.tx_raw(&hello).await?;
        let mut buf = [0u8; MAX_FRAME];
        let accept = self.rx_raw(&mut buf).await?;
        let (session, confirm) = hs.finish(me, accept, allow, now, DEFAULT_LIFETIME)?;
        let confirm_copy = confirm;
        self.tx_raw(&confirm_copy).await?;
        Ok(session)
    }

    /// Run the handshake as the **responder**: receive `Hello`, transmit
    /// `Accept`, receive `Confirm`, return the [`Session`].
    pub async fn handshake_responder(
        &mut self,
        me: &DeviceKey,
        rng: &mut impl Rng,
        allow: impl FnOnce(&Did) -> bool,
        now: Micros,
    ) -> Result<Session> {
        let mut buf = [0u8; MAX_FRAME];
        let hello = self.rx_raw(&mut buf).await?;
        let mut hello_copy = [0u8; MAX_FRAME];
        let hn = hello.len();
        hello_copy[..hn].copy_from_slice(hello);
        let (pending, accept) =
            Handshake::respond(me, rng, &hello_copy[..hn], allow, now, DEFAULT_LIFETIME)?;
        self.tx_raw(&accept).await?;
        let confirm = self.rx_raw(&mut buf).await?;
        pending.confirm(confirm)
    }

    /// Transmit raw bytes as one LoRa packet (a handshake message).
    async fn tx_raw(&mut self, bytes: &[u8]) -> Result<()> {
        self.radio
            .prepare_for_tx(
                &self.modulation,
                &mut self.tx_packet,
                i32::from(self.params.power_dbm),
                bytes,
            )
            .await
            .map_err(|_| Error::Hardware)?;
        self.radio.tx().await.map_err(|_| Error::Hardware)
    }

    /// Receive one LoRa packet into `buf`, returning the bytes read.
    async fn rx_raw<'b>(&mut self, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        self.radio
            .prepare_for_rx(RxMode::Continuous, &self.modulation, &self.rx_packet)
            .await
            .map_err(|_| Error::Hardware)?;
        let (len, _status) = self
            .radio
            .rx(&self.rx_packet, buf)
            .await
            .map_err(|_| Error::Hardware)?;
        Ok(&buf[..len as usize])
    }

    /// Seal `payload` with `session` and transmit it. The caller should have
    /// cleared the region duty cycle for `params.airtime(payload.len())`
    /// first (`lora::DutyCycle::try_send`).
    pub async fn send(&mut self, session: &mut Session, payload: &[u8]) -> Result<()> {
        let mut frame = [0u8; MAX_FRAME];
        let n = session.seal(payload, &mut frame)?;
        self.radio
            .prepare_for_tx(
                &self.modulation,
                &mut self.tx_packet,
                i32::from(self.params.power_dbm),
                &frame[..n],
            )
            .await
            .map_err(|_| Error::Hardware)?;
        self.radio.tx().await.map_err(|_| Error::Hardware)
    }

    /// Receive one frame and open it with `session`, returning the plaintext
    /// written into `out`. A refused frame returns the core error (counted in
    /// the session).
    pub async fn recv<'o>(&mut self, session: &mut Session, out: &'o mut [u8]) -> Result<&'o [u8]> {
        let mut frame = [0u8; MAX_FRAME];
        self.radio
            .prepare_for_rx(RxMode::Continuous, &self.modulation, &self.rx_packet)
            .await
            .map_err(|_| Error::Hardware)?;
        let (len, _status) = self
            .radio
            .rx(&self.rx_packet, &mut frame)
            .await
            .map_err(|_| Error::Hardware)?;
        let plain = session.open(&frame[..len as usize])?;
        if out.len() < plain.len() {
            return Err(Error::BufferTooSmall {
                needed: plain.len(),
            });
        }
        out[..plain.len()].copy_from_slice(plain);
        Ok(&out[..plain.len()])
    }
}

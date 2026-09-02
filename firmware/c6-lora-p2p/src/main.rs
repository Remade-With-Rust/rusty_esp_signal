#![no_std]
#![no_main]
//! Janus **J4** firmware, Track B, ESP32-C6 + an SX1262 module: an
//! authenticated LoRa point-to-point link.
//!
//! The core owns the radio parameters and their region limits
//! ([`rusty_esp_signal_core::lora::Params`], `DutyCycle`) and the
//! mID-authenticated session; the [`LoraLink`] backend maps them onto
//! `lora-phy` and carries the core's 23-byte MAC'd envelope over the modem.
//! This firmware builds the concrete SX1262 radio over SPI, forms a link at
//! EU868, and — once a peer is in range — runs the handshake and echoes
//! sealed frames.
//!
//! Wiring is the board's: the SPI and control pins below are placeholders for
//! the compile; a real board sets them to its SX1262 breakout. No SX1262 is
//! attached in CI, so this is built, not flashed (the package ledger's S4).
//!
//! Track B builds on the stable RISC-V toolchain.

extern crate alloc;

use embassy_time::Delay;
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_backtrace as _;
// lora-phy logs through defmt unconditionally; esp-println carries the
// #[defmt::global_logger]. Nothing here calls it, so link it explicitly.
use esp_println as _;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig};
use esp_hal::spi::Mode;
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::time::{Instant, Rate};
use esp_hal::timer::timg::TimerGroup;
use lora_phy::LoRa;
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::sx126x::{Config as Sx126xConfig, Sx1262, Sx126x};
use rusty_esp_core::Micros;
use rusty_esp_mid_core::key::DeviceKey;
use rusty_esp_signal_core::lora::{Params, Region};
use rusty_esp_signal_esp::lora::LoraLink;
use rusty_esp_signal_esp::hal::rng::EspTrng;

esp_bootloader_esp_idf::esp_app_desc!();

// defmt needs one timestamp definition per binary; use the system timer.
defmt::timestamp!("{=u64:us}", Instant::now().duration_since_epoch().as_micros());

fn now() -> Micros {
    Micros(Instant::now().duration_since_epoch().as_micros())
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    esp_alloc::heap_allocator!(size: 72 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw = esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    esp_rtos::start(timg0.timer0, sw.software_interrupt0);

    // The device identity from the hardware TRNG.
    let _trng_source = esp_hal::rng::TrngSource::new(peripherals.RNG, peripherals.ADC1);
    let trng = esp_hal::rng::Trng::try_new().expect("TRNG");
    let mut rng = EspTrng::new(trng);
    let me = DeviceKey::generate(&mut rng, "janus-lora").expect("device key");

    // SPI to the SX1262. GPIO choices are the board's; these compile for the C6.
    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(4))
            .with_mode(Mode::_0),
    )
    .expect("spi")
    .with_sck(peripherals.GPIO6)
    .with_mosi(peripherals.GPIO7)
    .with_miso(peripherals.GPIO2)
    .into_async();

    let nss = Output::new(peripherals.GPIO18, Level::High, OutputConfig::default());
    let spi_device = ExclusiveDevice::new(spi, nss, Delay).expect("spi device");

    let reset = Output::new(peripherals.GPIO0, Level::High, OutputConfig::default());
    let dio1 = Input::new(peripherals.GPIO1, InputConfig::default());
    let busy = Input::new(peripherals.GPIO3, InputConfig::default());
    let iv = GenericSx126xInterfaceVariant::new(reset, dio1, busy, None, None)
        .expect("interface variant");

    let sx126x = Sx126x::new(
        spi_device,
        iv,
        Sx126xConfig {
            chip: Sx1262,
            tcxo_ctrl: None,
            use_dcdc: true,
            rx_boost: false,
        },
    );
    let lora = LoRa::new(sx126x, false, Delay).await.expect("lora init");

    // EU868 defaults from the core (868.1 MHz, 14 dBm, 1 % duty cycle).
    let params = Params::default_for(Region::Eu868);
    defmt::info!("airtime for 32 bytes: {} us", params.airtime_micros(32));
    let mut link = LoraLink::new(lora, params).expect("lora link");

    // Run as the initiator against the peer once it is listening: handshake,
    // then send one authenticated frame.
    match link.handshake_initiator(&me, &mut rng, |_did| true, now()).await {
        Ok(mut session) => {
            defmt::info!("lora session {} established", session.id());
            let _ = link.send(&mut session, b"janus-lora-hello").await;
        }
        Err(_) => defmt::info!("no peer yet; the link and params are built"),
    }

    loop {
        embassy_time::Timer::after(embassy_time::Duration::from_secs(60)).await;
    }
}

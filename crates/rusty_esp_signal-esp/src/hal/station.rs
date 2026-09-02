//! Wi-Fi station lifecycle driven by the core's [`StationPolicy`].
//!
//! The core owns the policy — when to retry, how long to back off, when to
//! give up and fall back to provisioning — as a pure state machine over
//! [`Event`]s that yields [`Action`]s. This backend turns esp-radio's
//! `WifiController` into that event stream and executes the actions, so the
//! reconnect behaviour is tested on the host (the ledger's exact back-off
//! sequence) and only the radio calls live here.
//!
//! A firmware constructs the controller, sets the station credentials, and
//! calls [`run_station`] with a policy; it returns only if the policy decides
//! to start provisioning (Track B BLE), handing control back so the firmware
//! can bring up the BLE service.

use embassy_time::{Duration, Timer};
use esp_radio::wifi::WifiController;
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::wifi::{Action, Event, Phase, StationPolicy};

/// Drive a Wi-Fi station through the core policy until it asks to provision.
///
/// `now` is a monotonic clock read the caller supplies (esp-hal's
/// `esp_hal::time::Instant::now()` converted to microseconds); the loop reads
/// it once per transition. Returns the [`Phase`] the policy stopped in — only
/// [`Phase::Fallback`], which is the signal to start BLE provisioning.
pub async fn run_station(
    controller: &mut WifiController<'_>,
    policy: &mut StationPolicy,
    mut now: impl FnMut() -> Micros,
) -> Phase {
    // The device is provisioned (credentials are set): kick the policy.
    let mut action = policy.on(Event::Provisioned, now());
    loop {
        match action {
            Action::Connect => match controller.connect_async().await {
                Ok(_) => action = policy.on(Event::Connected, now()),
                Err(_) => action = policy.on(Event::Disconnected, now()),
            },
            Action::Wait(d) => {
                Timer::after(Duration::from_millis(d.as_millis())).await;
                action = policy.on(Event::Tick, now());
            }
            Action::StartProvisioning => return Phase::Fallback,
            Action::None => {
                // Connected and idle: wait for the radio to drop, then feed
                // the disconnect back into the policy.
                let _ = controller.wait_for_disconnect_async().await;
                action = policy.on(Event::Disconnected, now());
            }
        }
    }
}

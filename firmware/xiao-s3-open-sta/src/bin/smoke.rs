//! E1's receive check: upstream's `wifi_smoke` receive loop
//! (opensensor/esp-wifi-hal f159fcf, examples/src/bin/wifi_smoke.rs), on
//! the family's pins. Channels 1..11, 200 ms each, frames counted; nothing
//! is transmitted. Upstream's own build of it heard 43 frames on the bench
//! XIAO (2026-10-03) where the port's FoA scan heard none: this tells the
//! HAL port from the scan. `JANUS_SMOKE_CLOCK=max` runs the CPU at 240 MHz
//! as the cells do; otherwise esp-hal's default, as upstream's example does.
//! NOT Wi-Fi certified.
#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use esp_backtrace as _;
use esp_hal::timer::timg::TimerGroup;
use esp_println::println;
use esp_wifi_hal::prelude::*;
use static_cell::StaticCell;

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    let max = option_env!("JANUS_SMOKE_CLOCK") == Some("max");
    let config = if max {
        esp_hal::Config::default().with_cpu_clock(esp_hal::clock::CpuClock::max())
    } else {
        esp_hal::Config::default()
    };
    let peripherals = esp_hal::init(config);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);
    println!("smoke: boot clock={}", if max { "max" } else { "default" });
    static RESOURCES: StaticCell<WiFiResources<10>> = StaticCell::new();
    let mut wifi = WiFi::new(peripherals.WIFI, RESOURCES.init(WiFiResources::new()));
    println!("smoke: initialized");
    wifi.set_scanning_mode(0, ScanningMode::BeaconsOnly).unwrap();
    loop {
        let mut received = 0usize;
        for channel in 1..=11 {
            wifi.set_channel(channel).unwrap();
            let until = Instant::now() + Duration::from_millis(200);
            let mut on_channel = 0usize;
            while Instant::now() < until {
                if let Ok(frame) = with_timeout(Duration::from_millis(50), wifi.receive()).await
                    && frame.mpdu_buffer().len() >= 24
                {
                    on_channel += 1;
                }
            }
            received += on_channel;
            println!("smoke: rx channel={channel} frames={on_channel}");
        }
        println!("smoke: pass received={received}");
        Timer::after_secs(5).await;
    }
}

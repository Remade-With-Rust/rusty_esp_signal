//! The station: FoA over the open MAC, embassy-net over FoA's device, and
//! the core's station policy over FoA's join.

use embassy_net::{Config, DhcpConfig, Runner, Stack, StackResources};
use embassy_time::{Duration, Timer, with_timeout};
use foa::{FoAResources, FoARunner, VirtualInterface};
use foa_sta::{ConnectionConfig, Credentials, StaControl, StaNetDevice, StaResources, StaRunner};
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::wifi::{Action, Event, Phase, PolicyConfig, StationPolicy};
use static_cell::StaticCell;

/// How long one join may take: FoA scans for the network, authenticates,
/// associates and runs the WPA2 four-way handshake inside it.
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(25);
/// How long [`station_task`] rests after the policy gives up, before it
/// tries again (as `hal::netstack::FALLBACK_REST` in rusty_esp_signal-esp).
pub const FALLBACK_REST: Duration = Duration::from_secs(60);
/// How often a joined station asks FoA whether it still is: FoA has no
/// awaitable "link lost", only `connected()`.
pub const LINK_POLL: Duration = Duration::from_secs(1);

/// What [`stack`] builds: the station's control, the IP stack, and the
/// three runners a firmware spawns ([`mac_task`], [`sta_task`],
/// [`net_task`]) before anything awaits the stack.
pub struct OpenStation {
    /// Joins, leaves, scans (FoA's station control).
    pub control: StaControl<'static, 'static>,
    /// The IP stack, as `hal::netstack::stack` gives it.
    pub stack: Stack<'static>,
    /// FoA's lower-MAC runner, for [`mac_task`].
    pub mac: FoARunner<'static>,
    /// FoA's station runner, for [`sta_task`].
    pub sta: StaRunner<'static, 'static>,
    /// The IP stack's runner, for [`net_task`].
    pub net: Runner<'static, StaNetDevice<'static>>,
}

/// The open MAC brought up and an IP stack with DHCP over its station: the
/// counterpart of `hal::netstack::stack` with esp-radio's station
/// interface. Once per firmware (the MAC's resources are static). The
/// station takes the chip's base MAC address, as esp-radio's station does,
/// so a DHCP server sees one device across boots and stacks. `seed` salts
/// the stack's port and ID choices; take it from the hardware RNG.
pub fn stack<const SOCK: usize>(
    wifi: esp_hal::peripherals::WIFI<'static>,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
) -> OpenStation {
    static FOA: StaticCell<FoAResources> = StaticCell::new();
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static STA: StaticCell<StaResources<'static>> = StaticCell::new();
    let ([vif, ..], mac) = foa::init(FOA.init(FoAResources::new()), wifi);
    let (mut control, sta, device) =
        foa_sta::new_sta_interface(VIF.init(vif), STA.init(StaResources::default()));
    let base = esp_hal::efuse::base_mac_address();
    let mut address = [0u8; 6];
    address.copy_from_slice(base.as_bytes());
    // the interface is not up yet, so this cannot be refused
    let _ = control.set_mac_address(address);
    let (stack, net) = embassy_net::new(device, Config::dhcpv4(DhcpConfig::default()), resources, seed);
    OpenStation { control, stack, mac, sta, net }
}

/// FoA's lower-MAC runner, for the life of the firmware.
#[embassy_executor::task]
pub async fn mac_task(mut runner: FoARunner<'static>) {
    runner.run().await
}

/// FoA's station runner, for the life of the firmware.
#[embassy_executor::task]
pub async fn sta_task(mut runner: StaRunner<'static, 'static>) {
    runner.run().await
}

/// The IP stack's engine, for the life of the firmware.
#[embassy_executor::task]
pub async fn net_task(mut runner: Runner<'static, StaNetDevice<'static>>) -> ! {
    runner.run().await
}

/// One join, bounded by [`JOIN_TIMEOUT`]: true when FoA reports the station
/// associated and keyed.
pub async fn join(control: &mut StaControl<'static, 'static>, ssid: &str, passphrase: &str) -> bool {
    let attempt = control.connect_by_ssid(
        ssid,
        Some(ConnectionConfig { beacon_timeout: None, ..Default::default() }),
        Some(Credentials::Passphrase(passphrase)),
    );
    matches!(with_timeout(JOIN_TIMEOUT, attempt).await, Ok(Ok(())))
}

/// The core's station policy driven over FoA, as `hal::station::run_station`
/// drives it over esp-radio: join, back off, retry, until joined, then watch
/// the link. Returns the [`Phase`] the policy stopped in, which is only
/// [`Phase::Fallback`].
pub async fn run_station(
    control: &mut StaControl<'static, 'static>,
    ssid: &str,
    passphrase: &str,
    policy: &mut StationPolicy,
    mut now: impl FnMut() -> Micros,
) -> Phase {
    let mut action = policy.on(Event::Provisioned, now());
    loop {
        match action {
            Action::Connect => {
                let event = if join(control, ssid, passphrase).await {
                    Event::Connected
                } else {
                    Event::Disconnected
                };
                action = policy.on(event, now());
            }
            Action::Wait(d) => {
                Timer::after(Duration::from_millis(d.as_millis())).await;
                action = policy.on(Event::Tick, now());
            }
            Action::StartProvisioning => return Phase::Fallback,
            Action::None => {
                while control.connected() {
                    Timer::after(LINK_POLL).await;
                }
                action = policy.on(Event::Disconnected, now());
            }
        }
    }
}

/// Keeps the station joined for the life of the firmware, as
/// `hal::netstack::station_task` does with esp-radio. `now` is the clock
/// the policy times its back-off with.
#[embassy_executor::task]
pub async fn station_task(
    mut control: StaControl<'static, 'static>,
    ssid: &'static str,
    passphrase: &'static str,
    config: PolicyConfig,
    now: fn() -> Micros,
) -> ! {
    loop {
        let mut policy = StationPolicy::new(config);
        let _ = run_station(&mut control, ssid, passphrase, &mut policy, now).await;
        Timer::after(FALLBACK_REST).await;
    }
}

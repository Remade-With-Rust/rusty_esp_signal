//! An IP stack over the Wi-Fi station, on Track B: embassy-net over
//! esp-radio's station interface, with the join driven by the core's
//! [`StationPolicy`].
//!
//! This is what `wifi-sta` means on a bare-metal chip. ESP-IDF gives a Track A
//! firmware lwIP, DHCP and BSD sockets in C; here the same three are
//! `smoltcp`, its DHCP client and embassy-net's sockets, in Rust, and the
//! only C left under the station is Espressif's radio blob.
//!
//! Three pieces, all owned by the firmware that calls them:
//!
//! - [`stack`] builds the stack and its runner over a station [`Interface`]
//!   with DHCP; the firmware keeps the [`Stack`] (it is `Copy`) and hands the
//!   runner to [`net_task`].
//! - [`station_task`] owns the radio controller and keeps the station joined
//!   for the life of the firmware through [`run_station`] — the reconnect
//!   policy the core tests on the host. A policy that gives up ([`Phase::
//!   Fallback`]) has nothing to fall back to here (provisioning is the BLE
//!   firmware's job), so it rests for [`FALLBACK_REST`] and starts again.
//! - [`station_config`] turns an SSID and a passphrase into the radio's
//!   station configuration, refusing what the radio would.
//!
//! What a firmware then awaits is the stack's own state: [`Stack::wait_link_up`]
//! is the association, [`Stack::wait_config_up`] the DHCP lease. The two
//! timestamps around them are the join time the ledger records.
//!
//! The other way round — the board hosting the network, as a bench with no
//! router in the line wants (V1 was measured that way) — is the same stack
//! over the access-point [`Interface`] with a fixed address instead of a
//! lease: [`access_point_config`] and [`hosted_stack`]. The radio starts the
//! access point inside `set_config`; what the firmware must add is the DHCP
//! server a laptop expects, [`dhcp_server_task`] (feature `access-point`),
//! since embassy-net has a DHCP client and no server.

use embassy_net::{Config, DhcpConfig, Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4};
use embassy_time::{Duration, Timer};
use esp_radio::wifi::ap::AccessPointConfig;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{AuthenticationMethodConfig, Interface, WifiController};
use rusty_esp_signal_core::esp_core::error::{Error, Result};
use rusty_esp_signal_core::esp_core::Micros;
use rusty_esp_signal_core::wifi::{Phase, PolicyConfig, StationPolicy};

use super::station::run_station;

/// How long the station rests after the policy gives up, before it starts
/// the policy again from its first attempt.
pub const FALLBACK_REST: Duration = Duration::from_secs(60);

/// Sockets a firmware may open at once: the default for [`stack`]'s
/// resources. DHCP takes one.
pub const SOCKETS: usize = 4;

/// The station configuration for `ssid` and `passphrase` (WPA2-Personal;
/// an empty passphrase means an open network).
///
/// # Errors
///
/// `InvalidFormat` when the SSID is longer than 32 bytes or the passphrase
/// longer than the radio accepts.
pub fn station_config(ssid: &str, passphrase: &str) -> Result<esp_radio::wifi::Config> {
    let ssid = ssid.try_into().map_err(|_| Error::InvalidFormat)?;
    let authentication = if passphrase.is_empty() {
        AuthenticationMethodConfig::Open
    } else {
        AuthenticationMethodConfig::Wpa2Personal(
            passphrase.try_into().map_err(|_| Error::InvalidFormat)?,
        )
    };
    Ok(esp_radio::wifi::Config::Station(
        StationConfig::default()
            .with_ssid(ssid)
            .with_authentication(authentication),
    ))
}

/// The access-point configuration for a network the board hosts: `ssid`,
/// WPA2-Personal with `passphrase` (empty means open), `max_stations`
/// clients at once. The radio starts the access point when the firmware
/// hands this to `WifiController::set_config`.
///
/// # Errors
///
/// `InvalidFormat` when the SSID is longer than 32 bytes or the passphrase
/// is not what WPA2 accepts (8 to 63 bytes).
pub fn access_point_config(
    ssid: &str,
    passphrase: &str,
    max_stations: u16,
) -> Result<esp_radio::wifi::Config> {
    let ssid = ssid.try_into().map_err(|_| Error::InvalidFormat)?;
    let authentication = if passphrase.is_empty() {
        AuthenticationMethodConfig::Open
    } else {
        if !(8..=63).contains(&passphrase.len()) {
            return Err(Error::InvalidFormat);
        }
        AuthenticationMethodConfig::Wpa2Personal(
            passphrase.try_into().map_err(|_| Error::InvalidFormat)?,
        )
    };
    Ok(esp_radio::wifi::Config::AccessPoint(
        AccessPointConfig::default()
            .with_ssid(ssid)
            .with_authentication(authentication)
            .with_max_connections(max_stations),
    ))
}

/// An IP stack at a fixed `address` over the access-point interface: the
/// board is the gateway of the network it hosts. `resources` and `seed` as
/// for [`stack`].
pub fn hosted_stack<const SOCK: usize>(
    interface: Interface,
    address: Ipv4Cidr,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
) -> (Stack<'static>, Runner<'static, Interface>) {
    embassy_net::new(
        interface,
        Config::ipv4_static(StaticConfigV4 {
            address,
            gateway: Some(address.address()),
            dns_servers: Default::default(),
        }),
        resources,
        seed,
    )
}

/// An IP stack with DHCP over the station interface. `resources` must live
/// for the firmware; `seed` salts the stack's port and ID choices and should
/// come from the hardware random number generator.
pub fn stack<const SOCK: usize>(
    interface: Interface,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
) -> (Stack<'static>, Runner<'static, Interface>) {
    embassy_net::new(
        interface,
        Config::dhcpv4(DhcpConfig::default()),
        resources,
        seed,
    )
}

/// The stack's engine: runs forever, and must be spawned before anything
/// awaits the stack.
#[embassy_executor::task]
pub async fn net_task(mut runner: Runner<'static, Interface>) -> ! {
    runner.run().await
}

/// Keeps the station joined for the life of the firmware. `now` is the
/// monotonic clock the policy times its back-off with.
#[embassy_executor::task]
pub async fn station_task(
    mut controller: WifiController<'static>,
    config: PolicyConfig,
    now: fn() -> Micros,
) -> ! {
    loop {
        let mut policy = StationPolicy::new(config);
        let phase = run_station(&mut controller, &mut policy, now).await;
        debug_assert_eq!(phase, Phase::Fallback);
        // Nothing to provision here: rest, then try the policy over again.
        Timer::after(FALLBACK_REST).await;
    }
}

/// The DHCP server of a hosted network, for the life of the firmware: leases
/// from `.50` to `.200` of the board's subnet, the board as gateway; a UDP
/// socket on port 67, so [`SOCKETS`] must leave one for it. `address` is
/// what [`hosted_stack`] was given.
#[cfg(feature = "access-point")]
#[embassy_executor::task]
pub async fn dhcp_server_task(stack: Stack<'static>, address: Ipv4Cidr) -> ! {
    use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use edge_dhcp::io::{self, DEFAULT_SERVER_PORT};
    use edge_dhcp::server::{Server, ServerOptions};
    use edge_nal::UdpBind as _;
    use edge_nal_embassy::{Udp, UdpBuffers};

    let ip: Ipv4Addr = address.address();
    let now = || embassy_time::Instant::now().as_secs();
    let mut server = Server::<_, 8>::new(now, ip);
    let mut gateway = [ip];
    let options = ServerOptions::new(ip, Some(&mut gateway));
    let buffers = UdpBuffers::<1, 1500, 1500, 2>::new();
    let mut packet = [0u8; 1500];
    loop {
        let udp = Udp::new(stack, &buffers);
        match udp
            .bind(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::UNSPECIFIED,
                DEFAULT_SERVER_PORT,
            )))
            .await
        {
            Ok(mut socket) => {
                // returns only on a socket error; the lease table survives
                let _ = io::server::run(&mut server, &options, &mut socket, &mut packet).await;
            }
            Err(_) => {}
        }
        Timer::after(Duration::from_millis(500)).await;
    }
}

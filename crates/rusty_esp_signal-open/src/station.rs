//! The station: FoA over the open MAC, embassy-net over FoA's device, and
//! the core's station policy over FoA's join.

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use embassy_net::{Config, DhcpConfig, Runner, Stack, StackResources};
use embassy_time::{Duration, Timer, with_timeout};
use foa::{FoAResources, FoARunner, VirtualInterface};
use foa_sta::{
    ConnectionConfig, Credentials, StaControl, StaError, StaNetDevice, StaResources, StaRunner,
};
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

static ATTEMPTS: AtomicU32 = AtomicU32::new(0);
static JOINS: AtomicU32 = AtomicU32::new(0);
static LAST: AtomicU8 = AtomicU8::new(0);

/// Why the last join failed, by name ("none" before any failed).
const REASONS: [&str; 20] = [
    "none",
    "timeout",
    "lmac",
    "unable-to-find-ess",
    "ack-timeout",
    "response-timeout",
    "frame-deserialization-failed",
    "authentication-failure",
    "association-failure",
    "still-connected",
    "not-connected",
    "same-network",
    "invalid-bss",
    "router-operation-in-progress",
    "no-credentials-for-network",
    "four-way-handshake-failure",
    "no-key-slots-available",
    "invalid-psk-length",
    "group-key-handshake-failure",
    "other",
];

fn reason(e: &StaError) -> u8 {
    match e {
        StaError::LMacError(_) => 2,
        StaError::UnableToFindEss => 3,
        StaError::AckTimeout => 4,
        StaError::ResponseTimeout => 5,
        StaError::FrameDeserializationFailed => 6,
        StaError::AuthenticationFailure(_) => 7,
        StaError::AssociationFailure(_) => 8,
        StaError::StillConnected => 9,
        StaError::NotConnected => 10,
        StaError::SameNetwork => 11,
        StaError::InvalidBss => 12,
        StaError::RouterOperationAlreadyInProgress => 13,
        StaError::NoCredentialsForNetwork => 14,
        StaError::FourWayHandshakeFailure => 15,
        StaError::NoKeySlotsAvailable => 16,
        StaError::InvalidPskLength => 17,
        StaError::GroupKeyHandshakeFailure => 18,
        #[allow(unreachable_patterns)]
        _ => 19,
    }
}

/// The open MAC's transmit counters (the vendored driver's `tx_stats`):
/// frames, failures, first-attempt successes, attempts, radio time.
#[must_use]
pub fn tx_stats() -> esp_wifi_hal::tx_stats::TxStats {
    esp_wifi_hal::tx_stats::snapshot()
}

/// The joins tried, the joins that succeeded, and why the last one that
/// failed did: what a cell prints while it waits for its link (FoA's
/// station says nothing on its own; its logs can carry key material).
#[must_use]
pub fn join_stats() -> (u32, u32, &'static str) {
    let last = usize::from(LAST.load(Ordering::Relaxed)).min(REASONS.len() - 1);
    (ATTEMPTS.load(Ordering::Relaxed), JOINS.load(Ordering::Relaxed), REASONS[last])
}

/// The rate data frames start at once joined: OFDM 54 Mbit/s, the top of
/// 802.11g, which every 2.4 GHz access point takes (FoA associates without
/// HT capabilities, so HT rates are not ours to use). Each failed attempt
/// steps down a rate (vendored foa_sta's retry chain), so a poor link ends
/// at 6 Mbit/s, FoA's default for every frame, with more tries than before.
pub const DATA_RATE: esp_wifi_hal::rates::OfdmRate = esp_wifi_hal::rates::OfdmRate::Mbits54;

/// The 802.11g ladder the starting rate moves on, fastest first.
const LADDER: [esp_wifi_hal::rates::OfdmRate; 8] = {
    use esp_wifi_hal::rates::OfdmRate::*;
    [Mbits54, Mbits48, Mbits36, Mbits24, Mbits18, Mbits12, Mbits9, Mbits6]
};
/// A second with fewer frames than this says nothing about the link.
const RATE_MIN_FRAMES: u32 = 20;
/// Below this share of first-attempt successes, a step down.
const RATE_DOWN_BELOW_PERMILLE: u32 = 600;
/// Above this share, for [`RATE_UP_AFTER`] seconds running, a step up.
const RATE_UP_ABOVE_PERMILLE: u32 = 900;
/// How many good seconds in a row before trying a faster rate.
const RATE_UP_AFTER: u8 = 5;

static RATE_STEPS: AtomicU32 = AtomicU32::new(0);
static RATE_NOW: AtomicU8 = AtomicU8::new(0);

/// The starting rate for data frames, adapted once a second from the
/// driver's counters (E1): too many first attempts failing costs an ACK
/// timeout each, so the rate steps down; a run of clean seconds steps it
/// back up. Every frame still falls back down the ladder on its own
/// failures (vendored foa_sta's retry chain); this only moves where the
/// chain starts.
struct RateControl {
    index: usize,
    good_run: u8,
    last: esp_wifi_hal::tx_stats::TxStats,
}

impl RateControl {
    fn new() -> Self {
        let index = LADDER.iter().position(|r| *r == DATA_RATE).unwrap_or(0);
        RATE_NOW.store(index as u8, Ordering::Relaxed);
        Self { index, good_run: 0, last: esp_wifi_hal::tx_stats::snapshot() }
    }

    /// One second's counters: the rate to move to, if any.
    fn tick(&mut self, now: esp_wifi_hal::tx_stats::TxStats) -> Option<esp_wifi_hal::rates::OfdmRate> {
        let frames = now.frames.wrapping_sub(self.last.frames);
        let first_ok = now.first_ok.wrapping_sub(self.last.first_ok);
        self.last = now;
        if frames < RATE_MIN_FRAMES {
            return None;
        }
        let permille = first_ok * 1000 / frames;
        let next = if permille < RATE_DOWN_BELOW_PERMILLE && self.index + 1 < LADDER.len() {
            self.good_run = 0;
            self.index + 1
        } else if permille > RATE_UP_ABOVE_PERMILLE && self.index > 0 {
            self.good_run += 1;
            if self.good_run < RATE_UP_AFTER {
                return None;
            }
            self.good_run = 0;
            self.index - 1
        } else {
            if permille <= RATE_UP_ABOVE_PERMILLE {
                self.good_run = 0;
            }
            return None;
        };
        self.index = next;
        RATE_STEPS.fetch_add(1, Ordering::Relaxed);
        RATE_NOW.store(next as u8, Ordering::Relaxed);
        Some(LADDER[next])
    }
}

/// The data rate the station starts frames at now, in Mbit/s, and how many
/// times it has moved since boot.
#[must_use]
pub fn data_rate() -> (u8, u32) {
    const MBITS: [u8; 8] = [54, 48, 36, 24, 18, 12, 9, 6];
    let i = usize::from(RATE_NOW.load(Ordering::Relaxed)).min(MBITS.len() - 1);
    (MBITS[i], RATE_STEPS.load(Ordering::Relaxed))
}

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
    ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    match with_timeout(JOIN_TIMEOUT, attempt).await {
        Ok(Ok(())) => {
            JOINS.fetch_add(1, Ordering::Relaxed);
            // FoA resets its data rate to 6 Mbit/s on every join
            control.override_phy_rate(DATA_RATE.into());
            true
        }
        Ok(Err(e)) => {
            LAST.store(reason(&e), Ordering::Relaxed);
            false
        }
        Err(_) => {
            LAST.store(1, Ordering::Relaxed);
            false
        }
    }
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
                let mut rate = RateControl::new();
                while control.connected() {
                    Timer::after(LINK_POLL).await;
                    if let Some(next) = rate.tick(esp_wifi_hal::tx_stats::snapshot()) {
                        control.override_phy_rate(next.into());
                    }
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

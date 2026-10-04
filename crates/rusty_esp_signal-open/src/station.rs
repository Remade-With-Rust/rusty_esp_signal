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

/// E2's counters from the station: group-key handshakes taken, group-key
/// messages refused, unprotected data frames dropped after the join.
#[must_use]
pub fn air_stats() -> (u32, u32, u32) {
    foa_sta::air_stats()
}

/// The unprotected data frames the station dropped after the join, by
/// kind (E2): no payload, unicast with one, group-addressed with one, not
/// from the access point, the last one's subtype and ether type.
#[must_use]
pub fn dropped_unprotected() -> (u32, u32, u32, u32, u8, u16) {
    foa_sta::dropped_unprotected()
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
/// chain starts. Since [`SampledRate`] it is the A/B's control arm
/// (`JANUS_OPEN_RATE=threshold`).
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

/// Seconds of traffic at the chosen rate between probes of a neighbour.
const PROBE_EVERY: u8 = 10;
/// A probed rate takes over only if its goodput beats the chosen rate's by
/// this much (per mille of it): measurement noise must not flap the rate.
const PROBE_WIN_PERMILLE: u64 = 1030;
/// Below this share of first-attempt successes the chosen rate is failing
/// outright: a step down at once, without waiting for a probe.
const RATE_COLLAPSE_BELOW_PERMILLE: u32 = 300;

static RATE_PROBES: AtomicU32 = AtomicU32::new(0);
static GOODPUT_KBPS: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];

/// The starting rate for data frames, chosen by measured goodput (E1's
/// second rate control, in the manner of Minstrel's sampling). Each second
/// the driver's counters give the delivered MPDU bytes and the radio time
/// they took, retries, ACK timeouts and contention included: what a rate
/// actually delivers per microsecond of the radio, with its failures'
/// cost counted, where [`RateControl`] looked only at how often the first
/// attempt failed. Every [`PROBE_EVERY`] seconds one second is spent at a
/// neighbouring rate (alternately faster and slower), and the faster
/// deliverer of the two is kept.
struct SampledRate {
    index: usize,
    /// The neighbour being tried this second, if any.
    probing: Option<usize>,
    since_probe: u8,
    probe_up: bool,
    /// Per rate on [`LADDER`]: the goodput last measured, kbit/s (0: never).
    goodput: [u32; 8],
    last: esp_wifi_hal::tx_stats::TxStats,
}

impl SampledRate {
    fn new() -> Self {
        let index = LADDER.iter().position(|r| *r == DATA_RATE).unwrap_or(0);
        RATE_NOW.store(index as u8, Ordering::Relaxed);
        Self {
            index,
            probing: None,
            since_probe: 0,
            probe_up: true,
            goodput: [0; 8],
            last: esp_wifi_hal::tx_stats::snapshot(),
        }
    }

    fn settle(&mut self, index: usize) -> Option<esp_wifi_hal::rates::OfdmRate> {
        if index != self.index {
            self.index = index;
            RATE_STEPS.fetch_add(1, Ordering::Relaxed);
            RATE_NOW.store(index as u8, Ordering::Relaxed);
        }
        self.since_probe = 0;
        Some(LADDER[index])
    }

    /// One second's counters: the rate to move to, if any.
    fn tick(&mut self, now: esp_wifi_hal::tx_stats::TxStats) -> Option<esp_wifi_hal::rates::OfdmRate> {
        let frames = now.frames.wrapping_sub(self.last.frames);
        let first_ok = now.first_ok.wrapping_sub(self.last.first_ok);
        let bytes = now.bytes.wrapping_sub(self.last.bytes);
        let radio_us = now.radio_us.wrapping_sub(self.last.radio_us);
        self.last = now;
        let active = self.probing.unwrap_or(self.index);
        let measured = frames >= RATE_MIN_FRAMES && radio_us > 0;
        if measured {
            let kbps = u32::try_from(bytes * 8_000 / radio_us).unwrap_or(u32::MAX);
            let old = self.goodput[active];
            // a probe's second stands alone; the chosen rate's seconds blend
            self.goodput[active] = if self.probing.is_some() || old == 0 {
                kbps
            } else {
                ((u64::from(old) * 3 + u64::from(kbps)) / 4) as u32
            };
            GOODPUT_KBPS[active].store(self.goodput[active], Ordering::Relaxed);
        }
        if let Some(probe) = self.probing {
            if !measured {
                // an idle second says nothing: keep trying the neighbour
                return None;
            }
            self.probing = None;
            let wins = u64::from(self.goodput[probe]) * 1000
                > u64::from(self.goodput[self.index]) * PROBE_WIN_PERMILLE;
            return self.settle(if wins { probe } else { self.index });
        }
        if !measured {
            return None;
        }
        if first_ok * 1000 / frames < RATE_COLLAPSE_BELOW_PERMILLE && self.index + 1 < LADDER.len() {
            return self.settle(self.index + 1);
        }
        self.since_probe += 1;
        if self.since_probe < PROBE_EVERY {
            return None;
        }
        self.since_probe = 0;
        let up = (self.index > 0).then(|| self.index - 1);
        let down = (self.index + 1 < LADDER.len()).then(|| self.index + 1);
        let probe = if self.probe_up { up.or(down) } else { down.or(up) }?;
        self.probe_up = !self.probe_up;
        self.probing = Some(probe);
        RATE_PROBES.fetch_add(1, Ordering::Relaxed);
        Some(LADDER[probe])
    }
}

/// The airtime of a 1,500-byte MPDU at each rate on [`LADDER`], preamble
/// and SIGNAL included: 20 µs + 4 µs a symbol of 4 x rate bits, for the
/// 16 service bits, the frame and the 6 tail bits.
const AIRTIME_1500_US: [u32; 8] = [244, 272, 356, 524, 688, 1024, 1356, 2024];
/// A rate's success probability is updated once it has this many attempts.
const PROB_MIN_ATTEMPTS: u32 = 16;
/// An attempt's time beyond its frame's airtime (AIFS, backoff, SIFS and
/// the ACK; the others' frames while we wait): bounds on the measurement.
const OVERHEAD_MIN_US: u32 = 100;
const OVERHEAD_MAX_US: u32 = 2_000;
/// A rate takes over only if its expected throughput beats the chosen
/// rate's by this much (per mille).
const EXPECT_WIN_PERMILLE: u64 = 1030;
const PROB_UNKNOWN: u32 = u32::MAX;

static PROB_PERMILLE: [AtomicU32; 8] = [const { AtomicU32::new(PROB_UNKNOWN) }; 8];
static OVERHEAD_US: AtomicU32 = AtomicU32::new(0);

/// The starting rate for data frames by expected throughput (E1's third
/// rate control, Minstrel's in outline). The driver counts first attempts
/// and their ACKs per rate; one data frame in [`foa_sta::SAMPLE_EVERY`] starts at a
/// neighbouring rate (within two steps, a different one each second), so
/// every rate near the chosen one keeps a fresh success probability at the
/// cost of a few frames, where [`SampledRate`] spent a whole second at it.
/// A rate's expected throughput is its success probability times a
/// 1,500-byte frame over that frame's airtime plus the per-attempt
/// overhead measured on the board (contention, the ACK or its timeout,
/// the hotspot's own frames): a property of the rate, not of whatever
/// traffic the last second carried.
struct ExpectedRate {
    index: usize,
    /// Per rate, the success probability in per mille ([`PROB_UNKNOWN`]: none yet).
    prob: [u32; 8],
    /// Per rate, attempts and ACKs not yet folded into `prob`.
    pending: [(u32, u32); 8],
    overhead_us: u32,
    sample_step: u8,
    last_rates: [(u32, u32); 8],
    last: esp_wifi_hal::tx_stats::TxStats,
}

impl ExpectedRate {
    fn new() -> Self {
        let index = LADDER.iter().position(|r| *r == DATA_RATE).unwrap_or(0);
        RATE_NOW.store(index as u8, Ordering::Relaxed);
        Self {
            index,
            prob: [PROB_UNKNOWN; 8],
            pending: [(0, 0); 8],
            overhead_us: 150,
            sample_step: 0,
            last_rates: esp_wifi_hal::tx_stats::rate_snapshot(),
            last: esp_wifi_hal::tx_stats::snapshot(),
        }
    }

    /// The expected throughput at rate `i`, kbit/s (0: not known).
    fn throughput(&self, i: usize) -> u32 {
        if self.prob[i] == PROB_UNKNOWN {
            return 0;
        }
        self.prob[i] * 12_000 / (AIRTIME_1500_US[i] + self.overhead_us)
    }

    /// One second's counters: the rate to move to, if any.
    fn tick(
        &mut self,
        now: esp_wifi_hal::tx_stats::TxStats,
        rates: [(u32, u32); 8],
    ) -> Option<esp_wifi_hal::rates::OfdmRate> {
        for i in 0..LADDER.len() {
            let pending = &mut self.pending[i];
            pending.0 += rates[i].0.wrapping_sub(self.last_rates[i].0);
            pending.1 += rates[i].1.wrapping_sub(self.last_rates[i].1);
            if pending.0 >= PROB_MIN_ATTEMPTS {
                let p = (pending.1 * 1000 / pending.0).min(1000);
                self.prob[i] = if self.prob[i] == PROB_UNKNOWN { p } else { (self.prob[i] * 3 + p) / 4 };
                *pending = (0, 0);
                PROB_PERMILLE[i].store(self.prob[i], Ordering::Relaxed);
            }
        }
        self.last_rates = rates;
        let timed = now.timed.wrapping_sub(self.last.timed);
        let hw_us = now.hw_us.wrapping_sub(self.last.hw_us);
        self.last = now;
        if timed >= RATE_MIN_FRAMES {
            let per_attempt = u32::try_from(hw_us / u64::from(timed)).unwrap_or(u32::MAX);
            let overhead = per_attempt
                .saturating_sub(AIRTIME_1500_US[self.index])
                .clamp(OVERHEAD_MIN_US, OVERHEAD_MAX_US);
            self.overhead_us = (self.overhead_us * 3 + overhead) / 4;
            OVERHEAD_US.store(self.overhead_us, Ordering::Relaxed);
        }
        for i in 0..LADDER.len() {
            GOODPUT_KBPS[i].store(self.throughput(i), Ordering::Relaxed);
        }
        let best = (0..LADDER.len()).max_by_key(|&i| self.throughput(i)).unwrap_or(self.index);
        let moved = best != self.index
            && u64::from(self.throughput(best)) * 1000
                > u64::from(self.throughput(self.index)) * EXPECT_WIN_PERMILLE;
        if moved {
            self.index = best;
            RATE_STEPS.fetch_add(1, Ordering::Relaxed);
            RATE_NOW.store(best as u8, Ordering::Relaxed);
        }
        // the next second's sample: the neighbours within two steps in turn
        const OFFSETS: [isize; 4] = [-1, 1, -2, 2];
        let mut sample = None;
        for _ in 0..OFFSETS.len() {
            let j = self.index as isize + OFFSETS[usize::from(self.sample_step) % OFFSETS.len()];
            self.sample_step = self.sample_step.wrapping_add(1);
            if (0..LADDER.len() as isize).contains(&j) {
                sample = Some(LADDER[j as usize]);
                break;
            }
        }
        foa_sta::set_data_sample_rate(sample);
        RATE_PROBES.fetch_add(1, Ordering::Relaxed);
        moved.then(|| LADDER[self.index])
    }
}

/// The expected-throughput rate control's model: each rate's success
/// probability in per mille (54 down to 6 Mbit/s; `u32::MAX`: not yet
/// measured) and the per-attempt overhead it measured, µs.
#[must_use]
pub fn rate_model() -> ([u32; 8], u32) {
    (
        core::array::from_fn(|i| PROB_PERMILLE[i].load(Ordering::Relaxed)),
        OVERHEAD_US.load(Ordering::Relaxed),
    )
}

/// The goodput last measured at each rate on the ladder (54 down to 6
/// Mbit/s), in kbit/s of MPDU bytes per radio microsecond (0: never tried),
/// and how many probes the rate control has made. Under [`ExpectedRate`]
/// (the default) the figures are its expected throughput for a 1,500-byte
/// frame and the probes are its sampling seconds.
#[must_use]
pub fn rate_goodput() -> ([u32; 8], u32) {
    (
        core::array::from_fn(|i| GOODPUT_KBPS[i].load(Ordering::Relaxed)),
        RATE_PROBES.load(Ordering::Relaxed),
    )
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
                let mut threshold = RateControl::new();
                let mut sampled = SampledRate::new();
                let mut expected = ExpectedRate::new();
                while control.connected() {
                    Timer::after(LINK_POLL).await;
                    let counters = esp_wifi_hal::tx_stats::snapshot();
                    // JANUS_OPEN_RATE builds the A/B's arms: `fixed` keeps the
                    // starting rate, `threshold` the first-attempt thresholds,
                    // `probe` the measured goodput of whole seconds, anything
                    // else the expected throughput
                    let next = match option_env!("JANUS_OPEN_RATE") {
                        Some("fixed") => None,
                        Some("threshold") => threshold.tick(counters),
                        Some("probe") => sampled.tick(counters),
                        _ => expected.tick(counters, esp_wifi_hal::tx_stats::rate_snapshot()),
                    };
                    if let Some(next) = next {
                        control.override_phy_rate(next.into());
                    }
                }
                foa_sta::set_data_sample_rate(None);
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

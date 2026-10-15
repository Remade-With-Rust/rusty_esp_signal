//! The station: FoA over the open MAC, embassy-net over FoA's device, and
//! the core's station policy over FoA's join.

use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use embassy_net::{Config, DhcpConfig, Runner, Stack, StackResources};
use embassy_time::{Duration, Timer, with_timeout};
use foa::{FoARunner, VirtualInterface};
/// FoA's station control: [`Station::control`]'s type, which a firmware
/// names to hand it to its own task over [`run_station`].
pub use foa_sta::StaControl;
use foa_sta::{ConnectionConfig, Credentials, StaError, StaNetDevice, StaResources, StaRunner};
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
/// The channel of the network joined; 0 while not joined.
static JOINED_CHANNEL: AtomicU8 = AtomicU8::new(0);

/// The channel of the network the station is joined to, `None` while it is
/// not (an access point beside the station beacons
/// on its channel, the one radio being on one channel).
pub fn joined_channel() -> Option<u8> {
    match JOINED_CHANNEL.load(Ordering::Relaxed) {
        0 => None,
        c => Some(c),
    }
}

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

/// The MAC errors by interface and kind, the last one's raw code included.
pub fn tx_mac_detail() -> esp_wifi_hal::tx_stats::MacDetail {
    esp_wifi_hal::tx_stats::mac_detail()
}

/// E2's counters from the station: group-key handshakes taken, group-key
/// messages refused, unprotected data frames dropped after the join.
#[must_use]
pub fn air_stats() -> (u32, u32, u32) {
    foa_sta::air_stats()
}

/// The unprotected data frames with a payload the station dropped after
/// the join, by kind (E2): unicast, group-addressed, not from the access
/// point, the last one's subtype and ether type.
#[must_use]
pub fn dropped_unprotected() -> (u32, u32, u32, u8, u16) {
    foa_sta::dropped_unprotected()
}

/// Null and QoS Null data frames received (the access point's keep-alives;
/// no payload, never protected).
#[must_use]
pub fn null_frames() -> u32 {
    foa_sta::null_frames()
}

/// The Ethernet source a relay gives a frame it forwards
/// upstream (the station's address, locally administered bit flipped).
#[must_use]
pub const fn relay_mark(own: [u8; 6]) -> [u8; 6] {
    foa_sta::relay_mark(own)
}

/// Relayed frames upstream as background traffic (TID 1, never in the TID 0
/// aggregates), or not: relayed traffic behind the device's own, on the air.
pub fn set_relay_background(on: bool) {
    foa_sta::set_relay_background(on);
}

/// Relayed frames sent upstream as background since boot.
#[must_use]
pub fn relayed_as_background() -> u32 {
    foa_sta::relayed_as_background()
}

/// Group-addressed frames handed to the network stack: (to the broadcast
/// address, to another group address such as IPv6's solicited-node groups).
#[must_use]
pub fn group_delivered() -> (u32, u32) {
    foa_sta::group_delivered()
}

/// The joins tried, the joins that succeeded, and why the last one that
/// failed did: what a cell prints while it waits for its link (FoA's
/// station says nothing on its own; its logs can carry key material).
#[must_use]
pub fn join_stats() -> (u32, u32, &'static str) {
    let last = usize::from(LAST.load(Ordering::Relaxed)).min(REASONS.len() - 1);
    (
        ATTEMPTS.load(Ordering::Relaxed),
        JOINS.load(Ordering::Relaxed),
        REASONS[last],
    )
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
    [
        Mbits54, Mbits48, Mbits36, Mbits24, Mbits18, Mbits12, Mbits9, Mbits6,
    ]
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
        Self {
            index,
            good_run: 0,
            last: esp_wifi_hal::tx_stats::snapshot(),
        }
    }

    /// One second's counters: the rate to move to, if any.
    fn tick(
        &mut self,
        now: esp_wifi_hal::tx_stats::TxStats,
    ) -> Option<esp_wifi_hal::rates::OfdmRate> {
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
    fn tick(
        &mut self,
        now: esp_wifi_hal::tx_stats::TxStats,
    ) -> Option<esp_wifi_hal::rates::OfdmRate> {
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
        if first_ok * 1000 / frames < RATE_COLLAPSE_BELOW_PERMILLE && self.index + 1 < LADDER.len()
        {
            return self.settle(self.index + 1);
        }
        self.since_probe += 1;
        if self.since_probe < PROBE_EVERY {
            return None;
        }
        self.since_probe = 0;
        let up = (self.index > 0).then(|| self.index - 1);
        let down = (self.index + 1 < LADDER.len()).then(|| self.index + 1);
        let probe = if self.probe_up {
            up.or(down)
        } else {
            down.or(up)
        }?;
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
/// The rate data frames start at now, Mbit/s rounded down, and whether
/// the ladder is HT's (E8).
static RATE_MBITS: AtomicU8 = AtomicU8::new(54);
static LADDER_HT: AtomicU8 = AtomicU8::new(0);

/// The rates [`ExpectedRate`] chooses among, fastest first, and each one's
/// airtime for a 1,500-byte frame (E8): 802.11g's eight, or on an HT link
/// MCS 7 down to 0 (the short guard interval if the access point takes it
/// and the build does not turn it off with `JANUS_OPEN_SGI=off`).
#[derive(Clone, Copy, Debug)]
struct Ladder {
    rates: [esp_wifi_hal::rates::TxPhyRate; 8],
    airtime_us: [u32; 8],
    /// Each rate in Mbit/s, rounded down, for the watch line.
    mbits: [u8; 8],
    ht: bool,
}

impl Ladder {
    fn ofdm() -> Self {
        Self {
            rates: LADDER.map(esp_wifi_hal::rates::TxPhyRate::Ofdm),
            airtime_us: AIRTIME_1500_US,
            mbits: [54, 48, 36, 24, 18, 12, 9, 6],
            ht: false,
        }
    }

    fn for_link(link: Option<foa_sta::ht::Link>) -> Self {
        use esp_wifi_hal::rates::{HtRate, OfdmRate, TxPhyRate};
        // Mbit/s x10 at MCS 0-7, 20 MHz, long and short guard interval
        const LONG: [u16; 8] = [65, 130, 195, 260, 390, 520, 585, 650];
        const SHORT: [u16; 8] = [72, 144, 216, 288, 433, 577, 650, 722];
        let Some(ht) = link.and_then(|l| l.ht) else {
            return Self::ofdm();
        };
        let sgi = ht.short_gi && option_env!("JANUS_OPEN_SGI") != Some("off");
        let top = ht.highest_mcs().unwrap_or(0);
        let mcs = |i: usize| top.saturating_sub(i as u8);
        let table = if sgi { SHORT } else { LONG };
        Self {
            rates: core::array::from_fn(|i| {
                HtRate::new(mcs(i), sgi, false)
                    .map_or(TxPhyRate::Ofdm(OfdmRate::Mbits6), TxPhyRate::Ht)
            }),
            airtime_us: core::array::from_fn(|i| foa_sta::ht::ht_airtime_us(mcs(i), sgi, 1500)),
            mbits: core::array::from_fn(|i| (table[usize::from(mcs(i))] / 10) as u8),
            ht: true,
        }
    }

    fn snapshot(&self) -> [(u32, u32); 8] {
        if self.ht {
            esp_wifi_hal::tx_stats::ht_rate_snapshot()
        } else {
            esp_wifi_hal::tx_stats::rate_snapshot()
        }
    }
}

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
/// traffic the last second carried. On an HT link the same over MCS 7-0
/// (E8).
struct ExpectedRate {
    ladder: Ladder,
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
    fn new(ladder: Ladder) -> Self {
        // 802.11g starts at DATA_RATE; HT at the top MCS the access point takes
        let index = if ladder.ht {
            0
        } else {
            LADDER.iter().position(|r| *r == DATA_RATE).unwrap_or(0)
        };
        RATE_NOW.store(index as u8, Ordering::Relaxed);
        RATE_MBITS.store(ladder.mbits[index], Ordering::Relaxed);
        LADDER_HT.store(u8::from(ladder.ht), Ordering::Relaxed);
        for p in &PROB_PERMILLE {
            p.store(PROB_UNKNOWN, Ordering::Relaxed);
        }
        Self {
            ladder,
            index,
            prob: [PROB_UNKNOWN; 8],
            pending: [(0, 0); 8],
            overhead_us: 150,
            sample_step: 0,
            last_rates: ladder.snapshot(),
            last: esp_wifi_hal::tx_stats::snapshot(),
        }
    }

    /// The rate data frames start at now.
    fn rate(&self) -> esp_wifi_hal::rates::TxPhyRate {
        self.ladder.rates[self.index]
    }

    /// The expected throughput at rate `i`, kbit/s (0: not known).
    fn throughput(&self, i: usize) -> u32 {
        if self.prob[i] == PROB_UNKNOWN {
            return 0;
        }
        self.prob[i] * 12_000 / (self.ladder.airtime_us[i] + self.overhead_us)
    }

    /// One second's counters: the rate to move to, if any.
    fn tick(
        &mut self,
        now: esp_wifi_hal::tx_stats::TxStats,
    ) -> Option<esp_wifi_hal::rates::TxPhyRate> {
        let rates = self.ladder.snapshot();
        for i in 0..LADDER.len() {
            let pending = &mut self.pending[i];
            pending.0 += rates[i].0.wrapping_sub(self.last_rates[i].0);
            pending.1 += rates[i].1.wrapping_sub(self.last_rates[i].1);
            if pending.0 >= PROB_MIN_ATTEMPTS {
                let p = (pending.1 * 1000 / pending.0).min(1000);
                self.prob[i] = if self.prob[i] == PROB_UNKNOWN {
                    p
                } else {
                    (self.prob[i] * 3 + p) / 4
                };
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
                .saturating_sub(self.ladder.airtime_us[self.index])
                .clamp(OVERHEAD_MIN_US, OVERHEAD_MAX_US);
            self.overhead_us = (self.overhead_us * 3 + overhead) / 4;
            OVERHEAD_US.store(self.overhead_us, Ordering::Relaxed);
        }
        for i in 0..LADDER.len() {
            GOODPUT_KBPS[i].store(self.throughput(i), Ordering::Relaxed);
        }
        let best = (0..LADDER.len())
            .max_by_key(|&i| self.throughput(i))
            .unwrap_or(self.index);
        // E8: the chosen rate failing outright steps down at once. Its
        // neighbours unmeasured score zero, so no neighbour ever looked
        // better and a station whose starting rate the access point never
        // acknowledged stayed there (54 Mbit/s at 0 % against the owner's
        // router: 0.79 Mbit/s, every frame's first two attempts lost)
        let collapsed = self.prob[self.index] != PROB_UNKNOWN
            && self.prob[self.index] < RATE_COLLAPSE_BELOW_PERMILLE
            && self.index + 1 < LADDER.len();
        let best = if collapsed && self.throughput(best) <= self.throughput(self.index) {
            self.index + 1
        } else {
            best
        };
        let moved = best != self.index
            && (collapsed
                || u64::from(self.throughput(best)) * 1000
                    > u64::from(self.throughput(self.index)) * EXPECT_WIN_PERMILLE);
        if moved {
            self.index = best;
            RATE_STEPS.fetch_add(1, Ordering::Relaxed);
            RATE_NOW.store(best as u8, Ordering::Relaxed);
            RATE_MBITS.store(self.ladder.mbits[best], Ordering::Relaxed);
        }
        // the next second's sample: the neighbours within two steps in turn
        const OFFSETS: [isize; 4] = [-1, 1, -2, 2];
        let mut sample = None;
        for _ in 0..OFFSETS.len() {
            let j = self.index as isize + OFFSETS[usize::from(self.sample_step) % OFFSETS.len()];
            self.sample_step = self.sample_step.wrapping_add(1);
            if (0..LADDER.len() as isize).contains(&j) {
                sample = Some(self.ladder.rates[j as usize]);
                break;
            }
        }
        foa_sta::set_data_sample_rate(sample);
        RATE_PROBES.fetch_add(1, Ordering::Relaxed);
        moved.then(|| self.rate())
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

/// The data rate the station starts frames at now, in Mbit/s (an HT rate
/// rounded down: MCS 7 with the short guard interval reads 72), and how
/// many times it has moved since boot. On an HT link the rungs of
/// [`rate_model`] and [`rate_goodput`] are MCS 7 down to 0 (E8).
#[must_use]
pub fn data_rate() -> (u8, u32) {
    const MBITS: [u8; 8] = [54, 48, 36, 24, 18, 12, 9, 6];
    let mbits = if LADDER_HT.load(Ordering::Relaxed) != 0 {
        RATE_MBITS.load(Ordering::Relaxed)
    } else {
        MBITS[usize::from(RATE_NOW.load(Ordering::Relaxed)).min(MBITS.len() - 1)]
    };
    (mbits, RATE_STEPS.load(Ordering::Relaxed))
}

/// E8: A-MPDUs on or off at run time in a build with them (the in-run
/// A/B); the block-ack agreement and numbering stay.
pub fn set_ampdu_enabled(on: bool) {
    foa_sta::set_ampdu_enabled(on);
}

/// E8: (A-MPDU sends answered by a block-ack, subframes acknowledged,
/// resent, dropped after three rounds, BlockAckReqs sent).
#[must_use]
pub fn block_ack_stats() -> (u32, u32, u32, u32, u32) {
    foa_sta::block_ack_stats()
}

/// E8: block-ack action frames received, and the last one's action code |
/// status-or-parameters << 8.
#[must_use]
pub fn ba_census() -> (u32, u32) {
    foa_sta::ba_census()
}

/// E8's A-MPDU counters: (ADDBA requests sent, accepted, refused, the
/// block-ack window agreed now (0: none), A-MPDUs sent, subframes in them).
#[must_use]
pub fn ampdu_stats() -> (u32, u32, u32, u16, u32, u32) {
    foa_sta::ampdu_stats()
}

/// E8: whether the station's link is HT (its rate ladder MCS 7-0), and its
/// QoS counters: QoS data frames sent, A-MSDUs of two packets among them,
/// packets refused, ADDBA requests declined.
#[must_use]
pub fn ht_stats() -> (bool, (u32, u32, u32, u32)) {
    (LADDER_HT.load(Ordering::Relaxed) != 0, foa_sta::qos_stats())
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
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static STA: StaticCell<StaResources<'static>> = StaticCell::new();
    let ([vif, ..], mac) = foa::init(crate::FOA.take(), wifi);
    on_interface(
        VIF.init(vif),
        STA.init(StaResources::default()),
        mac,
        resources,
        seed,
        false,
    )
    .0
}

/// [`stack`], with FoA's second virtual interface kept for an access point
/// beside the station (both roles on one radio).
/// Host it with [`access_point::hosted_beside`](crate::access_point::hosted_beside)
/// once [`joined_channel`] names the channel; the one [`mac_task`] serves
/// both.
pub fn stack_beside_access_point<const SOCK: usize>(
    wifi: esp_hal::peripherals::WIFI<'static>,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
) -> (OpenStation, crate::SpareInterface) {
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static VIF_AP: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static STA: StaticCell<StaResources<'static>> = StaticCell::new();
    let ([vif, vif_ap, ..], mac) = foa::init(crate::FOA.take(), wifi);
    let (station, _) = on_interface(
        VIF.init(vif),
        STA.init(StaResources::default()),
        mac,
        resources,
        seed,
        false,
    );
    (station, crate::SpareInterface(VIF_AP.init(vif_ap)))
}

/// [`stack_beside_access_point`], with a [`splice`](crate::splice) between
/// the station's device and its IP stack: every frame the station receives
/// goes through the splice the firmware runs (a NAT relay, for one). The
/// stack is the same, on the splice.
pub fn stack_spliced_beside_access_point<const SOCK: usize>(
    wifi: esp_hal::peripherals::WIFI<'static>,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
) -> (OpenStation, crate::splice::Splice, crate::SpareInterface) {
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static VIF_AP: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static STA: StaticCell<StaResources<'static>> = StaticCell::new();
    let ([vif, vif_ap, ..], mac) = foa::init(crate::FOA.take(), wifi);
    let (station, splice) = on_interface(
        VIF.init(vif),
        STA.init(StaResources::default()),
        mac,
        resources,
        seed,
        true,
    );
    (
        station,
        splice.expect("asked for above"),
        crate::SpareInterface(VIF_AP.init(vif_ap)),
    )
}

/// [`stack_spliced_beside_access_point`], with the two virtual interfaces
/// the other way round: the **access point takes the radio's first
/// interface** and the station the second.
///
/// Why: the hardware encrypts a transmitted frame for the first interface
/// only, so an access point on the second cannot protect its own frames --
/// a fault measured on the bench. Hosting the access point first lets it
/// use the hardware as an access point alone on the radio does (eight
/// stations held that way), and moves the question to the station, which has one
/// key instead of a table of them.
///
/// Host the access point with
/// [`access_point::hosted_beside_spliced`](crate::access_point::hosted_beside_spliced)
/// as usual; it is told it is beside a station either way, so it still
/// expects the station's channel.
pub fn stack_spliced_with_access_point_first<const SOCK: usize>(
    wifi: esp_hal::peripherals::WIFI<'static>,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
) -> (OpenStation, crate::splice::Splice, crate::SpareInterface) {
    static VIF: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static VIF_AP: StaticCell<VirtualInterface<'static>> = StaticCell::new();
    static STA: StaticCell<StaResources<'static>> = StaticCell::new();
    // the first interface goes to the access point, the second to the station
    let ([vif_ap, vif, ..], mac) = foa::init(crate::FOA.take(), wifi);
    let (station, splice) = on_interface(
        VIF.init(vif),
        STA.init(StaResources::default()),
        mac,
        resources,
        seed,
        true,
    );
    (
        station,
        splice.expect("asked for above"),
        crate::SpareInterface(VIF_AP.init(vif_ap)),
    )
}

fn on_interface<const SOCK: usize>(
    vif: &'static mut VirtualInterface<'static>,
    sta_resources: &'static mut StaResources<'static>,
    mac: FoARunner<'static>,
    resources: &'static mut StackResources<SOCK>,
    seed: u64,
    spliced: bool,
) -> (OpenStation, Option<crate::splice::Splice>) {
    let (mut control, sta, device) = foa_sta::new_sta_interface(vif, sta_resources);
    let base = esp_hal::efuse::base_mac_address();
    let mut address = [0u8; 6];
    address.copy_from_slice(base.as_bytes());
    // the interface is not up yet, so this cannot be refused
    let _ = control.set_mac_address(address);
    // the stack's side of a splice: 2 frames each way (the station's own
    // channel to the MAC keeps its 8)
    static SPLICED: static_cell::ConstStaticCell<
        embassy_net_driver_channel::State<{ crate::splice::MTU }, 2, 2>,
    > = static_cell::ConstStaticCell::new(embassy_net_driver_channel::State::new());
    let (device, splice) = if spliced {
        let (device, splice) = crate::splice::splice(device, SPLICED.take(), address);
        (device, Some(splice))
    } else {
        (device, None)
    };
    let (stack, net) = embassy_net::new(
        device,
        Config::dhcpv4(DhcpConfig::default()),
        resources,
        seed,
    );
    (
        OpenStation {
            control,
            stack,
            mac,
            sta,
            net,
        },
        splice,
    )
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
pub async fn join(
    control: &mut StaControl<'static, 'static>,
    ssid: &str,
    passphrase: &str,
) -> bool {
    let attempt = control.connect_by_ssid(
        ssid,
        Some(ConnectionConfig {
            beacon_timeout: None,
            ..Default::default()
        }),
        Some(Credentials::Passphrase(passphrase)),
    );
    ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    match with_timeout(JOIN_TIMEOUT, attempt).await {
        Ok(Ok(())) => {
            JOINS.fetch_add(1, Ordering::Relaxed);
            JOINED_CHANNEL.store(control.channel().unwrap_or(0), Ordering::Relaxed);
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
                // E8: the ladder the association allows; an HT link starts
                // at the top MCS the access point takes
                let mut expected = ExpectedRate::new(Ladder::for_link(control.link()));
                if expected.ladder.ht {
                    control.override_phy_rate(expected.rate());
                }
                while control.connected() {
                    Timer::after(LINK_POLL).await;
                    let counters = esp_wifi_hal::tx_stats::snapshot();
                    // JANUS_OPEN_RATE builds the A/B's arms: `fixed` keeps the
                    // starting rate, `threshold` the first-attempt thresholds,
                    // `probe` the measured goodput of whole seconds (these
                    // three 802.11g only), anything else the expected throughput
                    let next = match option_env!("JANUS_OPEN_RATE") {
                        Some("fixed") => None,
                        Some("threshold") => threshold.tick(counters).map(Into::into),
                        Some("probe") => sampled.tick(counters).map(Into::into),
                        _ => expected.tick(counters),
                    };
                    if let Some(next) = next {
                        control.override_phy_rate(next);
                    }
                }
                foa_sta::set_data_sample_rate(None);
                JOINED_CHANNEL.store(0, Ordering::Relaxed);
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

//! LoRa modem parameters, exact time-on-air, the regional duty-cycle budget
//! and the unauthenticated discovery beacon.
//!
//! Nothing here talks to a radio. A backend takes a validated [`Params`],
//! programs the SX127x/SX126x, asks [`Params::airtime`] how long a frame
//! occupies the channel and asks [`DutyCycle`] whether the region still
//! allows it. The numbers come from three sources, named on each item:
//!
//! - Semtech, *SX1276/77/78/79 datasheet* rev. 7 §4.1.1 (symbol time,
//!   preamble, time-on-air) — the same formula the SX126x datasheet §6.1.4
//!   and the *LoRa Modem Calculator* tool use.
//! - The regulators: ETSI EN 300 220-2 (EU868), FCC 47 CFR §15.247 (US915),
//!   ACMA LIPD class licence (AU915), India WPC GSR 564(E) (IN865).
//! - LoRa Alliance *RP002-1.0.4 Regional Parameters* for the default
//!   channel plans, the AS923 group and the US915/AU915 dwell time.

use rusty_esp_core::Micros;
use rusty_esp_core::error::{Error, Result};

/// Spreading factor: a symbol carries `SF` bits and lasts `2^SF` chips.
///
/// SF7..=SF12 are the values every SX127x and SX126x supports and the only
/// ones with a LoRaWAN data rate. SF5/SF6 exist on the SX126x alone and are
/// not interoperable with the SX127x, so they are deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Sf {
    /// 128 chips per symbol.
    Sf7 = 7,
    /// 256 chips per symbol.
    Sf8 = 8,
    /// 512 chips per symbol.
    Sf9 = 9,
    /// 1024 chips per symbol.
    Sf10 = 10,
    /// 2048 chips per symbol.
    Sf11 = 11,
    /// 4096 chips per symbol.
    Sf12 = 12,
}

impl Sf {
    /// The numeric spreading factor, 7..=12.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// Chips per symbol, `2^SF` (128..=4096).
    #[must_use]
    pub const fn chips_per_symbol(self) -> u32 {
        1 << self.value()
    }

    /// The spreading factor with numeric value `v`, or `None` outside 7..=12.
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            7 => Some(Sf::Sf7),
            8 => Some(Sf::Sf8),
            9 => Some(Sf::Sf9),
            10 => Some(Sf::Sf10),
            11 => Some(Sf::Sf11),
            12 => Some(Sf::Sf12),
            _ => None,
        }
    }
}

/// Signal bandwidth.
///
/// The three widths every LoRa region and both Semtech families share.
/// Narrower SX127x bandwidths (7.8..62.5 kHz) are not modelled: no Janus
/// region uses them and the symbol times stop being exact microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bw {
    /// 125 kHz.
    Khz125,
    /// 250 kHz.
    Khz250,
    /// 500 kHz.
    Khz500,
}

impl Bw {
    /// The bandwidth in hertz.
    #[must_use]
    pub const fn hz(self) -> u32 {
        match self {
            Bw::Khz125 => 125_000,
            Bw::Khz250 => 250_000,
            Bw::Khz500 => 500_000,
        }
    }
}

/// Forward error correction coding rate, `4 / (4 + CR)`.
///
/// The discriminant is the `CR` term (1..=4) of Semtech's time-on-air
/// formula and the value of the SX127x `RegModemConfig1.CodingRate` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Cr {
    /// 4/5: one parity bit per four data bits (LoRaWAN's rate).
    Cr4_5 = 1,
    /// 4/6.
    Cr4_6 = 2,
    /// 4/7.
    Cr4_7 = 3,
    /// 4/8: the most robust, 2x overhead.
    Cr4_8 = 4,
}

impl Cr {
    /// The `CR` term of the airtime formula, 1..=4.
    #[must_use]
    pub const fn value(self) -> u8 {
        self as u8
    }

    /// The denominator of the rate: 5..=8 (the rate is `4 / denominator`).
    #[must_use]
    pub const fn denominator(self) -> u8 {
        4 + self.value()
    }
}

/// The symbol time at or above which Semtech mandates low data rate
/// optimisation: 16.38 ms (SX1276 datasheet §4.1.1.2; the SX126x driver
/// hard-codes the equivalent SF11/SF12 @ 125 kHz and SF12 @ 250 kHz rule).
pub const LDRO_THRESHOLD_MICROS: u64 = 16_380;

/// Low data rate optimisation (`DE` in the airtime formula).
///
/// It costs 2 bits per symbol of payload capacity and buys crystal-drift
/// tolerance on long symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Ldro {
    /// Semtech's rule: on when the symbol time is at least
    /// [`LDRO_THRESHOLD_MICROS`] (SF11/SF12 at 125 kHz, SF12 at 250 kHz).
    #[default]
    Auto,
    /// Always on.
    On,
    /// Always off (the modem may still refuse to demodulate long symbols
    /// without it; use only when both ends agree).
    Off,
}

impl Ldro {
    /// Whether `DE` is set for this SF/BW pair.
    #[must_use]
    pub const fn resolve(self, sf: Sf, bw: Bw) -> bool {
        match self {
            Ldro::On => true,
            Ldro::Off => false,
            Ldro::Auto => symbol_micros(sf, bw) >= LDRO_THRESHOLD_MICROS,
        }
    }
}

/// Symbol time in microseconds: `2^SF * 1_000_000 / BW_hz`.
///
/// Exact for every value of [`Sf`] and [`Bw`]: `2^SF * 1_000_000 / (125_000 *
/// k)` equals `2^SF * 8 / k` with `k` in {1, 2, 4}, an integer for SF >= 7.
/// The division truncates; it never has to for these inputs.
#[must_use]
pub const fn symbol_micros(sf: Sf, bw: Bw) -> u64 {
    (1u64 << sf.value()) * 1_000_000 / bw.hz() as u64
}

/// A regulatory region for unlicensed sub-GHz P2P operation.
///
/// Each region carries the band edges, the power ceiling, the duty-cycle or
/// dwell-time regime and a default frequency for peers that have not agreed
/// on one. The constants are for a *device* under the unlicensed rules, not
/// for a LoRaWAN gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Region {
    /// Europe, 863..870 MHz (ETSI EN 300 220-2 Annex B). Janus uses the g1
    /// sub-band 868.0..868.6 MHz: 25 mW (14 dBm) ERP, 1 % duty cycle.
    Eu868,
    /// United States, 902..928 MHz (FCC 47 CFR §15.247): 1 W (30 dBm),
    /// no duty cycle, 400 ms maximum channel occupancy.
    Us915,
    /// Australia, 915..928 MHz (ACMA LIPD class licence, 1 W EIRP), with
    /// the same 400 ms dwell time LoRaWAN RP002 applies to US915.
    Au915,
    /// Asia AS923-1 group (RP002 §2.7: Singapore, Thailand, Hong Kong,
    /// Taiwan, Vietnam ...): the 923..925 MHz window common to the group,
    /// 16 dBm EIRP, 1 % duty cycle. The AS923-2/-3/-4 frequency offsets are
    /// not modelled.
    As923,
    /// India, 865..867 MHz (WPC GSR 564(E), 2005): 1 W (30 dBm) transmitter
    /// power, no duty cycle.
    In865,
}

impl Region {
    /// Every region, in declaration order.
    pub const ALL: [Region; 5] = [
        Region::Eu868,
        Region::Us915,
        Region::Au915,
        Region::As923,
        Region::In865,
    ];

    /// A short stable name (`"EU868"` ...), for manifests and logs.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Region::Eu868 => "EU868",
            Region::Us915 => "US915",
            Region::Au915 => "AU915",
            Region::As923 => "AS923",
            Region::In865 => "IN865",
        }
    }

    /// Lowest carrier frequency the region allows, in hertz (inclusive).
    #[must_use]
    pub const fn freq_min_hz(self) -> u32 {
        match self {
            Region::Eu868 => 863_000_000,
            Region::Us915 => 902_000_000,
            Region::Au915 => 915_000_000,
            Region::As923 => 923_000_000,
            Region::In865 => 865_000_000,
        }
    }

    /// Highest carrier frequency the region allows, in hertz (inclusive).
    #[must_use]
    pub const fn freq_max_hz(self) -> u32 {
        match self {
            Region::Eu868 => 870_000_000,
            Region::Us915 => 928_000_000,
            Region::Au915 => 928_000_000,
            Region::As923 => 925_000_000,
            Region::In865 => 867_000_000,
        }
    }

    /// Whether `freq_hz` lies inside the band edges.
    #[must_use]
    pub const fn contains_freq(self, freq_hz: u32) -> bool {
        freq_hz >= self.freq_min_hz() && freq_hz <= self.freq_max_hz()
    }

    /// Maximum radiated power in dBm for an unlicensed P2P device.
    ///
    /// ERP for EU868 (ETSI states 25 mW ERP), EIRP elsewhere. A backend
    /// subtracts its antenna gain before programming the PA.
    #[must_use]
    pub const fn max_power_dbm(self) -> i8 {
        match self {
            Region::Eu868 => 14,
            Region::Us915 => 30,
            Region::Au915 => 30,
            Region::As923 => 16,
            Region::In865 => 30,
        }
    }

    /// Duty-cycle ceiling in permille of any one-hour window, or `None`
    /// where the regulator imposes none (US915, AU915, IN865).
    ///
    /// ETSI EN 300 220-2 Annex B defines duty cycle over one hour; 1 % is
    /// therefore 36 s of transmit time per hour on the sub-band.
    #[must_use]
    pub const fn duty_cycle_permille(self) -> Option<u16> {
        match self {
            Region::Eu868 | Region::As923 => Some(10),
            Region::Us915 | Region::Au915 | Region::In865 => None,
        }
    }

    /// Longest single transmission the region allows, or `None`.
    ///
    /// 400 ms for US915 (FCC §15.247(a)(1)(i): average channel occupancy
    /// no more than 0.4 s in any 20 s) and AU915 (RP002 §2.6, which mirrors
    /// the US rule). LoRaWAN also applies a 400 ms uplink dwell time to
    /// AS923; a P2P node there is bounded by the 1 % duty cycle instead and
    /// this table follows the regulator, not the network specification.
    #[must_use]
    pub const fn dwell_max(self) -> Option<Micros> {
        match self {
            Region::Us915 | Region::Au915 => Some(Micros::from_millis(400)),
            Region::Eu868 | Region::As923 | Region::In865 => None,
        }
    }

    /// The default P2P carrier for peers that have not negotiated one.
    ///
    /// - EU868: **868.1 MHz**, LoRaWAN default channel 1 in the g1 sub-band
    ///   (14 dBm, 1 %). 869.525 MHz in g3 would allow 27 dBm and 10 %, but
    ///   g3 is 250 kHz wide, shared with every other high-power SRD and
    ///   used by LoRaWAN RX2 downlinks; g1 is the quiet, interoperable
    ///   choice.
    /// - US915: **903.9 MHz**, LoRaWAN uplink channel 8, the first channel
    ///   of sub-band 2 (903.9..905.3 MHz) that TTN and Helium gateways
    ///   listen on. 915.0 MHz sits on no channel raster and in the middle of
    ///   the ISM band's densest FHSS traffic.
    /// - AU915: **916.8 MHz**, channel 8, the first of sub-band 2, for the
    ///   same reason.
    /// - AS923: **923.2 MHz**, AS923-1 default channel 1.
    /// - IN865: **865.0625 MHz**, IN865 default channel 1.
    #[must_use]
    pub const fn default_freq_hz(self) -> u32 {
        match self {
            Region::Eu868 => 868_100_000,
            Region::Us915 => 903_900_000,
            Region::Au915 => 916_800_000,
            Region::As923 => 923_200_000,
            Region::In865 => 865_062_500,
        }
    }
}

/// Smallest preamble the SX127x/SX126x transmit (`RegPreambleLsb` = 6; the
/// modem appends 4.25 symbols of sync on top).
pub const MIN_PREAMBLE_SYMBOLS: u16 = 6;

/// The LoRa physical layer's maximum payload, bytes (8-bit length field).
pub const MAX_PAYLOAD_LEN: usize = 255;

/// Everything the modem needs to send a frame, plus what the formula needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Params {
    /// Spreading factor.
    pub sf: Sf,
    /// Bandwidth.
    pub bw: Bw,
    /// Coding rate.
    pub cr: Cr,
    /// Carrier frequency in hertz.
    pub freq_hz: u32,
    /// Radiated power in dBm, checked against [`Region::max_power_dbm`].
    pub power_dbm: i8,
    /// Programmed preamble length in symbols (the air carries 4.25 more).
    /// Default 8, the LoRaWAN value; minimum [`MIN_PREAMBLE_SYMBOLS`].
    pub preamble_symbols: u16,
    /// `true` for the explicit header (length, CR and CRC flag sent on air);
    /// `false` for implicit mode, where both ends know the length. Default
    /// `true`.
    pub explicit_header: bool,
    /// Whether the 16-bit payload CRC is sent. Default `true`.
    pub crc: bool,
    /// Low data rate optimisation. Default [`Ldro::Auto`].
    pub ldro: Ldro,
}

impl Params {
    /// Build with the defaults: preamble 8, explicit header, CRC on, LDRO
    /// automatic.
    #[must_use]
    pub const fn new(sf: Sf, bw: Bw, cr: Cr, freq_hz: u32, power_dbm: i8) -> Self {
        Params {
            sf,
            bw,
            cr,
            freq_hz,
            power_dbm,
            preamble_symbols: 8,
            explicit_header: true,
            crc: true,
            ldro: Ldro::Auto,
        }
    }

    /// The region's default carrier and power ceiling at SF7/125 kHz/4/5.
    #[must_use]
    pub const fn default_for(region: Region) -> Self {
        Params::new(
            Sf::Sf7,
            Bw::Khz125,
            Cr::Cr4_5,
            region.default_freq_hz(),
            region.max_power_dbm(),
        )
    }

    /// Check the parameters against a region and the modem.
    ///
    /// `Unsupported` when the carrier lies outside the band, the power
    /// exceeds the region's ceiling, the preamble is shorter than the modem
    /// allows, or the SF/BW pair cannot carry even an empty frame within the
    /// region's dwell limit (SF12 @ 125 kHz needs 401 ms of preamble alone
    /// against the 400 ms US915/AU915 limit; this is why LoRaWAN stops at
    /// SF10 there).
    pub const fn validate(&self, region: Region) -> Result<()> {
        if !region.contains_freq(self.freq_hz) {
            return Err(Error::Unsupported);
        }
        if self.power_dbm > region.max_power_dbm() {
            return Err(Error::Unsupported);
        }
        if self.preamble_symbols < MIN_PREAMBLE_SYMBOLS {
            return Err(Error::Unsupported);
        }
        if let Some(dwell) = region.dwell_max() {
            if self.airtime_micros(0) > dwell.0 {
                return Err(Error::Unsupported);
            }
        }
        Ok(())
    }

    /// Whether `DE` is set: [`Ldro::resolve`] for this SF/BW pair.
    #[must_use]
    pub const fn ldro_enabled(&self) -> bool {
        self.ldro.resolve(self.sf, self.bw)
    }

    /// Symbol time in microseconds; see [`symbol_micros`].
    #[must_use]
    pub const fn symbol_micros(&self) -> u64 {
        symbol_micros(self.sf, self.bw)
    }

    /// Preamble time in microseconds: `(n_preamble + 4.25) * T_sym`,
    /// computed as `(4 * n_preamble + 17) * T_sym / 4`.
    ///
    /// Exact for every [`Sf`]/[`Bw`] pair (`T_sym` is always a multiple of
    /// 256 µs); the division truncates in general.
    #[must_use]
    pub const fn preamble_micros(&self) -> u64 {
        (4 * self.preamble_symbols as u64 + 17) * self.symbol_micros() / 4
    }

    /// Number of payload symbols (header, payload and CRC) for
    /// `payload_len` bytes — Semtech's formula, SX1276 datasheet §4.1.1.7:
    ///
    /// ```text
    /// 8 + max( ceil( (8 PL - 4 SF + 28 + 16 CRC - 20 IH) / (4 (SF - 2 DE)) ) * (CR + 4), 0 )
    /// ```
    ///
    /// `CRC` is 1 when the CRC is on, `IH` is 1 for the implicit header,
    /// `DE` is 1 with LDRO, `CR` is 1..=4. The ceiling is an exact integer
    /// `div_ceil`; a non-positive numerator contributes zero symbols.
    #[must_use]
    pub const fn payload_symbols(&self, payload_len: usize) -> u64 {
        let sf = self.sf.value() as i64;
        let pl = payload_len as i64;
        let crc: i64 = if self.crc { 1 } else { 0 };
        let ih: i64 = if self.explicit_header { 0 } else { 1 };
        let de: i64 = if self.ldro_enabled() { 1 } else { 0 };
        let numerator = 8 * pl - 4 * sf + 28 + 16 * crc - 20 * ih;
        // SF >= 7 and DE <= 1, so the denominator is at least 20.
        let denominator = (4 * (sf - 2 * de)) as u64;
        let blocks = if numerator <= 0 {
            0
        } else {
            (numerator as u64).div_ceil(denominator)
        };
        8 + blocks * (self.cr.value() as u64 + 4)
    }

    /// Time-on-air in microseconds for `payload_len` bytes:
    /// [`Self::preamble_micros`] plus [`Self::payload_symbols`] times
    /// [`Self::symbol_micros`]. Integer throughout; exact for every
    /// [`Sf`]/[`Bw`] pair because the symbol time is.
    ///
    /// `payload_len` above [`MAX_PAYLOAD_LEN`] is computed as asked; the
    /// modem will refuse it.
    #[must_use]
    pub const fn airtime_micros(&self, payload_len: usize) -> u64 {
        self.preamble_micros() + self.payload_symbols(payload_len) * self.symbol_micros()
    }

    /// [`Self::airtime_micros`] as a [`Micros`] duration.
    #[must_use]
    pub const fn airtime(&self, payload_len: usize) -> Micros {
        Micros(self.airtime_micros(payload_len))
    }
}

/// The duty-cycle window: ETSI measures over one hour.
pub const DUTY_WINDOW_MICROS: u64 = 3_600_000_000;

/// Transmissions remembered by [`DutyCycle`].
pub const DUTY_RING_LEN: usize = 32;

#[derive(Debug, Clone, Copy, Default)]
struct Slot {
    at: Micros,
    airtime: u64,
}

/// A sliding one-hour airtime budget for a [`Region`].
///
/// Remembers the last [`DUTY_RING_LEN`] transmissions as (start, airtime).
/// When the ring is full, the oldest entry is evicted **into its
/// neighbour**: its airtime is added to the next-oldest transmission, which
/// keeps it counted until that (newer) neighbour leaves the window. The
/// approximation therefore only ever over-counts — the budget is
/// conservative, never violated. Regions without a duty cycle always allow
/// a send but still record it, so [`Self::used_permille`] reports the true
/// occupancy anywhere.
#[derive(Debug, Clone)]
pub struct DutyCycle {
    region: Region,
    slots: [Slot; DUTY_RING_LEN],
    head: usize,
    len: usize,
}

impl DutyCycle {
    /// An empty budget for `region`.
    #[must_use]
    pub const fn new(region: Region) -> Self {
        DutyCycle {
            region,
            slots: [Slot {
                at: Micros::ZERO,
                airtime: 0,
            }; DUTY_RING_LEN],
            head: 0,
            len: 0,
        }
    }

    /// The region this budget enforces.
    #[must_use]
    pub const fn region(&self) -> Region {
        self.region
    }

    /// Transmit time allowed per [`DUTY_WINDOW_MICROS`], or `None` when the
    /// region has no duty cycle.
    #[must_use]
    pub const fn budget_micros(&self) -> Option<u64> {
        match self.region.duty_cycle_permille() {
            Some(permille) => Some(DUTY_WINDOW_MICROS / 1000 * permille as u64),
            None => None,
        }
    }

    /// Ask to transmit `airtime` starting at `now`, recording it on success.
    ///
    /// - `Unsupported` when `airtime` exceeds the region's dwell limit.
    /// - `Busy` when the airtime already spent in the hour ending at `now`
    ///   plus this transmission would exceed the region's permille.
    pub fn try_send(&mut self, now: Micros, airtime: Micros) -> Result<()> {
        if let Some(dwell) = self.region.dwell_max() {
            if airtime.0 > dwell.0 {
                return Err(Error::Unsupported);
            }
        }
        self.expire(now);
        if let Some(budget) = self.budget_micros() {
            if self.used_micros(now).saturating_add(airtime.0) > budget {
                return Err(Error::Busy);
            }
        }
        self.push(now, airtime.0);
        Ok(())
    }

    /// Microseconds of airtime recorded in the hour ending at `now`.
    #[must_use]
    pub fn used_micros(&self, now: Micros) -> u64 {
        let mut sum = 0u64;
        let mut i = 0;
        while i < self.len {
            if let Some(slot) = self.slots.get((self.head + i) % DUTY_RING_LEN) {
                if now.since(slot.at) < DUTY_WINDOW_MICROS {
                    sum = sum.saturating_add(slot.airtime);
                }
            }
            i += 1;
        }
        sum
    }

    /// Occupancy of the hour ending at `now`, in permille (0..=1000).
    #[must_use]
    pub fn used_permille(&self, now: Micros) -> u16 {
        let permille = self.used_micros(now) / (DUTY_WINDOW_MICROS / 1000);
        u16::try_from(permille.min(1000)).unwrap_or(1000)
    }

    /// Drop entries that have left the window at `now`.
    fn expire(&mut self, now: Micros) {
        while self.len > 0 {
            match self.slots.get(self.head) {
                Some(slot) if now.since(slot.at) >= DUTY_WINDOW_MICROS => {
                    self.head = (self.head + 1) % DUTY_RING_LEN;
                    self.len -= 1;
                }
                _ => break,
            }
        }
    }

    /// Record a transmission, merging the oldest into its neighbour when
    /// the ring is full (see the type docs).
    fn push(&mut self, at: Micros, airtime: u64) {
        if self.len == DUTY_RING_LEN {
            let next = (self.head + 1) % DUTY_RING_LEN;
            let carry = self.slots.get(self.head).map_or(0, |s| s.airtime);
            if let Some(neighbour) = self.slots.get_mut(next) {
                neighbour.airtime = neighbour.airtime.saturating_add(carry);
            }
            self.head = next;
            self.len -= 1;
        }
        let tail = (self.head + self.len) % DUTY_RING_LEN;
        if let Some(slot) = self.slots.get_mut(tail) {
            *slot = Slot { at, airtime };
            self.len += 1;
        }
    }
}

/// Wire size of a [`Beacon`]: 1 + 1 + 33 + 2 + 1.
pub const BEACON_LEN: usize = 38;

/// The unauthenticated discovery beacon a node sends so that peers can
/// start a handshake.
///
/// Wire layout, big-endian, [`BEACON_LEN`] bytes:
///
/// ```text
/// ver(1) kind(1) pubkey(33) interval_secs(2) flags(1)
/// ```
///
/// Nothing in it is trusted: the public key is a claim the handshake
/// proves, the flags a hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Beacon {
    /// Format version, always [`Beacon::VER`].
    pub ver: u8,
    /// Frame kind, always [`Beacon::KIND`].
    pub kind: u8,
    /// The device's P-256 public key, SEC1 compressed (0x02/0x03 prefix
    /// plus the 32-byte x-coordinate) — the same bytes as its `did:mata`.
    pub pubkey: [u8; 33],
    /// How often the beacon repeats, seconds.
    pub interval_secs: u16,
    /// [`Beacon::FLAG_ADOPTED`] and [`Beacon::FLAG_ACCEPTS_HANDSHAKE`].
    pub flags: u8,
}

impl Beacon {
    /// The only version this decoder accepts.
    pub const VER: u8 = 1;
    /// The beacon's frame kind.
    pub const KIND: u8 = 0x10;
    /// Bit 0: the node has been adopted (has an owner grant).
    pub const FLAG_ADOPTED: u8 = 0b01;
    /// Bit 1: the node will answer a handshake right now.
    pub const FLAG_ACCEPTS_HANDSHAKE: u8 = 0b10;

    /// A beacon of the current version.
    #[must_use]
    pub const fn new(pubkey: [u8; 33], interval_secs: u16, flags: u8) -> Self {
        Beacon {
            ver: Beacon::VER,
            kind: Beacon::KIND,
            pubkey,
            interval_secs,
            flags,
        }
    }

    /// Whether [`Self::FLAG_ADOPTED`] is set.
    #[must_use]
    pub const fn is_adopted(&self) -> bool {
        self.flags & Beacon::FLAG_ADOPTED != 0
    }

    /// Whether [`Self::FLAG_ACCEPTS_HANDSHAKE`] is set.
    #[must_use]
    pub const fn accepts_handshake(&self) -> bool {
        self.flags & Beacon::FLAG_ACCEPTS_HANDSHAKE != 0
    }

    /// Write the wire form into `out`, returning [`BEACON_LEN`].
    ///
    /// `BufferTooSmall { needed: 38 }` when `out` is shorter.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let Some(out) = out.get_mut(..BEACON_LEN) else {
            return Err(Error::BufferTooSmall { needed: BEACON_LEN });
        };
        let (head, rest) = out.split_at_mut(2);
        head.copy_from_slice(&[self.ver, self.kind]);
        let (key, rest) = rest.split_at_mut(33);
        key.copy_from_slice(&self.pubkey);
        let (interval, flags) = rest.split_at_mut(2);
        interval.copy_from_slice(&self.interval_secs.to_be_bytes());
        flags.copy_from_slice(&[self.flags]);
        Ok(BEACON_LEN)
    }

    /// Parse the wire form. Bytes beyond [`BEACON_LEN`] are ignored so a
    /// later version may append fields.
    ///
    /// `InvalidFormat` when shorter than [`BEACON_LEN`], when the version
    /// or kind differ, or when the key prefix is not a compressed SEC1
    /// point (0x02/0x03).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let Some(bytes) = bytes.get(..BEACON_LEN) else {
            return Err(Error::InvalidFormat);
        };
        let (head, rest) = bytes.split_at(2);
        if head != [Beacon::VER, Beacon::KIND] {
            return Err(Error::InvalidFormat);
        }
        let (key, rest) = rest.split_at(33);
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(key);
        if !matches!(pubkey.first(), Some(0x02 | 0x03)) {
            return Err(Error::InvalidFormat);
        }
        let (interval, flags) = rest.split_at(2);
        let interval_secs = u16::from_be_bytes([
            interval.first().copied().unwrap_or(0),
            interval.get(1).copied().unwrap_or(0),
        ]);
        Ok(Beacon {
            ver: Beacon::VER,
            kind: Beacon::KIND,
            pubkey,
            interval_secs,
            flags: flags.first().copied().unwrap_or(0),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(sf: Sf, bw: Bw) -> Params {
        Params::new(sf, bw, Cr::Cr4_5, 868_100_000, 14)
    }

    #[test]
    fn symbol_time_matches_the_datasheet() {
        assert_eq!(symbol_micros(Sf::Sf7, Bw::Khz125), 1_024);
        assert_eq!(symbol_micros(Sf::Sf12, Bw::Khz125), 32_768);
        assert_eq!(symbol_micros(Sf::Sf7, Bw::Khz500), 256);
        assert_eq!(symbol_micros(Sf::Sf9, Bw::Khz250), 2_048);
        // Every pair is an exact multiple of 256 us, so no rounding anywhere.
        for sf in [Sf::Sf7, Sf::Sf8, Sf::Sf9, Sf::Sf10, Sf::Sf11, Sf::Sf12] {
            for bw in [Bw::Khz125, Bw::Khz250, Bw::Khz500] {
                let t = symbol_micros(sf, bw);
                assert_eq!(t % 256, 0, "{sf:?}/{bw:?}");
                assert_eq!(
                    t * u64::from(bw.hz()),
                    u64::from(sf.chips_per_symbol()) * 1_000_000
                );
            }
        }
    }

    /// Semtech LoRa Modem Calculator: SF7, BW125, CR4/5, preamble 8,
    /// explicit header, CRC on, LDRO off, 10 bytes -> 41.216 ms.
    #[test]
    fn airtime_oracle_sf7_bw125_10_bytes() {
        let p = Params {
            ldro: Ldro::Off,
            ..params(Sf::Sf7, Bw::Khz125)
        };
        assert_eq!(p.symbol_micros(), 1_024);
        assert_eq!(p.preamble_micros(), 12_544);
        assert_eq!(p.payload_symbols(10), 28);
        assert_eq!(p.airtime_micros(10), 41_216);
        assert_eq!(p.airtime(10), Micros(41_216));
    }

    /// Semtech LoRa Modem Calculator: SF12, BW125, CR4/5, preamble 8,
    /// explicit header, CRC on, LDRO on, 10 bytes -> 991.232 ms.
    #[test]
    fn airtime_oracle_sf12_bw125_10_bytes_ldro() {
        let p = Params {
            ldro: Ldro::On,
            ..params(Sf::Sf12, Bw::Khz125)
        };
        assert_eq!(p.symbol_micros(), 32_768);
        assert_eq!(p.preamble_micros(), 401_408);
        assert_eq!(p.payload_symbols(10), 18);
        assert_eq!(p.airtime_micros(10), 991_232);
        // Auto resolves to the same answer at SF12/125.
        assert_eq!(params(Sf::Sf12, Bw::Khz125).airtime_micros(10), 991_232);
    }

    /// By hand — SF9, BW125, CR4/5, preamble 8, explicit, CRC, 20 bytes:
    ///   T_sym      = 2^9 * 1e6 / 125e3 = 4096 us (4.096 ms < 16.38 -> LDRO off)
    ///   T_preamble = (8 + 4.25) * 4096 = 50 176 us
    ///   numerator  = 8*20 - 4*9 + 28 + 16 = 168;  denominator = 4*9 = 36
    ///   ceil(168/36) = 5;  5 * (1+4) = 25;  8 + 25 = 33 symbols
    ///   T_payload  = 33 * 4096 = 135 168 us
    ///   total      = 185 344 us
    #[test]
    fn airtime_sf9_bw125_20_bytes_by_hand() {
        let p = params(Sf::Sf9, Bw::Khz125);
        assert!(!p.ldro_enabled());
        assert_eq!(p.preamble_micros(), 50_176);
        assert_eq!(p.payload_symbols(20), 33);
        assert_eq!(p.airtime_micros(20), 185_344);
    }

    #[test]
    fn airtime_header_and_crc_terms() {
        // Implicit header (-20) and no CRC (-16) at SF7: numerator 80-28+28-20 = 60,
        // ceil(60/28) = 3 -> 8 + 15 = 23 symbols.
        let p = Params {
            explicit_header: false,
            crc: false,
            ..params(Sf::Sf7, Bw::Khz125)
        };
        assert_eq!(p.payload_symbols(10), 23);
        // A non-positive numerator contributes nothing: SF12, no payload, no CRC:
        // -48 + 28 = -20 -> 8 symbols.
        let p = Params {
            crc: false,
            ..params(Sf::Sf12, Bw::Khz125)
        };
        assert_eq!(p.payload_symbols(0), 8);
        // CR4/8 multiplies the blocks by 8 instead of 5.
        let p = Params {
            cr: Cr::Cr4_8,
            ldro: Ldro::Off,
            ..params(Sf::Sf7, Bw::Khz125)
        };
        assert_eq!(p.payload_symbols(10), 8 + 4 * 8);
    }

    #[test]
    fn ldro_auto_follows_semtechs_rule() {
        let on = |sf, bw| Ldro::Auto.resolve(sf, bw);
        assert!(on(Sf::Sf11, Bw::Khz125));
        assert!(on(Sf::Sf12, Bw::Khz125));
        assert!(on(Sf::Sf12, Bw::Khz250));
        assert!(!on(Sf::Sf10, Bw::Khz125));
        assert!(!on(Sf::Sf11, Bw::Khz250));
        assert!(!on(Sf::Sf12, Bw::Khz500));
        assert!(!on(Sf::Sf7, Bw::Khz125));
        assert!(Ldro::On.resolve(Sf::Sf7, Bw::Khz500));
        assert!(!Ldro::Off.resolve(Sf::Sf12, Bw::Khz125));
    }

    #[test]
    fn enums_round_trip_their_numbers() {
        for sf in [Sf::Sf7, Sf::Sf8, Sf::Sf9, Sf::Sf10, Sf::Sf11, Sf::Sf12] {
            assert_eq!(Sf::from_u8(sf.value()), Some(sf));
        }
        assert_eq!(Sf::from_u8(6), None);
        assert_eq!(Sf::from_u8(13), None);
        assert_eq!(Cr::Cr4_5.denominator(), 5);
        assert_eq!(Cr::Cr4_8.denominator(), 8);
        assert_eq!(Bw::Khz250.hz(), 250_000);
    }

    #[test]
    fn region_table() {
        for region in Region::ALL {
            assert!(region.freq_min_hz() < region.freq_max_hz(), "{region:?}");
            assert!(
                region.contains_freq(region.default_freq_hz()),
                "{region:?} default outside band"
            );
            assert!(Params::default_for(region).validate(region).is_ok());
        }
        assert_eq!(Region::Eu868.max_power_dbm(), 14);
        assert_eq!(Region::Eu868.duty_cycle_permille(), Some(10));
        assert_eq!(Region::Eu868.dwell_max(), None);
        assert_eq!(Region::Us915.max_power_dbm(), 30);
        assert_eq!(Region::Us915.duty_cycle_permille(), None);
        assert_eq!(Region::Us915.dwell_max(), Some(Micros::from_millis(400)));
        assert_eq!(Region::Au915.dwell_max(), Some(Micros::from_millis(400)));
        assert_eq!(Region::As923.max_power_dbm(), 16);
        assert_eq!(Region::As923.duty_cycle_permille(), Some(10));
        assert_eq!(Region::In865.max_power_dbm(), 30);
        assert_eq!(Region::In865.duty_cycle_permille(), None);
        assert_eq!(Region::Eu868.default_freq_hz(), 868_100_000);
        assert_eq!(Region::Us915.default_freq_hz(), 903_900_000);
        assert_eq!(Region::Eu868.name(), "EU868");
    }

    #[test]
    fn validate_rejects_out_of_band_power_and_dwell() {
        let ok = params(Sf::Sf7, Bw::Khz125);
        assert_eq!(ok.validate(Region::Eu868), Ok(()));
        // 868.1 MHz is not a US915 frequency.
        assert_eq!(ok.validate(Region::Us915), Err(Error::Unsupported));
        let hot = Params {
            power_dbm: 15,
            ..ok
        };
        assert_eq!(hot.validate(Region::Eu868), Err(Error::Unsupported));
        let short = Params {
            preamble_symbols: 5,
            ..ok
        };
        assert_eq!(short.validate(Region::Eu868), Err(Error::Unsupported));
        // SF12/125 kHz: 401 ms of preamble alone breaks the 400 ms dwell.
        let slow = Params::new(Sf::Sf12, Bw::Khz125, Cr::Cr4_5, 903_900_000, 20);
        assert_eq!(slow.validate(Region::Us915), Err(Error::Unsupported));
        assert_eq!(slow.validate(Region::Au915), Err(Error::Unsupported));
        // ... but is fine at 250 kHz (200.7 ms preamble + 8 symbols = 331.8 ms).
        let slow250 = Params {
            bw: Bw::Khz250,
            ..slow
        };
        assert_eq!(slow250.validate(Region::Us915), Ok(()));
        // EU868 has no dwell limit, so SF12/125 is legal there.
        let eu_slow = Params {
            freq_hz: 868_100_000,
            power_dbm: 14,
            ..slow
        };
        assert_eq!(eu_slow.validate(Region::Eu868), Ok(()));
    }

    #[test]
    fn duty_cycle_eu868_is_36_seconds_per_hour() {
        let mut dc = DutyCycle::new(Region::Eu868);
        assert_eq!(dc.budget_micros(), Some(36_000_000));
        let second = Micros::from_secs(1);
        // 36 one-second frames fill the hour exactly.
        for i in 0..36u64 {
            let now = Micros::from_secs(i * 10);
            assert_eq!(dc.try_send(now, second), Ok(()), "frame {i}");
        }
        let now = Micros::from_secs(360);
        assert_eq!(dc.used_micros(now), 36_000_000);
        assert_eq!(dc.used_permille(now), 10);
        assert_eq!(dc.try_send(now, Micros(1)), Err(Error::Busy));
        // Nothing was recorded by the refusal.
        assert_eq!(dc.used_micros(now), 36_000_000);
        // 36 frames overflowed the 32-slot ring: frames 0..=3 were merged
        // into frame 4 (sent at 40 s), so at 3600 s nothing has expired yet
        // (conservative) ...
        assert_eq!(dc.used_micros(Micros::from_secs(3_600)), 36_000_000);
        // ... and at 3640 s frame 4 leaves the window with the 5 s it
        // carries, freeing exactly that much.
        let later = Micros::from_secs(3_640);
        assert_eq!(dc.used_micros(later), 31_000_000);
        assert_eq!(dc.try_send(later, Micros::from_secs(5)), Ok(()));
        assert_eq!(dc.try_send(later, Micros(1)), Err(Error::Busy));
    }

    #[test]
    fn duty_cycle_ring_overflow_is_conservative() {
        let mut dc = DutyCycle::new(Region::Eu868);
        // 40 frames of 100 ms, one per second: 8 more than the ring holds.
        for i in 0..40u64 {
            assert_eq!(
                dc.try_send(Micros::from_secs(i), Micros::from_millis(100)),
                Ok(())
            );
        }
        let now = Micros::from_secs(40);
        // Every frame is still counted after eviction.
        assert_eq!(dc.used_micros(now), 4_000_000);
        // Frames 0..=7 were merged, one by one, into frame 8 (sent at 8 s);
        // they expire with it at 3608 s, i.e. later than they should (frame
        // 0 alone would have left at 3600 s).
        assert_eq!(dc.used_micros(Micros::from_secs(3_600)), 4_000_000);
        assert_eq!(dc.used_micros(Micros::from_secs(3_607)), 4_000_000);
        assert_eq!(dc.used_micros(Micros::from_secs(3_608)), 3_100_000);
        assert_eq!(dc.used_micros(Micros::from_secs(3_609)), 3_000_000);
    }

    #[test]
    fn duty_cycle_expires_exactly_when_the_ring_does_not_overflow() {
        let mut dc = DutyCycle::new(Region::As923);
        for i in 0..DUTY_RING_LEN as u64 {
            assert_eq!(
                dc.try_send(Micros::from_secs(i), Micros::from_millis(500)),
                Ok(())
            );
        }
        let now = Micros::from_secs(3_599);
        assert_eq!(dc.used_micros(now), 16_000_000);
        // Frame 0 leaves at exactly 3600 s, frame 1 at 3601 s.
        assert_eq!(dc.used_micros(Micros::from_secs(3_600)), 15_500_000);
        assert_eq!(dc.used_micros(Micros::from_secs(3_601)), 15_000_000);
        // A send after expiry also prunes the ring.
        assert_eq!(
            dc.try_send(Micros::from_secs(3_601), Micros::from_millis(500)),
            Ok(())
        );
        assert_eq!(dc.used_micros(Micros::from_secs(3_601)), 15_500_000);
    }

    #[test]
    fn duty_cycle_dwell_and_no_limit_regions() {
        let mut us = DutyCycle::new(Region::Us915);
        assert_eq!(us.budget_micros(), None);
        assert_eq!(
            us.try_send(Micros::ZERO, Micros::from_millis(401)),
            Err(Error::Unsupported)
        );
        assert_eq!(us.try_send(Micros::ZERO, Micros::from_millis(400)), Ok(()));
        // No duty cycle: an hour of back-to-back 400 ms frames is allowed.
        for i in 1..9_000u64 {
            assert_eq!(
                us.try_send(Micros::from_millis(i * 400), Micros::from_millis(400)),
                Ok(())
            );
        }
        // ... and the occupancy is still reported honestly (ring merged).
        assert_eq!(us.used_permille(Micros::from_secs(3_599)), 1000);

        let mut india = DutyCycle::new(Region::In865);
        assert_eq!(india.try_send(Micros::ZERO, Micros::from_secs(5)), Ok(()));
        assert_eq!(india.used_permille(Micros::from_secs(1)), 1);
    }

    const KEY: [u8; 33] = [
        0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20,
    ];

    /// ver 1, kind 0x10, the key above, interval 300 s (0x012c), flags 0b11.
    const WIRE: [u8; 38] = [
        0x01, 0x10, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x01, 0x2c, 0x03,
    ];

    #[test]
    fn beacon_encodes_to_the_fixed_vector() {
        let beacon = Beacon::new(KEY, 300, 0b11);
        let mut out = [0u8; 64];
        assert_eq!(beacon.encode(&mut out), Ok(38));
        assert_eq!(&out[..38], &WIRE[..]);
        assert_eq!(
            beacon.encode(&mut out[..37]),
            Err(Error::BufferTooSmall { needed: 38 })
        );
    }

    #[test]
    fn beacon_decodes_the_fixed_vector() {
        let beacon = Beacon::new(KEY, 300, 0b11);
        assert_eq!(Beacon::decode(&WIRE), Ok(beacon));
        assert_eq!(beacon.ver, 1);
        assert_eq!(beacon.kind, 0x10);
        assert_eq!(beacon.pubkey, KEY);
        assert_eq!(beacon.interval_secs, 300);
        assert_eq!(beacon.flags, 0b11);
        assert!(beacon.is_adopted());
        assert!(beacon.accepts_handshake());
        // Trailing bytes are tolerated for forward compatibility.
        let mut longer = [0u8; 40];
        longer[..38].copy_from_slice(&WIRE);
        assert_eq!(Beacon::decode(&longer), Ok(beacon));
    }

    #[test]
    fn beacon_rejects_bad_input() {
        assert_eq!(Beacon::decode(&WIRE[..37]), Err(Error::InvalidFormat));
        assert_eq!(Beacon::decode(&[]), Err(Error::InvalidFormat));
        let mut bad_ver = WIRE;
        bad_ver[0] = 2;
        assert_eq!(Beacon::decode(&bad_ver), Err(Error::InvalidFormat));
        let mut bad_kind = WIRE;
        bad_kind[1] = 0x11;
        assert_eq!(Beacon::decode(&bad_kind), Err(Error::InvalidFormat));
        let mut bad_key = WIRE;
        bad_key[2] = 0x04; // uncompressed prefix cannot fit 33 bytes
        assert_eq!(Beacon::decode(&bad_key), Err(Error::InvalidFormat));
    }
}

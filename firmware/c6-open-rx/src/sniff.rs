//! One access point's beacons, followed on the air: where each lands
//! against its TBTT, the TBTTs it skipped, and whether its DTIM count keeps
//! one phase against the TSF (E3's power-save check, 2026-10-07). The
//! access point is named by its SSID at build time (`JANUS_SNIFF_SSID`):
//! ours, so the name may be printed; no address is.

use esp_println::println;

/// Lateness buckets' upper bounds, in microseconds.
const BUCKETS: [u32; 7] = [500, 1_000, 2_000, 5_000, 10_000, 50_000, u32::MAX];

#[derive(Default)]
pub struct Sniffer {
    beacons: u32,
    /// Microseconds from the TBTT to the beacon's timestamp, by bucket.
    late: [u32; BUCKETS.len()],
    late_max: u32,
    /// TBTTs with no beacon between two heard ones (an upper bound: a
    /// beacon lost on the air counts too).
    skipped: u32,
    /// Changes of `(tbtt + dtim_count) % period`: the DTIM moved against
    /// the TSF a station predicts it by.
    dtim_shifts: u32,
    /// Beacons whose TIM names a station (frames held for a dozer).
    tim_unicast: u32,
    last_tbtt: Option<u64>,
    /// This report window's earliest and latest phase (TSF modulo the
    /// interval), and the C6's own clock against the TSF over the window.
    window_min: u32,
    window_max: u32,
    window_first: Option<(u64, u32)>,
    window_last: Option<(u64, u32)>,
    dtim_phase: Option<u64>,
}

/// The beacon's elements, from the first after the fixed fields.
fn element(body: &[u8], id: u8) -> Option<&[u8]> {
    let mut at = 0;
    while at + 2 <= body.len() {
        let (eid, len) = (body[at], usize::from(body[at + 1]));
        let value = body.get(at + 2..at + 2 + len)?;
        if eid == id {
            return Some(value);
        }
        at += 2 + len;
    }
    None
}

impl Sniffer {
    /// A beacon's 802.11 frame (`frame` from its header on); ignored unless
    /// it is the named access point's.
    pub fn beacon(&mut self, frame: &[u8], ssid: &[u8], local_us: u32) {
        // header 24, then timestamp 8, interval 2, capabilities 2
        let Some(fixed) = frame.get(24..36) else {
            return;
        };
        let body = &frame[36..];
        if element(body, 0) != Some(ssid) {
            return;
        }
        let tsf = u64::from_le_bytes(fixed[..8].try_into().unwrap_or_default());
        let interval = u64::from(u16::from_le_bytes([fixed[8], fixed[9]])) * 1024;
        if interval == 0 {
            return;
        }
        self.beacons += 1;
        let tbtt = tsf / interval;
        let late = (tsf % interval) as u32;
        self.late_max = self.late_max.max(late);
        if self.window_first.is_none() {
            self.window_min = u32::MAX;
            self.window_max = 0;
            self.window_first = Some((tsf, local_us));
        }
        self.window_min = self.window_min.min(late);
        self.window_max = self.window_max.max(late);
        self.window_last = Some((tsf, local_us));
        if let Some(bucket) = BUCKETS.iter().position(|&b| late < b) {
            self.late[bucket] += 1;
        }
        if let Some(last) = self.last_tbtt {
            if tbtt > last + 1 {
                self.skipped += (tbtt - last - 1) as u32;
            }
        }
        self.last_tbtt = Some(tbtt);
        if let Some(tim) = element(body, 5) {
            if tim.len() >= 4 {
                let (count, period) = (u64::from(tim[0]), u64::from(tim[1]).max(1));
                let phase = (tbtt + count) % period;
                if self.dtim_phase.is_some_and(|p| p != phase) {
                    self.dtim_shifts += 1;
                }
                self.dtim_phase = Some(phase);
                // the partial virtual bitmap, bit 0 of its first octet aside
                // (AID 0, the group flag's place)
                let offset = usize::from(tim[2] & 0xfe);
                if tim[3..].iter().enumerate().any(|(i, &octet)| {
                    let octet = if i == 0 && offset == 0 {
                        octet & 0xfe
                    } else {
                        octet
                    };
                    octet != 0
                }) {
                    self.tim_unicast += 1;
                }
            }
        }
    }

    /// Every statistic packed: the gate that the arithmetic agrees.
    pub fn digest(&self) -> [u8; 52] {
        let mut d = [0u8; 52];
        let words = [
            self.beacons,
            self.late[0],
            self.late[1],
            self.late[2],
            self.late[3],
            self.late[4],
            self.late[5],
            self.late[6],
            self.late_max,
            self.skipped,
            self.dtim_shifts,
            self.tim_unicast,
            self.window_min,
        ];
        for (i, w) in words.iter().enumerate() {
            d[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        d
    }

    pub fn report(&mut self) {
        // over the window: TSF advanced against the C6's clock (ppm)
        let drift_ppm = match (self.window_first, self.window_last) {
            (Some((t0, l0)), Some((t1, l1))) if l1 != l0 => {
                let local = i64::from(l1.wrapping_sub(l0));
                ((t1 - t0) as i64 - local) * 1_000_000 / local.max(1)
            }
            _ => 0,
        };
        println!(
            "SNIFF window phase_min={} phase_max={} tsf_vs_local_ppm={drift_ppm}",
            self.window_min, self.window_max
        );
        self.window_first = None;
        self.window_last = None;
        println!(
            "SNIFF beacons={} late_us<500={} <1k={} <2k={} <5k={} <10k={} <50k={} more={} max={} skipped={} dtim_shifts={} tim_unicast={}",
            self.beacons,
            self.late[0],
            self.late[1],
            self.late[2],
            self.late[3],
            self.late[4],
            self.late[5],
            self.late[6],
            self.late_max,
            self.skipped,
            self.dtim_shifts,
            self.tim_unicast
        );
    }
}

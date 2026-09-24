//! The external oracle for `radar::csi`: two labelled ESP32-C6 captures
//! (`tests/fixtures/csi/SOURCE.md`) — an empty room and a person walking —
//! run through the detector exactly as a firmware would, frame by frame.
//!
//! The numbers this prints are the ones in `docs/LEDGER.md`. Run with
//! `--nocapture` to see them; set `JANUS_CSI_HELDOUT_DIR` to a directory
//! holding the dataset's `iter_2` files to check the thresholds transfer.

use std::path::{Path, PathBuf};

use rusty_esp_core::Micros;
use rusty_esp_signal_core::radar::csi::{Config, CsiFrame, Layout, PresenceDetector, Verdict};
use rusty_esp_signal_core::radar::phase::{PhaseConfig, PhaseDetector};
use rusty_esp_signal_core::radar::vitals::{Vitals, VitalsConfig, VitalsEstimator};

/// 50 frames at the dataset's 50 Hz: a one-second window.
const WINDOW: usize = 50;
const FRAME_MICROS: u64 = 20_000;

struct Row {
    rssi: i8,
    iq: [i8; 128],
}

fn parse(path: &Path) -> Vec<Row> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut rows = Vec::with_capacity(3000);
    for (n, line) in text.lines().enumerate() {
        let mut fields = line.split(',');
        assert_eq!(fields.next(), Some("CSI_DATA"), "row {n}");
        let rssi: i8 = fields
            .next()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or_else(|| panic!("row {n}: rssi"));
        let len: usize = fields
            .next()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or_else(|| panic!("row {n}: len"));
        assert_eq!(len, 128, "row {n}");
        let mut iq = [0i8; 128];
        for (k, slot) in iq.iter_mut().enumerate() {
            *slot = fields
                .next()
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or_else(|| panic!("row {n}: sample {k}"));
        }
        rows.push(Row { rssi, iq });
    }
    rows
}

#[derive(Debug)]
struct Stats {
    frames: usize,
    judged: usize,
    present: usize,
    /// Frame index of the last `Present` verdict, if any.
    last_present: Option<usize>,
    wander_p50: u16,
    wander_p95: u16,
    wander_max: u16,
    /// For the ledger's table; printed, not asserted.
    #[allow(dead_code)]
    rssi_mean: i32,
    /// `Present` per judged frame, in order, so two detectors' verdicts can
    /// be fused frame by frame after the fact.
    flags: Vec<bool>,
}

fn run(path: &Path, config: Config) -> Stats {
    let rows = parse(path);
    let mut det = PresenceDetector::<WINDOW>::new(config);
    let mut wanders = Vec::with_capacity(rows.len());
    let mut flags = Vec::with_capacity(rows.len());
    let mut present = 0usize;
    let mut last_present = None;
    let mut judged = 0usize;
    let mut rssi_sum = 0i32;
    for (n, row) in rows.iter().enumerate() {
        let now = Micros(n as u64 * FRAME_MICROS);
        let frame = CsiFrame {
            timestamp: now,
            rssi: row.rssi,
            channel: 6,
            iq: &row.iq,
        };
        let f = frame
            .features(&Layout::C6_HT20_NATURAL)
            .expect("layout fits the row");
        assert_eq!(f.count, 56);
        rssi_sum += i32::from(row.rssi);
        match det.push(&f, now) {
            Verdict::Warming => {}
            v => {
                judged += 1;
                wanders.push(det.wander());
                let p = matches!(v, Verdict::Present { .. });
                flags.push(p);
                if p {
                    present += 1;
                    last_present = Some(n);
                }
            }
        }
    }
    wanders.sort_unstable();
    let pct = |p: usize| wanders[(wanders.len() - 1) * p / 100];
    Stats {
        frames: rows.len(),
        judged,
        present,
        last_present,
        wander_p50: pct(50),
        wander_p95: pct(95),
        wander_max: *wanders.last().unwrap_or(&0),
        rssi_mean: rssi_sum / rows.len() as i32,
        flags,
    }
}

/// The default thresholds, or the `JANUS_CSI_ON` / `JANUS_CSI_OFF` /
/// `JANUS_CSI_HOLD_MS` overrides for calibration runs.
fn config() -> Config {
    let mut c = Config::default();
    let get = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok());
    if let Some(on) = get("JANUS_CSI_ON") {
        c.on_permille = on as u16;
    }
    if let Some(off) = get("JANUS_CSI_OFF") {
        c.off_permille = off as u16;
    }
    if let Some(ms) = get("JANUS_CSI_HOLD_MS") {
        c.hold = Micros::from_millis(ms);
    }
    c
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/csi")
        .join(name)
}

#[test]
fn empty_room_and_walking_person_separate_at_the_default_thresholds() {
    let config = config();
    let empty = run(&fixture("c6_empty_room_iter1.csv"), config);
    let walk = run(&fixture("c6_walking_person_iter1.csv"), config);
    println!("config {config:?} window {WINDOW} frames at {FRAME_MICROS} us");
    println!("empty room   : {empty:?}");
    println!("walking      : {walk:?}");
    assert_eq!(empty.frames, 3000);
    assert_eq!(walk.frames, 3000);
    assert_eq!(empty.judged, 3000 - WINDOW + 1);
    // The empty-room capture carries three two-second transients of 74–85 ‰
    // wander in its first 17 seconds (seconds 5–6, 8–9 and 15–16: something
    // moved; the dataset labels whole files). The detector flags them and
    // nothing else: after second 22 the room reads absent to the end. The
    // walking capture reads present for at least 80 % of its judged frames
    // (the gaps are the subject pausing at the ends of the walk).
    assert!(
        empty.present * 100 <= empty.judged * 20,
        "empty room present {}/{}: {empty:?}",
        empty.present,
        empty.judged
    );
    assert!(
        empty.last_present.is_some_and(|n| n < 22 * 50),
        "presence after the transients in the empty room: {empty:?}"
    );
    assert!(
        walk.present * 100 >= walk.judged * 80,
        "walking capture present {}/{}: {walk:?}",
        walk.present,
        walk.judged
    );
    // The medians sit on opposite sides of the hysteresis band and the
    // empty room's floor stays under `off` except in the transients.
    assert!(empty.wander_p50 < config.off_permille, "{empty:?}");
    assert!(walk.wander_p50 >= config.on_permille, "{walk:?}");
    assert!(empty.wander_max < walk.wander_max, "{empty:?} vs {walk:?}");
    assert!(empty.wander_p95 < walk.wander_p95, "{empty:?} vs {walk:?}");
}

/// The fixed-point wander the chip computes against the float replica in
/// `tools/csi_wander_oracle.py` (an independent implementation: `hypot`,
/// `sqrt`, no integer tricks), frame by frame over both fixtures.
#[test]
fn fixed_point_wander_tracks_the_float_oracle() {
    for name in ["c6_empty_room_iter1", "c6_walking_person_iter1"] {
        let golden = std::fs::read_to_string(fixture(&format!("{name}.wander.txt")))
            .expect("golden wander series; regenerate with tools/csi_wander_oracle.py");
        let floats: Vec<f64> = golden
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.trim().parse().expect("float"))
            .collect();
        let rows = parse(&fixture(&format!("{name}.csv")));
        let mut det = PresenceDetector::<WINDOW>::new(Config::default());
        let mut fixed = Vec::with_capacity(rows.len());
        for (n, row) in rows.iter().enumerate() {
            let now = Micros(n as u64 * FRAME_MICROS);
            let f = CsiFrame {
                timestamp: now,
                rssi: row.rssi,
                channel: 6,
                iq: &row.iq,
            }
            .features(&Layout::C6_HT20_NATURAL)
            .expect("layout");
            if det.push(&f, now) != Verdict::Warming {
                fixed.push(f64::from(det.wander()));
            }
        }
        assert_eq!(fixed.len(), floats.len(), "{name}: judged frames");
        let mut max_abs = 0.0f64;
        let mut sum = 0.0f64;
        let mut worst = 0usize;
        for (i, (x, o)) in fixed.iter().zip(&floats).enumerate() {
            let d = x - o;
            sum += d;
            if d.abs() > max_abs {
                max_abs = d.abs();
                worst = i;
            }
        }
        let mean = sum / floats.len() as f64;
        println!(
            "{name}: fixed vs float wander over {} frames: mean delta {mean:+.3} permille, max |delta| {max_abs:.3} at frame {worst} (fixed {} vs float {:.3})",
            floats.len(),
            fixed[worst],
            floats[worst]
        );
        // The chip rounds down at every step (integer sqrt, integer
        // division), so it reads at or just under the float value: measured
        // mean −0.85 / −0.77 ‰, max 1.65 ‰ on the two fixtures (ledger).
        assert!(mean <= 0.0 && mean > -1.5, "{name}: mean delta {mean}");
        assert!(max_abs < 2.0, "{name}: max |delta| {max_abs}");
    }
}

/// The phase twin, run over the same frames with the same window. Its
/// `wander_*` fields are in **ppm** (the phase detector's unit), clipped to
/// the u16 the amplitude stats use; on these captures nothing comes near.
fn run_phase(path: &Path, config: PhaseConfig) -> Stats {
    let rows = parse(path);
    let mut det = PhaseDetector::<WINDOW>::new(config);
    let mut wanders = Vec::with_capacity(rows.len());
    let mut flags = Vec::with_capacity(rows.len());
    let mut present = 0usize;
    let mut last_present = None;
    let mut judged = 0usize;
    let mut rssi_sum = 0i32;
    for (n, row) in rows.iter().enumerate() {
        let now = Micros(n as u64 * FRAME_MICROS);
        let p = CsiFrame {
            timestamp: now,
            rssi: row.rssi,
            channel: 6,
            iq: &row.iq,
        }
        .phases(&Layout::C6_HT20_NATURAL)
        .expect("layout fits the row");
        assert_eq!(p.count, 56);
        rssi_sum += i32::from(row.rssi);
        match det.push(&p, now) {
            Verdict::Warming => {}
            v => {
                judged += 1;
                wanders.push(det.wander().min(u32::from(u16::MAX)) as u16);
                let p = matches!(v, Verdict::Present { .. });
                flags.push(p);
                if p {
                    present += 1;
                    last_present = Some(n);
                }
            }
        }
    }
    wanders.sort_unstable();
    let pct = |p: usize| wanders[(wanders.len() - 1) * p / 100];
    Stats {
        frames: rows.len(),
        judged,
        present,
        last_present,
        wander_p50: pct(50),
        wander_p95: pct(95),
        wander_max: *wanders.last().unwrap_or(&0),
        rssi_mean: rssi_sum / rows.len() as i32,
        flags,
    }
}

/// W1's judgement: the phase-variance twin against the amplitude wander on
/// the same frames, the same window, the same rule for the thresholds
/// (`on` at 1.5 × the empty room's ceiling, `off` just above it).
///
/// What the data said, and what this pins:
///
/// - **Phase wins the empty room outright.** Zero present frames, where
///   the amplitude flags 514 -- the three "transients" in the first 17 s.
///   Phase does not see them. Consistent with those being receiver-gain
///   events, which move amplitude and not phase; stated as a hypothesis.
/// - **Amplitude wins the walk.** 86 % present against the phase's 39 %:
///   the phase's median barely clears its threshold while its 95th
///   percentile and maximum separate 3× and 5.5× -- it sees the crossings,
///   not the pauses.
///
/// So the two are complementary, and the fusion rows this prints (either /
/// both) are the input to W1b. The assertions below are the phase's OWN
/// bars, from these numbers, plus the complementarity itself.
#[test]
fn phase_variance_separates_the_two_captures_like_the_amplitude_wander() {
    let amp = config();
    let ph = PhaseConfig::default();
    let empty_a = run(&fixture("c6_empty_room_iter1.csv"), amp);
    let walk_a = run(&fixture("c6_walking_person_iter1.csv"), amp);
    let empty_p = run_phase(&fixture("c6_empty_room_iter1.csv"), ph);
    let walk_p = run_phase(&fixture("c6_walking_person_iter1.csv"), ph);
    println!("amplitude {amp:?}");
    println!("  empty room : {empty_a:?}");
    println!("  walking    : {walk_a:?}");
    println!("phase     {ph:?} (wander in ppm)");
    println!("  empty room : {empty_p:?}");
    println!("  walking    : {walk_p:?}");

    // The fusions, frame by frame over the same judged frames.
    let fuse = |a: &Stats, p: &Stats| -> (usize, usize) {
        let either = a
            .flags
            .iter()
            .zip(&p.flags)
            .filter(|(x, y)| **x || **y)
            .count();
        let both = a
            .flags
            .iter()
            .zip(&p.flags)
            .filter(|(x, y)| **x && **y)
            .count();
        (either, both)
    };
    let (e_or, e_and) = fuse(&empty_a, &empty_p);
    let (w_or, w_and) = fuse(&walk_a, &walk_p);
    println!(
        "FUSION either: empty {e_or}/{} walking {w_or}/{} | both: empty {e_and}/{} walking {w_and}/{}",
        empty_p.judged, walk_p.judged, empty_p.judged, walk_p.judged
    );

    assert_eq!(empty_p.judged, 3000 - WINDOW + 1);
    // The phase's own bars.
    assert_eq!(
        empty_p.present, 0,
        "phase: the empty room must read empty: {empty_p:?}"
    );
    assert!(
        walk_p.present * 100 >= walk_p.judged * 30,
        "phase: walking present {}/{} fell under the 30 % floor (measured 39 %): {walk_p:?}",
        walk_p.present,
        walk_p.judged
    );
    assert!(u32::from(empty_p.wander_max) < ph.on_ppm, "{empty_p:?}");
    assert!(u32::from(empty_p.wander_p50) < ph.off_ppm, "{empty_p:?}");
    assert!(
        walk_p.wander_p95 > 2 * empty_p.wander_p95,
        "{empty_p:?} vs {walk_p:?}"
    );
    assert!(
        walk_p.wander_max > 4 * empty_p.wander_max,
        "{empty_p:?} vs {walk_p:?}"
    );
    // The complementarity, as facts about these captures.
    assert!(
        empty_p.present < empty_a.present,
        "phase should be the quieter empty room"
    );
    assert!(
        walk_a.present > walk_p.present,
        "amplitude should be the stronger walk"
    );
    // And the fusion that keeps the best of each: "either" inherits the
    // walk from amplitude; "both" inherits the empty room from phase.
    assert!(w_or >= walk_a.present);
    assert_eq!(e_and, 0);
}

/// The fixed-point phase wander the chip computes against the float replica
/// in `tools/csi_phase_oracle.py`, frame by frame over both fixtures.
#[test]
fn fixed_point_phase_wander_tracks_the_float_oracle() {
    for name in ["c6_empty_room_iter1", "c6_walking_person_iter1"] {
        let golden = std::fs::read_to_string(fixture(&format!("{name}.phase.txt")))
            .expect("golden phase series; regenerate with tools/csi_phase_oracle.py");
        let floats: Vec<f64> = golden
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.trim().parse().expect("float"))
            .collect();
        let rows = parse(&fixture(&format!("{name}.csv")));
        let mut det = PhaseDetector::<WINDOW>::new(PhaseConfig::default());
        let mut fixed = Vec::with_capacity(rows.len());
        for (n, row) in rows.iter().enumerate() {
            let now = Micros(n as u64 * FRAME_MICROS);
            let p = CsiFrame {
                timestamp: now,
                rssi: row.rssi,
                channel: 6,
                iq: &row.iq,
            }
            .phases(&Layout::C6_HT20_NATURAL)
            .expect("layout");
            if det.push(&p, now) != Verdict::Warming {
                // The chip reports ppm; the float replica writes permille.
                fixed.push(f64::from(det.wander()) / 1000.0);
            }
        }
        assert_eq!(fixed.len(), floats.len(), "{name}: judged frames");
        let mut max_abs = 0.0f64;
        let mut sum = 0.0f64;
        let mut worst = 0usize;
        for (i, (x, o)) in fixed.iter().zip(&floats).enumerate() {
            let d = x - o;
            sum += d;
            if d.abs() > max_abs {
                max_abs = d.abs();
                worst = i;
            }
        }
        let mean = sum / floats.len() as f64;
        println!(
            "{name}: fixed vs float PHASE wander over {} frames: mean delta {mean:+.3} permille, max |delta| {max_abs:.3} at frame {worst} (fixed {} vs float {:.3})",
            floats.len(),
            fixed[worst],
            floats[worst]
        );
        // Measured after the rounding fix: mean −0.001 / −0.002 ‰, max
        // 0.013 / 0.015 ‰ on the two fixtures (ledger). Before it the chip
        // read a constant +0.061 ‰ above the float -- one unit of 2^14 --
        // from truncation landing on the same side at every step.
        assert!(mean.abs() < 0.01, "{name}: mean delta {mean}");
        assert!(max_abs < 0.05, "{name}: max |delta| {max_abs}");
    }
}

/// W1b's judgement, and the fact it settled.
///
/// The amplitude detector's three "transients" in the empty room were a
/// hypothesis: receiver-gain events, not motion. A common gain step
/// multiplies every subcarrier by the same factor, so dividing each frame
/// by its own mean cancels it exactly while a change of shape survives.
/// Through `Features::normalised`, at thresholds re-derived by the same
/// rule (the normalised empty room's ceiling is 21 ‰ → `on` 32, `off` 23):
///
/// | detector | empty present | walking present |
/// |---|---|---|
/// | raw amplitude, 42/32 | 514 | 2 540 (86 %) |
/// | normalised amplitude, 32/23 | **0** | 2 169 (74 %) |
/// | phase, 380/260 ppm | 0 | 1 139 (39 %) |
/// | normalised ⋁ phase | 0 | 2 186 |
///
/// The transients are not attenuated by normalisation; they are gone --
/// max 21 ‰ against a floor of 17 -- so they were gain. That is the fact.
/// The trade is twelve points of the walk for the whole of the empty room,
/// and this test pins it. `Verdict::either` with phase is free on the
/// empty room and adds 17 frames to the walk; it is a primitive, not
/// a claim.
#[test]
fn normalising_the_amplitude_removes_the_empty_rooms_transients() {
    use rusty_esp_signal_core::radar::csi::MAX_SUBCARRIERS;
    let cfg = Config::normalised_default();
    assert_eq!((cfg.on_permille, cfg.off_permille), (32, 23));
    let mut out = Vec::new();
    for name in ["c6_empty_room_iter1", "c6_walking_person_iter1"] {
        let rows = parse(&fixture(&format!("{name}.csv")));
        let mut d = PresenceDetector::<WINDOW>::new(cfg);
        let mut pd = PhaseDetector::<WINDOW>::new(PhaseConfig::default());
        let mut wanders = Vec::new();
        let (mut present, mut fused, mut last) = (0usize, 0usize, None);
        for (n, row) in rows.iter().enumerate() {
            let now = Micros(n as u64 * FRAME_MICROS);
            let frame = CsiFrame {
                timestamp: now,
                rssi: row.rssi,
                channel: 6,
                iq: &row.iq,
            };
            let f = frame
                .features(&Layout::C6_HT20_NATURAL)
                .unwrap()
                .normalised();
            assert_eq!(f.count, 56);
            assert!(
                f.amplitude[..56].iter().all(|&a| a < 4 * 1024),
                "a ratio to the mean"
            );
            let ph = frame.phases(&Layout::C6_HT20_NATURAL).unwrap();
            let va = d.push(&f, now);
            let vp = pd.push(&ph, now);
            if va != Verdict::Warming {
                wanders.push(d.wander());
                if matches!(va, Verdict::Present { .. }) {
                    present += 1;
                    last = Some(n);
                }
                if matches!(va.either(vp), Verdict::Present { .. }) {
                    fused += 1;
                }
            }
        }
        wanders.sort_unstable();
        let pct = |p: usize| wanders[(wanders.len() - 1) * p / 100];
        println!(
            "normalised {name}: present {present}/{} last {last:?} p50 {} p95 {} max {} | either-with-phase {fused}",
            wanders.len(),
            pct(50),
            pct(95),
            *wanders.last().unwrap()
        );
        out.push((
            name,
            present,
            fused,
            wanders.len(),
            pct(50),
            pct(95),
            *wanders.last().unwrap(),
        ));
    }
    let _ = MAX_SUBCARRIERS;
    let (_, e_present, e_fused, e_judged, e_p50, _, e_max) = out[0];
    let (_, w_present, w_fused, w_judged, w_p50, w_p95, w_max) = out[1];
    assert_eq!(e_judged, 3000 - WINDOW + 1);
    // The fact: the transients are gone, not attenuated.
    assert_eq!(
        e_present, 0,
        "the empty room must read empty once gain is cancelled"
    );
    assert!(
        e_max < cfg.on_permille,
        "empty ceiling {e_max} must sit under on {}",
        cfg.on_permille
    );
    assert!(e_p50 < cfg.off_permille);
    // The trade: the walk keeps at least 70 % (measured 73.5 %).
    assert!(
        w_present * 100 >= w_judged * 70,
        "normalised walk present {w_present}/{w_judged} under the 70 % floor"
    );
    assert!(
        w_p50 >= cfg.off_permille,
        "the walk's median {w_p50} should clear off"
    );
    assert!(
        w_p95 > 2 * e_p50 && w_max > 3 * e_max,
        "separation: {w_p95}/{e_p50}, {w_max}/{e_max}"
    );
    // The fusion is free on the empty room and never loses on the walk.
    assert_eq!(e_fused, 0);
    assert!(w_fused >= w_present);
}

/// The normalised fixed-point wander against the float replica's
/// gain-normalised series (`tools/csi_wander_oracle.py`, `.nwander.txt`),
/// so this path has the same independent twin as the raw one.
#[test]
fn fixed_point_normalised_wander_tracks_the_float_oracle() {
    for name in ["c6_empty_room_iter1", "c6_walking_person_iter1"] {
        let golden = std::fs::read_to_string(fixture(&format!("{name}.nwander.txt")))
            .expect("golden normalised wander series; regenerate with tools/csi_wander_oracle.py");
        let floats: Vec<f64> = golden
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.trim().parse().expect("float"))
            .collect();
        let rows = parse(&fixture(&format!("{name}.csv")));
        let mut det = PresenceDetector::<WINDOW>::new(Config::normalised_default());
        let mut fixed = Vec::with_capacity(rows.len());
        for (n, row) in rows.iter().enumerate() {
            let now = Micros(n as u64 * FRAME_MICROS);
            let f = CsiFrame {
                timestamp: now,
                rssi: row.rssi,
                channel: 6,
                iq: &row.iq,
            }
            .features(&Layout::C6_HT20_NATURAL)
            .expect("layout")
            .normalised();
            if det.push(&f, now) != Verdict::Warming {
                fixed.push(f64::from(det.wander()));
            }
        }
        assert_eq!(fixed.len(), floats.len(), "{name}: judged frames");
        let mut max_abs = 0.0f64;
        let mut sum = 0.0f64;
        let mut worst = 0usize;
        for (i, (x, o)) in fixed.iter().zip(&floats).enumerate() {
            let d = x - o;
            sum += d;
            if d.abs() > max_abs {
                max_abs = d.abs();
                worst = i;
            }
        }
        let mean = sum / floats.len() as f64;
        println!(
            "{name}: fixed vs float NORMALISED wander over {} frames: mean delta {mean:+.3} permille, max |delta| {max_abs:.3} at frame {worst} (fixed {} vs float {:.3})",
            floats.len(),
            fixed[worst],
            floats[worst]
        );
        // Same floor bias as the raw path (integer sqrt and division round
        // down), and the 1 024 scale adds a hair; bounds set from the print.
        assert!(mean <= 0.0 && mean > -1.5, "{name}: mean delta {mean}");
        assert!(max_abs < 2.5, "{name}: max |delta| {max_abs}");
    }
}

// ------------------------------------------------------------------ W2: vitals

/// Run the estimator over a capture on normalised features; every estimate
/// it makes, in order.
fn run_vitals(path: &Path, cfg: VitalsConfig) -> Vec<Vitals> {
    let rows = parse(path);
    let mut est = VitalsEstimator::<200>::new(cfg);
    let mut out = Vec::new();
    for (n, row) in rows.iter().enumerate() {
        let now = Micros(n as u64 * FRAME_MICROS);
        let f = CsiFrame {
            timestamp: now,
            rssi: row.rssi,
            channel: 6,
            iq: &row.iq,
        }
        .features(&Layout::C6_HT20_NATURAL)
        .expect("layout")
        .normalised();
        if let Some(v) = est.push(&f, now) {
            out.push(v);
        }
    }
    out
}

/// The float replica's estimates for a capture (`tools/csi_vitals_oracle.py`).
fn golden_vitals(name: &str, suffix: &str) -> Vec<(f64, f64)> {
    std::fs::read_to_string(fixture(&format!("{name}{suffix}")))
        .unwrap_or_else(|e| {
            panic!("{name}{suffix}: {e}; regenerate with tools/csi_vitals_oracle.py")
        })
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let mut it = l.split_whitespace();
            (
                it.next().unwrap().parse().unwrap(),
                it.next().unwrap().parse().unwrap(),
            )
        })
        .collect()
}

/// Fixed against float, estimate by estimate; the worst differences are
/// printed and bounded.
///
/// `bpm_tol` is `None` for a capture with no rhythm in it: a rate read off
/// noise is the first local maximum of a flat curve, and two implementations
/// landing on different lags there is not a disagreement about anything.
/// The confidence is what says "nothing here", and it is always compared.
fn compare_vitals(
    name: &str,
    fixed: &[Vitals],
    golden: &[(f64, f64)],
    bpm_tol: Option<f64>,
    conf_tol: f64,
) {
    assert_eq!(fixed.len(), golden.len(), "{name}: estimate count");
    let mut worst_bpm = 0.0f64;
    let mut worst_conf = 0.0f64;
    for (v, &(bpm, conf)) in fixed.iter().zip(golden) {
        let db = (f64::from(v.bpm_x10) / 10.0 - bpm).abs();
        let dc = (f64::from(v.confidence) / 1000.0 - conf).abs();
        worst_bpm = worst_bpm.max(db);
        worst_conf = worst_conf.max(dc);
    }
    println!(
        "{name}: fixed vs float VITALS over {} estimates: worst |Δbpm| {worst_bpm:.3}, worst |Δconfidence| {worst_conf:.4}",
        golden.len()
    );
    if let Some(tol) = bpm_tol {
        assert!(worst_bpm <= tol, "{name}: |Δbpm| {worst_bpm}");
    }
    assert!(worst_conf <= conf_tol, "{name}: |Δconfidence| {worst_conf}");
}

/// A synthetic capture breathing at exactly 15 per minute, with a
/// frequency-selective modulation of a few percent and unit noise on I/Q,
/// in the real fixtures' row format. The estimator must read the rate it
/// was given, and agree with the float replica.
#[test]
fn a_synthetic_breath_at_15_bpm_is_read_back() {
    let out = run_vitals(
        &fixture("synth_breathing_15bpm.csv"),
        VitalsConfig::breathing(50),
    );
    assert!(!out.is_empty());
    let last = out.last().unwrap();
    println!("synth 15 bpm: {} estimates, last {last:?}", out.len());
    assert!(
        (f64::from(last.bpm_x10) / 10.0 - 15.0).abs() <= 0.5,
        "read {} x0.1 bpm for a 15.0 bpm breath",
        last.bpm_x10
    );
    assert!(last.accepted, "{last:?}");
    // And every estimate after the first agrees with the rate.
    for v in &out {
        assert!((f64::from(v.bpm_x10) / 10.0 - 15.0).abs() <= 1.0, "{v:?}");
    }
    // Measured: worst |Δbpm| 0.048, worst |Δconfidence| 0.0018.
    compare_vitals(
        "synth_breathing_15bpm",
        &out,
        &golden_vitals("synth_breathing_15bpm", ".breath.txt"),
        Some(0.2),
        0.02,
    );
}

/// Two rhythms at once: breathing at 12 and a heartbeat at 72, the latter
/// five times weaker -- 0.6 % of an amplitude near 30, which is a fifth of
/// one LSB of the unit noise on I/Q. The breathing band reads the first to
/// a tenth. The heart band, after its high-pass, reads the second to within
/// about ten percent at a confidence under a tenth, and **flags it** -- and
/// the float replica says the same. That is the honest ceiling of one
/// amplitude link at this noise, and it is what "a band to try, not a
/// number to trust" means. A clean heartbeat alone is read to a tenth
/// (`heart_at_72_bpm_is_read_from_the_heart_band_on_a_clean_signal`).
#[test]
fn a_synthetic_breath_and_heartbeat_are_read_from_their_own_bands() {
    let breath = run_vitals(
        &fixture("synth_vitals_12_72bpm.csv"),
        VitalsConfig::breathing(50),
    );
    let heart = run_vitals(
        &fixture("synth_vitals_12_72bpm.csv"),
        VitalsConfig::heart(50),
    );
    let (b, h) = (breath.last().unwrap(), heart.last().unwrap());
    println!("synth 12/72: breathing band {b:?}");
    println!("synth 12/72: heart band     {h:?}");
    assert!((f64::from(b.bpm_x10) / 10.0 - 12.0).abs() <= 0.5, "{b:?}");
    assert!(b.accepted, "{b:?}");
    // Within ten percent, and NOT accepted: the flag is the claim.
    assert!((f64::from(h.bpm_x10) / 10.0 - 72.0).abs() <= 8.0, "{h:?}");
    assert!(
        !h.accepted,
        "a heart rate at this SNR must be flagged: {h:?}"
    );
    // Measured: breath 0.056 / 0.0020; heart 0.616 / 0.0013 -- the heart's
    // parabola sits on a low, flat peak where one lag of rounding is a BPM.
    compare_vitals(
        "synth_vitals_12_72bpm/breath",
        &breath,
        &golden_vitals("synth_vitals_12_72bpm", ".breath.txt"),
        Some(0.2),
        0.02,
    );
    compare_vitals(
        "synth_vitals_12_72bpm/heart",
        &heart,
        &golden_vitals("synth_vitals_12_72bpm", ".heart.txt"),
        Some(1.5),
        0.02,
    );
}

/// The one property the real captures can hold the estimator to without a
/// label: **an empty room must not grow a breathing rate.** Every estimate
/// over the Cuenca empty room stays below the accept floor. The walk is
/// printed, not asserted -- a walking person's rhythm is their gait, and
/// what the breathing band makes of it is a number to look at, not a claim.
#[test]
fn an_empty_room_grows_no_breathing_rate() {
    let cfg = VitalsConfig::breathing(50);
    let empty = run_vitals(&fixture("c6_empty_room_iter1.csv"), cfg);
    let walk = run_vitals(&fixture("c6_walking_person_iter1.csv"), cfg);
    let max_conf = |v: &[Vitals]| v.iter().map(|e| e.confidence).max().unwrap_or(0);
    println!(
        "empty room: {} estimates, max confidence {} ‰, accepted {}",
        empty.len(),
        max_conf(&empty),
        empty.iter().filter(|e| e.accepted).count()
    );
    println!(
        "walking   : {} estimates, max confidence {} ‰, accepted {}, rates seen {:?}",
        walk.len(),
        max_conf(&walk),
        walk.iter().filter(|e| e.accepted).count(),
        walk.iter().map(|e| e.bpm_x10).collect::<Vec<_>>()
    );
    assert!(!empty.is_empty());
    // The walk is a person moving: its first peak is the gait, faster than
    // any breath, so every estimate is flagged even where it is confident.
    assert_eq!(
        walk.iter().filter(|e| e.accepted).count(),
        0,
        "a walker accepted as breathing"
    );
    assert_eq!(
        empty.iter().filter(|e| e.accepted).count(),
        0,
        "the empty room grew a breathing rate: max confidence {} ‰ against an accept floor of {} ‰",
        max_conf(&empty),
        cfg.accept_permille
    );
    // No rhythm, so no rate to compare; confidence measured at 0.0090.
    compare_vitals(
        "c6_empty_room_iter1",
        &empty,
        &golden_vitals("c6_empty_room_iter1", ".breath.txt"),
        None,
        0.03,
    );
}

#[test]
fn held_out_captures_transfer() {
    let Some(dir) = std::env::var_os("JANUS_CSI_HELDOUT_DIR") else {
        eprintln!("JANUS_CSI_HELDOUT_DIR unset: skipping the held-out check");
        return;
    };
    let dir = PathBuf::from(dir);
    let config = config();
    for entry in std::fs::read_dir(&dir).expect("held-out dir") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if !name.ends_with(".csv") || !name.contains("iter_2") {
            continue;
        }
        let stats = run(&path, config);
        println!("held-out {name}: {stats:?}");
        if name.starts_with("empty") {
            assert_eq!(stats.present, 0, "{name}: {stats:?}");
        } else if name.starts_with("motion") {
            // The second walk is weaker (mean RSSI −44 dBm against −45 and
            // the subject spends longer at the ends): 55 % is the floor it
            // clears at the default thresholds, without retuning to it.
            assert!(
                stats.present * 100 >= stats.judged * 55,
                "{name}: {stats:?}"
            );
        }
    }
}

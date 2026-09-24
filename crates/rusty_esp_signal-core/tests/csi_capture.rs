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

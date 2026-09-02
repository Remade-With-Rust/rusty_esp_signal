# rusty_esp_signal — ledger

Every number a README or plan claims lives here first, with how it was taken.
Discipline: external oracle before self-metric; nothing on a radio is claimed
until a radio ran it.

## S0 — the core on the host (2026-09-02)

Machine: Windows 11, Rust 1.98.0 stable. `rusty_esp_signal-core` only; no
chip, no radio.

### CSI presence against a labelled capture

The external oracle is the Universidad de Cuenca ESP32-C6 Wi-Fi sensing
dataset (HeliosSm; CC BY 4.0 via Zenodo 10.5281/zenodo.21148028; provenance
and citation in `crates/rusty_esp_signal-core/tests/fixtures/csi/SOURCE.md`):
two ESP32-C6, the transmitter injecting frames at 50 Hz, the receiver
capturing CSI in promiscuous mode, 2.4 GHz channel 6, 20 MHz, 3000 frames
(60 s) per file, labels per **file**: "empty static room" and "one person
walking across the line of sight". Two files are in the repository as
fixtures (`iter_1` of each label); the dataset's `iter_2` files are the
held-out pair, run through the same test with `JANUS_CSI_HELDOUT_DIR` and
never used to choose a threshold.

Method: `tests/csi_capture.rs` feeds every row through
`CsiFrame::features(&Layout::C6_HT20_NATURAL)` (56 live subcarriers) and
`PresenceDetector::<50>` (a one-second window at 50 Hz), frame timestamps
20 ms apart, the default `Config` (`on` 42 ‰, `off` 32 ‰, hold 3 s). The
wander is the fixed-point coefficient of variation the chip computes
(amplitude with two fractional bits, standard deviation with four); a float
replica in Python agreed with it to within a permille on every file. The
first 49 frames are `Warming` and not judged.

| capture | label | judged frames | `Present` frames | wander p50 / p95 / max (‰) | mean RSSI |
|---|---|---|---|---|---|
| `c6_empty_room_iter1` (fixture) | empty | 2 951 | **514** (17.4 %), last at frame 1 028 (20.6 s) | 25 / 73 / 85 | −39 dBm |
| `c6_walking_person_iter1` (fixture) | walking | 2 951 | **2 540** (86.1 %) | 44 / 76 / 120 | −45 dBm |
| `linea_base_iter_2` (held out) | empty | 2 951 | **0** | 23 / 26 / 27 | −39 dBm |
| `movimiento_humano_iter_2` (held out) | walking | 2 951 | **1 793** (60.8 %) | 32 / 59 / 95 | −44 dBm |

How the thresholds were chosen: the held-in empty capture's floor is 24–30 ‰
in every second except three two-second transients (seconds 5–6, 8–9 and
15–16) at 74–85 ‰, and the held-out empty capture never exceeds 27 ‰ over
its whole minute; the walking captures read 45–120 ‰ while the subject
crosses and 25–37 ‰ while it pauses at the ends. `on` is 1.5 × the 28 ‰
ceiling; `off` sits just above it. The transients are real channel changes
(something moved; the dataset labels whole files), the detector flags them
and nothing else: **after second 22 the empty room reads absent to the
end**. The walking files' "present" fractions are a lower bound on accuracy
because their quiet gaps (the subject pausing) are correctly absent under a
per-file label. Per-frame hand labels — the J4 kill test's "stated
accuracy" — need a recording of our own and are not claimed here.

The fixed-point wander against an independent float implementation
(`tools/csi_wander_oracle.py`: `hypot`, `sqrt`, no integer tricks), frame
by frame over the two fixtures (`fixed_point_wander_tracks_the_float_oracle`):

| fixture | frames | mean (fixed − float) | max \|fixed − float\| |
|---|---|---|---|
| `c6_empty_room_iter1` | 2 951 | −0.845 ‰ | 1.645 ‰ (frame 8: 25 vs 26.645) |
| `c6_walking_person_iter1` | 2 951 | −0.768 ‰ | 1.550 ‰ (frame 2 749: 32 vs 33.550) |

The chip rounds down at every step (integer square root, integer division)
and reads under the float value by under a permille on average; the test
holds the mean inside (−1.5, 0] and the maximum under 2 ‰.

Two things worth recording. Whole-number amplitudes were too coarse: at the
dataset's amplitudes (20–40) integer rounding alone put a ~11 ‰ floor on the
wander, a third of the empty room's real signal; two fractional bits on the
amplitude and four on the standard deviation removed it (unit tests and the
table above are with them). And at thresholds `on` 60 / `off` 30 (the first
guess) the walking file read present only 32 % of the time; the data, not
the guess, set the working point.

### Wire and state-machine gates

| gate | result |
|---|---|
| `link`: three-message handshake (Noise-KK shape over P-256, HKDF-SHA256, HMAC-SHA256/16) | both sides derive the same id and keys; frames flow both ways |
| `link`: a replayed frame; a frame with one payload bit flipped; a frame with one tag bit flipped; the sender's own frame reflected; a frame for another session | all refused, each counted in its own counter; a bad tag never moves the replay window |
| `link`: reordering inside the 64-frame window; a frame older than the window; sequence-space exhaustion; expiry | accepted / refused / `Denied` / `expired` as specified |
| `link`: a stranger's DID (policy says no) on either side; a tampered `Accept`; a forged `Confirm`; an impostor without the device key | `Denied`, `Crypto`, `Crypto`, `Crypto` |
| `link` wire sizes | `Hello` 84 B, `Accept` 100 B, `Confirm` 18 B, envelope overhead 23 B → 227 B of payload in a 250 B ESP-NOW datagram |
| `link` golden vectors from an independent implementation (`tools/link_golden.py`: Python `hmac` + `hashlib`) | envelope tag for a fixed key/header/payload and the HKDF key schedule split (`k_i2r`, `k_r2i`, `k_confirm`, id) match byte for byte, through `Session::seal` |
| `radar::csi` unit tests (isqrt over 70 000 values, layouts, features, hysteresis timing to the frame, layout-change reset) | pass |
| unit tests, `rusty_esp_signal-core` | **78** pass (ble 7 · link 17 · lora 16 · csi 5 · ld2410 22 · wifi 11) + **3** capture-oracle tests |
| `cargo deny check` (advisories, bans, licenses, sources) | clean — every git sibling pinned by version |
| clippy `--all-targets -D warnings`, `cargo fmt --check` | clean |
| `riscv32imac-unknown-none-elf` core-only and `alloc` | check green |

## Not yet measured

- **Anything on a radio.** S1's C6 ↔ C6 ESP-NOW link (1000 frames each way
  with loss, replay-rejected and bad-tag counters), S2's presence in a room
  against our own hand-labelled recording, S3's BLE provisioning from a
  phone, S4's LoRa range/RSSI/PER table, S5's LD2410 against the module's
  own serial tool, S6's 24-hour reconnect soak.
- The LD2410 parser is verified against the protocol document's example
  frames, not against a module.
- LoRa time-on-air is verified against Semtech's published calculator
  values, not against a modem.

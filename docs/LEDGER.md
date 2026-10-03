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

## S1 groundwork - the Track B backends and their firmware (2026-09-02)

The radios are now **ingested**, not just interpreted: `rusty_esp_signal-esp`
carries a backend per signal type and three ESP32-C6 firmware projects compile
them. Machine: Windows 11, **stable** Rust 1.98.0 with the
`riscv32imac-unknown-none-elf` target - Track B on a RISC-V part needs no
espup, unlike the Xtensa firmware in the other Janus repos.

Pins (exact, `=`): esp-hal 1.1.2, esp-radio 1.0.0-beta.0, esp-rtos 0.3.0,
esp-alloc 0.10.0, esp-bootloader-esp-idf 0.5.0, esp-println 0.17.0,
esp-backtrace 0.19.0, embassy-executor 0.10, embassy-time 0.5,
trouble-host 0.6.0, bt-hci 0.8, lora-phy 3.0.1, embedded-hal-bus 0.3.

| firmware | radios compiled in | release ELF | warnings |
|---|---|---|---|
| `c6-mesh-node` | ESP-NOW authenticated link, Wi-Fi CSI, LD2410 UART, Wi-Fi station policy | **1 744 812 B** | 0 |
| `c6-lora-p2p` | LoRa P2P (SX1262 over SPI) | **339 592 B** | 0 |
| `c6-ble-provision` | BLE GATT server (provisioning, manifest, telemetry) | **932 836 B** | 0 |

All three link (`cargo build --release`, `opt-level = "s"`, fat LTO,
`codegen-units = 1`, `panic = "abort"`). The host workspace is unchanged: 78
unit + 3 oracle tests, clippy clean, because the backends are behind features
the host build does not enable.

Four things this cost, worth writing down:

- **The chip feature belongs to the firmware, never the library.** esp-hal
  refuses to build without exactly one, so `rusty_esp_signal-esp` names none
  and is compiled only as part of a firmware, which supplies it through
  cargo's feature unification.
- **The backend features are decomposed by what they actually use.**
  `esp-radio` (CSI, ESP-NOW, station) is separate from `esp-hal` (TRNG,
  LD2410), and `lora` / `ble` touch no esp crate at all - they are generic
  over the modem and the HCI controller. A LoRa-only firmware that pulled
  esp-radio failed to build for want of a chip feature; that is why.
- **lora-phy 3.0.1 logs through defmt unconditionally** and its defmt
  dependency is not optional, so a firmware linking it must provide a
  `#[defmt::global_logger]` (esp-println's `defmt-espflash`, referenced with
  `use esp_println as _;` or it is garbage-collected) **and** a
  `defmt::timestamp!`. Two undefined symbols at link, in that order.
- **`trouble-host`'s GATT macros** expand to references to `embassy-sync` and
  `static_cell`, which the invoking crate must depend on by name; arrays over
  32 bytes have no `Default` impl, so those characteristics need an explicit
  `value = [0u8; N]`; and the generated items are undocumented, so the macro
  block sits in a module with `#[allow(missing_docs)]`.

## Not yet measured

- **Anything on a radio.** The three firmwares above build but **none has
  been flashed**: S1's C6 ↔ C6 ESP-NOW link (1000 frames each way with loss,
  replay-rejected and bad-tag counters), S2's presence in a room against our
  own hand-labelled recording, S3's BLE provisioning from a phone, S4's LoRa
  range/RSSI/PER table, S5's LD2410 against the module's own serial tool,
  S6's 24-hour reconnect soak.
- **Anything about the backends' behaviour.** A compile proves the types
  agree with esp-radio, `lora-phy` and `trouble-host`; it says nothing about
  whether a handshake completes over a real ESP-NOW datagram, whether the
  CSI callback keeps up, or whether a phone can write the credential TLV.
- The LD2410 parser is verified against the protocol document's example
  frames, not against a module.
- LoRa time-on-air is verified against Semtech's published calculator
  values, not against a modem.

## S3 host half: the provisioning session and page (host, 2026-09-02)

| Gate | Result |
|---|---|
| A `credentials` write → `Action::Connect`, status `Connecting` notified; `Connected` event → notified once, a repeat is silent; `Debug` of the session never contains the passphrase | **pass** |
| A malformed write changes nothing (`InvalidFormat`); writes to `status`, `scan` and any other table characteristic are `Denied`; an unknown UUID is `Unsupported`; `credentials` never reads back (`Denied`); a zero-length status read reports the byte it needs | pass |
| Restore from storage joins; new credentials while joined re-join; `forget` wipes, resets the policy and opens provisioning | pass |
| `ScanList`: insert by strength with eviction of the weakest, TLV round trip, whole entries only into a short buffer; eight 32-byte names → six fit the 240-byte characteristic | pass |
| `docs/provision.html` names the same seven UUIDs, four TLV tags and five phase names as the crate, and never logs the secret (`include_str!` test) | pass |

Core: **83 unit + 3 capture-oracle tests** (6 new), clippy `-D warnings`, `riscv32imac` no_std check, `cargo deny`. The `-esp` crate with `ble` checks and lints clean on the host (the trouble-host feature list now names `derive` and `default-packet-pool` itself instead of inheriting them from the firmware). `c6-ble-provision` with the session wired in: **builds, 936 896 B ELF**, 37 s cold. The page has not been driven against a board: that is S3's board half.

## The no-panic gate (host, 2026-09-02)

Every parser that takes bytes from a wire, a store or a bus must return an
error on bad input, never panic — the house rule made a test:
`tests/no_panic.rs` feeds each one random inputs from an LCG (the same corpus
on every machine) and mutations of a valid encoding (bit flips, overwrites,
truncation, extension, insertion, removal), under `catch_unwind` so a failure
names the parser and prints the input.

| covered | result |
|---|---|
| `Credentials::decode`, `ScanEntry::decode`, `ScanList::decode` (20 000), `link::Envelope::parse` and `lora::Beacon::decode` (30 000), the LD2410 `Frame` / `Report` / `Ack` parsers and the streaming `Parser` (20 000 mutated report frames) | no finding |

## BLE provisioning on Track A: Bluedroid speaks the same GATT (host, 2026-09-04)

`rusty_esp_signal-esp` gains `idf::ble::BleProvisioning` behind the
`esp-idf` feature: the core's provisioning service over esp-idf-svc 0.52's
`EspGatts` / `EspBleGap` — `credentials` WRITE answered by the app (the
passphrase never rests in Bluedroid's attribute store), `status` READ | NOTIFY
and `scan` READ answered by the stack from values the module sets, the core's
`Provisioner` deciding everything, and the station policy's actions handed to
the firmware over a channel. The S3 firmware
`firmware/xiao-s3-sense-idf-ble-provision` joins Wi-Fi with the provisioned
credentials and notifies the phase back. It exists so a Wi-Fi + camera device
on ESP-IDF can be provisioned from a phone without a second track.

| gate | result |
|---|---|
| `cargo build --release` in `firmware/xiao-s3-sense-idf-ble-provision` (`xtensa-esp32s3-espidf`, the esp toolchain, IDF v5.5.1 with `CONFIG_BT_ENABLED` + Bluedroid BLE-only, `CARGO_TARGET_DIR=C:/janus-g`) | **builds on the first try: ELF 1,829,716 B; app image 1,240,928 B, 39.4 % of the XIAO's `factory`** (`espino save-image --app-only`); 6 min 33 s cold, the IDF configure included |
| `unsafe` in `idf/ble.rs` | none — the FFI boundary is esp-idf-svc's |
| host gates (`cargo test --workspace`, clippy `-D warnings`, fmt, deny) | **89 tests, 0 failed**; clippy, fmt and deny clean — the `esp-idf` feature compiles only inside an IDF firmware, so the host never sees the module |

~~Not run: a radio.~~ **Run on 2026-09-05, on a plain ESP32.** The same
backend, inside espino's generated C6 firmware, provisioned an AI-Thinker
ESP32-CAM from Chrome over Web Bluetooth (this page, served by
`espino serve` at `/provision`): the device joined 7.5 s after the write and
notified the phase back, and the next boot joined alone. Two defects in this
crate came out of it and are fixed here — the name moved to the scan
response because a 128-bit service UUID and a name do not both fit in a
31-byte advertisement, and the GATT attributes are added one at a time so
`status`'s CCCD lands behind `status` rather than behind `scan`. Rows in
espino's ledger. The S3 kill test still waits for the XIAO.

---

## W1 of the RuView plan: the phase half of CSI — 2026-09-23

`espino/docs/plans/ruview-function.md` W1. The amplitude detector kept the
magnitude of each CSI entry and threw the angle away; `radar::phase` keeps
it, on the same raw buffer, in fixed point. Additive — this crate is
published and `Features` is not `#[non_exhaustive]`, so nothing existing
changed shape.

### What it is

- **Binary radians.** Every angle is an `i16` with 65 536 to the turn, so
  `wrapping_sub` between neighbouring subcarriers IS the shortest arc — the
  unwrap step of phase sanitisation, for free, no `2π` anywhere.
- `atan2_brad`: one octant from a 257-entry table, the rest by symmetry.
  Worst error over every (x, y) an `i8` pair can hold: **40.4 brads,
  0.222°** (`atan2_brad_is_within_a_table_step_of_float_everywhere`).
- `CsiFrame::phases`: raw angles, unwrapped across the subcarriers, then
  the least-squares line through them removed — the per-frame carrier
  offset and sampling-time slope, the two artefacts that have nothing to
  do with the room. Q16 in `i64`, once per frame.
- `PhaseDetector<W>`: the amplitude detector's shape — a ring, sums
  carried by the one frame that changes, the same hysteresis — with
  **circular variance** as the statistic (`1 − |mean unit vector|`, a
  257-entry quarter-wave sine at 2^14), because the residual is still an
  angle. Reported in **ppm**.

### Two things the fixed point taught

- **The zeroed ring is `W` copies of angle 0, whose unit vector is
  `(UNIT, 0)`.** Sums started at zero subtracted a phantom on every push
  into a never-filled slot, and the same frame pushed `W` times read
  883 ‰ of variance instead of none. The amplitude detector has no such
  trap — an amplitude of 0 contributes 0 — which is exactly why this one
  had it. The sums start at `(W · UNIT, 0)`.
- **Every floor landed on the same side.** Truncating the mean vector's
  components and its square root read a constant **+0.061 ‰** above the
  float replica on both captures — exactly one unit of 2^14, no scatter.
  Rounded division and a double-resolution `isqrt` removed it.

Against the float replica (`tools/csi_phase_oracle.py`: `atan2`, unwrap,
least squares, `cmath` unit vectors — none of the integer tricks), frame by
frame (`fixed_point_phase_wander_tracks_the_float_oracle`):

| fixture | frames | mean (fixed − float) | max \|fixed − float\| |
|---|---|---|---|
| `c6_empty_room_iter1` | 2 951 | −0.001 ‰ | 0.013 ‰ |
| `c6_walking_person_iter1` | 2 951 | −0.002 ‰ | 0.015 ‰ |

The pipeline's own noise floor: a perfectly still channel reads up to ~60
ppm from the table's unit vectors being unit length to ±1 in 16 384. A
fifth of an empty room's real reading.

### The judgement — both detectors, same frames, same window, same rule

Thresholds by the amplitude's rule: `on` at 1.5 × the empty room's
ceiling (254 → **380 ppm**), `off` just above it (**260 ppm**), hold 3 s.

| detector | capture | present | p50 | p95 | max |
|---|---|---|---|---|---|
| amplitude (‰) | empty | **514** / 2 951 (17.4 %) | 25 | 73 | 85 |
| amplitude (‰) | walking | **2 540** / 2 951 (86.1 %) | 44 | 76 | 120 |
| phase (ppm) | empty | **0** / 2 951 | 184 | 208 | 254 |
| phase (ppm) | walking | **1 139** / 2 951 (38.6 %) | 250 | 660 | 1 401 |

**Phase wins the empty room outright, amplitude wins the walk.** Phase does
not see the three amplitude "transients" in the empty room's first 17 s at
all — consistent with those being receiver-gain events, which move
amplitude and not phase; a hypothesis, stated as one. On the walk the
phase's median barely clears its threshold while its 95th percentile and
maximum separate **3.2× and 5.5×** (amplitude: 1.04× and 1.4×) — it sees
the crossings, not the pauses.

Fused frame by frame over the same judged frames:

| fusion | empty present | walking present |
|---|---|---|
| either | 514 / 2 951 | 2565 / 2 951 |
| both | 0 / 2 951 | 1114 / 2 951 |

"Either" keeps amplitude's walk; "both" keeps phase's empty room. Neither
is free. That trade is **W1b** in the plan, and it is not made here.

### What is not claimed

The held-out Cuenca pair is not on this machine
(`JANUS_CSI_HELDOUT_DIR` unset); the harness runs it the day it is. No
accuracy is stated: the labels are per file, and a per-frame labelled
recording of our own is W0's hardware step.

Gates: 7 new unit tests in `radar::phase`, 2 new capture-oracle tests,
clippy `--all-targets -D warnings`, `cargo fmt --check`, and the
`riscv32imac-unknown-none-elf` core-only check — all green.

### W1b — the transients were gain, and normalising removes them (2026-09-23)

The fusion trade above was never made, because the data settled the
question underneath it. The hypothesis — that the empty room's three
"transients" were receiver-gain events — is testable without a new
capture: a common gain step multiplies every subcarrier by the same factor,
so dividing each frame's amplitudes by that frame's mean cancels it
exactly, while a change of shape (a body) survives. Run:

| detector | thresholds | empty present | empty max | walking present |
|---|---|---|---|---|
| raw amplitude | 42 / 32 ‰ | 514 | 85 ‰ | 2 540 (86.1 %) |
| **normalised amplitude** | 32 / 23 ‰ (by the rule: ceiling 21 × 1.5) | **0** | **21 ‰** | 2 169 (73.5 %) |
| phase | 380 / 260 ppm | 0 | 254 ppm | 1 139 (38.6 %) |
| normalised ⋁ phase (`Verdict::either`) | — | 0 | — | 2 186 (74.1 %) |
| corroborated rise (amplitude only with phase ≥ 254) | — | 150 | — | 2 297 |

**The transients are not attenuated by normalisation; they are gone** —
a ceiling of 21 ‰ against a floor of 17, with no event in the first
17 s at all. They were gain. That is a fact now, not a hypothesis, and it
says something about the raw amplitude detector: a third of what it called
presence in an empty room was the receiver adjusting itself.

The trade is twelve points of the walk for the whole of the empty room, and
it is made: `Features::normalised` and `Config::normalised_default` (32 /
23 ‰, re-derived by the same rule on the same captures) are what this
module now recommends. The raw defaults are unchanged for anyone who
constructed them. The normalised path has its own float twin
(`.nwander.txt`), like every other.

`Verdict::either` fuses a normalised-amplitude verdict with a phase
verdict: free on the empty room (both read zero), 17 frames on this
walk. A primitive, not a claim; the phase's 5.5× tail separation may matter
on a capture this one is not.

The corroborated-rise candidate only trades (150 empty frames for 2 297 of
walk at its best setting) and is recorded here so nobody rebuilds it.

---

## W2 of the RuView plan: breathing, and a heart band to try — 2026-09-23

`radar::vitals`: the slow rhythm in the channel, in fixed point, on
normalised features. Decimate (50 → 10 Hz), a 20 s window, the
autocorrelation per subcarrier over the band's lags (`dot_i16` and
`sum_sq_i16` from the DSP crate — the S3's vectorised kernels, plain loops
on the C6), normalised and overlap-corrected, summed across subcarriers,
the first significant peak from lag 2 up, a parabola, a rate and a
confidence. 25.6 KiB of ring at `N = 200`.

### The oracle, and what it is not

The Cuenca dataset has no vitals labels and there is no recording of our
own. So the estimator is held to three things, and **no accuracy against a
person is claimed**:

1. it must read back the rate it was given from a synthetic capture in the
   real fixtures' row format — a static multipath shape per subcarrier,
   each subcarrier modulated with its own depth and sign (a changing path
   is frequency-selective, which is also why breathing survives gain
   normalisation), unit Gaussian noise on I/Q, a slow drift;
2. the chip's integer pipeline must agree with an independent float replica
   (`tools/csi_vitals_oracle.py`) estimate by estimate;
3. on the real captures, **an empty room must not grow a breathing rate**.

| capture | band | reads | float replica | Δ fixed−float (bpm / conf) | accepted |
|---|---|---|---|---|---|
| synthetic, 15.0 per min | breathing | **15.0**, 633 ‰ | 15.05, 0.634 | 0.048 / 0.0018 | yes |
| synthetic, 12.0 + 72 | breathing | **11.9**, 639 ‰ | 11.91, 0.641 | 0.056 / 0.0020 | yes |
| synthetic, 12.0 + 72 | heart | 78.4, **74 ‰** | 78.37, 0.073 | 0.616 / 0.0013 | **no** — flagged |
| Cuenca empty room | breathing | —, max **47 ‰** | max 0.03 | — / 0.0090 | 0 of 41 |
| Cuenca walking | breathing | 300 per min (lag 2), 805 ‰ | 300, 0.70 | — | 0 of 41 |

### Three rules the synthetic captures forced, in both implementations

- **The first significant peak, not the highest.** A rhythm's
  autocorrelation peaks at every multiple of its period, and the overlap
  correction favours the longer lag, so the float replica read a 12 per
  minute breath as **6** before this rule — the sub-harmonic.
- **Scan from lag 2, not from the band's edge.** A 1.2 Hz heartbeat has a
  perfect peak at 2.5 s, inside the breathing band; an in-band scan read it
  as 24 breaths a minute at 99 % confidence. From lag 2 the true period is
  found first, below the band, and the estimate is reported with its real
  rate and **flagged**. The same rule flags the walker (first peak at lag
  2: broadband motion, no rhythm) on all 41 estimates at up to 805 ‰
  confidence — which is why acceptance is a rule and not a threshold.
- **A high-pass for the heart band.** Breathing is 25× the power of a
  heartbeat; over the heart's short lags the autocorrelation was the
  breath's slow curve and the peak sat on the band's edge (130 per
  minute). A one-second moving average subtracted cuts 0.2 Hz by ~24 dB.

### Heart rate, as measured

After the high-pass, 78 for 72 at 7 % confidence — within ten percent,
flagged, and the float replica says the same. A 0.6 % modulation on
amplitudes near 30 is a fifth of one LSB of the noise; that is the ceiling
of one amplitude link at this SNR. A clean heartbeat alone reads to a
tenth (unit test). **A band to try, not a number to trust**, exactly as
the plan said; phase (W1) is the more sensitive carrier and the obvious
next input.

### What W2 does not claim

The plan's own judge — *BPM error against a reference, per recording,
stated* — needs a recording of our own with a reference count. That is a
hardware step and it has not happened. What is stated is the synthetic
error (under 0.06 per minute), the fixed–float agreement, and the
empty-room floor (47 ‰ against an accept floor of 400).

Gates: 7 new unit tests, 3 new capture tests, clippy `-D warnings`, fmt,
the bare-metal core-only check — green.

---

## W3 of the RuView plan: the payload — 2026-09-23

`radar::presence::Presence` at **version 2**: 18 bytes become 28 —
breathing and heart rate in tenths per minute, each with its confidence in
permille, and the room's fingerprint distance. The path it rides was traced
before it was widened: a sketch encodes the record, the facade's
`mesh::push_telemetry` copies the bytes at their own length into the
`"tlm "` codec on `janus/media/1`, and a home computer decodes them. Nothing
on the way assumes a length; every consumer sizes by `ENCODED_LEN`. The BLE
`presence` characteristic carries a two-byte summary and is untouched.

**A version 1 record still decodes**, its new fields zero — a device flashed
before this reads on a home computer built after it. A version nobody knows
is refused.

**A rate is on the wire only when it was accepted.** A flagged estimate —
the heartbeat at seven percent, a walker's gait through the breathing band
— contributes its confidence and a rate of zero. A consumer that reads the
rate and ignores the confidence still cannot be misled; the confidence is
there for the one that wants to know the sensor tried.

`radar::fingerprint::Baseline`: calibrated from normalised frames in the
room's reference state, it reports the permille departure of a frame's
across-subcarrier variance from the mean it learned. One number, not a
verdict; what 200 ‰ means is the application's to decide per room. A gain
step during calibration does not move it, and a change of shape reads as a
distance (unit tests).

Not done here, and said so: the facade (`rusty_esp_arduino`) takes this
crate by git URL and re-exports `ENCODED_LEN` symbolically — it follows on
its next pin, with no code change. Adding public fields to `Presence` is a
minor bump for a 0.x crate (0.3.0), which is the maintainer's call at
release, not made in this branch.

Gates: 3 new tests on the record, 3 on the fingerprint; clippy
`-D warnings`, fmt, the bare-metal core-only check — green.

---

## W4 of the RuView plan: CSI on ESP-IDF, so a camera can watch the room — 2026-09-23

`rusty_esp_signal-esp::idf::csi`, behind `esp-idf-csi`: the Track A twin of
`hal::csi`. Until it existed, every camera cell and the mesh were `std` on
ESP-IDF and CSI was esp-radio only, so a device that watched the room could
not also show it or reach the owner over iroh. espino's `presence-csi` is now
`Track::Either`.

### The shape, and why

ESP-IDF delivers channel state to a C callback on the Wi-Fi task with a
buffer valid only for the call. So the callback does the one thing that
must happen inside it — copy the buffer out, blank the first two entries
when the chip flags them, `features()` — and parks the result in a slot
the sketch drains on its own thread. It never blocks the Wi-Fi task
(`try_lock`; a contended slot is a counted drop, not a stalled radio). The
detector, the estimators and the telemetry all live with the sketch.

This is the crate's one `allow(unsafe_code)` seam: three ESP-IDF entry
points and one `extern "C"` trampoline, each with its contract written at
the block, the way `rusty_esp_iroh-esp` opens its own. Everything either
side of the seam is safe Rust over the core.

**Which training field is the caller's choice, and both-at-once is
refused.** Legacy LTF only (`Config::recommended`) is the default: every
OFDM frame carries one, so any data frame from the access point produces a
reading and the buffer is exactly `Layout::LLTF_20MHZ`'s 64 entries. HT-LTF
only is the other supported shape. Both enabled concatenates fields in an
order this crate has not verified on silicon, and a layout guessed wrong
reads a room from the wrong subcarriers with every status clean — so it
returns `ESP_ERR_INVALID_ARG` instead. The channel filter is off, on
ESP-IDF's own advice for keeping adjacent subcarriers independent.

### What it changed in espino

The catalogue names a package's dependencies once, and the signal backend
crate selects its track by feature — the two tracks are `compile_error!`
together. `radar-ld2410` said `esp-idf` with a comment that a Track B
firmware "takes `esp-hal` instead", and nothing did the taking: a Track B
cell with a radar would have failed on the first line of its Cargo.toml.
Both generators now translate the signal crate's features by track
(`signal_esp_features`), and the C8 test holds that no Track A feature
reaches a Track B firmware.

Cell **C9**: the XIAO's camera page plus `presence-csi` on one board. The
std sketch begins the capture after the network is up, drains the slot in
the loop through a gain-normalised detector at the W1b thresholds, and logs
one line per verdict change with the radio's own counters beside it.

### The gate

The generated C9 project (espino) compiled this module for the first
time -- it is `cfg`'d out on the host, so the firmware build is its
compile -- with **zero warnings**:

| step | result |
|---|---|
| `espino make image --host-only --planned --force --patch-siblings <umbrella> --release` on the C9 manifest (`xiao-esp32s3-sense`; `wifi-sta` \| `camera-ov2640` + `presence-csi` \| `mjpeg-page`) | 14 files generated, Track A (`rusty_esp_signal-esp` at `["esp-idf", "esp-idf-csi"]`, no Track B feature in the file) |
| `cargo build --release`, `xtensa-esp32s3-espidf`, ESP-IDF v5.5.1, patched to the sibling checkouts | `Finished release` in **2 m 36 s** cold for the siblings (1 m 01 s on the rebuild); ELF **1,652,352 B**; **0 warnings** in the generated project |
| the image, unchanged | **8,376,320 B**; app **1,130,304 B** in the 3 MiB `factory` (**35.9 %**); filesystem 299 B in `littlefs`; `identity` kept |

The first build carried two warnings and the rebuild none: the presence
record's import is now emitted only when `telemetry` is chosen (it is
only encoded then), and a `let mut` in the boot record that esp-idf-svc
0.52 no longer needs -- pre-existing, cleared in passing.

### What it does not claim

Nothing has run on a board. `Verified` is CSI frames per second on the XIAO
**with the MJPEG page streaming** — radio contention is the risk and it is
measured, not assumed — and the layout the S3 delivers is confirmed by the
first capture, not by this text. The vitals estimators (W2) are not yet in
the sketch: the record a C9-with-telemetry would send carries the verdict
and zeros for the rates, honestly, until W5 wires them.

---

## W4 hammered: the callback's ingest and ring are host-tested, and the ring holds sixteen — 2026-09-23

The first ESP-IDF backend parked **one** frame, and the two things a
callback must get right — what to make of the chip's buffer, and what
happens when frames arrive faster than the sketch drains them — were
`cfg`'d out on the host, so nothing tested them.

`rusty_esp_signal-esp::csi_queue`, compiled on every track and the host:
`ingest` (the short check, the first-word blanking the legacy layout needs
because it keeps entry 1, `features()`) and `Ring<N>` (push overwrites the
oldest when full and counts it; pop is oldest first). Six tests on the
host, including the one that says a late sketch sees the latest N in
order and the count it missed. `idf::csi` is the FFI around them now.

**Why sixteen.** A sketch that shares its loop with a camera drains the
ring every pass, and a pass is a frame grab — twenty to forty
milliseconds — while a steady transmitter delivers channel state every
twenty. With a slot of one, half the frames were overwritten before the
sketch saw them, and the vitals estimators downstream decimate by
**count**, so the rate they were configured for was wrong by the same
half. Sixteen is 320 ms at 50 Hz, longer than any pass of a camera loop;
later than that, the sketch sees the latest sixteen and `Stats::dropped`
says how many it missed. Never a stalled radio (still `try_lock`), never
a silent gap.

### The gate

C9 regenerated and rebuilt under ESP-IDF v5.5.1 (`xtensa-esp32s3-espidf`, `--release`) 2026-09-23: ELF 1,714,488 B (+4,132 B for the ring of sixteen and the minute line), app 1,187,936 B in the 3 MiB factory slot (37.7 %), image 8,376,320 B, zero warnings, 1 m 43 s -- the first compile of `csi_queue` behind the FFI.

### Still not claimed

Nothing has run on a board. W4 is judged by CSI frames/s on the XIAO with
the MJPEG page streaming; the C9 sketch prints that number once a minute
now, and this ring is what makes the number the radio's, not the loop's.

---

## W5 of the RuView plan: one CSI frame on the wire, raw I/Q — 2026-09-23

`radar::csi_stream::Sample` (PR #9, on #7): the record a device sends per
frame and a subscriber reads. **Raw I/Q, not features.** Features are what
the on-device detector wants; a subscriber wants everything the radio
delivered — the phase half needs I/Q, a recording in this ledger's own
fixture format is I/Q, and a model trained later wants what was measured,
not what one release summarised. 141 bytes at 64 entries; 7 KB/s at
50 Hz, which ESP-NOW's 227-byte sealed payloads, the bridge and the LAN
carry without noticing.

The header names the buffer's layout by tag, so a receiver that knows the
tag computes the same features the device did (`Sample::features`, and a
test says so); one that does not still has the bytes. Decode takes the
whole buffer or refuses it — a version nobody knows, a short header, a
`len` over 128 or one the bytes do not match — never a guess.
`csi_queue::Frame` carries the raw I/Q and the tag beside the features;
`Frame::sample()` is the frame as one record (the ring entry is ~280 B,
sixteen of them 4.5 KiB).

The other halves: the facade's `mesh::push_csi` (rusty_esp_arduino #2),
the bridge's `MSG_CSI` → `nbrc` with the host's decoder and CSV recorder
(rusty_esp_iroh #4), and espino's `csi-stream` package with cell C10.

### The gate

C10 generated and built under ESP-IDF v5.5.1 (`xtensa-esp32s3-espidf`, `--release`) 2026-09-23: ELF 10,062,356 B (a mesh cell: iroh on the chip), app 4,700,800 B in the factory slot (74.7 %), image 8,376,320 B, zero warnings, 2 m 52 s -- the first compile of `push_csi`, `Frame::sample` and the record-with-vitals path on a device. The first attempt failed in rusty_esp_iroh-host: the sibling patch named `rusty_esp_signal-esp` but not `-core`, so the mesh built against git main's -core; every std project patches -core now, and the C2 test that said otherwise was wrong.

### Not claimed

Nothing has run on a board. W5 is judged by packets counted end to end
the way C2 was; on the host the bridge test counts three through the
bridge to a subscriber, decoded, none lost — the LAN is where it is
judged, and the home computer stays on the iroh gap.

---

## W7 of the RuView plan: a fall, as a shape in the wander — 2026-09-24

`radar::fall::FallDetector`, `no_std`, integer, a few comparisons a frame
over the wander `PresenceDetector` already computes: moving (with a
three-second grace, because a walker is not above threshold between every
step), then a **burst** above anything walking does, then **stillness**
that begins within three seconds and lasts ten. It says *suspected*: an
empty room and a person lying still read the same amplitude, and only a
breath (`radar::vitals`) separates them, so the caller asks.

### Evidence (`rusty_esp_sense bench-fall`, the Cuenca captures)

No labelled ESP32 fall recording under a usable licence was found (the
candidates carried no licence, or their "raw" files were synthetic). So:

| what | result |
|---|---|
| tuning half: highest one-second wander | walking 178 ‰, walking + traffic 138, traffic 35, empty 28 |
| defaults set from it | burst 232 ‰ (1.3 × 178), still 30 ‰ (above the empty room's 28) |
| test half, 0.84 h of real channel state, no falls in it | **0 false events** — at 95 % that bounds the rate below ~3.6 / h, no tighter |
| margin | the test half raises its first false event only at 114 ‰ |
| splices, SYNTHETIC: a capture's most active 10 s, a 0.5 s burst, 20 s of an empty room | 10 / 10 raised |
| splices without a burst (someone leaving) | 0 / 10 raised |

Two fixes the bench forced, both with regression tests: motion first ended
on any dip below "still" (1 splice in 10 caught), and "still" first reused
the presence `off` of 23 ‰, below the tuning half's empty-room ceiling.
The splices first took each walking capture's first 10 s, one of which
had no frame of motion in it; they take its most active 10 s now.

Not claimed: any detection rate on a real fall.

## X0 of the killing-C plan: the C census — 2026-09-30

`python tools/c-census.py build && python tools/c-census.py report --ledger` from the umbrella, so sibling crates are the checkouts beside this one: each firmware is linked `--release` with a linker map and `--emit-relocs`, and the two are read together. Every input section the linker kept is charged to the archive the map names for it, one owner per address; every FUNC and OBJECT symbol in the ELF to the archive whose section holds its address; and a mask-ROM routine counts when a kept relocation names it (a linker script defines every ROM symbol whether or not anything calls it). `image B` is code + data as flashed; bss is RAM only. `tools/c-census.py verify` is the gate: the bytes charged equal the bytes the ELF loads, and every symbol charged to a C archive is one `llvm-nm` finds defined in that archive; on an ESP-IDF build the image bytes of every archive also equal what Espressif's own `esp_idf_size` reports from the same map. Two limits: a string table the linker merged is shared by everything that contributed to it, so it is charged where the map puts it (GNU ld) or to the linker row (lld, which names no contributor); and with LTO the Rust side is one object, so its crates are not told apart. Where a firmware reads its network at compile time the build is given placeholders for all of it (`census` / `census-pass`, stream destinations in 192.0.2.0/24): a firmware given no destination compiles its networking out, and the census would measure an image nobody ships.

**What it says.** `c6-lora-p2p` is the one image in the family with no C above
the mask ROM: 0 C symbols, 0 blob archives. The three Track B firmwares with a
radio up are the opposite: 63% to 76% of
the image is Espressif's blob, and every C symbol in them is a blob symbol —
so on the C6 the floor the killing-C plan can reach is what these tables show,
not zero. `c6-mesh-node` and `c6-s1-link` keep the same nine archives to the
byte (420,033 B); `libwpa_supplicant.a` is
50,464 B of that, shipped closed by `esp-wifi-sys`
though ESP-IDF builds it from source. The Rust side is not ROM-free either: its
memory copies and 64-bit division resolve to mask-ROM routines.

The Track A BLE firmware is the largest C share measured:
79.3%. The Bluedroid host (`bt`) alone is
233,726 B and 2,508 symbols — what X3 removes by moving the
S3 to `trouble-host` — and the controller (`libbtdm_app.a`,
68,869 B) stays. It calls 1,122 mask-ROM routines,
nearly three times any other firmware, and 763 of them are the
controller's own `r_*` routines: on the S3 most of the Bluetooth controller is
in the ROM, not in the archive. Leaving ESP-IDF removes 676,690 B and 6,823 symbols.

### `c6-lora-p2p` — C6, Track B, `w7/fall@8ee35a4`

| origin | objects | symbols | code B | data B | bss B |
|---|---:|---:|---:|---:|---:|
| Rust | 2 | 1,050 | 93,408 | 19,556 | 75,966 |
| linker (merged constants, padding, reservations) | 2 | 151 | 38 | 7,480 | 365,090 |

**C in this image: 0 symbols, 0 B of 120,482 B (0.0%). The blob floor is 0 symbols in 0 archives.** The 2nd-stage bootloader that starts it is espflash 4.6.0's bundled `esp32c6-bootloader.bin`: 22,016 B of C outside this image.

Mask-ROM routines called: 5 — 0 from C, 5 from Rust: `__udivdi3`, `ets_delay_us`, `memcpy`, `memset`, `rtc_get_reset_reason`.

### `c6-ble-provision` — C6, Track B, `w7/fall@8ee35a4`

| origin | objects | symbols | code B | data B | bss B |
|---|---:|---:|---:|---:|---:|
| Rust | 2 | 1,295 | 115,986 | 23,150 | 106,944 |
| precompiled Espressif archives (the blob) | 4 | 1,417 | 253,724 | 7,927 | 315 |
| linker (merged constants, padding, reservations) | 2 | 181 | 38 | 13,311 | 307,813 |

**C in this image: 1,417 symbols, 261,651 B of 414,136 B (63.2%). The blob floor is 1,417 symbols in 4 archives.** The 2nd-stage bootloader that starts it is espflash 4.6.0's bundled `esp32c6-bootloader.bin`: 22,016 B of C outside this image.

Mask-ROM routines called: 90 — 88 from C, 9 from Rust: `__divdi3`, `__udivdi3`, `ets_clk_get_xtal_freq`, `ets_delay_us`, `memcmp`, `memcpy`, `memmove`, `memset`, `rtc_get_reset_reason`.

| C archive | origin | symbols | image B | bss B |
|---|---|---:|---:|---:|
| `libble_app.a` | blob | 1,218 | 223,276 | 310 |
| `libphy.a` | blob | 147 | 28,377 | 4 |
| `libprintf.a` | blob | 15 | 5,044 | 0 |
| `libbtbb.a` | blob | 37 | 4,954 | 1 |

### `c6-mesh-node` — C6, Track B, `w7/fall@8ee35a4`

| origin | objects | symbols | code B | data B | bss B |
|---|---:|---:|---:|---:|---:|
| Rust | 2 | 1,188 | 94,942 | 16,178 | 103,071 |
| precompiled Espressif archives (the blob) | 9 | 2,210 | 362,962 | 57,071 | 15,324 |
| linker (merged constants, padding, reservations) | 2 | 152 | 38 | 19,223 | 265,053 |

**C in this image: 2,210 symbols, 420,033 B of 550,414 B (76.3%). The blob floor is 2,210 symbols in 9 archives.** The 2nd-stage bootloader that starts it is espflash 4.6.0's bundled `esp32c6-bootloader.bin`: 22,016 B of C outside this image.

Mask-ROM routines called: 309 — 306 from C, 10 from Rust: `__divdi3`, `__eqdf2`, `__udivdi3`, `ets_clk_get_xtal_freq`, `ets_delay_us`, `memcmp`, `memcpy`, `memmove`, `memset`, `rtc_get_reset_reason`.

| C archive | origin | symbols | image B | bss B |
|---|---|---:|---:|---:|
| `libnet80211.a` | blob | 926 | 214,775 | 10,867 |
| `libpp.a` | blob | 764 | 114,545 | 2,893 |
| `libwpa_supplicant.a` | blob | 303 | 50,464 | 1,483 |
| `libphy.a` | blob | 169 | 29,825 | 4 |
| `libprintf.a` | blob | 17 | 4,880 | 0 |
| `libespnow.a` | blob | 23 | 4,379 | 64 |
| `libregulatory.a` | blob | 2 | 752 | 0 |
| `libcore.a` | blob | 5 | 353 | 9 |
| `libmesh.a` | blob | 1 | 60 | 4 |

### `c6-s1-link` — C6, Track B, `w7/fall@8ee35a4`

| origin | objects | symbols | code B | data B | bss B |
|---|---:|---:|---:|---:|---:|
| Rust | 2 | 1,201 | 98,928 | 16,235 | 103,047 |
| precompiled Espressif archives (the blob) | 9 | 2,210 | 362,962 | 57,071 | 15,324 |
| linker (merged constants, padding, reservations) | 2 | 161 | 38 | 19,446 | 265,061 |

**C in this image: 2,210 symbols, 420,033 B of 554,680 B (75.7%). The blob floor is 2,210 symbols in 9 archives.** The 2nd-stage bootloader that starts it is espflash 4.6.0's bundled `esp32c6-bootloader.bin`: 22,016 B of C outside this image.

Mask-ROM routines called: 309 — 306 from C, 10 from Rust: `__divdi3`, `__eqdf2`, `__udivdi3`, `ets_clk_get_xtal_freq`, `ets_delay_us`, `memcmp`, `memcpy`, `memmove`, `memset`, `rtc_get_reset_reason`.

| C archive | origin | symbols | image B | bss B |
|---|---|---:|---:|---:|
| `libnet80211.a` | blob | 926 | 214,775 | 10,867 |
| `libpp.a` | blob | 764 | 114,545 | 2,893 |
| `libwpa_supplicant.a` | blob | 303 | 50,464 | 1,483 |
| `libphy.a` | blob | 169 | 29,825 | 4 |
| `libprintf.a` | blob | 17 | 4,880 | 0 |
| `libespnow.a` | blob | 23 | 4,379 | 64 |
| `libregulatory.a` | blob | 2 | 752 | 0 |
| `libcore.a` | blob | 5 | 353 | 9 |
| `libmesh.a` | blob | 1 | 60 | 4 |

### `xiao-s3-sense-idf-ble-provision` — S3, Track A, `w7/fall@8ee35a4`

| origin | objects | symbols | code B | data B | bss B |
|---|---:|---:|---:|---:|---:|
| Rust | 1 | 587 | 105,556 | 140,272 | 117 |
| ESP-IDF, built from C source | 40 | 6,572 | 534,516 | 53,594 | 6,757 |
| precompiled Espressif archives (the blob) | 8 | 1,998 | 278,500 | 29,121 | 9,605 |
| toolchain C runtime (libc, libgcc) | 2 | 251 | 82,684 | 5,896 | 337 |
| linker (merged constants, padding, reservations) | 1 | 0 | 10,739 | 437 | 82,413 |

**C in this image: 8,821 symbols, 984,311 B of 1,241,315 B (79.3%). The blob floor is 1,998 symbols in 8 archives.** The 2nd-stage bootloader that starts it is espflash 4.6.0's bundled `esp32s3-bootloader.bin`: 21,072 B of C outside this image.

Mask-ROM routines called: 1122 — 1122 from C, 6 from Rust: `__udivdi3`, `memcmp`, `memcpy`, `memmove`, `memset`, `strlen`.

| C archive | origin | symbols | image B | bss B |
|---|---|---:|---:|---:|
| `bt` | idf | 2,508 | 233,726 | 589 |
| `libnet80211.a` | blob | 633 | 133,315 | 7,590 |
| `libc.a` | toolchain | 196 | 87,096 | 320 |
| `lwip` | idf | 689 | 69,105 | 2,470 |
| `libbtdm_app.a` | blob | 531 | 68,869 | 680 |
| `libpp.a` | blob | 487 | 62,626 | 1,234 |
| `mbedtls` | idf | 608 | 56,428 | 252 |
| `wpa_supplicant` | idf | 457 | 54,974 | 1,330 |
| `libphy.a` | blob | 181 | 33,598 | 86 |
| `esp_hw_support` | idf | 262 | 26,234 | 156 |
| `freertos` | idf | 205 | 18,898 | 757 |
| `hal` | idf | 160 | 16,157 | 4 |
| `spi_flash` | idf | 222 | 14,231 | 24 |
| `esp_system` | idf | 196 | 13,802 | 309 |
| `nvs_flash` | idf | 151 | 13,046 | 24 |
| `heap` | idf | 107 | 9,638 | 8 |
| `libcoexist.a` | blob | 142 | 5,471 | 6 |
| `libbtbb.a` | blob | 18 | 3,456 | 0 |
| `libcore.a` | blob | 5 | 283 | 9 |
| `libespnow.a` | blob | 1 | 3 | 0 |
| … 30 smaller | | 1,062 | 63,355 | 851 |

## X2 of the killing-C plan: an IP stack over the station on Track B — built, not yet joined (2026-09-30)

`rusty_esp_signal-esp::hal::netstack` (feature `embassy-net`): embassy-net
0.9 over esp-radio's station interface with DHCP, a `net_task` that runs the
stack and a `station_task` that keeps the station joined through the core's
`StationPolicy` — the same host-tested policy `hal::station` drives on the
C6, now under an address and sockets. `station_config` turns an SSID and a
passphrase into the radio's configuration and refuses what the radio would.
It is what `wifi-sta` means on a bare-metal chip: where ESP-IDF gives Track A
lwIP, DHCP and BSD sockets in C, this gives Track B smoltcp, its DHCP client
and embassy-net's sockets in Rust, and the only C under the station is
Espressif's radio blob.

Two firmwares compile it for the ESP32-S3, the first of this family's on
that chip with a radio up: `rusty_esp_audio/firmware/xiao-s3-sense-hal-pdm-udp`
(PCM over UDP) and `rusty_esp_video/firmware/xiao-s3-sense-hal-page` (the
camera page over TCP). Their census is the number the killing-C plan waited
for (its §1.4, item 2): **on the S3, a Track B firmware with Wi-Fi up keeps
320,574 B of blob in 8 archives (1,710 symbols)** — `libnet80211` 169,861 B,
`libpp` 66,954, `libwpa_supplicant` 42,754, `libphy` 32,824, `libprintf`,
`libbtbb`, `libregulatory`, `libespnow` — against 229,745 B in 5 under
ESP-IDF, which builds `wpa_supplicant` from source and drops `libbtbb`. So
esp-radio keeps about 90 KB more closed code than IDF on this chip, and
everything else C is gone: 6 bytes of `crti.o`.

**Not yet joined.** No 2.4 GHz network was reachable from the bench when this
was built (the laptop's networks are all 5 GHz, and the plan in
`docs/plans/ap-remaking.md` has the answer: the router's 2.4 GHz SSID, or a
phone hotspot), and a passphrase is the operator's to type — Requirement C
there says it never reaches the assistant. The join, the lease and their
times are the first three lines the firmwares print; the ledger row waits
for them. What is established: the module compiles for the chip in both
firmwares, `cargo clippy -D warnings` is clean on both with the esp
toolchain, and the policy it runs is the one `rusty_esp_signal-core`'s host
tests cover.

The `embassy-net` feature is not built by this repository's own CI (no C6
firmware enables it yet); the two firmwares above are its compile checks,
and their CI jobs can only be green once this crate is pushed with the
feature.

## X3 of the killing-C plan: BLE provisioning on the S3 with no Bluedroid — kill test passed on the XIAO (2026-09-30)

### The backend, on the 1.2 companion set

`rusty_esp_signal-esp::ble` now speaks `trouble-host` 0.7 over `bt-hci`
0.9, the line esp-radio 1.0.0-beta.1 (esp-hal 1.2, esp-rtos 0.4) hands
out; 0.6 / 0.8 was the beta.0 set's, and a caret on both lets the firmware
pick the set, as for esp-hal. Three things changed with it:

- **The advertisement carries the provisioning service UUID; the name rides
  in the scan response.** It used to carry the flags and the name only — so
  `espino serve`'s page, which filters on the service (Chrome shows only
  what matches), could never have found a Track B device. A legacy
  advertisement holds 31 bytes and the UUID takes 18; the split is the one
  the IDF backend already used (ledger, 2026-09-05).
- **A session that outlives the write.** `accept` advertises and returns a
  `Session` (the phone, with the attribute server attached);
  `Session::serve` answers it until it writes credentials;
  `Session::attend(fut)` runs the join while still answering the phone's
  reads and writes, so a request during those seconds is not left to the
  ATT timeout; `Session::report(event)` feeds the join's outcome to the
  core's `Provisioner` and notifies the phase. The one-shot `serve` remains
  for a firmware with nothing to join. Dropping the session drops the link.
- The 0.7 API: a write's bytes come through `with_data`, `notify` takes a
  `store` flag, `HostResources` names its controller, `Stack` hands out
  `runner()` and `peripheral()`.

`c6-ble-provision` moved to the 1.2 set with it (`FROM_CPU_INTR0` in place
of the software interrupt) and builds: 446,062 B image, 261,651 B of C in
4 blob archives — the same C as on the 1.1.2 set, 32 KB more Rust.

### The firmware

`firmware/xiao-s3-sense-hal-ble-provision`: the IDF twin rebuilt on the C6
firmware's stack, with the join the C6 has no Wi-Fi stack for. Two boots,
the way the Track A sketch lives (ledger, 2026-09-05): **provisioning** —
advertise as `janus-s3`, take the write, join with the phone still
connected (both radios up on the S3's one modem, esp-radio's `coex`),
notify `Connected`, stash the credentials, software reset; **station** —
Bluetooth never initialised, the station joined through `hal::netstack`
with DHCP, the address and the join time printed. The stash is RTC fast RAM
behind a checksum: a software reset keeps it, a power cycle does not, and
X4's NVS reader replaces it. A failed join notifies `Backoff` and keeps the
phone connected: a corrected write is the retry (the policy retries on
`Tick`, and a new write always yields `Connect`). A `diag` feature turns on
esp-radio's, trouble-host's and esp-println's own log lines for the bench
(48 KB of image).

Census (`tools/c-census.py`, `verify` closes, `llvm-nm` agrees on all 2,414
C symbols):

| | this firmware | the ESP-IDF twin |
|---|---:|---:|
| image | 705,259 B | 1,241,315 B |
| C in the image | 414,612 B (58.8 %) | 984,311 B (79.3 %) |
| C symbols | 2,428 | 8,821 |
| of which the radio blob | 414,606 B, 10 archives | 307,621 B, 8 archives |
| C that is not the blob | 6 B (`crti.o`) | 676,690 B |
| Bluedroid host (`bt` component) | — | 233,726 B, 2,508 symbols |
| ROM routines called | 1,008 (22 from Rust) | 1,122 (6) |

Leaving ESP-IDF took **569,699 B of C and 6,393 C symbols** out from under
the same GATT table; the Bluedroid host, lwIP (69 KB), mbedTLS (56 KB) and
FreeRTOS are gone. What is left is the blob, larger than under IDF by the
same 90 KB X2 found (`wpa_supplicant` closed, `libregulatory`, `libprintf`)
plus `libbtdm_app` 86,396 B — the BLE controller, which is what Bluetooth
costs on Track B: 560 symbols against Bluedroid's 2,508 + the controller's
531.

### On the board

Flashed to the XIAO on COM4 (`diag` build): both radios initialise
(`coex-initialize`, `btdm_controller_init`), trouble-host comes up
(`[host] initialized`, `Device Address 6A:EE:8F:51:74:65`), and the
laptop's Bluetooth sees it — the service UUID from the advertisement, the
name from the scan response, 31 packets in 30 s at −46 dBm.

**The write path, measured** (`tools/ble-provision.ps1`, a network that
does not exist, so the join must fail; times are the laptop's clock):

| step | result |
|---|---|
| connect, read `status` | `Unprovisioned`; the DID characteristic reads empty (identity is X4's) |
| subscribe to `status` | `Success` |
| write the credential TLV (10 + 11 bytes) | `Success` at 13:03:10.172 |
| the first notification | `Connecting`, 23 ms after the write |
| the join, both radios up | the board: `provisioned: Provisioner { phase: Connecting, has_credentials: true, scan_len: 0 } -> Connect`, then `join failed: the join failed` — esp-radio refused the association in 3.2 s, well inside the 20 s timeout |
| the second notification | `Backoff`, 3.2 s after the first |
| the link | still connected 60 s later: the phone can write again |

The first attempt at this write was rejected with ATT `0x13`
(`VALUE_NOT_ALLOWED`) — our own refusal: trouble-host 0.7's
`WriteEvent::with_data(|a, b| …)` hands the write's **offset** first, not
its length, and the backend had sliced the data to `..offset`, i.e. to
nothing, so the core saw an empty TLV. Fixed (offset 0 or refused; the
whole slice to the core).

### The kill test, passed (13:38)

`Tineco_5413` — an open 2.4 GHz network on channel 1 that appeared on the
bench in the afternoon (an appliance's setup AP), so no passphrase was
involved — through `tools/x3-kill-test.ps1` (flash → reset and log →
`ble-provision.ps1` → a scan afterwards → the log):

| step | the laptop | the board |
|---|---|---|
| the write | `Success`, 13:38:15.435 | `provisioned: Provisioner { phase: Connecting, has_credentials: true, scan_len: 0 } -> Connect` |
| `Connecting` | notified 11 ms after the write | |
| the join, both radios up | | `joined join_ms=14` — fast scan finds the AP on channel 1, open authentication, no handshake |
| `Connected` | notified 12 ms after the write | then 700 ms for it to leave |
| the restart | link `Disconnected` 10.5 s after `Connected`: the board reset without hanging up and Windows waited out its supervision timeout (fixed after this run: the session is dropped and given 300 ms before the reset) | `restarting into station mode` → `rst:0x3 (RTC_SW_SYS_RST)` → `== … mode=station reset=Some(CoreSw) ==`, with no `btdm_controller_init` and no `[host]` line: Bluetooth was never initialised |
| the station | a 12 s scan 17 s later: 6 advertisers, **none named `janus-s3`** | `station ssid_len=11 joining` → **`mode=station ip=192.168.0.100 join_ms=64 dhcp_ms=254`** (from boot), then `link=up` every ten seconds for the two minutes the log ran |

Next to Track A's 7.5 s to join on the ESP32-CAM (2026-09-05): 64 ms from
boot to the association and 254 ms to the lease. An open network on
channel 1 is the best case — the fast scan stops at the first channel and
there is no 4-way handshake — so this is the floor; a WPA2 network adds
the handshake and its channel's place in the scan. Row X3's kill test is
met; the operator's WPA2 network is the same script with `-PskEnv`.

**A second pass (13:44), with the hang-up before the reset:** the same
write, `Connecting` and `Connected` 9 ms after it, `joined join_ms=25`,
then `disconnection event on handle 1, reason: Connection Terminated By
Local Host` on the board and the link gone on the laptop **836 ms after
`Connected`** (the 700 ms the notification is given, then the disconnect)
where the first pass had waited out a 10.5 s supervision timeout; the
restart, `mode=station`, `join_ms=70`, no `janus-s3` on the air. The lease
took `dhcp_ms=10271` this time against 254 ms before: the association was
as fast, so the 10 s is smoltcp's DISCOVER retry after the access point
did not answer the first one — the appliance's DHCP server, not the
firmware. Two passes, two joins, two restarts, two addresses.

The bench is one board and, this afternoon, two sessions: within twelve
seconds of this firmware's second flash, another session's
`espflash flash --monitor … flac-chipbench` reflashed the XIAO and held
COM4 with its monitor (`Get-CimInstance Win32_Process` names the holder;
the boot banner — `== JANUS BLE …` against `== FLACBENCH …` — is the
check before trusting any run). The kill test waits for a window with the
board to itself.

`tools/ble-provision.ps1` (umbrella) is the laptop's half without Chrome:
the same contract as the page — the service filter, the DID, the status
read, the subscription, the credential TLV write, the phases as they arrive
— from Windows' own Bluetooth stack (a C# class over WinRT, compiled with
the Framework's csc; Windows PowerShell 5.1 cannot subscribe to WinRT
events and `Add-Type` cannot take a `.winmd`). The passphrase is read from
an environment variable the operator names and never printed. Found on the
way: its first scanner merged an advertisement and its scan response
last-writer-wins per address, which is how a device can appear to advertise
a name and no service — the two packets are merged now.

CI: a `firmware-xtensa` job (espup's toolchain, no ESP-IDF) builds this
firmware; the `ble` feature is built by both the C6 and the S3 jobs.

## X5's network half: the board hosting its own network on Track B (2026-09-30)

X5's stream had to be measured the way V1 was — the laptop on a network the
board hosts, no router in the line — and embassy-net has a DHCP client but
no server. `hal::netstack` grew the other direction:

- `access_point_config(ssid, passphrase, max_stations)`: WPA2-Personal (an
  empty passphrase means open; 8–63 bytes otherwise, refused before the
  radio sees it). The radio starts the access point inside
  `WifiController::set_config`, so there is no start call to make.
- `hosted_stack(interface, address, resources, seed)`: the stack over
  `Interface::access_point()` at a fixed address, the board as gateway.
- `dhcp_server_task(stack, address)` (feature `access-point`): edge-dhcp
  0.8's packet server over edge-nal 0.7's UDP traits, which edge-nal-embassy
  0.9 implements on embassy-net 0.9 — leases from `.50` to `.200`, the board
  as router; one UDP socket on port 67, so `SOCKETS` leaves it one. The
  server survives a socket error (the lease table is kept) and rebinds.
- `auto-icmp-echo-reply` on embassy-net, which lwIP has built in and
  embassy-net makes opt-in. Found the hard way: the first run's laptop
  joined, took lease 192.168.71.50 from the new server, and then waited 40 s
  for a ping the board would never answer, so the runner declared it absent.
  The gate is port 80 now, and the ping is a separate row.

On the XIAO, the page firmware hosting `janus-cam` (WPA2, channel 1): the
laptop associated on the first attempt, took `.50`, fetched the page (200),
answered 10 of 10 pings at 1 / 9.1 / 60 ms (min / mean / max; the 60 is one
outlier, the rest under 5), and decoded 1,500 frames of `/stream` at 27.04
fps — the row is in `rusty_esp_video`'s ledger. `PAGE station=joined aid=1`
and `station=left` bracket the visit on the board's serial.

## X9 of the killing-C plan: the link over UDP, and the accept that arrived late (2026-10-01)

`rusty_esp_signal-esp::hal::link::UdpLink` (feature `embassy-net`): the
mID-authenticated link (`link::Handshake` / `Session`, Noise-KK, the same
frames as over ESP-NOW) over an embassy-net UDP socket the caller bound,
to one peer endpoint. `handshake_initiator(me, rng, allow, now, patience)`
sends `Hello`, waits for `Accept` within `patience`, sends `Confirm` and
returns the `Session`; `send` seals one payload into one datagram; `recv`
opens one datagram from the peer within `patience` (others are dropped
without a word). It is what the camera cell behind a bridge (espino's C14,
X9) runs on the network it hosts, with `rusty_esp_iroh-bridge`'s
`UdpRadio` on the laptop's side; no second radio on the bench.

**The accept that arrived late (X9, run 3).** After a hard reset the
laptop takes seconds to rejoin the board's network; the node's first hello
timed out at 3 s and its accept arrived during the second attempt, where
it failed the transcript check (`Error::Crypto`) — and from then on every
attempt read the accept of the attempt before, fifteen times, while the
bridge answered every hello and linked none. `handshake_initiator` now
drains the socket before it sends a hello. One attempt is still wasted
when an accept is in flight at that moment (run 4: a timeout, one
refusal, a session): `Handshake::finish` consumes the handshake, so an
initiator cannot try the next datagram on a refused one. A `finish` that
borrows, or a handshake that can be run again, would let the initiator
wait out its patience for the accept that matches; the responder's side
(`Pending::confirm`) has the same shape.

The C6 mesh node (`c6-mesh-node`, and espino's C8 from it) responds to a
hello; so does a bridge. Two responders never link. A node behind a bridge
initiates, as `UdpLink` does; the ESP-NOW node should too once its peer is
a bridge rather than the bench's `s1-link`.

## The optimization campaign after X11: the link's MAC keyed once a session (2026-10-01)

`Session` keeps two HMAC-SHA256 states keyed at the handshake (`mac_send`,
`mac_recv`) and clones one per frame, so the key's inner and outer pad
blocks (two SHA-256 compressions) are not hashed again on every `seal` and
`open`. The tags are the same bytes: the golden test pins a frame's tag and
the full suite (140 tests) passes. On the XIAO's probe at 80 MHz, a
220-byte payload sealed and opened: 919.4 → 651.3 µs (0.708). Numbers and
method: rusty_esp_dsp's ledger.

On drop the keyed states are overwritten with a state keyed by zeros
behind a compiler fence and `black_box`: best effort, because the crate
is `forbid(unsafe_code)` (no volatile write) and the hash states do not
implement `Zeroize`. The raw keys are still zeroised as before.

## Round 2: the link's HMAC on the SHA unit (2026-10-01)

The core keeps each direction's HMAC key as its two SHA-256 midstates and
runs the blocks through a `Sha256Blocks` engine: `seal`/`open` use
`SoftSha` (`sha2`'s own block function), `seal_with`/`open_with` take any
engine. `rusty_esp_signal-esp`'s `hal::sha::EspSha` (feature `sha-accel`,
every chip but the ESP32) loads the midstate into the S3's SHA unit, feeds
aligned blocks a word at a load, and takes a message and its padded tail in
one trip (`compress2`). `UdpLink::with_sha` makes the link's own `send` and
`recv` use it; `FrameBuf` keeps frames on a word.

| a 220-byte frame sealed and opened, XIAO at 80 MHz | us |
|---|---:|
| before (round 1's end) | 651.2 |
| `SoftSha`, the midstate HMAC | 638.0 |
| the SHA unit, first engine | 97.5 |
| the SHA unit, word feed + one trip per message | **66.2** |

The midstate HMAC equals the `hmac` crate at every length 0-300 under four
keys; frames from the engine are byte-identical to `seal`'s; a forged tag
is refused on both paths. The midstates are plain words now, so `zeroize`
reaches them on drop (it could not reach `hmac`'s states). dsp's ledger, "Round 2", has the method, every run and the refuted shapes.

## Round 3: the SHA engine's state in digest byte order (2026-10-01)

**B9.** The link's HMAC midstates (`Keyed`) and the `Sha256Blocks` engines
now hold the SHA-256 state in the byte order the S3's SHA unit reads and
writes its H registers: the IV words are stored `swap_bytes`, `SoftSha`
swaps at its own edges, `hmac_with` emits the digest with `to_le_bytes`,
and `rusty_esp_signal-esp`'s `hal::sha` copies words in and out with no
swap at all. Frames are byte-identical to `seal`'s (the probe's link
checksum; the host tests pin the midstate HMAC to the `hmac` crate at every
message length 0-300 under four keys).

| XIAO, 80 MHz | before | after |
|---|---:|---:|
| `link_seal_open_hw` (a frame sealed and opened on the SHA unit) | 66.1 us | **55.8 us** |

The handshake is faster too, but not here: its P-256 work went from 1,404
to 526 ms on the probe through `rusty_esp_mid/vendor/p256` (mid's
ledger, "Round 3"). dsp's ledger, "Round 3", has the method and every run.

## enc-ble M1: the setup session's cryptographic core (2026-10-02)

`rusty_esp_signal-core::setup`, the protocol of the umbrella's
`docs/setup-protocol.md` (v1, suite 1), host-first, `no_std`, allocation-free,
secrets zeroised on drop:

| piece | file |
|---|---|
| the setup code: Crockford base32, normalisation (`O`/`I`/`L`, hyphens, case), display, 50-bit generation | `setup/code.rs` |
| `w0`, `w1` by PBKDF2-HMAC-SHA256 (hand-rolled on `hmac`), the 40-byte halves reduced mod `n`; the 118-byte `setup.v` record and its refusals | `setup/verifier.rs` |
| SPAKE2+ (RFC 9383, P-256) both roles, the key schedule, the Reply's prehash and the browser's check of the device's signature | `setup/spake.rs` |
| ChaCha20-Poly1305 (`chacha20poly1305` 0.10, no alloc), one key per direction, counted nonces, the header as associated data | `setup/seal.rs` |

New dependencies: `chacha20poly1305` 0.10.1 and `subtle` 2.6 (both already in
a P-256 firmware's graph), and p256's `ecdsa` feature for the verify.

**Held to.**

- In Rust: RFC 9383's P-256 / SHA-256 / HMAC vector (`K_confirmP`,
  `K_confirmV`, both confirmations, `K_shared`, through both roles),
  RFC 8439 section 2.8.2 (the AEAD), RFC 7914 section 11 (PBKDF2), RFC 9383's
  compressed `M` and `N`.
- `tools/setup_golden.py`, an independent oracle in pure Python (its own
  P-256, PBKDF2, HKDF, RFC 6979 ECDSA with low-s, ChaCha20-Poly1305), which
  first checks itself against RFC 8439, RFC 6979 A.2.5 and RFC 9383, then
  writes one complete session (`tests/fixtures/setup/session-v1.txt`;
  `--check` compares). `tests/session_vectors.rs` reproduces it **byte for
  byte from both halves**: the code as typed, `w0`, `w1`, `setup.v`, the
  Context, both shares and confirmations, the Reply's prehash, **the device's
  signature made by mID's `DeviceKey` (equal to the oracle's RFC 6979
  low-s signature)**, and every sealed message (Ready, Settings, Result).
- Refusals: a wrong code (on both sides), another carrier's Context, an
  impostor's signature, the device's signature over another session, shares
  off the curve or of the wrong length, `setup.v` records with a zero or
  out-of-range `w0`, `L` off the curve, another version, too few iterations.
- 141 unit tests (twelve new) and 7 session tests pass on **i686 and
  x86_64**; `cargo build --no-default-features` passes for `wasm32-unknown-
  unknown`, `xtensa-esp32s3-none-elf` and `xtensa-esp32-none-elf`
  (`-Z build-std=core`). Clippy is clean on the new code.

**Found on the way.** On 32-bit Windows an executable with "setup" in its
name triggers the installer detection and asks for elevation (`os error
740`): the test binary `setup_vectors-*.exe` would not start on i686 while
the x86_64 one ran. The file is `session_vectors.rs`.

**Not here yet:** the messages' framing, the session's state machine, the
window and the lockout (M2); the signature helpers in mID (M3); the wasm
half (M4). The device's per-session cost is measured on the board in M6.

## enc-ble M2: the setup session (2026-10-02)

The session of `docs/setup-protocol.md` on top of M1's core, both halves,
`no_std` and allocation-free:

| piece | file |
|---|---|
| framing (version, kind, body; 512 bytes at most), Discover, the shared code table `ResultCode` | `setup/message.rs` |
| the settings record: decode with every standalone check (the network through `wifi::Credentials`, a name, a maker through mID's `Did::parse`, a verifier, an adoption's syntax), `RecordWriter` for the browser | `setup/record.rs` |
| the device: `Device` over two `Kv` stores (`settings`: the network, `setup.v`, `setup.fail`; `identity`: mID's `mid.adopt` and `mid.owner`, as the link keeps them), the window, the backoff, the lockout, the idle timeout, signing through mID's `DeviceSigner` | `setup/device.rs` |
| the browser: `Browser` (start from Discover and the code, Reply, Ready, Settings, Result), a device's `Error` surfaced as `Failure::Remote(code)` | `setup/browser.rs` |

A record is checked whole (an adoption by mID's `Adoption::accept` against
this device and the pinned owner) before the first write; values are stored
as NVS's reader returns them (strings without a NUL, `blink_ms`
little-endian).

**Tests.** `tests/session_flow.rs`, eleven, the browser against the device
over the message bytes: a device set up end to end (every stored value
checked); a wrong code counted even when the guesser walks away; the 1, 2,
4, 8 s backoff, the lockout at five, a non-power-on reset changing nothing,
one guess per power cycle, the right code clearing the count; the window on
a provisioned device (closed without a power-on, the button's ten minutes to
the microsecond); `Busy` leaving the first session alone, `Order`, the idle
timeout, a wrong version, a fragment; a replay refused at the device (an old
Confirm against a fresh Reply), at the browser (an old Reply) and inside a
fresh session (an old Settings does not open); another device refused by the
browser; ten refused records that write nothing (a good name beside a bad
passphrase included); a rotated code (the old one stops working) and an
adoption accepted, then another owner's refused; a store that fails
mid-record answering `StoreFailed`; a Discover claiming four billion
iterations refused in under 100 ms. `tests/session_fuzz.rs` (the
`no_panic.rs` shape): 20,000 inputs through every decoder, 3,000 device
rounds across its three states, 3,000 browser rounds across its steps,
random bytes and mutations of a recorded session; no panic, every answer at
most 512 bytes, nothing written without a Result.

**176 tests on i686 and x86_64** (141 unit, 10 + 4 existing, 11 + 3 + 7
setup); the `no_std` builds for wasm32, the S3 and the ESP32 pass; clippy is
clean on the new code; the M1 fixture still matches its oracle.

**Two protocol fixes the tests found.**

- *The failure count.* The first spec said abandoning a session told the
  guesser nothing, so only a wrong Confirm counted. But Reply carries
  `confirmV`, which lets whoever sent Start check the one guess its share was
  made from, offline: a guesser who never sends Confirm was never counted.
  Now every answered Start counts, and a verified Confirm clears the count
  (spec sections 6 and 9).
- *The iteration bound.* The browser runs as many PBKDF2 iterations as
  Discover names; the first fuzz run spent twenty minutes of CPU on a
  mutated count before it was stopped. A device claiming four billion would
  freeze the person's page. Counts outside 1,000 to 2,000,000 are refused
  before any work, in `Secrets::derive` and in a stored record (spec 3.2).

**Not here:** mID's own helpers and its release (M3), the wasm half (M4),
the carriers (M5). On the ESP-IDF cell (C6) the settings keys are typed NVS
entries; the `Kv` there must write them so (M7).

## enc-ble M3: the session's identity pieces are mID's (2026-10-02)

`setup::reply_prehash` and `setup::verify_reply` now call
`rusty_esp_mid_core::setup` (so a high-s signature, which the first version
accepted, is refused by mID's rule), the device signs through mID's
`sign_reply`, and `setup.v` / `setup.fail` are read and written through mID's
accessors under mID's key names. Compile-time asserts tie this crate's
`SETUP_V_LEN`, `SHARE_LEN` and `CONFIRM_LEN` to mID's. 176 tests on i686 and
x86_64, unchanged; the `no_std` builds pass. Building against mID still uses
the umbrella's sibling patch until mID is released.

**M3 closed: signal against the released mID.** A copy of this repository
outside the umbrella (no `.cargo/config.toml`, so no sibling patch) resolves
`rusty_esp_mid-core` 0.1.1 from GitHub (`139dcb36`) and passes all 176 tests
(release, x86_64), the setup suites included. This repository's own changes
(the setup module, M1-M3) are not committed yet.

## enc-ble M4: PBKDF2 on the compression function (2026-10-02)

`setup::verifier`'s PBKDF2 absorbs the HMAC key's two pads once and runs
every later iteration as two `sha2::compress256` calls on one fixed,
pre-padded block (`U || 0x80 || 0.. || 768`), the state kept as words.
Byte-identical: `pbkdf2_is_the_generic_loop_byte_for_byte` holds it to the
old HMAC loop across keys of 0, 6, 63, 64, 65 and 100 bytes (over a block
is hashed first), 1 to 1,000 iterations and 1 to 80 bytes out, and
`pbkdf2_matches_rfc_7914_at_80000` to the RFC's second vector; the golden
session is unchanged. In wasm (V8, sha2 at `opt-level = 3`) 118 -> 110 ms
for 100,000 iterations; the larger lever was the opt-level (espino's
`wasm-release` now builds sha2 at 3). 178 tests on i686 and x86_64; the
`no_std` builds pass.

## enc-ble M5: the provisioning service carries the setup session (2026-10-02)

The plaintext path is gone: `credentials` (Wi-Fi in the clear) and the
public `scan` are retired from the table, their UUIDs not reused; `setup`
(`…-0104`, WRITE|READ|NOTIFY, 512) and `discover` (`…-0105`, READ, 59) carry
the session (the Janus umbrella's `docs/setup-protocol.md`, 11.1).

| piece | what |
|---|---|
| `provision::Provisioner<E: SetupEnv, N>` | the session's GATT router: `new(policy, devpub, reset, now, env)`, `boot` (a stored network adopted), `on_write`/`read` by UUID, `Outcome.answer` (the header to notify), `carrier_closed`, `advertising`, `window`, `button`, `tick`, `forget` (wipes `wifi.*`); the scan list goes out sealed in Ready |
| `provision::Env` | settings, identity, rng, signer as one `SetupEnv` |
| `setup::ResultCode::describe` | a refusal in words (the page and espino-web say the same) |
| `-esp` `ble` (trouble-host) | `att-queued-writes` on; `setup`/`discover` are `heapless::Vec` values; the answer stored after the write is acknowledged, its header sent with `notify_raw(.., false)`; `accept` returns `None` outside the window and races the advertising against the window's end (a legacy advertisement has no duration of its own) |
| `-esp` `idf::ble` (Bluedroid) | prepared writes assembled here (they were refused) and run on the execute; `setup`/`discover` answered by the app at the offset asked for; one peer at a time; `tick()` starts and stops the advertising with the window |
| `rusty_esp_signal-web` | the page's wasm (`SetupSession`, `offer`), `sim` = the device half behind this router |
| `docs/provision.html` | rebuilt on it: Connect, the code, the network; `tools/build-provision-page.py` inlines the wasm (`--check`) |

**Held to.** `provision` tests (10): a whole session over the table, the
refusals (status/discover not writable, the retired UUIDs no one's), a
wrong code then the peer leaving (Busy until `carrier_closed`), boot and
forget, a network that never joins reopening the window, `Debug` printing
neither the network nor the answer, the page agreeing with the table.
`tools/provision-page-check.mjs` (7): the page's own `session` script and
inlined wasm against `sim` through fake Web Bluetooth characteristics, the
notification delivered before and after the write's response; a wrong
code, another device (refused with no write), the settings checked before
sealing, a device refusal in words. Headless Chrome loads the page's wasm.
181 tests on i686 and x86_64; clippy clean (core, web host and wasm32, esp
`ble`). Firmwares (`c6-ble-provision`, `xiao-s3-sense-hal-ble-provision`,
`xiao-s3-sense-idf-ble-provision`) moved to the session with the identity
partition, the owner's `janus` namespace and the chip's RNG, and all three
build in release; the Bluedroid backend compiled on its first build.

**Found.** Result's phase is the one the record was applied in; a network's
join shows on `status` right after (the spec now says so). Bluedroid's
backend refused long writes outright, so a Settings longer than one ATT
packet could never have reached it. A network that never joins left a
provisioned device unreachable until a power cycle: the policy's
`Fallback` now opens the window.

**Not yet.** Nothing on the radio: Chrome's long write and long read, both
stacks with a real phone, and the device's time per session are M6 (C13)
and M7 (C6). espino-make's templates still generate the retired calls.

## enc-ble M6: the session on the radio, from an independent central (2026-10-02)

`tools/setup_v1.py` is the oracle's library (the golden fixture unchanged,
`--check`), with the browser's side added (`Prover`, `aead_open`), held to
the golden session byte for byte. `tools/setup_central.py` drives a board
over bleak with it: discover, wrong-code, wrong-device, session (a 263-byte
long write), replay, second-writer, lockout. On C13 (espino's ledger has the
table) every scenario behaved as the spec says; device time per session
about 265-271 ms (Start 259-262 ms). Core changes found on the way: the first
failed join of a network a session just applied reopens the window (spec 9),
and the trouble-host backend's `serve_observed` reports each message's time.
The page sends on Unlock's session and only on `Order` opens a fresh one (9
page checks).

**`ScanList::push`: one line per name** (2026-10-02). A mesh or dual-band
router answers a scan from several access points; the list keeps each name
once, at its strongest. 183 tests on both widths. On C13 the scan list
reached the page's side sealed in Ready (espino's ledger).

## enc-ble M7, the host half (2026-10-02, night)

`setup_central.py provision`: a network, sealed (the passphrase from an
environment variable, never printed), then the join watched on `status`;
`tools/ble-provision.ps1` in the umbrella is now its wrapper (the plaintext
tool it replaces is in git history). The page lists the device's networks and
says, for a typed name, that an SSID is case-sensitive and the ESP32 radios
are 2.4 GHz only. Page check 9/9, `--check` reproduces it.

**enc-ble M7 on the ESP32-CAM (2026-10-02, night).** The Bluedroid backend
logs each setup message's time (`setup msg=<kind> took_us=<n>`, as
`serve_observed` on Track B): Start 694-790 ms on the ESP32's portable P-256
path. `ble::advertised_name`: the name cut to what a legacy scan response
carries (29 bytes, at a character boundary), used by both backends; a 64-byte
owner's name made Bluedroid refuse the service. The prepared-write assembly
carried a 262-byte Settings on the radio. espino's ledger has the run.

## E0 of the experiments plan: the blob's bill — every later row's baseline (2026-10-03)

What esp-radio costs the XIAO ESP32-S3 Sense today, on C13 as it is (the
camera page provisioned over BLE, station on the owner's network, Track B,
esp-radio 1.0.0-beta.1 with `wifi`, `ble`, `coex`), so that E1 (the open
lower MAC) and every row after it is a difference from these numbers. One
board run, one image, serial plus the laptop's runner.

**Method.** The image is C13 as espino generates it plus probes
(`tools/e0-build.py` adds `tools/e0/e0.rs` to a copy; the cell's template
carries none of it):

- *Heap.* The 160 KiB internal heap is the probe's own array, painted
  `0xA5` before esp-alloc gets it; esp-alloc's `alloc-hooks` keep the live
  internal bytes, their peak, and every live block of 1 KiB or more. A
  freed block is painted again until the address is up.
- *Stacks.* esp-rtos (without its `esp-alloc` feature) takes each task's
  stack from `malloc_internal`: a 4-byte header, a 16-byte alignment
  prefix, then the blob's depth plus 64 B of watchpoint room rounded to
  16. Those blocks are 16·k + 4 bytes, which no buffer the radio takes is;
  the paint left at a stack's bottom is what it never used. The main stack
  (embassy's executor and every interrupt) is painted below main's frame at
  entry; the 2,480 B already above that frame count as used.
- *Jitter.* Every sleep of the camera task (1 ms per frame, 2 ms while it
  waits for a picture) is timed for how late it woke (a histogram in
  100 µs buckets), and the period between good grabs is kept, per state:
  radio never started (the first 30 s: the camera runs, esp-rtos is up,
  `WifiController::new` not yet called), joining, idle, under a UDP test,
  under the stream, both. The tables are in PSRAM (see the finding below).
- *Network.* The laptop is on the same home network (its 5 GHz side, the
  board on 2.4 GHz, one consumer router between; the laptop's own Wi-Fi was
  never taken). `tools/e0-run.py measure`: 100 pings; UDP echo 500 × 64 B
  and 300 × 1,400 B back to back, and 60 × 64 B 250 ms apart; 2,000 × 1,400 B
  up (counted and timed by the board) and down (sent by the board as fast as
  embassy-net's `send_to` takes them, counted and timed by the laptop) —
  all once at rest and once under `/stream`, read and JPEG-checked by the
  runner. The probe's own UDP socket and the page's buffers come from the
  heap after the `dhcp` line, so they are not in the radio's bill.
- *Surface.* `c-census.py blob` (new, the mirror of `rom`): the call and
  reference graph from the disassembly (a call or jump to a function's first
  address; an `l32r` literal holding one), each function charged to its
  archive through the linker map. The receive path is the closure from the
  station's six entries into the blob's layers (`wDev_ProcessFiq`,
  `wDev_ProcessRxSucData`, `ppRxPkt`, `sta_rx_cb`, `wpa_sm_rx_eapol`,
  `ieee80211_handle_rx_frm`): the blob calls between its layers through
  tables filled at init (`*_funcs_init`), so no call edge joins them and
  each needs its own root. A reference counts as an edge, so "reached" is
  an upper bound. `verify` closes on the image (1,484,561 B charged of
  1,484,561 loaded; 2,434 of 2,434 C symbols in the archive charged).

The DID on the boot line is the board's (unchanged); the page token is
redacted in every saved line. Raw files: `F:/jt-w/e0/` (serial.txt,
results.json, blob.json, census.json; run 1, on the build before the stack
detector was right, in `run1/`).

**RAM** (internal heap of 160 KiB; `used` is esp-alloc's region count, `live` the hooks' sum of live block sizes)

| point of the boot | internal used B | free B | live B | peak live B | PSRAM used B |
|---|---:|---:|---:|---:|---:|
| boot | 0 | 163,840 | 0 | 0 | 0 |
| camera | 80 | 163,760 | 78 | 78 | 98,560 |
| before-radio | 80 | 163,760 | 78 | 78 | 103,840 |
| radio-init | 53,272 | 110,568 | 53,222 | 53,394 | 103,840 |
| stack-spawned | 53,292 | 110,548 | 53,242 | 53,467 | 103,840 |
| dhcp | 54,100 | 109,740 | 54,044 | 60,892 | 103,840 |
| last minute line (t = 485 s) | 89,448 | 74,392 | 89,392 | 114,868 | 103,840 |

The radio's bill on the heap: **53,192 B** at `WifiController::new`, **54,020 B** once joined with an address (the embassy-net stack's own buffers are static, not in this).

esp-rtos stacks (the last reading): **2 tasks, 15,048 B** of the heap; the main stack (embassy and every interrupt): 11,840 B used at most of 17,336 B.

| stack at | size B | used at most B | never touched B |
|---|---:|---:|---:|
| `0x3fcaa23c` | 6,756 | 2,384 | 4,340 |
| `0x3fcb3c68` | 8,292 | 988 | 7,272 |

Live internal blocks of 1 KiB or more: before-radio 0 (0 B), radio-init 14 (43,480 B), dhcp 14 (43,480 B).

Static, from the census: the blob archives hold 366,344 B of code, 53,131 B of initialised data (flash constants and RAM `.data`) and 11,653 B of `.bss`.

**Jitter** (the camera task: its 1 ms and 2 ms sleeps, how late each woke; the period between good grabs)

| state | grabs | period mean µs | sd µs | min µs | max µs | sleeps | late mean µs | p50 ≤ | p99 ≤ | p99.9 ≤ | max µs |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| off | 96 | 311,399 | 59,506 | 1,175 | 324,180 | 3,534 | 24 | 100 | 100 | 100 | 9,416 |
| joining | 14 | 283,002 | 211,325 | 35,602 | 903,473 | 422 | 490 | 100 | 200 | 20,100 | 196,705 |
| idle | 624 | 317,904 | 43,746 | 1,146 | 432,295 | 22,077 | 74 | 100 | 100 | 700 | 115,833 |
| udp | 135 | 324,161 | 796 | 324,084 | 324,262 | 4,676 | 119 | 100 | 700 | 1,400 | 73,218 |
| stream | 462 | 312,935 | 58,437 | 34,232 | 468,263 | 15,928 | 118 | 100 | 900 | 1,700 | 107,113 |
| stream+udp | 199 | 308,596 | 68,634 | 34,050 | 468,265 | 6,635 | 173 | 100 | 1,100 | 2,500 | 105,452 |

**Latency** (ms, p50 / p99 / max; laptop on the home network's 5 GHz side, the board on 2.4 GHz, one router between)

| test | at rest | under the stream |
|---|---|---|
| ICMP echo, 100 | 117.0 / 264.0 / 264.0 (7 lost) | 107.0 / 253.0 / 253.0 (6 lost) |
| UDP echo 64 B, 500 | 3.0 / 257.27 / 271.75 | 3.52 / 261.95 / 335.22 |
| UDP echo 1,400 B, 300 | 4.72 / 260.39 / 305.29 | 5.87 / 267.03 / 426.56 |
| UDP echo 64 B, 60, 250 ms apart | 73.86 / 227.4 / 227.4 (2 lost) | 74.44 / 400.09 / 400.09 (9 lost) |

**Throughput** (2,000 datagrams of 1,400 B)

| direction | at rest | under the stream |
|---|---|---|
| up (laptop → board, board-timed) | 8.24 Mbit/s, 74.35 % lost | 5.35 Mbit/s, 85.9 % lost |
| down (board → laptop, laptop-timed) | 4.32 Mbit/s, 0.0 % lost | 2.57 Mbit/s, 0.0 % lost |

The stream itself while the tests ran: 646 JPEGs in 206.6 s (3.13 fps, 0.06 Mbit/s).

**Surface** (`c-census.py blob` on this image)

2,109 blob functions, 324,584 B of code. Rust enters **65** of them (a call or its address handed over); **1,636** (260,834 B) are reachable from those. The station's receive path, from its 6 entries, reaches **597 blob functions (100,404 B)** and 10 Rust functions.

| archive | functions | code B | Rust's entries | receive path | B |
|---|---:|---:|---:|---:|---:|
| `libnet80211.a` | 641 | 113,821 | 22 | 269 | 52,484 |
| `libbtdm_app.a` | 472 | 77,858 | 19 | 0 | 0 |
| `libpp.a` | 470 | 55,036 | 1 | 191 | 22,091 |
| `libwpa_supplicant.a` | 274 | 39,504 | 2 | 102 | 18,753 |
| `libphy.a` | 183 | 29,200 | 8 | 23 | 2,760 |
| `libprintf.a` | 17 | 4,540 | 0 | 12 | 4,316 |
| `libbtbb.a` | 18 | 2,963 | 1 | 0 | 0 |
| `libcoexist.a` | 34 | 1,662 | 12 | 0 | 0 |

**What the table says.**

- **RAM: 53 KB of the heap at init, and nothing more once joined.** The 14
  blocks of 1 KiB or more are 43,480 B of it: ten 2,220 B buffers
  (22,200 B), the two esp-rtos task stacks (15,048 B: 6,756 B, the Wi-Fi
  task's 6,656 B depth, used at most 2,384; and 8,292 B, used at most 988),
  one 4,632 B and one 1,600 B block; the other ~9.7 KB is small blocks.
  Joining adds 828 B. The later growth to 89,448 B is the page's buffers
  (15,360 B) and this probe's UDP socket (~20 KB), both taken after the
  `dhcp` line; the peak live, 114,868 B, is about 25 KB above that steady
  state: the radio's buffers in flight under load. Three quarters of the
  stacks' 15 KB was never touched. The archives add 11,653 B of `.bss`.
- **Jitter: the radio's tasks are the long tail.** With the radio never
  started the camera's sleeps woke at most 9.4 ms late and 99.9 % within
  100 µs. With it up and idle, p99.9 is 700 µs and the worst 116 ms;
  under the stream or a UDP test p99 is 0.7–1.1 ms and p99.9 1.4–2.5 ms,
  with single wakes 73–107 ms late. Joining is the worst state: 197 ms. The
  period between grabs is the sensor's (311–324 ms with the radio off as
  on; see the camera finding below), so the jitter shows in the sleeps, not
  the frame rate.
- **Latency: 3 ms when busy, 70–120 ms when it has been quiet.** Back to
  back, a 64 B UDP echo takes 3.0 ms at the median; 250 ms apart, 74 ms;
  pings 1 s apart, 117 ms (7 of 100 lost at rest). The router answers the
  laptop in 1–6 ms, and the blob reports power save off
  (`esp_wifi_get_ps` = `WIFI_PS_NONE`, which esp-radio sets at init), so the
  wake cost is not the station's modem sleep as configured; whether it is
  the router holding frames for a station it believes asleep, or the blob,
  is open. E1 runs the same runner on the same router, which separates the
  two. The p99 of every busy test sits at 255–267 ms whatever the size: the
  same stall, met about one time in a hundred.
- **Throughput: about 4 Mbit/s down, 5–8 Mbit/s up, and most of a burst
  dropped.** A burst of 2,000 datagrams from the laptop (sent at ~400
  Mbit/s) reached the board 513 times at rest (8.2 Mbit/s over its
  arrival) and 282 times under the stream; nothing says yet whether the
  router or the board's receive queue (esp-radio's rx queue of 5, X9) drops
  them. Down, `send_to` paces the board with no loss: 4.3 Mbit/s at rest,
  2.6 under the stream.
- **Surface: 597 blob functions, 100 KB, read every received frame.** Of
  2,109 blob functions linked (324,584 B of code), Rust enters 65 directly
  (64 without the probe's power-save query)
  (Wi-Fi, BLE, PHY and coexistence entry points) and 1,636 are reachable
  from them. The station's receive path reaches 597 (100,404 B): 269 in
  net80211, 191 in pp, 102 in the supplicant, 23 in the PHY and 12 in
  libprintf; Bluetooth's archives are off it. The blob calls back into 19
  Rust functions, 10 from the receive path (the allocator, `memmove`,
  `strlen`, time, randomness, the event post and printf).

**Found on the way.**

- *The main stack is what static RAM leaves.* The probe's first build put
  5 KB of timing tables and 3 KB of UDP buffers in static RAM; the main
  stack shrank from C13's 18,496 B to 9,120 B, and the provisioning boot
  (BLE up, the camera running) overflowed it. On the S3 the overflow
  watchpoint fires with no stack left to report from, so the board froze
  with no panic line: the camera's own periodic line stopped too. With the
  tables in PSRAM and the buffers on the heap, E0's main stack is 17,592 B
  (C13's less 904 B for the probe's block table), and the BLE provisioning
  boot used at most 15,472 B of it: under 2 KB to spare here, about 3 KB
  on C13 as it ships. Any cell that grows static RAM by a few KB should be checked
  against that.
- *The camera runs at 3.2 frames a second on this board.* The OV3660 at a
  20 MHz XCLK, QVGA JPEG, quality scale 12: 311 ms between pictures with
  the radio off, the same with it on; the stream delivered 3.13 fps (646
  JPEGs in 207 s, all whole). The cell's 15 fps cap is never reached. Not
  a radio cost, and not E0's to fix; the cell's own row. *Followed up the
  same morning (espino's ledger, "C13's frame rate"):* the run was at
  midnight, and the OV3660 stretches its frames in the dark (the reference
  capture firmware, 27.3 fps in X5's light, made 16.0 at dawn); but C13
  also lost most of what the sensor made, to a 32 KB DMA ring and a pacer
  that only spaced frames. With a 64 KB ring and a burst allowance, C13
  streams 14.7 fps where it streamed 6.1, in the same light.

## E1 of the experiments plan: the open lower MAC, host half — built, not booted (2026-10-03)

**Not Wi-Fi certified.** The decisions (the owner's, 2026-10-03): D-E1 yes,
D-E2 station only with the PHY untouched (no power, channel or regulatory
change by our code), D-E3 vendor and port to the family's pins. No
sacrificial S3 is on the bench, so nothing here has run on a radio: the
first boot waits for one (the bench rule; the authors' warning).

**What came in** (`vendor/open-mac/UPSTREAM.md` has the commits, licences,
credits and every change): OpenSensor's `esp-wifi-hal` at `f159fcf`, the
last commit before that fork began replacing `libphy` with Rust (so D-E2
holds by construction; upstream's S3 port was esp32-open-mac PR #23,
closed unmerged); the S3 Wi-Fi register mapping at `opensensor/esp-pacs`
`37b54bd` (esp-rs/esp-pacs#511), as a register crate of its own over
svd2rust's generic module from the PAC esp-hal 1.2 links, so nothing else
in an image is patched; FoA's `foa` and `foa_sta` at `39f4476`.

**The port** onto esp-hal 1.2.0 / esp-phy 0.3.0 / esp-wifi-sys 0.3.0 (from
1.1 / 0.2 / 0.2) took three changes beyond manifests: two OS-adapter slots
renamed as esp-wifi-sys 0.3 names them; `phy_printf` and `sprintf` defined
in Rust (libphy's only reasons to link `libprintf.a`: its diagnostics,
counted and never formatted); and a compile-time assertion that the two
OS-adapter slots the S3 ROM reads by offset (`_slowclk_cal_get` at 0x148,
`_coex_pti_get` at 0x1a8, as the reviewed C reference pins them from IDF
v5.4) are where 0.3 puts them. They are.

**Upstream's S3 host tests, on the port** (`tools/open-mac-host-tests.py`,
Windows with clang and a one-call `mmap` shim; the test files unchanged):
the C reference's regressions (3 groups), the Rust MAC initialization
against that reference access by access, `s3_mac_helpers` (6),
`s3_phy` (5), `ht20` (3), `rx` (4) and the S3 DMA list (5): all pass.

**The seam.** `crates/rusty_esp_signal-open` (not published: crates.io
refuses the vendored path dependencies; cells take it by git URL):
`stack()` gives the embassy-net stack with DHCP over FoA's station on the
chip's base MAC, `mac_task`/`sta_task`/`net_task` to spawn, `join()`, and
`run_station`/`station_task` driving the core's `StationPolicy` over FoA as
`hal::station` does over esp-radio (FoA has no awaitable link loss: a
joined station polls `connected()` once a second). Empty without its
`esp32s3` feature; the vendor tree is excluded from the workspace (a path
dependency inside it would otherwise join it and be built for the host).
`firmware/xiao-s3-open-sta` is the probe: one join from the build
environment, DHCP, 100 gateway pings.

**The census, the same camera page on both arms** (espino's C11 generated
as a station, and C15, the same manifest with `wifi-sta-open`; `verify`
closes on both):

| | C11 as a station (esp-radio) | C15 (the open MAC) |
|---|---:|---:|
| image B | 653,565 | **419,583** |
| C B (share) | 320,540 (49.0 %) | **33,507 (8.0 %)** |
| blob symbols / archives | 1,710 / 8 | **180 / 1** (`libphy.a`) |
| blob code / data / bss B | 276,000 / 44,540 / 10,920 | 32,200 / 1,307 / 46 |
| Rust code / data / bss B | 212,143 / 116,436 / 218,057 | 265,150 / 118,843 / 265,962 |
| static bss, all origins B | 324,736 | 328,228 |

`libnet80211`, `libpp`, `libwpa_supplicant`, `libprintf`, `libcoexist`,
`libbtbb`, `libregulatory`, `libespnow` are gone; `libphy.a` is the one
archive left, as E6's claim will say. The station, the WPA2 handshake and
the lower MAC are 53 KB more Rust. Static RAM is level (+3.5 KB): the open
MAC's receive buffers are static Rust where esp-radio takes its own from
the heap (53 KB at `WifiController::new`, E0), which the board run will
weigh.

**What waits for the board.** B1: the probe's first boot on a sacrificial
S3 (scan, WPA2 join, DHCP, pings). B2: C15 on the bench XIAO through C11's
kill test (WPA2, 100/100 pings, the page, ffmpeg decodes 1,500 frames of
`/stream`), and E0's table re-taken on both arms with the same runner
(`tools/e0-build.py` builds the probes on either; images
`F:/jt-w/e0/c11s-app.bin` 673,504 B and `c15-app.bin` 435,328 B). Until
then C15 is Host and `wifi-sta-open` a development build.

## E1 of the experiments plan: the open MAC on the XIAO — kill test passed, E0's table on both arms (2026-10-03)

**Not Wi-Fi certified.** No spare S3 exists, so by the owner's decision the
bench XIAO took the open MAC's first boot (a full 8 MB backup first; the
board was given back with its previous image, dldeploy's C13, restored
from it). The network was the owner's phone hotspot (2.4 GHz; the home
router's 2.4 GHz side was off that day), set into the board's nvs by C13's
setup session from Chrome, so no passphrase passed through any tool.

**B1, the first boot, found three things, in order:**

1. *The radio was deaf on our port.* The probe brought the MAC up in 28 ms
   and ran clean, but FoA's scan heard nothing on any channel, where
   esp-radio on the same board had just heard three networks. Upstream's
   own `wifi_smoke`, built at its pins (esp-hal 1.1, esp-phy 0.2), heard 43
   frames on the board; the same loop on ours heard 0. The cause:
   **esp-phy 0.3 brings a combo module's radio up out of the Wi-Fi RX
   state** (`phy_init_param_set(1)` in `enable_phy`, as ESP-IDF does) and
   leaves `phy_wifi_enable_set(1)` to the Wi-Fi driver; esp-radio does it,
   upstream's MAC (written against 0.2) does not. One call after
   `enable_phy()` (vendor/open-mac/UPSTREAM.md): 48 frames, and FoA's scan
   hears 20–26 networks a pass.
2. *FoA's join overflowed a 43 KB main stack* (a write to the stack guard,
   in the ROM's memset). The open arm now takes the BLE cells' dram2 heap
   split: 116,728 B of main stack; E0 measured the join's peak at 55,552 B.
3. *The station is silent.* `rusty_esp_signal-open` now counts joins and
   keeps the last failure's reason; C15 prints them until the link is up.
   That showed `unable-to-find-ess` while the phone's hotspot was off, and
   the join as soon as it came back.

**The kill test** (C11's, `tools/e1-kill.py`, over the hotspot; the laptop
on it for the run): C15 joined WPA2 and took a lease 60 ms after the link,
**100/100 pings** (9 / 37 / 166 ms min / median / max), the page **403**
without the token and **200** with it, and ffmpeg decoded **1,500 frames**
of `/stream` at 12.93 fps with no error; the DID the board's own. C15's
status stays **Host**: the plan keeps the open stack off by default (D-E2),
and making it orderable is the owner's call, not a test's.

**E0's table on both arms** (E0's probes, `tools/e0-build.py`, on C11 as a
station over esp-radio and on C15 over the open MAC: the same camera page,
the same 128 KB heap — C15's split 72 KB in dram2 + 56 KB static — the same
board, the same hotspot, one run each, back to back. A phone hotspot is a
noisier network than E0's router: the network rows are one run each and
read as such.)

| | C11 as a station (esp-radio) | C15 (the open MAC) |
|---|---:|---:|
| internal heap at radio init / once joined (B) | 53,108 / 53,912 | **108 / 108** |
| internal heap at the last minute line / peak live (B) | 89,260 / 115,394 | **35,308 / 35,393** |
| radio task stacks (esp-rtos) | 2, 15,048 B | **none** |
| main stack used at most / size (B) | 11,840 / 48,456 | 55,552 / 115,448 |
| static RAM, all origins (census, B) | 324,736 | 328,228 |
| camera sleep lateness, radio off: p99.9 / max | ≤100 µs / 4.2 ms | ≤100 µs / 3.4 ms |
| idle: p99.9 / max | ≤300 µs / 116 ms | **≤100 µs / 84 ms** |
| under UDP: p99 / max | ≤400 µs / 73 ms | ≤300 µs / 67 ms |
| under the stream: p99 / max | ≤600 µs / 93 ms | ≤600 µs / 101 ms |
| joining: p99.9 / max | ≤20.1 ms / 781 ms | ≤20.1 ms / 377 ms |
| ping at rest / under the stream, p50 / p99 (ms) | 25 / 104, 30 / 582 | **18 / 84, 19 / 107** |
| UDP echo 64 B at rest, p50 / p99 (ms), lost | 22.8 / 108, 0 | **12.9 / 80.5**, 10 of 500 |
| up, laptop → board (Mbit/s, lost): at rest / under the stream | 31.0 (0.15 %) / 9.2 (**59 %**) | 23.9 (0 %) / **14.8 (1.5 %)** |
| down, board → laptop (Mbit/s, lost): at rest / under the stream | **8.7 (0 %) / 13.6 (0 %)** | 3.5 (0.7 %) / 2.7 (0.6 %) |
| the stream while tested | 13.98 fps | 13.20 fps |

**What it says.** The heap is where the open MAC wins outright: esp-radio
takes 53 KB at init and peaks 80 KB above the open MAC over the run, whose
buffers are static (the census's +3.5 KB) and whose radio needs no task
stacks. The price is stack: FoA's join runs on the main stack and peaks at
55 KB, which the dram2 split pays for. Jitter is the same or better with
the open MAC, except while joining (its scan is busy). Latency is lower
and receiving under load holds (esp-radio dropped 59 % of a burst under
the stream; E0 suspected its receive queue of 5). **Sending is the open
MAC's weak side**: 2.5–5× slower board → laptop, with a little loss —
FoA's transmit path (one frame in flight, its rate control) is where E2's
and the next row's work starts. The census row is E0's: the same page is
653,565 B with 320,540 B of C in 8 archives on esp-radio, and 419,583 B
with 33,507 B (`libphy.a` alone) on the open MAC.

Raw: `F:/jt-w/e0/{c11s,c15}-results.json` and `-serial.txt` (tokens
redacted), `F:/jt-w/e1/c15-kill.json`.

### E1 follow-up: data frames at 54 Mbit/s with a fallback chain (2026-10-03)

FoA sent every data frame at OFDM 6 Mbit/s (its default; it has no rate
control). Data frames now start at the station's rate, which
`rusty_esp_signal-open` sets to 54 Mbit/s on joining, and step down the
802.11g ladder per failed attempt (54, 54, 48, 36, 24, 12, 6, 6: eight
attempts where upstream made seven at 6). OFDM only: FoA associates
without HT capabilities. FoA's `multi_rate_retry` had never compiled (it
names `heapless` without depending on it): fixed. Measured on the XIAO over
the owner's hotspot, the two C15 builds back to back with E0's runner:

| | 6 Mbit/s (before) | 54 Mbit/s chain |
|---|---:|---:|
| down, board → laptop, at rest (Mbit/s, lost) | 3.55 (1.3 %) | **6.25 (1.15 %)** |
| down under the stream | 3.01 (0.8 %) | **5.48 (0.55 %)** |
| the board's send loop, 2,000 × 1,400 B | 6.19 s (3.1 ms a frame) | **3.52 s (1.76 ms a frame)** |
| up, laptop → board, at rest / under the stream | 28.2 / 24.4 | 22.1 / 21.0 |
| ping p50 / p99 at rest (ms) | 12 / 187 | 26 / 65 |

Sending is 1.8× faster; esp-radio sent 8.7–13.6 Mbit/s in the same place
(earlier run). The airtime the rate saves (about 1.6 ms a 1,400-byte frame)
is nearly all the gain: about 1.5 ms a frame is left that does not depend
on the rate, which points at the transmit path in software (one frame in
flight, the completion and the wake per frame), not the radio. That is the
next measurement (esp-wifi-hal's `timing-probe`). The two runs are one each
over a phone hotspot; the receive and ping rows moved both ways between
them and are not attributed to the change.

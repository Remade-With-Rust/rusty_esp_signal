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

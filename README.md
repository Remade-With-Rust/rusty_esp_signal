# rusty_esp_signal

[![crates.io](https://img.shields.io/crates/v/rusty_esp_signal.svg)](https://crates.io/crates/rusty_esp_signal)
[![docs.rs](https://docs.rs/rusty_esp_signal/badge.svg)](https://docs.rs/rusty_esp_signal)
[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The radio-application layer remade in Rust: Wi-Fi CSI radar (presence/motion), LoRa point-to-point over lora-phy, BLE provisioning and telemetry over trouble-host, Wi-Fi station/AP lifecycle and ESP-NOW framing — every frame mID-signed. Memory safe, no_std core.

Part of **Janus**, the Remade-With-Rust programme that rebuilds the Espressif
ESP32 and Arduino application portfolio in memory-safe Rust so hardware makers
can ship products that plug straight into the MATA home computer.

- This package's plan: [docs/plans/rusty_esp_signal.md](docs/plans/rusty_esp_signal.md)
- The family plan: Janus `docs/plans/janus-mission.md` (umbrella repo)

**Claims discipline:** this README makes no performance or capability claim that
is not backed by a test, a benchmark ledger entry, or a kill test recorded in the
plan. "Scaffold" means scaffold.

## Status

**S0 shipped on the host (2026-09-02).** The whole radio-application core
exists in `no_std`, `forbid(unsafe)`, fixed-size memory, and is tested against
external oracles before any radio: **78 unit tests + 3 capture-oracle tests**,
clippy clean, `riscv32imac` / `riscv32imafc` checks green, `cargo deny` clean.

- `radar::csi` — presence from Wi-Fi CSI in fixed point; on a labelled
  ESP32-C6 dataset (empty room vs a person walking, CC BY 4.0) the held-out
  empty minute reads absent for all 2 951 judged frames and the walking
  minutes read present for 86 % / 61 % of theirs (`docs/LEDGER.md`).
- `radar::ld2410` — the HLK-LD2410/LD2410C UART protocol: streaming parser,
  every command, ACK decoders, verified against the protocol documents'
  own frames.
- `link` — the mID-authenticated session (P-256, Noise-KK shape, forward
  secrecy) and the 23-byte MAC'd envelope every ESP-NOW and LoRa frame
  travels in; replay window, key confirmation, 15 refusal tests.
- `wifi` — credentials that never print (redacted `Debug`, zeroised on
  drop) and the station policy: exponential back-off 1 s → 60 s, fallback
  to provisioning after ten failures.
- `ble` — the GATT table (provisioning, manifest, telemetry) as data under
  the Janus base UUID.
- `provision` (S3's host half, 2026-09-02) — the provisioning session over
  that table: a `credentials` write becomes the station policy's join, the
  `status` byte is the phase and every change a notification, `scan` is the
  networks strongest first as TLV, the secret never reads back and never
  prints; `docs/provision.html` is the Web Bluetooth page a phone opens (no
  app), and a test holds it to the same UUIDs, tags and phase names.
- `lora` — modem parameters, exact time-on-air (matches Semtech's calculator
  to the microsecond), region limits, a duty-cycle budget, the discovery
  beacon.

Each signal type answers to its own standard and was tested against its own
external oracle; the table is in the plan (§4b).

**The chip backends are written and compile (2026-09-02).**
`rusty_esp_signal-esp` carries one backend per signal type - the hardware TRNG
behind the core's `Rng` seam, the ESP-NOW transport under the authenticated
session, a CSI frame borrowed into the detector, an LD2410 UART reader, the
Wi-Fi station policy, a `lora-phy` P2P link, and a `trouble-host` GATT server
built from the core's table - and three ESP32-C6 firmware projects compile them
on **stable** Rust (Track B on RISC-V needs no espup):

| firmware | radios | ELF |
|---|---|---|
| `c6-mesh-node` | ESP-NOW, CSI, LD2410, station | 1 744 812 B |
| `c6-lora-p2p` | LoRa (SX1262) | 339 592 B |
| `c6-ble-provision` | BLE GATT | 932 836 B |

**Nothing has been flashed.** A build proves the types agree with the radio
crates; every on-radio number (S1-S6) waits for boards.

## What it is

- A pure-Rust remake of the *application* layer Espressif ships in C for this
  function. Same job, same protocols and file formats, new code, permissive
  licence, `forbid(unsafe)` in the core.
- Track-agnostic: the core crate is `no_std + alloc` and knows nothing about
  ESP-IDF or `esp-hal`. Backends are thin and feature-gated.

## What it is not

- Not a rewrite of the radio PHY, the ROM, or Espressif's Wi-Fi/BT controller
  blob. Where the silicon must be touched, the `-esp` crate **wraps** the
  esp-rs HAL or ESP-IDF and says so.
- Not a fork of esp-hal, esp-radio, espflash or ESP-IDF. Those are dependencies.

## Layout

```text
crates/rusty_esp_signal          facade: re-exports + prelude; the crate you depend on
crates/rusty_esp_signal-core     no_std + alloc; forbid(unsafe); types, traits, algorithms
crates/rusty_esp_signal-esp      the WRAP crate: `esp-hal` (Track B) | `esp-idf` (Track A)
firmware/                per-chip example projects, excluded from the workspace
docs/plans/              the mission plan for this package
```

## Two tracks, one core

| Track | Feature | Runtime | Use when |
|---|---|---|---|
| **A** | `esp-idf` | `std` on ESP-IDF (FreeRTOS) | you need iroh, TLS, or a driver ESP-IDF has and esp-hal lacks |
| **B** | `esp-hal` | `no_std` + Embassy | the purity path; every driver upstream in esp-rs |

The core compiles on both and on the host, which is where its tests run.

## Build

```sh
cargo test --workspace                                   # host: the tests
cargo check -p rusty_esp_signal-core --no-default-features \
  --target riscv32imac-unknown-none-elf                  # ESP32-C6 class, no alloc
cargo check -p rusty_esp_signal-core --no-default-features --features alloc \
  --target riscv32imac-unknown-none-elf
```

Firmware examples (Xtensa needs `espup`; RISC-V works on stable) are built from
their own directories under `firmware/`.

## License

MIT OR Apache-2.0, at your option.

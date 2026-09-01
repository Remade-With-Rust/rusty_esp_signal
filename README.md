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

**M0 — scaffold.** Crate layout, feature ladder and CI gates exist. Nothing here
runs on a chip yet. The first milestone with a kill test is listed in the plan.

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

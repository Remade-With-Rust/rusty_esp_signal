# The open MAC, vendored (experiments plan E1)

**Not Wi-Fi certified.** This is the open lower MAC and an 802.11 station
in Rust for the ESP32-S3, behind `rusty_esp_signal-esp`'s `open-mac`
feature (off by default). The PHY (RF bring-up, calibration, channel,
power) stays Espressif's `libphy`; nothing here changes transmit power,
channels or regulatory tables (the umbrella's `docs/plans/experiments.md`,
D-E2).

Everything here is MIT OR Apache-2.0, as upstream licensed it; the licence
files are beside each crate. Upstream authors keep their credit: the
esp32-open-mac project (Frostie314159 and contributors) for
`esp-wifi-hal` and FoA, okhsunrog for the C3 driver draft the S3 port built
on, and OpenSensor Engineering (Matt Davis) for the S3 port and the S3
register mapping.

## What, from where

| directory | upstream | commit | notes |
|---|---|---|---|
| `esp-wifi-hal/` | https://github.com/opensensor/esp-wifi-hal (`esp-wifi-hal/`) | `f159fcf` (2026-09-11) | the last commit before the fork began replacing `libphy` with Rust (`65bc9a2`). The S3 port was proposed upstream as https://github.com/esp32-open-mac/esp-wifi-hal/pull/23 (closed unmerged 2026-09-10; head `909be70`, an ancestor of this commit) |
| `esp32s3-wifi-regs/src/wifi.rs`, `src/wifi/` | https://github.com/opensensor/esp-pacs (`esp32s3/src/`) | `37b54bd` (2026-09-10) | svd2rust output for the Wi-Fi MAC; proposed upstream as https://github.com/esp-rs/esp-pacs/pull/511. `lib.rs.upstream.diff` is the 9 lines the commit added to the PAC's root; `svd/wifi.yaml` the patch they were generated from |
| `foa/`, `foa_sta/` | https://github.com/opensensor/FoA (fork of https://github.com/esp32-open-mac/FoA) | `39f4476` | what `f159fcf`'s station example pinned |

Taken as they were at those commits (H1); every change since is in git
history here and listed below.

## Changes (H2 onward)

The port onto the family's pins (esp-hal 1.2.0 and the esp-phy 0.3.0 /
esp-wifi-sys-esp32s3 0.3.0 / esp-sync 0.3.0 it pairs with; upstream was on
esp-hal 1.1, esp-phy 0.2.0, esp-wifi-sys 0.2.0):

- `esp-wifi-hal/Cargo.toml`: those pins; the S3 alone (the ESP32, S2 and C3
  features and their PAC / esp-wifi-sys dependencies removed); the
  workspace profiles and the `[patch.crates-io]` table removed (a vendored
  crate's patches are its firmware's business; nothing is patched).
- `esp-wifi-hal/src/lib.rs`: the PAC is `esp32s3-wifi-regs`.
- `esp-wifi-hal/src/ffi.rs`: esp-wifi-sys 0.3 names two OS-adapter slots
  `_wifi_pm_sleep_lock_acquire` / `_release` (0.2: `_wifi_apb80m_request` /
  `_release`); both `None`, as upstream. `phy_printf` and `sprintf` are
  defined in Rust (counted, the format string logged under `log`, the
  arguments never read), so the linker leaves `libprintf.a` out: libphy's
  only reason for it. Census on the probe: `libphy.a` the one C archive.
  And a compile-time check that the two OS-adapter slots the S3 ROM and
  the reviewed C reference pin (`_slowclk_cal_get` at 0x148,
  `_coex_pti_get` at 0x1a8) have not moved: they have not in 0.3.
- `esp-wifi-hal/src/ll.rs`: after `enable_phy()`, `phy_wifi_enable_set(1)`
  on the S3. esp-phy 0.3 brings a combo module's radio up out of the Wi-Fi
  RX state (as ESP-IDF does) and leaves turning RX on to the Wi-Fi driver;
  upstream was written against 0.2, and on the bench XIAO the port heard
  nothing on any channel until this (upstream's own `wifi_smoke`, built at
  its pins, heard 43 frames; the port with the call, 48).
- `esp32s3-wifi-regs/`: a crate of its own around the upstream files:
  `Cargo.toml`, `src/lib.rs` (the `WIFI` peripheral at `0x6003_3000`, as
  upstream's lib.rs lines, less their `Debug` impl), and svd2rust's
  `src/generic.rs` + `src/generic/raw.rs` copied unchanged from the esp32s3
  PAC 0.36.0 that esp-hal 1.2.0 links (MIT OR Apache-2.0).
- `foa/Cargo.toml`, `foa_sta/Cargo.toml`: out of their upstream workspace
  (each `workspace = true` replaced by the version the workspace named,
  esp-hal and esp-config moved to the family's 1.2.0 / 0.8.0), `esp-wifi-hal`
  by path, an `esp32s3` feature in place of `esp32` / `esp32s2`.

## Host tests

`host-tests/esp32s3/` is upstream's `docs/esp32s3/tests/` and
`docs/esp32s3/src/hal_mac.c` at `f159fcf`, unchanged; `host-tests/win/`
is ours (the one `mmap` call, on Windows). `tools/open-mac-host-tests.py`
runs what upstream's `run-rust-tests.sh` runs for the S3, against these
sources: the C reference's regressions, the Rust MAC initialization
against that reference, four of the crate's own test modules, the DMA
list. All pass on the port (2026-10-03).

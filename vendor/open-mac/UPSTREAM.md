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

None yet.

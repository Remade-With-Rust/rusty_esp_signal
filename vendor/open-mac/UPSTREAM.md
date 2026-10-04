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
| `ieee80211/` | https://crates.io/crates/ieee80211 0.5.9 (https://github.com/Frostie314159/ieee80211-rs `6a26b0a`) | the published crate | the frame parsers and EAPOL code under FoA; vendored for E2 (the umbrella's `docs/plans/e2-air-interface.md`), byte-identical to the published files in `4cf7d60` |

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
- `foa/Cargo.toml`, `foa/src/tx_queue.rs`: `multi_rate_retry` named
  `heapless` without depending on it (it never compiled upstream): the
  dependency added; the chain holds 8 rates (upstream 3).
- `foa_sta/Cargo.toml`, `foa_sta/src/runner.rs`: data frames retry down the
  802.11g ladder from the station's rate (two attempts at it, one a step,
  padded with 6 Mbit/s to eight), where upstream sent every data frame at
  6 Mbit/s with seven retries; other rates keep upstream's behaviour.
  `rusty_esp_signal-open` sets the station's rate to 54 Mbit/s on joining.
  Data frames also go without RTS/CTS (`Forced(false)`; upstream's driver
  default sends one before every unicast frame); `JANUS_OPEN_RTS=on`
  builds upstream's behaviour.
- `esp-wifi-hal/src/tx_stats.rs` (new) and its call in `async_driver.rs`:
  per-frame transmit counters (frames, exhausted, first-attempt successes,
  attempts, radio time), read with `tx_stats::snapshot()`.
- `esp32s3-wifi-regs/`: a crate of its own around the upstream files:
  `Cargo.toml`, `src/lib.rs` (the `WIFI` peripheral at `0x6003_3000`, as
  upstream's lib.rs lines, less their `Debug` impl), and svd2rust's
  `src/generic.rs` + `src/generic/raw.rs` copied unchanged from the esp32s3
  PAC 0.36.0 that esp-hal 1.2.0 links (MIT OR Apache-2.0).
- `foa/Cargo.toml`, `foa_sta/Cargo.toml`: out of their upstream workspace
  (each `workspace = true` replaced by the version the workspace named,
  esp-hal and esp-config moved to the family's 1.2.0 / 0.8.0), `esp-wifi-hal`
  by path, an `esp32s3` feature in place of `esp32` / `esp32s2`.

## Changes for E2 (the air interface under our rules)

- `foa/Cargo.toml`, `foa_sta/Cargo.toml`: `ieee80211` by path, the
  vendored copy.
- `ieee80211/src/crypto/key_mgmt.rs`, `deserialize_eapol_data_frame`
  (E2's F5): it panicked on frames anyone in range can send during a
  handshake, before any key is in play: an EAPOL frame ending before its key
  information (a slice past the end), key data longer than the frame (an
  `ok_or(..).unwrap()`), key data under 8 bytes (an underflow into a slice
  end). Now every read is checked, wrapped key data must be whole AES
  key-wrap blocks of at least 16 bytes, and encrypted key data without a
  MIC is refused before it is unwrapped (802.11-2020 12.7.2). The crate's
  own 49 tests pass; `host-tests/air/tests/eapol_deserialise.rs` is the
  regression.
- `ieee80211/src/frames/data_frame/mod.rs`, `potentially_wrapped_payload`
  (E2's F7): a data frame with the Protected bit set and a payload too short
  for its CCMP header panicked (an `unwrap`); now `None`, as the unprotected
  branch beside it answers. `host-tests/air/tests/data_frame.rs`.
- `ieee80211/src/crypto/crypto_header.rs`, `CryptoWrapper`'s parse (E2's
  F8): a payload shorter than its MIC underflowed into a slice end; now an
  error. Not reachable from FoA's station, which reads with
  `MicState::NotPresent` (the hardware strips the MIC); the corpus found it
  through the crate's API.
- `ieee80211/src/frames/data_frame/amsdu.rs`, the A-MSDU subframe parse
  (E2's F9): the offset was rounded up to four past the end of the bytes
  when the last subframe carries no padding (as the standard sends it), and
  the iterator then sliced out of bounds; the rounding now stops at the end.
  Not changed, noted (E2's F10): the subframe length is read little-endian
  where 802.11 (as 802.3) is big-endian; FoA's station does not negotiate
  HT, so an access point sends it no A-MSDU.
- `sta_handshake/` (ours, E2): the station's half of WPA2-PSK's 4-way and
  group-key handshakes as pure functions (no hardware, no clock, no
  randomness), so FoA's station and the host tests run one code. What it
  requires of each message is in its crate docs.
- `foa_sta/` on `sta_handshake` (E2's F1, F2, F3, F4, F6, F11):
  `operations/connect.rs`'s 4-way handshake reads and writes its frames
  through it (a GTK of any length but 16 bytes refused, where it panicked);
  `runner.rs` takes a group-key handshake after the join (it had none: the
  station did not answer a rekey), installs the new GTK
  (`rsn.rs`'s `update_gtksa`, commented out upstream) with its starting RSC,
  answers with message 2 protected under the PTK, refuses replayed group
  messages, and drops unprotected data frames once keys are installed (it
  passed them up to the network stack); no key material in any log line
  (the handshake printed the PMK, KCK, KEK, TK and GTK at `debug`).
  `host-tests/air/tests/handshake.rs` runs it against a simulated access
  point.
- `host-tests/air/tests/corpus.rs` (E2's A3): seeded mutations of synthetic
  frames and the crate's own published fixtures through the chain FoA's
  station runs; found F8 and F9 (58 and 2 panics in its first runs), clean
  since at 20,000 and 300,000 rounds a seed.

## Host tests

`host-tests/air/` (ours, E2): the receive path on the host, std, against
the vendored crates; `cargo test --release` in that directory.


`host-tests/esp32s3/` is upstream's `docs/esp32s3/tests/` and
`docs/esp32s3/src/hal_mac.c` at `f159fcf`, unchanged; `host-tests/win/`
is ours (the one `mmap` call, on Windows). `tools/open-mac-host-tests.py`
runs what upstream's `run-rust-tests.sh` runs for the S3, against these
sources: the C reference's regressions, the Rust MAC initialization
against that reference, four of the crate's own test modules, the DMA
list. All pass on the port (2026-10-03).

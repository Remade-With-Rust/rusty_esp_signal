# firmware/

Per-chip example projects for `rusty_esp_signal`. Each directory here is a
**separate cargo project**, excluded from the workspace, because every chip
needs its own target triple, linker script and (for Xtensa parts) its own
toolchain.

| project | chip | track | radios it ingests | status |
|---|---|---|---|---|
| [`c6-mesh-node`](c6-mesh-node/) | ESP32-C6 | B (`no_std`) | ESP-NOW (authenticated link), Wi-Fi CSI, LD2410 UART, Wi-Fi station | **builds** 2026-09-02, 1 744 812 B |
| [`c6-lora-p2p`](c6-lora-p2p/) | ESP32-C6 + SX1262 | B | LoRa P2P over `lora-phy` | **builds** 2026-09-02, 339 592 B |
| [`c6-ble-provision`](c6-ble-provision/) | ESP32-C6 | B | BLE GATT (provisioning, manifest, telemetry); the provisioning service carries the setup session, the settings and the device key in NVS | **builds** 2026-10-02 on the setup session, 1 145 896 B ELF (2026-09-02 on the plaintext TLV: 932 836 B) |
| [`xiao-s3-sense-idf-ble-provision`](xiao-s3-sense-idf-ble-provision/) | XIAO ESP32-S3 Sense | **A** (`std`, ESP-IDF, Bluedroid) | BLE GATT provisioning (the same contract, `idf::ble`: the setup session), then Wi-Fi station with the network the session applied | **builds** 2026-10-02 on the setup session, 1 948 948 B ELF (2026-09-04 on the plaintext TLV: 1 829 716 B ELF, app image 1 240 928 B) |
| [`xiao-s3-sense-hal-ble-provision`](xiao-s3-sense-hal-ble-provision/) | XIAO ESP32-S3 Sense | B (`no_std`, trouble-host) | the same, with no ESP-IDF: the setup session, the join, a restart into station mode | **builds** 2026-10-02 on the setup session, 1 311 316 B ELF |
| [`c6-s1-link`](c6-s1-link/) | ESP32-C6 (also the S3 and the plain ESP32, by feature) | B | ESP-NOW on esp-radio: S1's two halves of the authenticated link, one source; `JANUS_S1_REARM_S` restarts it after its verdict (a board with no reset line) | **builds**; its responder on an ESP32-CAM was the blob's half of E4's passes (2026-10-04), and its initiator on the XIAO the baseline: 950 to 960 of 1,000 round trips on broadcast |
| [`xiao-s3-open-link`](xiao-s3-open-link/) | XIAO ESP32-S3 | B, **open MAC** | the same link on raw ESP-NOW frames it builds itself (`rusty_esp_signal-open::raw_link`): no esp-radio, no `libespnow`; S1's two roles. Not Wi-Fi certified | **ran on the XIAO** 2026-10-04 against the blob's responder: 1000 of 1000 round trips, three passes, 6.9 to 7.0 s, no heap in use; app image 192 416 B (the blob's S1 for the S3: 471 776 B) |
| [`espnow-relay`](espnow-relay/) | ESP32-C6, the S3, the plain ESP32 | B | ESP-NOW on esp-radio, passed to and from the serial port as text lines: a bench relay that holds no key (E4); `JANUS_RELAY_BAUD` sets the line's speed | **builds** 2026-10-04; on an ESP32-CAM at 460800 baud it carried E4's kill test: a 540 512 B signed update in 46.9 s, no datagram lost |

A plain ESP32 older than revision 3.0 (the ESP32-CAM on the bench is 1.0)
needs `ESP_HAL_CONFIG_MIN_CHIP_REVISION=100` in the build's environment:
esp-hal builds for 3.0 unless told, and both the flasher and the loader
refuse the image otherwise.

The provisioning firmwares take a session only once a setup code's verifier
(`setup.v`) is in the board's settings (`nvs`, namespace `janus`), which the
portal (espino) writes at flash time; without one, Discover offers no code.

**Of this table, only E4's three have run on a board** (`c6-s1-link`,
`xiao-s3-open-link`, `espnow-relay`: `docs/LEDGER.md`, "E4"). Every other
on-radio number is a kill test in `docs/LEDGER.md` waiting for boards
(S1–S6).

## Building

Track B on a RISC-V part needs **no espup**: the C6 builds on stable Rust with
the `riscv32imac-unknown-none-elf` target.

```sh
rustup target add riscv32imac-unknown-none-elf
cd firmware/c6-mesh-node && cargo build --release
```

Inside the Janus umbrella run `python tools/gen-sibling-patches.py` once so the
sibling crates resolve to the local checkouts; a standalone clone resolves them
from GitHub. On Windows set a short `CARGO_TARGET_DIR`.

Track A on the XIAO needs the Espressif toolchain (`espup install`, the
`esp` channel named in the project's `rust-toolchain.toml`), ESP-IDF v5.5.1
in the global tools dir (fetched on the first build), `ldproxy`, and on
Windows the Xtensa toolchain binaries and `libclang` on `PATH` /
`LIBCLANG_PATH` (see `rusty_esp_iroh/firmware/xiao-s3-sense-idf-mesh/README.md`
for the exact environment). The first build configures the IDF with
Bluedroid: about six and a half minutes on the laptop.

## Rules

- Depend on this repo's crates by **path** (`../../crates/...`) inside a
  firmware; depend on siblings by git URL as usual.
- **The chip feature is selected here, never in the library.** `esp-hal` refuses
  to build without exactly one, and a library that picked one would fix the chip
  for every consumer. The firmware turns on `rusty_esp_signal-esp`'s backend
  features and its own `esp-hal`/`esp-radio` chip feature; cargo's feature
  unification compiles the backends for that chip.
- Release profile for a chip: `opt-level = "s"` (or `"z"`), `lto = "fat"`,
  `codegen-units = 1`, `panic = "abort"`.
- A firmware example is not a test. The library's tests run on the host.

# firmware/

Per-chip example projects for `rusty_esp_signal`. Each directory here is a
**separate cargo project**, excluded from the workspace, because every chip
needs its own target triple, linker script and (for Xtensa parts) its own
toolchain.

| project | chip | track | radios it ingests | status |
|---|---|---|---|---|
| [`c6-mesh-node`](c6-mesh-node/) | ESP32-C6 | B (`no_std`) | ESP-NOW (authenticated link), Wi-Fi CSI, LD2410 UART, Wi-Fi station | **builds** 2026-09-02, 1 744 812 B |
| [`c6-lora-p2p`](c6-lora-p2p/) | ESP32-C6 + SX1262 | B | LoRa P2P over `lora-phy` | **builds** 2026-09-02, 339 592 B |
| [`c6-ble-provision`](c6-ble-provision/) | ESP32-C6 | B | BLE GATT (provisioning, manifest, telemetry) | **builds** 2026-09-02, 932 836 B |

**Nothing has been flashed.** Every on-radio number is a kill test in
`docs/LEDGER.md` waiting for boards (S1–S6).

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

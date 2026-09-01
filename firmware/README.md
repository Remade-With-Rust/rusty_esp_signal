# firmware/

Per-chip example projects for `rusty_esp_signal`. Each directory here is a **separate
cargo project**, excluded from the workspace, because every chip needs its own
target triple, linker script and (for Xtensa parts) its own toolchain. n0's
iroh-on-ESP32 work reached the same conclusion: keep the firmware projects out
of the library workspace so architecture-specific patches never leak into it.

Naming: `<board>-<track>-<demo>/`, for example `xiao-s3-sense-idf-mjpeg/`.

| Track | Generate with | Target |
|---|---|---|
| A (`std`, ESP-IDF) | `cargo generate esp-rs/esp-idf-template` | `xtensa-esp32s3-espidf`, `riscv32imac-esp-espidf` |
| B (`no_std`, esp-hal) | `esp-generate --chip esp32c6 <name>` | `riscv32imac-unknown-none-elf`, `xtensa-esp32s3-none-elf` |

Rules:

- Depend on this repo's crates by **path** (`../../crates/rusty_esp_signal`) inside a
  firmware example; depend on siblings by git URL as usual.
- Release profile for a chip: `opt-level = "s"` (or `"z"`), `lto = true`,
  `codegen-units = 1`, `panic = "abort"`.
- A firmware example is not a test. The library's tests run on the host.

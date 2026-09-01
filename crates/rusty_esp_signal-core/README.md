# rusty_esp_signal-core

The pure `no_std + alloc` core of [`rusty_esp_signal`](https://crates.io/crates/rusty_esp_signal):
types, traits and algorithms with no drivers, no allocator and no product types.
`forbid(unsafe)`. Tests run on the host; the crate compiles for riscv32 bare
metal with `--no-default-features`.

Feature ladder: `std` ⊃ `alloc` ⊃ core-only.

Part of Janus (Remade With Rust). Plan: `docs/plans/rusty_esp_signal.md` in the repo.

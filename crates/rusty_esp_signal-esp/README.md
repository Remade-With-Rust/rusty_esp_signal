# rusty_esp_signal-esp

The chip backends for [`rusty_esp_signal`](https://crates.io/crates/rusty_esp_signal): the
**wrap** crate. Exactly one track is enabled at a time:

- `esp-hal` — Track B, bare metal: esp-hal + Embassy (`no_std`).
- `esp-idf` — Track A, `std` on ESP-IDF via esp-idf-svc.

With neither feature the crate compiles to the backend traits only, so the host
build and the tests never need a chip. This is the only crate in the workspace
that may contain a fenced `unsafe` block, and only at a DMA or FFI boundary,
with the invariant written beside it.

Part of Janus (Remade With Rust). Plan: `docs/plans/rusty_esp_signal.md` in the repo.

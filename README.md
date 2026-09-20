### In The Wild with 39 Active Installs

FREE RAG Converter Online -- <a href="https://RAGconverter.com">RAGconverter.com</a>

# rusty_esp_signal

[![Remade With Rust](https://img.shields.io/badge/Remade%20With-Rust-000?logo=rust&logoColor=fff)](https://github.com/remade-with-rust) [![By Mata Network](https://img.shields.io/badge/by-Mata%20Network-5b2be0)](https://www.mata.network) [![crates.io](https://img.shields.io/crates/v/rusty_esp_signal.svg)](https://crates.io/crates/rusty_esp_signal) [![docs.rs](https://docs.rs/rusty_esp_signal/badge.svg)](https://docs.rs/rusty_esp_signal) [![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/Remade-With-Rust/rusty_esp_signal/blob/main/LICENSE-MIT)

Radios and sensing for the **Janus** ESP32 family: Wi-Fi station policy,
provisioning a device that has no network yet, a peer-to-peer link for chips
with no access point, long-range radio, presence from channel state, and a
millimetre-wave radar. Pure Rust, no C, no FFI, `no_std` by default.

* **A device with no network can still be given one.** A browser hands an
  ESP32-CAM its credentials over Bluetooth, on a page with no app and no
  server: **joined in 7.5 seconds**, and the next boot joins alone in 9.5
  seconds with Bluetooth off entirely. The passphrase never reaches a server, a
  log, or a command line.
* **Presence from the Wi-Fi channel itself**, judged against a labelled public
  capture rather than our own recording: an empty room reads 17.4% occupancy
  and a walking person 86.1%, with a held-out pair at 60.8%.
* **A link where there is no access point.** Peer-to-peer framing sized to fit:
  227 bytes of payload inside a 250-byte datagram, with hello, accept and
  confirm at 84, 100 and 18 bytes.
* **The radar's own documentation is wrong, and the tests say where.** Field
  offsets in the vendor datasheet do not match the vendor's tool; ours follow
  the wire.

## What has run on hardware

| what | measured |
|---|---|
| provisioning over Bluetooth | **joined in 7.5 s**; the reboot joins alone in **9.5 s** with no Bluetooth |
| the identity behind it | the same `did:mata` held across six reflashes |
| the advertisement budget | 31 bytes, which is what forced the name and service layout |
| a failed join | must not spend the modem — a device that cannot join has to stay askable |

**A known gap, stated plainly:** channel-state presence and the peer-to-peer
link are verified against captures and against the host, not yet on two chips
talking to each other. Those rows need boards that are not on this bench, and
the ledger says so rather than implying otherwise.

Every number, with the run that produced it:
[`docs/LEDGER.md`](https://github.com/Remade-With-Rust/rusty_esp_signal/blob/main/docs/LEDGER.md).

## Using it

```rust
use rusty_esp_signal::prelude::*;

// A device with no credentials advertises itself and waits to be told.
let mut provisioner = Provisioner::new("janus-doorbell");
if let Some((ssid, psk)) = provisioner.poll()? {
    match wifi.join(&ssid, &psk) {
        Ok(()) => provisioner.report(true),
        // A refusal has to leave the device askable, not spent.
        Err(_) => provisioner.report(false),
    }
}
```

## Two tracks

| track | what it is | this crate |
|---|---|---|
| **A** | `std` on ESP-IDF — Wi-Fi, Bluetooth provisioning, the radar's serial port | `rusty_esp_signal-esp --features esp-idf` |
| **B** | `no_std` on `esp-hal` — the protocols, the detector, the framing | `rusty_esp_signal-core`, default |

## Part of Janus

**Janus** rebuilds the Espressif ESP32 and Arduino application portfolio as
independent, memory-safe Rust packages — so a hardware maker can ship a device
that the [MATA](https://www.mata.network) home computer discovers, catalogs honestly, adopts
under its own identity, and pays for. Ten packages, three layers, and the
dependency direction never reverses.

| layer | packages |
|---|---|
| **0 — the vocabulary** | [`rusty_esp_core`](https://crates.io/crates/rusty_esp_core) · [`rusty_esp_dsp`](https://crates.io/crates/rusty_esp_dsp) |
| **1 — the functions** | [`rusty_esp_image`](https://crates.io/crates/rusty_esp_image) · [`rusty_esp_video`](https://crates.io/crates/rusty_esp_video) · [`rusty_esp_audio`](https://crates.io/crates/rusty_esp_audio) · [`rusty_esp_signal`](https://crates.io/crates/rusty_esp_signal) · [`rusty_esp_mid`](https://crates.io/crates/rusty_esp_mid) · [`rusty_esp_iroh`](https://crates.io/crates/rusty_esp_iroh) |
| **2 — the surfaces** | [`rusty_esp_arduino`](https://crates.io/crates/rusty_esp_arduino) — the sketch facade · `espino` — the maker's CLI (not published) |

Every package is host-verified against an external oracle and keeps a ledger
in which no number appears without the run that produced it. **Five of seven
device profiles have now run their kill tests on real silicon**, three of them
over a Wi-Fi network the board hosts itself.

Also check out the rest of [Remade With Rust](https://github.com/remade-with-rust) — including
[`rusty_alloc`](https://crates.io/crates/rusty_alloc), the pure-Rust rebuild of
mimalloc that these firmwares run on, and
[`rusty_jpeg`](https://crates.io/crates/rusty_jpeg), the JPEG engine behind the
camera path — and our sister project
[remade_ffmpeg_rs](https://github.com/Remade-With-Rust/remade_ffmpeg_rs), a ground-up Rust rebuild of FFmpeg.

## About Mata Network

[Mata Network](https://www.mata.network) builds sovereign, self-hostable infrastructure.
**Remade With Rust** is our open-source home for the permissively-licensed
building blocks that work depends on.

## License

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](https://github.com/Remade-With-Rust/rusty_esp_signal/blob/main/LICENSE-MIT)
and [LICENSE-APACHE](https://github.com/Remade-With-Rust/rusty_esp_signal/blob/main/LICENSE-APACHE).

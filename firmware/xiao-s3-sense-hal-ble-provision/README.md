# xiao-s3-sense-hal-ble-provision

Janus **S3 on Track B** (`no_std` on esp-hal): the XIAO ESP32-S3 Sense
provisioned over BLE with no ESP-IDF and no Bluedroid under it — row X3 of
the killing-C plan. The core's GATT table served by `trouble-host` over
esp-radio's BLE controller, the encrypted setup session (SPAKE2+, the
umbrella's `docs/setup-protocol.md`, 11.1) carried to the core's
`Provisioner`, the join by esp-radio's station, the phase back to the phone
as a `status` notification, and a restart into station mode.

It is [`xiao-s3-sense-idf-ble-provision`](../xiao-s3-sense-idf-ble-provision)
rebuilt, and [`c6-ble-provision`](../c6-ble-provision)'s stack with the join
the C6 firmware has no Wi-Fi stack for. Where the ESP-IDF twin ran
Bluedroid's host, FreeRTOS and lwIP in C, this runs `trouble-host`, esp-rtos
and `smoltcp` in Rust. What is left in C is Espressif's radio blob and the
2nd-stage bootloader.

## The setup session

The provisioning service carries `status` (the phase), `setup` (the
session's messages) and `discover`; `credentials` (the plaintext Wi-Fi TLV)
and the public `scan` are retired. The phone reads `discover`, subscribes to
`setup`, and writes the session's messages to it (a long write when one
exceeds the MTU); the device stores each answer in `setup` and notifies its
two header bytes, and the phone reads it. The network arrives sealed in the
session's Settings, and the scan list leaves sealed in its Ready.

**A device takes a session only once a setup code's verifier (`setup.v`) is
in its settings**, which the portal (espino) writes into the `nvs`
partition at flash time. Without one, Discover offers no code and every
Start is answered `NoVerifier`.

The settings are the `janus` namespace of the `nvs` partition, read and
written by the Rust NVS module over esp-storage: the verifier, the failure
count, and what a session applies (the network among them). The device key
lives in the `identity` partition's `janus` namespace, minted on the first
boot and loaded on every other; a partition table without `identity` keeps
it in `nvs`, and a re-provision then re-mints the DID.

The service is advertised only while the setup window is open (protocol
section 9): from boot until a network is stored, and for ten minutes after a
power-on once one is. A software or watchdog reset does not open it.

## Two boots

1. **Provisioning** (the window is open): advertise as `janus-s3` with the
   provisioning service UUID in the advertisement and the name in the scan
   response; carry the session; join with the phone still connected (the
   S3's one modem is shared by both radios, esp-radio's `coex`); notify
   `Connected`; software reset. A provisioned board's power-on window that
   closes with nobody connected also resets into station mode.
2. **Station** (a stored network, the window closed): Bluetooth is never
   initialised. The station joins through `rusty_esp_signal-esp::hal::netstack`
   with DHCP, prints its address and the join time, then a line every ten
   seconds.

The network is in NVS, so it survives a power cycle; the RTC stash this
firmware used before row X4 is gone.

## Prerequisites (one-time, this machine)

- `espup install` (the `esp` Xtensa toolchain) and `cargo install espflash`.
  No ESP-IDF, no Python, no CMake, no `ldproxy`.

## Build

Nothing is compiled in: the network arrives over the air.

```sh
export CARGO_TARGET_DIR=F:/jt-mic   # any short directory
cargo build --release
```

## The run (needs the board)

```sh
espino flash   --board xiao-esp32s3-sense --port COM4 --app $CARGO_TARGET_DIR/xtensa-esp32s3-none-elf/release/xiao-s3-sense-hal-ble-provision
espino monitor --board xiao-esp32s3-sense --port COM4 --timeout 120 > provision.txt
```

The board's `nvs` partition must hold a setup code's verifier first (the
portal writes it at flash time). Then provision it from Chrome: `espino
serve`, open `http://127.0.0.1:7333/provision`, choose the device, type the
setup code and the network. The page runs the session's browser half in
wasm; the passphrase leaves it sealed, and never goes to a file, a commit,
or a server. (`tools/ble-provision.ps1` speaks the retired plaintext
contract and no longer provisions this firmware.)

## What the monitor says

```
== JANUS BLE xiao-s3 track=B mode=provision reset=… ==
BLE device did:mata:…
BLE advertising name=janus-s3 boot_ms=…
BLE peer connected at_ms=…
BLE provisioned: Provisioner { phase: Connecting, has_credentials: true, … } -> Connect
BLE joined join_ms=…
BLE restarting into station mode
== JANUS BLE xiao-s3 track=B mode=station reset=… ==
BLE device did:mata:…
BLE station ssid_len=… joining
BLE mode=station ip=… join_ms=… dhcp_ms=…
BLE station up_s=10 link=up ip=…
```

A failed join prints `BLE join failed: …`, notifies `Backoff`, and keeps the
phone connected. The network was stored when the session applied it, so the
window is now the provisioned one: a new session with a corrected network is
the retry while a power-on's ten minutes last, and after them a power cycle
opens the window again. Measured on the XIAO 2026-09-30 (the plaintext
contract) with a network that does not exist: `Connecting` notified 23 ms
after the write, `Backoff` 3.2 s later, the link still up a minute on.

## The kill test (X3) — passed 2026-09-30, on the retired plaintext contract

C6's kill test, on the XIAO, with the S3's own name: the network written
over Web Bluetooth (the page, or `tools/ble-provision.ps1`, which speaks
the same contract); the device joins, the status reads `Connected`, the
device restarts into station mode with no Bluetooth up (a scan afterwards
finds no `janus-s3`), and prints its address; the census shows no C archive
but the blob.

Run on an open 2.4 GHz network (`Tineco_5413`, channel 1) through
`tools/x3-kill-test.ps1 -Ssid Tineco_5413`: write `Success`; `Connecting`
and `Connected` notified 11 and 12 ms later; `joined join_ms=14`; the
software reset; `mode=station` with no host line; `ip=192.168.0.100
join_ms=64 dhcp_ms=254` from boot; link up for the two-minute log; a scan
afterwards with nothing named `janus-s3`. Your own WPA2 network is the same
script with `-PskEnv JANUS_WIFI_PASS` and the variable set in your shell.

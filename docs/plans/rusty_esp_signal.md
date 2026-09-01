# rusty_esp_signal — mission plan

**One sentence:** the radio *application* layer remade in Rust — Wi-Fi CSI
radar (presence, motion, breathing), ESP-NOW and LoRa point-to-point links
whose every session is mID-authenticated, BLE provisioning and telemetry
services, Wi-Fi station/AP lifecycle, and mmWave radar modules over UART —
over the esp-rs radio stack it does not try to replace.

Family plan: Janus `docs/plans/janus-mission.md`. Layer 1 · connectivity.
Depends on `rusty_esp_core` and `rusty_esp_mid` (session authentication).

Written 2026-09-01. Status: **scaffold.**

---

## 1. Espressif map

| Espressif item | Job | Class | Janus |
|---|---|---|---|
| **ESP-CSI** examples, `esp-radar` component (motion from subcarrier amplitude variance; breathing at 0.2–0.5 Hz; positioning) | presence & motion from Wi-Fi | **REMAKE** the algorithms | `radar::csi::{CsiFrame, Features, PresenceDetector, MotionDetector, BreathDetector}` |
| `esp_wifi_set_csi_rx_cb` / esp-radio `wifi::csi` (`csi` + `unstable`), `esp-csi-rs` collector (sniffer / station / AP / emitter) | CSI capture | **WRAP** | `-esp`: `esp-csi-rs` 0.10 (Track B); esp-idf CSI callback (Track A) |
| HLK-LD2410/LD2410C/LD2450 mmWave modules (HiLink UART protocol) | radar without CSI | REMAKE the protocol | `radar::ld2410::{Frame, Target, Config}` parser + command builder |
| **ESP-NOW** (`esp_now.h`) | connectionless 2.4 GHz frames, 250 B | WRAP the radio; **REMAKE** the envelope | `link::{Envelope, Session}` over esp-radio `esp_now` |
| `wifi_provisioning` (BLE / SoftAP, protocomm, security 1/2) | credentials in | REMAKE the flow with mID | `wifi::{Provisioner, Credentials}`; BLE service in `ble::provisioning` |
| Wi-Fi station / SoftAP lifecycle, scan, RSSI | connectivity | WRAP + a REMADE policy | `wifi::StationPolicy` (reconnect, AP-fallback → provisioning) |
| NimBLE / Bluedroid GATT servers | BLE | WRAP (`trouble-host` + `bt-hci` Track B; esp-idf-svc `bt` Track A) | `ble::{ProvisioningService, ManifestService, TelemetryService}` — GATT **definitions** live in core |
| (none — Espressif has no LoRa) SX126x / SX127x | sub-GHz P2P | WRAP `lora-phy` 3.0; **REMAKE** framing | `lora::{Beacon, P2pFrame, Link}`; `lorawan-device` optional behind `lorawan` |
| 802.15.4 / Thread / Zigbee (C6, H2) | mesh radios | **out of v1** | mata-master's Thread border router plan owns this; a Janus node as an RCP is a later item |
| Wi-Fi/BT controller blob, RF cal, MAC in ROM | PHY | **NEVER** | |

## 2. Crate surface

### `rusty_esp_signal-core` (`no_std`, `forbid(unsafe)`)

```rust
pub mod radar {
    pub mod csi {
        pub struct CsiFrame<'a> { pub timestamp: Micros, pub rssi: i8, pub channel: u8, pub iq: &'a [i8] /* interleaved I,Q per subcarrier */ }
        pub struct Features { pub amplitude: [u16; MAX_SUBCARRIERS], pub mean: u16, pub variance: u32 }   // fixed-point
        pub struct PresenceDetector { /* moving variance over a ring of N frames, hysteresis */ }
        pub struct MotionDetector; pub struct BreathDetector; /* band-pass 0.1–0.6 Hz on amplitude, peak pick */
        pub enum Verdict { Absent, Present { motion: u8 }, Breathing { bpm: u8 } }
    }
    pub mod ld2410 { pub struct Parser; pub struct Report { pub moving: Option<Target>, pub still: Option<Target> } }
}
pub mod link {
    /// Sign the SESSION, MAC the FRAMES: a P-256 ECDH session key (from rusty_esp_mid), then
    /// HMAC-SHA256 truncated to 16 bytes per frame. ESP-NOW's 250-byte MTU leaves ~200 B of payload.
    pub struct Envelope<'a> { pub ver: u8, pub session: u16, pub seq: u32, pub payload: &'a [u8], pub tag: [u8; 16] }
    pub struct Session { /* key, send seq, receive window (replay), expiry */ }
    pub struct Handshake; /* Hello(signed by device key) -> Accept(signed) -> derived key */
}
pub mod wifi { pub struct Credentials { ssid, psk }; pub enum Phase { Unprovisioned, Connecting, Connected, Fallback }; pub struct StationPolicy; }
pub mod ble  { pub const SERVICE_PROVISIONING: Uuid128; pub const SERVICE_MANIFEST: Uuid128; pub const SERVICE_TELEMETRY: Uuid128;
               pub struct GattTable; /* characteristic ids, properties, sizes — data */ }
pub mod lora { pub struct Params { sf, bw, cr, freq_hz, power_dbm }; pub struct Beacon; pub struct P2pFrame<'a>; }
```

Rules: every detector is developed on the host from **recorded captures**
against an external reference (esp-csi's own outputs, hand labels) before it
touches a radio — the codec bring-up discipline. Fixed-point only in
detectors; `f32` is allowed on the host oracle side. Session establishment
uses `rusty_esp_mid` signatures; frames use a MAC, because a 64-byte
signature per LoRa frame is airtime nobody has.

### `rusty_esp_signal-esp`

| Feature | Backend |
|---|---|
| `esp-hal` (Track B, the primary track for this package) | esp-radio 1.0-beta (`wifi`, `esp_now`, `ble` controller, `csi`), `esp-csi-rs` collector, `trouble-host` GATT server, `lora-phy` over `esp_hal::spi` + Embassy |
| `esp-idf` (Track A) | esp-idf-svc `wifi` + CSI callback, `espnow`, Bluedroid GATT, `lora-phy` over `esp-idf-hal` SPI |

Radio modules are features (`wifi`, `csi`, `espnow`, `ble`, `lora`, `mmwave`)
inside one `-esp` crate. Split into `-radar` / `-wifi` / `-ble` / `-lora`
crates when any one exceeds a few thousand lines, not before.

## 3. House crates

| Need | Use | Note |
|---|---|---|
| session keys, signatures | `rusty_esp_mid` (P-256 ECDH + ECDSA) | never ed25519 in the family |
| MAC / hash | RustCrypto `hmac`, `sha2` (`no_std`) | |
| CSI capture | `esp-csi-rs` 0.10.1 (Apache-2.0, early) | ESP32, C3, C5, C6, S3; C5/C6 can inject raw frames (emitter role) |
| BLE host | `trouble-host` 0.8, `bt-hci` 0.10 | any controller with the `bt-hci` traits |
| LoRa | `lora-phy` 3.0.1, `lorawan-device` 0.12 | SX126x / SX127x |
| Presence consumer | Lighthouse `RfSensor` shape in `mata-master` | the verdict feeds the same presence pipeline |

## 4. Milestones and kill tests

| # | Deliverable | Kill test |
|---|---|---|
| **S0** | core: CSI features + presence/motion detectors on recorded captures; LD2410 parser with fixtures; `Envelope` + `Session` + replay window with tests; GATT table; riscv32 green | detectors reproduce esp-csi's reference verdicts on its published captures within a stated margin; a replayed frame is rejected; a frame with a bad tag is rejected before any parse |
| **S1** | C6 ↔ C6 ESP-NOW authenticated link (Track B) | 1000 frames each way; loss, replay-rejected and bad-tag counters recorded; a third unadopted C6 cannot join |
| **S2** (J4) | CSI presence on C6 (and S3) in a room | matches a hand-labelled 10-minute recording at a stated accuracy; false-positive rate stated |
| **S3** | BLE provisioning over `trouble-host`; the manifest readable over GATT | a phone provisions Wi-Fi from a Web Bluetooth page — no app-store app; credentials never appear in a log |
| **S4** | LoRa P2P on two SX1262 nodes with signed session + MAC'd frames | a range/RSSI/PER table at SF7 and SF12; ledger row |
| **S5** | LD2410C over UART | reports match the module's own serial tool for 10 minutes |
| **S6** | `StationPolicy`: reconnect back-off, AP fallback → provisioning, RSSI telemetry | a 24-hour soak with the reconnect counter recorded |

## 5. Measurement

- Detector quality is an **external-oracle** number (labels, esp-csi
  outputs), never a self-metric.
- Link quality is counters: sent, received, replayed, rejected, PER.
- `docs/LEDGER.md` from the first number.

## 6. Risks

| Risk | Mitigation |
|---|---|
| esp-radio's CSI API is `unstable` and `esp-csi-rs` is early | pin exact versions; the detector core is capture-driven and does not care which collector produced the frames |
| CSI presence is environment-sensitive | ship with calibration ops (background window, sensitivity) and honest accuracy tables per room class |
| BLE controller availability per chip / track | Track B first on C6; Track A Bluedroid as the fallback |
| Regulatory duty cycle on LoRa | `lora::Params` carries region limits; the beacon rate is capped in code |

## 7. Decision log

| Date | Decision |
|---|---|
| 2026-09-01 | One package for the radio application layer; sub-crates only when size forces it. |
| 2026-09-01 | Sign the session, MAC the frames. P-256 ECDH from `rusty_esp_mid`; HMAC-SHA256/16 per frame. |
| 2026-09-01 | Detectors are host-developed from recorded captures against an external oracle before any radio work. |
| 2026-09-01 | 802.15.4 / Thread is out of v1 (owned by the home computer's border-router plan). |

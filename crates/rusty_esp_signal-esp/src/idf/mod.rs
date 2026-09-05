//! Track A backends: std on ESP-IDF through `esp-idf-svc`.
//!
//! Compiled only as part of a firmware (the IDF build supplies the chip and
//! the sdkconfig); the host never sees this module. The first backend is BLE
//! provisioning over Bluedroid — the same GATT contract [`crate::ble`] serves
//! on Track B — so a Wi-Fi + camera device on ESP-IDF can be provisioned from
//! a phone without a second track.

pub mod ble;

//! Track A backends: std on ESP-IDF through `esp-idf-svc`.
//!
//! Compiled only as part of a firmware (the IDF build supplies the chip and
//! the sdkconfig); the host never sees this module. The first backend is BLE
//! provisioning over Bluedroid — the same GATT contract [`crate::ble`] serves
//! on Track B — so a Wi-Fi + camera device on ESP-IDF can be provisioned from
//! a phone without a second track; it needs the firmware's sdkconfig to set
//! `CONFIG_BT_ENABLED`, so it sits behind `esp-idf-ble`. The second is the
//! LD2410 radar, whose reader was bare metal only: a device that also wants
//! the mesh is on this track, because iroh needs `std`, and it needs nothing
//! of the IDF beyond a UART. The third is Wi-Fi CSI ([`csi`], behind
//! `esp-idf-csi`): until it existed a device that watched the room could not
//! also show it or reach the owner over iroh, because every camera cell and
//! the mesh are on this track and CSI was esp-radio only.

#[cfg(feature = "esp-idf-ble")]
pub mod ble;
#[cfg(feature = "esp-idf-csi")]
pub mod csi;
pub mod ld2410;

//! The ESP32-S3 Wi-Fi MAC register block, as `opensensor/esp-pacs` 37b54bd
//! maps it (pending upstream as esp-rs/esp-pacs#511): `wifi.rs` and `wifi/`
//! are that commit's svd2rust output, unchanged. They name svd2rust's generic
//! register types through `crate::` and write inherent impls on them, so the
//! generic module is this crate's own: `generic.rs` and `generic/raw.rs`
//! copied unchanged from the esp32s3 PAC 0.36.0 that esp-hal 1.2 links
//! (svd2rust 0.37.1). The one peripheral is added; nothing else in an image is
//! patched (`../UPSTREAM.md`). Not Wi-Fi certified.
#![no_std]
#![allow(clippy::all, missing_docs, non_camel_case_types, unused)]

#[allow(unused_imports)]
use generic::*;
/// Common register and bit access and modify traits (svd2rust's, from the
/// esp32s3 PAC 0.36.0).
pub mod generic;
pub use esp32s3::Interrupt;

/// MAC controller for the Wi-Fi peripheral (the 9 lines the upstream commit
/// added to the PAC's root, less its `Debug` impl, which only the PAC's own
/// crate may write for `Periph`).
pub type WIFI = Periph<wifi::RegisterBlock, 0x6003_3000>;

/// MAC controller for the Wi-Fi peripheral.
pub mod wifi;

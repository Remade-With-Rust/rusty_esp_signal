//! Radar: presence, motion and breathing without a camera.
//!
//! [`csi`] turns Wi-Fi channel state information into a verdict; [`ld2410`]
//! speaks the HLK-LD2410 mmWave module's UART protocol.

pub mod csi;
pub mod ld2410;

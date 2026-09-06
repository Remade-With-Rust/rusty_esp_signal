//! Radar: presence, motion and breathing without a camera.
//!
//! [`csi`] turns Wi-Fi channel state information into a verdict; [`ld2410`]
//! speaks the HLK-LD2410 mmWave module's UART protocol; [`presence`] is the
//! one record both answer in, so a device sends presence without the owner
//! or the transport learning which sensor produced it.

pub mod csi;
pub mod ld2410;
pub mod presence;

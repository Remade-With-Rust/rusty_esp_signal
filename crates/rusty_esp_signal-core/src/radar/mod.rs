//! Radar: presence, motion and breathing without a camera.
//!
//! [`csi`] turns Wi-Fi channel state information into a verdict; [`phase`]
//! does the same from the angle of each entry; [`vitals`] finds the slow
//! rhythm of breathing (and, with caveats, a heartbeat) in the same
//! channel; [`ld2410`] speaks the HLK-LD2410 mmWave module's UART protocol;
//! [`presence`] is the one record the presence sensors answer in, so a
//! device sends presence without the owner or the transport learning which
//! sensor produced it.

pub mod csi;
pub mod ld2410;
pub mod phase;
pub mod presence;
pub mod vitals;

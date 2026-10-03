//! The link's HMAC blocks on the chip's SHA accelerator (round 2, R3).
//!
//! [`EspSha`] is a [`Sha256Blocks`] engine for
//! [`Session::seal_with`] and [`Session::open_with`]: it loads the HMAC
//! midstate into the accelerator's H registers, runs the message blocks,
//! and reads the state back. On an ESP32-S3 at 80 MHz a block measured
//! 6.1 us against 61.7 us for `sha2`'s software arm, the same state out
//! (`rusty_esp_dsp`'s probe, `sha_hw` and `sha_soft`).
//!
//! It owns esp-hal's [`Sha`] driver, which holds the peripheral and keeps
//! its clock on, so nothing else in the firmware can drive the unit while
//! a block is in it. (The Wi-Fi supplicant links its own software SHA and
//! never touches the unit; checked against the S3 blobs' symbols.)
//!
//! **Chips:** those whose SHA unit takes a midstate in `H_MEM` and resumes
//! with `CONTINUE` -- the ESP32-S2, S3 and the C/H series. Not the original
//! ESP32, whose SHA unit has neither; esp-hal's own context restore draws
//! the same line (`cfg(not(esp32))`). A firmware for that chip leaves the
//! `sha-accel` feature off and keeps [`SoftSha`].
//!
//! The crate's second `unsafe` seam: the PAC marks raw register writes
//! unsafe. Every write here is a whole word into a register esp-hal's own
//! restore path writes the same way.
//!
//! [`Sha256Blocks`]: rusty_esp_signal_core::link::Sha256Blocks
//! [`Session::seal_with`]: rusty_esp_signal_core::link::Session::seal_with
//! [`Session::open_with`]: rusty_esp_signal_core::link::Session::open_with
//! [`SoftSha`]: rusty_esp_signal_core::link::SoftSha
//! [`Sha`]: esp_hal::sha::Sha
#![allow(unsafe_code)]

use esp_hal::peripherals::SHA;
use esp_hal::sha::Sha;
use rusty_esp_signal_core::link::Sha256Blocks;

/// SHA-256 in the unit's `MODE` register.
const MODE_SHA256: u8 = 2;

/// The SHA accelerator as a block engine for the link.
pub struct EspSha<'d> {
    _sha: Sha<'d>,
}

impl<'d> EspSha<'d> {
    /// Take the SHA peripheral for the link.
    #[must_use]
    pub fn new(sha: SHA<'d>) -> Self {
        Self {
            _sha: Sha::new(sha),
        }
    }
}

impl EspSha<'_> {
    /// Load `state`, run every block of every part, unload the state: one
    /// trip through the H registers however many parts there are.
    fn run(state: &mut [u32; 8], parts: &[&[u8]]) {
        let r = SHA::regs();
        // SAFETY (each write): a whole word into a register of a unit this
        // value owns, as esp-hal's restore path writes it.
        r.mode().write(|w| unsafe { w.mode().bits(MODE_SHA256) });
        // H_MEM holds the state in digest byte order, the order the trait
        // carries it in (round 3: no swap either way). The message words go
        // in as they sit in memory.
        for (i, s) in state.iter().enumerate() {
            r.h_mem(i).write(|w| unsafe { w.bits(*s) });
        }
        for part in parts {
            let aligned = (part.as_ptr() as usize) % 4 == 0;
            for block in part.chunks_exact(64) {
                if aligned {
                    // a word a load where the block allows it: one `l32i`
                    // in place of four byte loads and six shifts and ors
                    let words = block.as_ptr().cast::<u32>();
                    for i in 0..16 {
                        // SAFETY: `block` is 64 readable bytes on a 4-byte
                        // boundary (the part is, and blocks are 64 apart).
                        let v = unsafe { words.add(i).read() };
                        r.m_mem(i).write(|w| unsafe { w.bits(v) });
                    }
                } else {
                    for (i, c) in block.chunks_exact(4).enumerate() {
                        let v = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
                        r.m_mem(i).write(|w| unsafe { w.bits(v) });
                    }
                }
                r.continue_().write(|w| w.continue_().set_bit());
                while r.busy().read().state().bit_is_set() {}
            }
        }
        for (i, s) in state.iter_mut().enumerate() {
            *s = r.h_mem(i).read().bits();
        }
    }
}

impl Sha256Blocks for EspSha<'_> {
    fn compress(&mut self, state: &mut [u32; 8], blocks: &[u8]) {
        Self::run(state, &[blocks]);
    }

    fn compress2(&mut self, state: &mut [u32; 8], first: &[u8], second: &[u8]) {
        Self::run(state, &[first, second]);
    }
}

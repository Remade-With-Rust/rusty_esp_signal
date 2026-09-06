//! An HLK-LD2410 mmWave module on an ESP-IDF UART, feeding the core's
//! [`Parser`].
//!
//! The Track A twin of [`crate::hal::ld2410`]: the same core parser and the
//! same counters, over `esp-idf-hal`'s [`UartDriver`] instead of esp-hal's
//! async receiver. It exists because a device that also wants the mesh is on
//! Track A (iroh needs `std`), and until now the only way to read this module
//! was bare metal.
//!
//! The caller owns the UART and configures it: the module streams report
//! frames at [`BAUD`] unless the core's `SetBaud` command changed it, and it
//! wants 5 V on its own supply pin, not the 3V3 rail. Sending commands is the
//! caller's job too — build them with the core's `Command` and write them
//! with the same driver — because the command and acknowledgement handshake
//! is the firmware's control flow, not this reader's.

use esp_idf_svc::hal::uart::UartDriver;
use esp_idf_svc::sys::EspError;
use rusty_esp_signal_core::radar::ld2410::{Frame, Parser, Report, Stats};

/// The module's default baud rate.
pub const BAUD: u32 = 256_000;

/// Bytes read per poll. One report frame is far smaller; this only bounds
/// how much of a backlog a single call clears.
const SCRATCH: usize = 128;

/// The read side of an LD2410 link: an ESP-IDF UART and the core's streaming
/// parser over a small scratch buffer.
pub struct Ld2410Uart<'d> {
    uart: UartDriver<'d>,
    parser: Parser,
    scratch: [u8; SCRATCH],
}

impl<'d> Ld2410Uart<'d> {
    /// Wrap a UART already configured for the module's baud ([`BAUD`]).
    #[must_use]
    pub fn new(uart: UartDriver<'d>) -> Self {
        Self {
            uart,
            parser: Parser::new(),
            scratch: [0u8; SCRATCH],
        }
    }

    /// Parser counters (frames, resyncs, dropped, malformed) for the ledger.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.parser.stats()
    }

    /// The UART, for the command side of the protocol.
    pub fn uart(&self) -> &UartDriver<'d> {
        &self.uart
    }

    /// Read whatever has arrived and return the newest report in it, or
    /// `None` when no complete report was in this read.
    ///
    /// `wait_ticks` is handed to the driver: `0` polls and returns at once,
    /// which is what a sketch loop wants.
    ///
    /// Every byte read is fed to the parser before this returns, even after
    /// a report completes. Returning early would leave the rest of the read
    /// unfed and the next read would resume mid-frame, which the parser can
    /// only answer with a resync.
    ///
    /// # Errors
    ///
    /// The driver's [`EspError`] when the UART read fails.
    pub fn poll(&mut self, wait_ticks: u32) -> Result<Option<Report>, EspError> {
        let n = self.uart.read(&mut self.scratch, wait_ticks)?;
        let mut newest = None;
        for &byte in &self.scratch[..n] {
            if let Some(Frame::Report(report)) = self.parser.feed(byte) {
                newest = Some(report);
            }
        }
        Ok(newest)
    }
}

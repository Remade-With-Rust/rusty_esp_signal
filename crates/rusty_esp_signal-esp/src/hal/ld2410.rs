//! An HLK-LD2410 mmWave module on a UART, feeding the core's [`Parser`].
//!
//! The module streams report frames at its baud (256000 by default, or the
//! rate the core's `SetBaud` command set). This wrapper owns the async
//! [`UartRx`] and a [`Parser`]; [`Ld2410Uart::next_frame`] reads bytes and
//! returns the next complete frame, resynchronising through garbage the way
//! the core parser does. A firmware calls it in a loop and acts on the
//! [`Report`]s (presence, distance) or [`Ack`]s (a command's reply).
//!
//! Sending commands is the caller's job: build them with the core's
//! [`Command`] into a small buffer and write them with the paired
//! [`esp_hal::uart::UartTx`], because the command/ack handshake is the
//! firmware's control flow, not this reader's.

use esp_hal::Async;
use esp_hal::uart::UartRx;
use rusty_esp_signal_core::radar::ld2410::{Frame, Parser, Report, Stats};

/// The read side of an LD2410 link: an async UART receiver and the core's
/// streaming parser over a small scratch buffer.
pub struct Ld2410Uart<'d> {
    rx: UartRx<'d, Async>,
    parser: Parser,
    scratch: [u8; 64],
}

impl<'d> Ld2410Uart<'d> {
    /// Wrap an async UART receiver. Configure the UART for the module's baud
    /// (256000 default) before calling this.
    #[must_use]
    pub fn new(rx: UartRx<'d, Async>) -> Self {
        Self {
            rx,
            parser: Parser::new(),
            scratch: [0u8; 64],
        }
    }

    /// Parser counters (frames, resyncs, dropped, malformed) for the ledger.
    #[must_use]
    pub fn stats(&self) -> Stats {
        self.parser.stats()
    }

    /// Read until the next complete frame, or until the UART errors.
    ///
    /// Returns `Ok(None)` when a read returned no bytes (so the caller can
    /// yield), `Err(())` on a UART read error. A returned [`Report`] is the
    /// module's presence/distance reading; an [`Frame::Ack`] is a command's
    /// reply. The frame borrows the parser, so it is mapped to a `Report`
    /// (which is owned) before returning.
    pub async fn next_report(&mut self) -> Result<Option<Report>, ()> {
        loop {
            let n = self
                .rx
                .read_async(&mut self.scratch)
                .await
                .map_err(|_| ())?;
            if n == 0 {
                return Ok(None);
            }
            for &byte in &self.scratch[..n] {
                if let Some(frame) = self.parser.feed(byte) {
                    if let Frame::Report(report) = frame {
                        return Ok(Some(report));
                    }
                    // An ACK arrived unsolicited to this reader; the command
                    // path owns ACKs. Keep reading for the next report.
                }
            }
        }
    }
}

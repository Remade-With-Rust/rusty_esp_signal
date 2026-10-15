//! E8's length sweep, received (`JANUS_E8_TALLY`): the XIAO's open MAC
//! sends broadcast test frames (`xiao-s3-open-link` with `JANUS_SWEEP`)
//! at ten lengths and four rates; this tallies, per length and rate, how
//! many arrived, whether whole (the received length equals the length in
//! the tag) and intact (the counting pattern unbroken), and their signal.
//! Whether a long frame leaves the XIAO whole, and whether its HT frames
//! decode worse than its 802.11g ones at the same modulation, with no
//! access point in the way. Frames are recognised by their tag, `JE8`;
//! no address is printed.

use esp_println::println;

/// The sweep's lengths (MPDU, FCS not counted), as the sender's.
pub const LENGTHS: [usize; 10] = [1500, 1800, 1900, 1950, 2000, 2050, 2100, 2500, 3000, 3600];
/// Rate codes 1-4: OFDM 54, MCS 6, OFDM 6, MCS 0 (long GI).
const RATES: [&str; 4] = ["ofdm54", "mcs6", "ofdm6", "mcs0"];

#[derive(Clone, Copy, Default)]
struct Cell {
    heard: u32,
    rssi_sum: i32,
    /// Received shorter or longer than the tag says.
    wrong_len: u32,
    /// The counting pattern broken somewhere.
    corrupt: u32,
}

#[derive(Default)]
pub struct Tally {
    cells: [[Cell; 4]; LENGTHS.len()],
    /// Tagged frames whose length or rate code is not in the sweep.
    unknown: u32,
    /// The longest frame of any kind received (anyone's): the receiver's
    /// own ceiling, read off the air.
    longest_any: usize,
}

impl Tally {
    /// One received frame: `frame` from its header on (the buffer may hold
    /// less than `frame_len` when the frame outran it), `frame_len` the
    /// length the MAC reported (FCS not counted).
    pub fn frame(&mut self, frame: &[u8], frame_len: usize, rssi: i8) {
        self.longest_any = self.longest_any.max(frame_len);
        if frame.len() < 34 || frame[0] != 0x08 || &frame[24..27] != b"JE8" {
            return;
        }
        let tagged = usize::from(u16::from_be_bytes([frame[27], frame[28]]));
        let code = usize::from(frame[29]);
        let (Some(row), true) = (LENGTHS.iter().position(|l| *l == tagged), (1..=4).contains(&code)) else {
            self.unknown += 1;
            return;
        };
        let cell = &mut self.cells[row][code - 1];
        cell.heard += 1;
        cell.rssi_sum += i32::from(rssi);
        if frame_len != tagged {
            cell.wrong_len += 1;
        }
        let end = frame.len().min(frame_len).min(tagged);
        if frame[34..end].iter().enumerate().any(|(i, b)| *b != i as u8) {
            cell.corrupt += 1;
        }
    }

    pub fn report(&self) {
        for (row, length) in LENGTHS.iter().enumerate() {
            let c = &self.cells[row];
            let cell = |i: usize| {
                let x = c[i];
                let rssi = if x.heard > 0 { x.rssi_sum / x.heard as i32 } else { 0 };
                (x.heard, rssi, x.wrong_len, x.corrupt)
            };
            let (a, b, d, e) = (cell(0), cell(1), cell(2), cell(3));
            println!(
                "E8 tally len={length} {}={}/{}dBm/{}/{} {}={}/{}dBm/{}/{} {}={}/{}dBm/{}/{} {}={}/{}dBm/{}/{}",
                RATES[0], a.0, a.1, a.2, a.3, RATES[1], b.0, b.1, b.2, b.3,
                RATES[2], d.0, d.1, d.2, d.3, RATES[3], e.0, e.1, e.2, e.3
            );
        }
        println!(
            "E8 tally (heard/rssi/wrong_len/corrupt) unknown={} longest_any={}",
            self.unknown, self.longest_any
        );
    }
}

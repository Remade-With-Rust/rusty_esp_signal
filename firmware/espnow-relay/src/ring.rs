//! The relay's receive ring: bytes the UART's interrupt took off the
//! hardware queue, for the loop. A module of its own so `c6-insn-bench`
//! counts the code the relay runs (the optimisation round, 2026-10-07).

/// The receive ring: seven full lines.
pub const RING: usize = 4096;

/// Bytes the UART's interrupt took off the hardware queue, for the loop.
pub struct Ring {
    bytes: [u8; RING],
    head: usize,
    len: usize,
    /// Bytes that found the ring full, and reads the UART reported in error
    /// (its own queue overran): either way a line was damaged.
    pub lost: u32,
}

impl Ring {
    pub const fn new() -> Self {
        Ring {
            bytes: [0; RING],
            head: 0,
            len: 0,
            lost: 0,
        }
    }

    /// `data` in, as much as there is room for; the rest counted lost (one
    /// per byte, as before). At most two copies where a byte at a time,
    /// each index wrapped, was the loop before.
    pub fn push(&mut self, data: &[u8]) {
        let take = data.len().min(RING - self.len);
        self.lost += (data.len() - take) as u32;
        let tail = (self.head + self.len) % RING;
        let first = take.min(RING - tail);
        self.bytes[tail..tail + first].copy_from_slice(&data[..first]);
        self.bytes[..take - first].copy_from_slice(&data[first..take]);
        self.len += take;
    }

    /// Up to `out.len()` bytes out, oldest first: at most two copies (to
    /// the ring's end, then from its start) where a byte at a time, each
    /// index wrapped, was the loop before.
    pub fn pop(&mut self, out: &mut [u8]) -> usize {
        let n = self.len.min(out.len());
        let first = n.min(RING - self.head);
        out[..first].copy_from_slice(&self.bytes[self.head..self.head + first]);
        out[first..n].copy_from_slice(&self.bytes[..n - first]);
        self.head = (self.head + n) % RING;
        self.len -= n;
        n
    }
}

/// The command line being assembled from the host's bytes.
pub struct Lines<const N: usize> {
    pub line: [u8; N],
    pub len: usize,
    /// Bytes arrived for this line that did not fit: it is damaged.
    pub overrun: bool,
}

impl<const N: usize> Lines<N> {
    pub const fn new() -> Self {
        Lines {
            line: [0; N],
            len: 0,
            overrun: false,
        }
    }

    /// `bytes` up to and including the first newline into the line, as much
    /// as fits (the rest marks it overrun): how many were taken, and whether
    /// the line ended. One search and one copy where a byte at a time --
    /// compare, check, store -- was the loop before (2026-10-07).
    pub fn take(&mut self, bytes: &[u8]) -> (usize, bool) {
        let (segment, ended) = match newline(bytes) {
            Some(i) => (&bytes[..i], true),
            None => (bytes, false),
        };
        let fit = segment.len().min(N - self.len);
        self.line[self.len..self.len + fit].copy_from_slice(&segment[..fit]);
        self.len += fit;
        if fit < segment.len() {
            self.overrun = true;
        }
        (segment.len() + usize::from(ended), ended)
    }
}

/// Where the first newline is: four bytes a step on the aligned middle (a
/// zero byte in `word ^ 0x0a0a0a0a` is a newline; the classic test sets the
/// top bit of every zero byte and of no byte below the first), a byte a step
/// on the ends. `bytes.iter().position` took a compare and a branch a byte.
pub fn newline(bytes: &[u8]) -> Option<usize> {
    const NL: u32 = 0x0a0a_0a0a;
    const LOW: u32 = 0x0101_0101;
    const HIGH: u32 = 0x8080_8080;
    // SAFETY: every bit pattern is a u32; `align_to` keeps the order and
    // splits off what is not aligned
    let (head, words, tail) = unsafe { bytes.align_to::<u32>() };
    if let Some(i) = head.iter().position(|&b| b == b'\n') {
        return Some(i);
    }
    for (w, &word) in words.iter().enumerate() {
        let x = word ^ NL;
        let zero = x.wrapping_sub(LOW) & !x & HIGH;
        if zero != 0 {
            // little-endian: the lowest set top bit is the first newline
            return Some(head.len() + 4 * w + (zero.trailing_zeros() / 8) as usize);
        }
    }
    let at = head.len() + 4 * words.len();
    tail.iter().position(|&b| b == b'\n').map(|i| at + i)
}

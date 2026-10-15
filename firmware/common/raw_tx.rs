//! E5's P4: arming a transmit slot by hand, shared by the two stacks so the
//! SAME code runs under two different bring-ups.
//!
//! P4 established that the slot is taken and the frame is never fetched --
//! the descriptor's owner bit is still set, `tx_complete_status` is 0 and
//! `tx_error_status` holds bit 13 -- and then refuted every register
//! difference between our bring-up and the blob's across
//! `0x600a0000`..`0x600b0000`. Which leaves two halves to tell apart:
//!
//! 1. the ARMING sequence (this module), or
//! 2. the BRING-UP that precedes it.
//!
//! A register comparison cannot separate them, but running this module on a
//! MAC that esp-radio brought up can: if a frame radiates there and not
//! under our own bring-up, the arming is right and the whole of the missing
//! step is in bring-up. That is why this lives in `common` and not in
//! either firmware.
//!
//! NOT Wi-Fi certified.

#![allow(dead_code)]

use esp_hal::dma::{DmaDescriptor, Owner};

/// The transmit slots: five of them, stride 16, `config` at +8 and `plcp0`
/// at +12. Found by arming each of twelve candidate addresses in turn --
/// `0x600a4d20`..`0x600a4d60` all answer, the addresses on either side are
/// inert, and `0x600a4dc0` never clears the bit at all (P4, 2026-10-08).
pub const SLOT_BASE: u32 = 0x600a_4d20;
pub const SLOT_STRIDE: u32 = 0x10;
pub const SLOTS: u32 = 5;
/// The slot esp-radio's own driver uses, observed by watching its writes
/// across a beacon run.
pub const BLOB_SLOT: u32 = 4;

const CONFIG: u32 = 0x8;
const PLCP0: u32 = 0xc;

/// `plcp0`'s low 20 bits are the descriptor's address within SRAM; the
/// hardware supplies the `0x40800000` that completes it.
const DMA_MASK: u32 = 0x000f_ffff;
/// Bits 21-22, which the blob sets and which are not part of the address:
/// its own `plcp0` reads `0x0061e068`, and a field wide enough to hold them
/// would put the descriptor at offset `0x61e068`, outside the C6's 512 KB.
const PLCP0_FLAGS: u32 = 0x0060_0000;
const SLOT_VALID: u32 = 1 << 30;
const SLOT_ENABLED: u32 = 1 << 31;

/// `config` as the blob leaves it: AIFSN 2, timeout `0x3ff`. The backoff
/// bits are the hardware's to randomise, and they are the only part of this
/// word the blob rewrites per frame.
const CONFIG_VALUE: u32 = 0x0200_23ff;

/// The transmit queues' four state words, as the S3's map names them.
/// `0x600a4ca8` is `tx_error_status`, NOT the "transmit block" P4 first
/// read it as.
pub const TXQ_ERROR_CLEAR: u32 = 0x600a_4ca4;
pub const TXQ_ERROR_STATUS: u32 = 0x600a_4ca8;
pub const TXQ_COMPLETE_CLEAR: u32 = 0x600a_4cac;
pub const TXQ_COMPLETE_STATUS: u32 = 0x600a_4cb0;

fn read(address: u32) -> u32 {
    // SAFETY: a volatile read of a peripheral register
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

fn write(address: u32, value: u32) {
    // SAFETY: a volatile write to a peripheral register
    unsafe { core::ptr::write_volatile(address as *mut u32, value) }
}

/// What the hardware did with one armed slot. Every field is read from the
/// chip, so this is the hardware's account and not ours.
#[derive(Clone, Copy)]
pub struct Verdict {
    /// `tx_complete_status`: nonzero means the MAC transmitted.
    pub complete: u32,
    /// `tx_error_status`: bit 13 on every attempt so far.
    pub error: u32,
    /// `plcp0` once the hardware had finished with the slot.
    pub plcp0: u32,
    /// The descriptor's first word. **The owner bit still being set means
    /// the DMA engine never read the frame**, which is the whole finding.
    pub desc_word0: u32,
    /// Whether the hardware cleared the enable bit at all.
    pub finished: bool,
    /// How many polls of `plcp0` it took. **This is the physical check**:
    /// a 107-octet frame occupies the air for about a millisecond at
    /// 1 Mbit/s and 36 microseconds even at 54, so a slot the hardware
    /// hands back after a handful of polls cannot have transmitted
    /// anything, whatever the status registers say. Calibrate with
    /// [`polls_per_us`].
    pub polls: u64,
}

impl Verdict {
    /// Whether the DMA engine took the frame: the engine clears the owner
    /// bit when it has read the buffer.
    pub fn dma_read_the_frame(&self) -> bool {
        self.desc_word0 >> 31 == 0
    }
}

/// The descriptor's first word as the hardware sees it.
fn desc_word0(desc: &DmaDescriptor) -> u32 {
    // SAFETY: a read of the descriptor's own first word, a plain u32 at its
    // start
    unsafe { core::ptr::read_volatile((desc as *const DmaDescriptor).cast::<u32>()) }
}

/// Arm `slot_address` with `buf[..n]` and wait for the hardware to finish
/// with it, for at most `patience_us`.
///
/// The frame's length goes in the DESCRIPTOR and nowhere else: 16 KB of the
/// MAC was searched for it under four spellings, and nine beacons of five
/// different lengths moved not one bit of any register (P4). On the S3
/// `plcp1` carries it per frame; on the C6 it does not exist.
pub fn arm(
    slot_address: u32,
    desc: &mut DmaDescriptor,
    buf: &mut [u8],
    n: usize,
    patience_us: u32,
) -> Verdict {
    desc.buffer = buf.as_mut_ptr();
    desc.next = core::ptr::null_mut();
    write_descriptor_word0(desc, n + 4, buf.len());

    // The blob writes `config` and `plcp0` per frame and nothing else:
    // `conf0` and `conf1` stay zero through a whole beacon run, and the
    // per-slot PLCP block is written once on its FIRST transmit and never
    // again.
    write(slot_address + CONFIG, CONFIG_VALUE);
    // this frame's verdict, not the last one's
    write(TXQ_ERROR_CLEAR, !0);
    write(TXQ_COMPLETE_CLEAR, !0);

    let address = (desc as *const DmaDescriptor) as u32;
    write(
        slot_address + PLCP0,
        (address & DMA_MASK) | PLCP0_FLAGS | SLOT_VALID | SLOT_ENABLED,
    );

    // Spun rather than timed off a clock, so this module needs nothing from
    // either firmware's notion of time: the two stacks have different ones.
    let budget = patience_us as u64 * 40;
    let mut spins = budget;
    let mut plcp0 = read(slot_address + PLCP0);
    while plcp0 & SLOT_ENABLED != 0 && spins > 0 {
        plcp0 = read(slot_address + PLCP0);
        spins -= 1;
    }
    Verdict {
        complete: read(TXQ_COMPLETE_STATUS),
        error: read(TXQ_ERROR_STATUS),
        plcp0,
        desc_word0: desc_word0(desc),
        finished: plcp0 & SLOT_ENABLED == 0,
        polls: budget - spins,
    }
}

/// Polls of the same shape as [`arm`]'s wait loop per microsecond, measured
/// against a caller-supplied clock, so the poll count above can be read as
/// a time without assuming a CPU frequency.
pub fn polls_per_us(elapsed_us: impl Fn() -> u64, polls: u64) -> u64 {
    let start = elapsed_us();
    let mut sink = 0u32;
    for _ in 0..polls {
        sink = sink.wrapping_add(read(TXQ_COMPLETE_STATUS));
    }
    core::hint::black_box(sink);
    let took = elapsed_us().saturating_sub(start).max(1);
    polls / took
}

/// One line of the hardware's account, in the one format both firmwares
/// print so two runs can be compared by eye or by grep.
pub fn report(tag: &str, slot_address: u32, n: usize, v: &Verdict) {
    esp_println::println!(
        "RAWTX {tag} slot=0x{slot_address:08x} len={n} finished={} complete={:04x} error={:04x} \
         plcp0={:08x} desc={:08x} dma_took_frame={} polls={}",
        v.finished as u8,
        v.complete & 0xffff,
        v.error & 0xffff,
        v.plcp0,
        v.desc_word0,
        v.dma_read_the_frame() as u8,
        v.polls
    );
}

/// The descriptor esp-radio's own driver last pointed the slot at, read
/// out of `plcp0` before we overwrite it, and the three words it holds.
///
/// With bring-up exonerated -- our arming fails identically on a MAC the
/// blob brought up and had just transmitted through -- the descriptor is
/// the suspect the symptom names: the DMA engine never reads the frame.
/// This prints the blob's descriptor beside ours, so a difference in the
/// layout the hardware actually accepts is visible rather than inferred
/// from another chip's register map.
pub fn describe_blob_descriptor(slot_address: u32) -> u32 {
    let plcp0 = read(slot_address + PLCP0);
    // the hardware supplies the 0x40800000 that completes the low 20 bits
    let address = 0x4080_0000 | (plcp0 & DMA_MASK);
    let w = |i: u32| read(address + i * 4);
    esp_println::println!(
        "RAWTX blobdesc plcp0={plcp0:08x} at=0x{address:08x}          word0={:08x} buffer={:08x} next={:08x}          size={} length={} eof={} owner={}",
        w(0),
        w(1),
        w(2),
        w(0) & 0xfff,
        (w(0) >> 12) & 0xfff,
        (w(0) >> 30) & 1,
        w(0) >> 31
    );
    address
}

/// Arm the slot at the descriptor the BLOB last used, without touching its
/// contents: it still holds a frame the blob transmitted successfully. If
/// that radiates, our descriptor is the fault; if it does not, the
/// descriptor is exonerated and what is left is the value we write or a
/// per-frame write we have never observed.
pub fn arm_foreign_descriptor(slot_address: u32, descriptor: u32, patience_us: u32) -> Verdict {
    write(slot_address + CONFIG, CONFIG_VALUE);
    write(TXQ_ERROR_CLEAR, !0);
    write(TXQ_COMPLETE_CLEAR, !0);
    write(
        slot_address + PLCP0,
        (descriptor & DMA_MASK) | PLCP0_FLAGS | SLOT_VALID | SLOT_ENABLED,
    );
    let mut spins = patience_us as u64 * 40;
    let mut plcp0 = read(slot_address + PLCP0);
    while plcp0 & SLOT_ENABLED != 0 && spins > 0 {
        plcp0 = read(slot_address + PLCP0);
        spins -= 1;
    }
    Verdict {
        complete: read(TXQ_COMPLETE_STATUS),
        error: read(TXQ_ERROR_STATUS),
        plcp0,
        // the foreign descriptor's own word, so the owner bit is still the
        // question being asked
        desc_word0: read(0x4080_0000 | (descriptor & DMA_MASK)),
        finished: plcp0 & SLOT_ENABLED == 0,
        polls: 0,
    }
}

/// The blob's descriptor sampled against a frame of KNOWN length, which is
/// what pins the field order the hardware actually uses.
///
/// `esp-hal`'s `DmaDescriptor` puts `size` in bits 0-11 and `length` in
/// bits 12-23, and the blob's descriptor read back under that layout gives
/// size 332 with length 1172 -- a length larger than its buffer, which no
/// descriptor can mean. So either the order is reversed on this chip's MAC
/// DMA or the word is not what we think. Printing both readings beside the
/// frame's real length settles it: the field that tracks the frame is the
/// length, and the other is the buffer's capacity.
pub fn watch_blob_descriptor(slot_address: u32, mpdu_len: u32) {
    let plcp0 = read(slot_address + PLCP0);
    let address = 0x4080_0000 | (plcp0 & DMA_MASK);
    let word0 = read(address);
    let low = word0 & 0xfff;
    let high = (word0 >> 12) & 0xfff;
    esp_println::println!(
        "RAWTX descwatch mpdu={mpdu_len} fcs={} plcp0={plcp0:08x} at=0x{address:08x}          word0={word0:08x} low[0:11]={low} high[12:23]={high} buffer={:08x}",
        mpdu_len + 4,
        read(address + 4)
    );
}

/// The descriptor's first word, in the layout the C6's MAC DMA actually
/// wants -- which is NOT the one `esp-hal`'s `set_size`/`set_length` write.
///
/// Read off the blob's own descriptor against beacons of five known
/// lengths (E5's P4, 2026-10-08). With the payload at 60, 100, 150, 200 and
/// 250 octets, so a frame of 103, 143, 193, 243 and 293 octets with its
/// FCS, the word's two halves came back:
///
/// | frame+FCS | bits 0-11 | bits 12-23 |
/// |---|---|---|
/// | 103 | 140 | 412 |
/// | 143 | 180 | 572 |
/// | 193 | 232 | 772 |
/// | 243 | 280 | 972 |
/// | 293 | 332 | 1172 |
///
/// `bits 12-23 = 4 x (frame + FCS)` for every one of the five, and bits
/// 0-11 are the buffer's capacity (the payload plus 80, rounded up to a
/// multiple of four). So the length is carried in bits 14-23 -- or
/// equivalently in bits 12-23 scaled by four, with bits 12-13 always zero.
///
/// `esp-hal`'s `set_length(n)` puts `n` in bits 12-23, which is a quarter
/// of what the hardware reads. That is what P4 had been arming the slot
/// with: a frame of 107 octets announced as 107 where the MAC wanted 428.
/// Reading the blob's descriptor under esp-hal's layout is what gave the
/// impossible "size 332, length 1172" that started this.
fn write_descriptor_word0(desc: &mut DmaDescriptor, frame_len: usize, buffer_len: usize) {
    const OWNER: u32 = 1 << 31;
    const SUC_EOF: u32 = 1 << 30;
    // the capacity, four-byte aligned as the blob's is
    let size = ((buffer_len.min(0xfff) + 3) & !3) as u32;
    let length = (frame_len as u32 * 4) & 0xfff;
    let word0 = (size & 0xfff) | (length << 12) | SUC_EOF | OWNER;
    // SAFETY: the descriptor's own first word, a plain u32 at its start.
    // Written directly because esp-hal's setters encode the other layout.
    unsafe { core::ptr::write_volatile((desc as *mut DmaDescriptor).cast::<u32>(), word0) };
    let _ = Owner::Dma;
}

/// Distinct values of the slot's four words seen while a frame was going
/// out, kept small and fixed so the sampler allocates nothing.
const SAMPLE_SLOTS: usize = 24;
static mut SAMPLES: [[u32; 4]; SAMPLE_SLOTS] = [[0; 4]; SAMPLE_SLOTS];
static mut SAMPLE_COUNT: usize = 0;
static mut SAMPLE_POLLS: u32 = 0;

/// Sample the slot's four words until this future is dropped, recording
/// every DISTINCT reading. It yields between samples, which is what lets
/// the driver underneath actually get on with the transmission -- a tight
/// loop on one core would starve the very thing being watched.
///
/// Never completes: it is meant to lose a `select` against the send.
pub async fn sample_while(slot_address: u32) {
    // SAFETY: single-threaded, and the sampler is the only writer
    unsafe {
        SAMPLE_COUNT = 0;
        SAMPLE_POLLS = 0;
    }
    let mut last = [u32::MAX; 4];
    loop {
        let now = [
            read(slot_address),
            read(slot_address + 4),
            read(slot_address + CONFIG),
            read(slot_address + PLCP0),
        ];
        // SAFETY: as above
        unsafe {
            SAMPLE_POLLS = SAMPLE_POLLS.saturating_add(1);
            if now != last && SAMPLE_COUNT < SAMPLE_SLOTS {
                SAMPLES[SAMPLE_COUNT] = now;
                SAMPLE_COUNT += 1;
            }
        }
        last = now;
        embassy_futures::yield_now().await;
    }
}

/// What the sampler saw, one line per distinct reading. `plcp0`'s top two
/// bits are called out on their own: if they are never set while a frame is
/// in the air, then they are not how the blob launches one and P4's whole
/// arming sequence is built on a register map from another chip.
pub fn report_samples(payload_len: u32) {
    // SAFETY: single-threaded; the sampler has been dropped by now
    let (count, polls) = unsafe { (SAMPLE_COUNT, SAMPLE_POLLS) };
    esp_println::println!("SAMPLE payload={payload_len} distinct={count} polls={polls}");
    for i in 0..count {
        // SAFETY: as above, and i < count <= SAMPLE_SLOTS
        let w = unsafe { SAMPLES[i] };
        esp_println::println!(
            "SAMPLE   [{i}] conf0={:08x} conf1={:08x} config={:08x} plcp0={:08x} bit31={} bit30={}",
            w[0],
            w[1],
            w[2],
            w[3],
            w[3] >> 31,
            (w[3] >> 30) & 1
        );
    }
}

/// A WINDOW of registers watched while a frame is in the air.
///
/// The slot's own four words do not change at all during a transmission and
/// `plcp0`'s top two bits are never set, so the blob launches a frame by
/// writing something else. This widens the aperture: for every word of a
/// window it records whether the value ever moved from what it was at the
/// start, and the first value it moved to.
pub const WINDOW_WORDS: usize = 256;
static mut WINDOW_FIRST: [u32; WINDOW_WORDS] = [0; WINDOW_WORDS];
static mut WINDOW_CHANGED: [u32; WINDOW_WORDS] = [0; WINDOW_WORDS];
static mut WINDOW_HITS: [u16; WINDOW_WORDS] = [0; WINDOW_WORDS];
static mut WINDOW_BASE: u32 = 0;
static mut WINDOW_PASSES: u32 = 0;

/// Watch `words` words from `base` until dropped. Yields between passes so
/// the driver underneath can get on with the transmission.
pub async fn sample_window_while(base: u32, words: usize) {
    let words = words.min(WINDOW_WORDS);
    // SAFETY: single-threaded, and the sampler is the only writer
    unsafe {
        WINDOW_BASE = base;
        WINDOW_PASSES = 0;
        for i in 0..words {
            WINDOW_FIRST[i] = read(base + (i as u32) * 4);
            WINDOW_CHANGED[i] = 0;
            WINDOW_HITS[i] = 0;
        }
    }
    loop {
        for i in 0..words {
            let now = read(base + (i as u32) * 4);
            // SAFETY: as above, and i < words <= WINDOW_WORDS
            unsafe {
                if now != WINDOW_FIRST[i] {
                    if WINDOW_HITS[i] == 0 {
                        WINDOW_CHANGED[i] = now;
                    }
                    WINDOW_HITS[i] = WINDOW_HITS[i].saturating_add(1);
                }
            }
        }
        // SAFETY: as above
        unsafe { WINDOW_PASSES = WINDOW_PASSES.saturating_add(1) };
        embassy_futures::yield_now().await;
    }
}

/// Every word of the window that moved while the frame was in the air.
pub fn report_window(payload_len: u32, words: usize) {
    let words = words.min(WINDOW_WORDS);
    // SAFETY: single-threaded; the sampler has been dropped by now
    let (base, passes) = unsafe { (WINDOW_BASE, WINDOW_PASSES) };
    let mut moved = 0u32;
    for i in 0..words {
        // SAFETY: as above
        let (first, changed, hits) =
            unsafe { (WINDOW_FIRST[i], WINDOW_CHANGED[i], WINDOW_HITS[i]) };
        if hits > 0 {
            moved += 1;
            esp_println::println!(
                "WINDOW payload={payload_len} 0x{:08x} was={first:08x} became={changed:08x} hits={hits}",
                base + (i as u32) * 4
            );
        }
    }
    esp_println::println!("WINDOW payload={payload_len} moved={moved} of={words} passes={passes}");
}

/// Arm the slot the way the blob appears to: `plcp0` carries the
/// descriptor and its two flag bits and NOTHING else, and the write to
/// `config` is what starts the frame.
///
/// The evidence for this shape, all from sampling the slot WHILE a frame
/// was in the air (E5's P4, 2026-10-08):
///
/// - across 172 to 452 samples a frame, `plcp0` never had bit 30 or bit 31
///   set and never changed at all -- it held `0x0061e068` throughout, so
///   the "slot valid" and "slot enabled" bits P4 took from the S3's
///   register map are not how this chip launches anything;
/// - the only word the blob writes per frame is `config`, whose backoff
///   field carries a fresh random value each time;
/// - nothing else in `0x600a4c00`..`0x600a5000` is written: the four words
///   that move there are a counter that ticks every pass and status the
///   hardware updates once a frame.
///
/// So the descriptor pointer is set up once and each frame is started by
/// writing the channel-access parameters. Writing `plcp0` afterwards with
/// bits 30-31, as P4 did, overwrites a slot that was already armed -- and
/// the hardware threw it back in under a third of a microsecond.
pub fn arm_by_config(
    slot_address: u32,
    desc: &mut DmaDescriptor,
    buf: &mut [u8],
    n: usize,
    backoff: u32,
) {
    desc.buffer = buf.as_mut_ptr();
    desc.next = core::ptr::null_mut();
    write_descriptor_word0(desc, n + 4, buf.len());

    // the descriptor, with no launch bits of any kind
    let address = (desc as *const DmaDescriptor) as u32;
    write(slot_address + PLCP0, (address & DMA_MASK) | PLCP0_FLAGS);

    // and then the doorbell: AIFSN 2, timeout 0x3ff, this frame's backoff
    let config = (CONFIG_VALUE & !(0x3ff << 12)) | ((backoff & 0x3ff) << 12);
    write(slot_address + CONFIG, config);
}

/// What the slot and its neighbours look like a moment after
/// [`arm_by_config`], for a report that does not pretend to know which bit
/// means what.
pub fn report_after(tag: &str, slot_address: u32, n: usize) {
    esp_println::println!(
        "RAWTX {tag} len={n} conf0={:08x} conf1={:08x} config={:08x} plcp0={:08x}          err={:08x} cmp={:08x}",
        read(slot_address),
        read(slot_address + 4),
        read(slot_address + CONFIG),
        read(slot_address + PLCP0),
        read(TXQ_ERROR_STATUS),
        read(TXQ_COMPLETE_STATUS)
    );
}

/// Transmit by filling the descriptor the slot ALREADY points at, and
/// touching nothing else.
///
/// The remaining explanation for everything P4 has seen: `plcp0` is latched
/// once at a descriptor and never written again, nothing is written per
/// frame except `config`, and the hardware polls the descriptor's owner
/// bit. If that is how the C6 works, then a frame placed in the blob's own
/// descriptor with the owner bit set goes out with no register write at
/// all -- and every attempt P4 made to "arm a slot" was addressing a
/// doorbell that does not exist.
///
/// Returns the descriptor's address and its buffer's, so the caller can
/// read back whether the owner bit cleared.
pub fn arm_in_place(slot_address: u32, frame: &[u8]) -> (u32, u32) {
    let plcp0 = read(slot_address + PLCP0);
    let descriptor = 0x4080_0000 | (plcp0 & DMA_MASK);
    let buffer = read(descriptor + 4);
    // the frame into the buffer the hardware already knows about
    for (i, byte) in frame.iter().enumerate() {
        // SAFETY: the buffer the slot's own descriptor points at, which the
        // driver sized for a full frame; `frame` is at most 256 octets
        unsafe { core::ptr::write_volatile((buffer as *mut u8).add(i), *byte) };
    }
    // and the descriptor's own word: this frame's length, owner set. The
    // capacity is left as the driver had it.
    let word0 = read(descriptor);
    let size = word0 & 0xfff;
    let length = ((frame.len() as u32 + 4) * 4) & 0xfff;
    write(descriptor, size | (length << 12) | (1 << 30) | (1 << 31));
    (descriptor, buffer)
}

/// Whether the hardware took a frame left in place, read from the
/// descriptor itself.
pub fn report_in_place(tag: &str, descriptor: u32, buffer: u32, len: usize) {
    let word0 = read(descriptor);
    esp_println::println!(
        "RAWTX {tag} desc=0x{descriptor:08x} buffer=0x{buffer:08x} len={len}          word0={word0:08x} owner={} length={} err={:08x} cmp={:08x}",
        word0 >> 31,
        (word0 >> 12) & 0xfff,
        read(TXQ_ERROR_STATUS),
        read(TXQ_COMPLETE_STATUS)
    );
}

/// The tightest comparison P4 can make: ONE register write, identical to
/// the one the blob's driver must be making, on a MAC the blob brought up
/// with a valid frame already in the descriptor the slot points at.
///
/// Nothing else is touched -- not `config`, not the status registers, not
/// the descriptor. If the blob launches a frame by setting bits 30-31 of
/// `plcp0`, then this single write re-sends whatever the blob sent last.
///
/// The detector needs no new frame format and no tag: the descriptor still
/// holds the blob's OWN last beacon, so a successful relaunch makes the
/// relay report that beacon's sequence number AGAIN. A duplicate sequence
/// in the relay's log is the frame, and nothing else can produce one.
///
/// Returns `plcp0` read straight back, and the two status words.
pub fn relaunch(slot_address: u32) -> (u32, u32, u32) {
    let plcp0 = read(slot_address + PLCP0);
    // bits 30-31 added to EXACTLY what the slot already holds
    write(slot_address + PLCP0, plcp0 | SLOT_VALID | SLOT_ENABLED);
    let after = read(slot_address + PLCP0);
    (after, read(TXQ_ERROR_STATUS), read(TXQ_COMPLETE_STATUS))
}

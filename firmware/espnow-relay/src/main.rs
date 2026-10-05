#![no_std]
#![no_main]
//! **E4's bench relay**: ESP-NOW datagrams between the air and the serial
//! port, on the blob (esp-radio's ESP-NOW), so the bridge on the laptop
//! reaches a node whose link rides raw frames on the open MAC -- and the
//! laptop's own Wi-Fi is never taken. The relay holds no key and reads no
//! frame: the link's session is between the node and the bridge, and what
//! passes here is sealed.
//!
//! It is also the independent implementation: the node's frames are laid
//! out by hand (`espnow_frame`), and it is the blob's ESP-NOW that takes
//! them or does not.
//!
//! # The serial side (text lines, so the console's own lines can share it)
//!
//! ```text
//! relay -> host   R <source: 12 hex> <payload: hex>     a datagram heard
//! host  -> relay  T <destination: 12 hex> <payload: hex> a datagram to send
//! relay -> host   K <0|1>                                 that send's verdict (1: acknowledged)
//! host  -> relay  ?                                       who is there
//! relay -> host   relay: espnow-relay mac=<12 hex> channel=<n> ...  (also at boot)
//! ```
//!
//! The host waits for `K` before its next `T`. `ffffffffffff` is broadcast.
//! Anything else the relay prints starts with `relay:`.
//!
//! The serial line is UART0 at `JANUS_RELAY_BAUD` (115200 unless the build
//! says otherwise; a signed update through the relay wants more: at 115200
//! a 250-byte datagram is 45 ms of hex, 4 KB/s, and the bridge's client
//! gives a neighbour's update 60 s and 10 KB/s). The receive side is
//! drained by the UART's interrupt into a ring, so a line coming in while
//! another is being printed is not lost to the 128-byte hardware queue.
//!
//! The channel is `JANUS_LINK_CHANNEL` at build time (6 by default: the
//! channel the hosting cells are on); ESP-NOW rides the station's.

extern crate alloc;

use core::cell::RefCell;

use critical_section::Mutex;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::Blocking;
use esp_hal::handler;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config as UartConfig, RxConfig, Uart, UartInterrupt};
use esp_println::{Printer, println};
use esp_radio::esp_now::{BROADCAST_ADDRESS, EspNowWifiInterface, PeerInfo};

esp_bootloader_esp_idf::esp_app_desc!();

const CHANNEL: u8 = {
    let n = match option_env!("JANUS_LINK_CHANNEL") {
        Some(s) => parse_number(s),
        None => 6,
    };
    assert!(n >= 1 && n <= 13, "JANUS_LINK_CHANNEL is 1 to 13");
    n as u8
};
const BAUD: u32 = match option_env!("JANUS_RELAY_BAUD") {
    Some(s) => parse_number(s),
    None => 115_200,
};
/// `T `, twelve hex digits, a space, 250 bytes in hex, the line's end.
const LINE: usize = 2 + 12 + 1 + 500 + 2;
/// The receive ring: several lines.
const RING: usize = 4096;

const fn parse_number(s: &str) -> u32 {
    let b = s.as_bytes();
    let mut n = 0u32;
    let mut i = 0;
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "a number, in digits");
        n = n * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    n
}

/// Bytes the UART's interrupt took off the hardware queue, for the loop.
struct Ring {
    bytes: [u8; RING],
    head: usize,
    len: usize,
    /// Bytes that found the ring full, and reads the UART reported in error
    /// (its own queue overran): either way a line was damaged.
    lost: u32,
}

impl Ring {
    const fn new() -> Self {
        Ring {
            bytes: [0; RING],
            head: 0,
            len: 0,
            lost: 0,
        }
    }

    fn push(&mut self, data: &[u8]) {
        for &b in data {
            if self.len == RING {
                self.lost += 1;
                continue;
            }
            self.bytes[(self.head + self.len) % RING] = b;
            self.len += 1;
        }
    }

    fn pop(&mut self, out: &mut [u8]) -> usize {
        let n = self.len.min(out.len());
        for slot in &mut out[..n] {
            *slot = self.bytes[self.head];
            self.head = (self.head + 1) % RING;
        }
        self.len -= n;
        n
    }
}

static SERIAL: Mutex<RefCell<Option<Uart<'static, Blocking>>>> = Mutex::new(RefCell::new(None));
static RX: Mutex<RefCell<Ring>> = Mutex::new(RefCell::new(Ring::new()));

/// The UART has bytes (its queue reached the threshold, or the line went
/// quiet): all of them into the ring.
#[handler]
fn on_serial() {
    critical_section::with(|cs| {
        let mut serial = SERIAL.borrow_ref_mut(cs);
        let Some(uart) = serial.as_mut() else {
            return;
        };
        let mut ring = RX.borrow_ref_mut(cs);
        let mut chunk = [0u8; 64];
        // bounded: an error is reported once and the next read goes on
        for _ in 0..8 {
            match uart.read_buffered(&mut chunk) {
                Ok(0) => break,
                Ok(n) => ring.push(&chunk[..n]),
                Err(_) => ring.lost += 1,
            }
        }
        uart.clear_interrupts(UartInterrupt::RxFifoFull | UartInterrupt::RxTimeout);
    });
}

const DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_into(bytes: &[u8], out: &mut [u8]) -> usize {
    for (i, b) in bytes.iter().enumerate() {
        out[2 * i] = DIGITS[usize::from(b >> 4)];
        out[2 * i + 1] = DIGITS[usize::from(b & 0xf)];
    }
    bytes.len() * 2
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `text` as hex into `out`: the bytes written, or `None` on an odd length,
/// a digit that is not one, or too many.
fn unhex(text: &[u8], out: &mut [u8]) -> Option<usize> {
    if text.len() % 2 != 0 || text.len() / 2 > out.len() {
        return None;
    }
    for (i, pair) in text.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(text.len() / 2)
}

/// A `T <destination> <payload>` line: the destination and the payload's
/// length in `payload`.
fn parse_send(line: &[u8], payload: &mut [u8; 250]) -> Option<([u8; 6], usize)> {
    let rest = line.strip_prefix(b"T ")?;
    let (to, rest) = rest.split_at_checked(12)?;
    let mut destination = [0u8; 6];
    unhex(to, &mut destination)?;
    let hex = rest.strip_prefix(b" ")?;
    let n = unhex(hex, payload)?;
    Some((destination, n))
}

/// Who this is: the station's address is the chip's base address, what a
/// node is built to send to when it is not left to learn it from a
/// broadcast.
fn hello(channel_set: bool) {
    let mut mac = [0u8; 12];
    hex_into(esp_hal::efuse::base_mac_address().as_bytes(), &mut mac);
    let mac = core::str::from_utf8(&mac).unwrap_or("?");
    println!(
        "relay: espnow-relay mac={mac} channel={CHANNEL} channel_set={channel_set} baud={BAUD} (the blob's ESP-NOW)"
    );
    println!("relay: ready");
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    // The plain ESP32 has little contiguous DRAM (96 KB there eats the main
    // stack) and the radio takes some 53 KB at start: it gets the DRAM its
    // ROM loader used, free once the application runs (`dram2_seg`).
    #[cfg(feature = "chip-esp32")]
    {
        esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 98_768);
        esp_alloc::heap_allocator!(size: 32 * 1024);
    }
    #[cfg(not(feature = "chip-esp32"))]
    esp_alloc::heap_allocator!(size: 96 * 1024);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, peripherals.FROM_CPU_INTR0);

    // The console: UART0, where the board's USB-serial bridge is. The
    // receive half is this driver's, drained by its interrupt; the transmit
    // half is written by esp-println (the same UART, so the same speed).
    #[cfg(feature = "chip-esp32c6")]
    let (rx_pin, tx_pin) = (peripherals.GPIO17, peripherals.GPIO16);
    #[cfg(feature = "chip-esp32s3")]
    let (rx_pin, tx_pin) = (peripherals.GPIO44, peripherals.GPIO43);
    #[cfg(feature = "chip-esp32")]
    let (rx_pin, tx_pin) = (peripherals.GPIO3, peripherals.GPIO1);
    let config = UartConfig::default().with_baudrate(BAUD).with_rx(
        RxConfig::default()
            .with_fifo_full_threshold(32)
            .with_timeout(2),
    );
    let mut serial = Uart::new(peripherals.UART0, config)
        .expect("uart0")
        .with_rx(rx_pin)
        .with_tx(tx_pin);
    serial.set_interrupt_handler(on_serial);
    // The driver is where the handler finds it BEFORE the first interrupt
    // can be taken: enabled outside this section, an interrupt already
    // pending (a byte the pin's connection made) ran the handler with
    // nothing to read or clear, again and for ever -- the first image
    // built this way never printed a line.
    critical_section::with(|cs| {
        serial.listen(UartInterrupt::RxFifoFull | UartInterrupt::RxTimeout);
        SERIAL.borrow_ref_mut(cs).replace(serial);
    });
    // the chips with a USB serial port of their own answer on it as well
    #[cfg(any(feature = "chip-esp32c6", feature = "chip-esp32s3"))]
    let (mut usb, _usb_tx) =
        esp_hal::usb::usb_serial_jtag::UsbSerialJtag::new(peripherals.USB_DEVICE).split();

    let mut wifi = esp_radio::wifi::WifiController::new(
        peripherals.WIFI,
        esp_radio::wifi::ControllerConfig::default(),
    )
    .expect("wifi controller");
    wifi.set_config(&esp_radio::wifi::Config::Station(
        esp_radio::wifi::sta::StationConfig::default(),
    ))
    .expect("station config");
    let esp_now = wifi.esp_now();
    let channel_set = esp_now.set_channel(CHANNEL).is_ok();
    let (manager, mut sender, receiver) = esp_now.split();

    hello(channel_set);

    let mut line = [0u8; LINE];
    let mut len = 0usize;
    let mut overrun = false;
    let mut payload = [0u8; 250];
    let mut chunk = [0u8; 128];
    // `R `, the source, a space, the payload, the line's end
    let mut out = [0u8; 2 + 12 + 1 + 500 + 2];
    let (mut heard, mut sent, mut failed, mut bad_lines) = (0u32, 0u32, 0u32, 0u32);
    let mut ticks = 0u32;
    loop {
        // the air -> the host: each datagram one write
        while let Some(received) = receiver.receive() {
            heard += 1;
            out[..2].copy_from_slice(b"R ");
            let mut n = 2 + hex_into(&received.info.src_address, &mut out[2..]);
            out[n] = b' ';
            n += 1;
            n += hex_into(received.data(), &mut out[n..]);
            out[n..n + 2].copy_from_slice(b"\r\n");
            Printer::write_bytes(&out[..n + 2]);
        }
        // the host -> the air, a line at a time
        let n = critical_section::with(|cs| RX.borrow_ref_mut(cs).pop(&mut chunk));
        #[cfg(any(feature = "chip-esp32c6", feature = "chip-esp32s3"))]
        let n = if n == 0 {
            usb.drain_rx_fifo(&mut chunk)
        } else {
            n
        };
        for &byte in &chunk[..n] {
            if byte != b'\n' {
                if len < line.len() {
                    line[len] = byte;
                    len += 1;
                } else {
                    overrun = true;
                }
                continue;
            }
            let text = line[..len].strip_suffix(b"\r").unwrap_or(&line[..len]);
            if text == b"?" && !overrun {
                // a board with no reset line is asked rather than restarted
                hello(channel_set);
                len = 0;
                continue;
            }
            let parsed = if overrun {
                None
            } else {
                parse_send(text, &mut payload)
            };
            len = 0;
            overrun = false;
            let Some((to, n)) = parsed else {
                if !text.is_empty() {
                    bad_lines += 1;
                }
                continue;
            };
            if to != BROADCAST_ADDRESS && !manager.peer_exists(&to) {
                let _ = manager.add_peer(PeerInfo {
                    interface: EspNowWifiInterface::Station,
                    peer_address: to,
                    lmk: None,
                    channel: None,
                    encrypt: false,
                });
            }
            let ok = sender.send_async(&to, &payload[..n]).await.is_ok();
            if ok {
                sent += 1;
            } else {
                failed += 1;
            }
            Printer::write_bytes(if ok { b"K 1\r\n" } else { b"K 0\r\n" });
        }
        ticks += 1;
        if ticks % 20_000 == 0 {
            let lost = critical_section::with(|cs| RX.borrow_ref(cs).lost);
            println!(
                "relay: heard={heard} sent={sent} failed={failed} bad_lines={bad_lines} serial_lost={lost}"
            );
        }
        // nothing waiting: let the radio's tasks run
        if n == 0 {
            Timer::after(Duration::from_micros(250)).await;
        }
    }
}

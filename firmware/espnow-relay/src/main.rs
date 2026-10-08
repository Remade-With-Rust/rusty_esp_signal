#![no_std]
#![no_main]
//! **The bridge's radio on a wire**: ESP-NOW datagrams between the air and
//! the serial port, on the blob (esp-radio's ESP-NOW), so a bridge on a
//! computer reaches a node whose link rides raw frames on the open MAC --
//! and the computer's own Wi-Fi is never taken. The relay holds no key and
//! reads no frame: the link's session is between the node and the bridge,
//! and what passes here is sealed.
//!
//! It is also the independent implementation: the node's frames are laid
//! out by hand (`espnow_frame`), and it is the blob's ESP-NOW that takes
//! them or does not.
//!
//! # The serial side, protocol 2 (text lines, so the console's own lines can share it)
//!
//! ```text
//! host  -> relay  T <id: 2 hex> <destination: 12 hex> <payload: hex>   a datagram to send
//! relay -> host   K <id> <0|1>          that send's verdict (1: acknowledged on the air)
//! relay -> host   R <source: 12 hex> <rssi> <payload: hex>             a datagram heard
//! relay -> host   b <tag> <sequence> <rssi>                            a beacon heard (below)
//! host  -> relay  ?                     who is there
//! relay -> host   relay: espnow-relay proto=2 mac=<12 hex> channel=<n> baud=<n> rate=<n> ...
//! host  -> relay  U <baud>              the line's speed from the next byte on
//! host  -> relay  P <rate>              the air's rate to each peer, in Mbit/s (1, 2, 5, 11, 6, 12, 24, 54)
//! host  -> relay  B <count> <gap_us> <length>                          send that many beacons
//! host  -> relay  C <channel>           the 2.4 GHz channel, 1 to 13
//! host  -> relay  W <quarter-dBm>       the radio's transmit power cap (esp-radio's
//!                                       default is 20, 5 dBm; ESP-IDF's is 80, 20 dBm)
//! ```
//!
//! **Pipelined.** The host may have several `T` lines on the wire at once:
//! they queue in the receive ring (4 KB, drained from the UART by its
//! interrupt) while a frame is on the air, and each gets its verdict by its
//! id. The ring holds seven full datagrams; a host that keeps six
//! outstanding never overruns it.
//!
//! **The line's speed.** UART0 starts at 115200 (the ROM's and the loader's
//! speed, so a board's whole boot reads on one setting) and `U` raises it:
//! a 250-byte datagram is 45 ms of hex at 115200 and under 6 ms at 921600.
//! A speed nobody answers at within three seconds is dropped for 115200
//! again, so a wrong guess costs three seconds and no button.
//!
//! **Beacons** are numbered broadcasts for counting one-way loss: `JB`, a
//! tag octet, a 32-bit sequence number, filler. `B` sends them (tag `R`);
//! one heard is printed as a short `b` line with its signal strength, so a
//! receiver keeps up with a fast sender. `JANUS_BEACON=count,gap_us,length`
//! at build time sends them once at start (a board whose console takes no
//! input).
//!
//! The channel is `JANUS_LINK_CHANNEL` at build time (6 by default: the
//! channel the hosting cells are on) until a `C` names another; ESP-NOW
//! rides the station's.

extern crate alloc;

use core::cell::RefCell;

use critical_section::Mutex;
use embassy_time::{Duration, Instant, Timer};
use esp_backtrace as _;
use esp_hal::Blocking;
use esp_hal::handler;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::uart::{Config as UartConfig, RxConfig, Uart, UartInterrupt};
use esp_println::{Printer, println};
use esp_radio::esp_now::{
    BROADCAST_ADDRESS, EspNowManager, EspNowSender, EspNowWifiInterface, PeerInfo, PhyMode,
    RateConfig, WifiPhyRate,
};

esp_bootloader_esp_idf::esp_app_desc!();

const CHANNEL: u8 = {
    let n = match option_env!("JANUS_LINK_CHANNEL") {
        Some(s) => parse_number(s),
        None => 6,
    };
    assert!(n >= 1 && n <= 13, "JANUS_LINK_CHANNEL is 1 to 13");
    n as u8
};
/// The speed the line starts at, and falls back to.
const BOOT_BAUD: u32 = 115_200;
/// `T `, an id, twelve hex digits, a space, 250 bytes in hex, the line's end.
const LINE: usize = 2 + 3 + 12 + 1 + 500 + 2;
/// How long a new speed waits for the host to speak at it.
const BAUD_PATIENCE: Duration = Duration::from_secs(3);

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

mod ring;
use ring::{Lines, Ring};

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

fn console(baud: u32) -> UartConfig {
    UartConfig::default().with_baudrate(baud).with_rx(
        RxConfig::default()
            .with_fifo_full_threshold(32)
            .with_timeout(2),
    )
}

/// The line at `baud` from here on: whether the UART took it.
fn set_baud(baud: u32) -> bool {
    critical_section::with(|cs| {
        let mut serial = SERIAL.borrow_ref_mut(cs);
        let Some(uart) = serial.as_mut() else {
            return false;
        };
        let ok = uart.apply_config(&console(baud)).is_ok();
        uart.listen(UartInterrupt::RxFifoFull | UartInterrupt::RxTimeout);
        ok
    })
}

mod hex;
use hex::{decimal_into, hex_into, unhex};

/// A `T <id> <destination> <payload>` line: the id, the destination and
/// the payload's length in `payload`.
fn parse_send(line: &[u8], payload: &mut [u8; 250]) -> Option<(u8, [u8; 6], usize)> {
    let rest = line.strip_prefix(b"T ")?;
    let (id_text, rest) = rest.split_at_checked(2)?;
    let mut id = [0u8; 1];
    unhex(id_text, &mut id)?;
    let rest = rest.strip_prefix(b" ")?;
    let (to, rest) = rest.split_at_checked(12)?;
    let mut destination = [0u8; 6];
    unhex(to, &mut destination)?;
    let hex = rest.strip_prefix(b" ")?;
    let n = unhex(hex, payload)?;
    Some((id[0], destination, n))
}

/// Up to three numbers after a one-letter verb: `U 921600`, `B 2000 5000 100`.
fn parse_numbers(line: &[u8], verb: u8) -> Option<[u32; 3]> {
    let (first, rest) = line.split_first()?;
    if *first != verb {
        return None;
    }
    let text = core::str::from_utf8(rest).ok()?;
    let mut out = [0u32; 3];
    let mut count = 0;
    for part in text.split_ascii_whitespace() {
        if count == 3 {
            return None;
        }
        out[count] = part.parse().ok()?;
        count += 1;
    }
    (count > 0).then_some(out)
}

/// ESP-NOW's rate for `mbps`, or `None` for one it does not have.
fn rate_for(mbps: u32) -> Option<RateConfig> {
    let (phy_mode, rate) = match mbps {
        1 => (PhyMode::_11b, WifiPhyRate::Rate1mL),
        2 => (PhyMode::_11b, WifiPhyRate::Rate2m),
        5 => (PhyMode::_11b, WifiPhyRate::Rate5mL),
        11 => (PhyMode::_11b, WifiPhyRate::Rate11mL),
        6 => (PhyMode::_11g, WifiPhyRate::Rate6m),
        12 => (PhyMode::_11g, WifiPhyRate::Rate12m),
        24 => (PhyMode::_11g, WifiPhyRate::Rate24m),
        54 => (PhyMode::_11g, WifiPhyRate::Rate54m),
        _ => return None,
    };
    Some(RateConfig {
        phy_mode,
        rate,
        ersu: false,
        dcm: false,
    })
}

/// Who this is: the station's address is the chip's base address, what a
/// node is built to send to when it is not left to learn it from a
/// broadcast.
fn hello(channel: u8, channel_set: bool, baud: u32, rate: u32, power: i8) {
    let mut mac = [0u8; 12];
    hex_into(esp_hal::efuse::base_mac_address().as_bytes(), &mut mac);
    let mac = core::str::from_utf8(&mac).unwrap_or("?");
    println!(
        "relay: espnow-relay proto=2 mac={mac} channel={channel} channel_set={channel_set} baud={baud} rate={rate} power={power} (the blob's ESP-NOW)"
    );
    println!("relay: ready");
}

/// `count` numbered broadcasts `gap_us` apart, `length` bytes each: how
/// many the radio refused.
async fn beacons(sender: &mut EspNowSender, tag: u8, count: u32, gap_us: u32, length: u32) -> u32 {
    let length = (length as usize).clamp(7, 250);
    let mut frame = [0xA5u8; 250];
    frame[..2].copy_from_slice(b"JB");
    frame[2] = tag;
    let started = Instant::now();
    let mut failed = 0u32;
    for sequence in 0..count {
        Timer::at(started + Duration::from_micros(u64::from(sequence) * u64::from(gap_us))).await;
        frame[3..7].copy_from_slice(&sequence.to_be_bytes());
        if sender
            .send_async(&BROADCAST_ADDRESS, &frame[..length])
            .await
            .is_err()
        {
            failed += 1;
        }
    }
    println!(
        "relay: beacons sent={count} failed={failed} gap_us={gap_us} length={length} elapsed_ms={}",
        started.elapsed().as_millis()
    );
    failed
}

/// The peer `to` on the station's interface, at `rate` when one is set.
fn know(manager: &EspNowManager, to: &[u8; 6], rate: Option<RateConfig>) {
    if *to == BROADCAST_ADDRESS || manager.peer_exists(to) {
        return;
    }
    let _ = manager.add_peer(PeerInfo {
        interface: EspNowWifiInterface::Station,
        peer_address: *to,
        lmk: None,
        channel: None,
        encrypt: false,
    });
    if let Some(rate) = rate {
        let _ = manager.set_peer_rate(to, rate);
    }
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
    let mut serial = Uart::new(peripherals.UART0, console(BOOT_BAUD))
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

    let mut baud = BOOT_BAUD;
    // a speed just taken, until the host speaks at it
    let mut baud_on_trial: Option<Instant> = None;
    let mut rate_mbps = 1u32;
    let mut rate: Option<RateConfig> = None;
    let mut channel = CHANNEL;
    let mut channel_set = channel_set;
    // the radio's transmit power cap, in quarter dBm: esp-radio leaves it
    // at 20 (5 dBm), which a receiver hears 15 dB below the open MAC's
    // frames from the same place (E4's beacon count)
    let mut power = 20i8;
    hello(channel, channel_set, baud, rate_mbps, power);

    // a board whose console takes no input sends its beacons at start
    if let Some(plan) = option_env!("JANUS_BEACON") {
        let mut numbers = plan.split(',').filter_map(|p| p.trim().parse::<u32>().ok());
        if let (Some(count), Some(gap_us), Some(length)) =
            (numbers.next(), numbers.next(), numbers.next())
        {
            // let the receiver's capture start
            Timer::after(Duration::from_secs(3)).await;
            println!("S1 beacon stack=blob count={count} gap_us={gap_us} len={length}");
            let failed = beacons(&mut sender, b'B', count, gap_us, length).await;
            println!("RESULT: beacons done sent={count} failed={failed}");
        }
    }

    let mut lines = Lines::<LINE>::new();
    let mut payload = [0u8; 250];
    let mut chunk = [0u8; 128];
    // `R `, the source, the signal strength, the payload, the line's end
    let mut out = [0u8; 2 + 12 + 1 + 5 + 1 + 500 + 2];
    let (mut heard, mut sent, mut failed, mut bad_lines) = (0u32, 0u32, 0u32, 0u32);
    let mut last_report = Instant::now();
    loop {
        // the air -> the host: each datagram one write
        while let Some(received) = receiver.receive() {
            heard += 1;
            let data = received.data();
            let rssi = received.info.rx_control.rssi;
            let mut n;
            if data.len() >= 7 && &data[..2] == b"JB" {
                // a beacon: its tag, its number, how strong
                out[..2].copy_from_slice(b"b ");
                out[2] = if data[2].is_ascii_graphic() {
                    data[2]
                } else {
                    b'?'
                };
                out[3] = b' ';
                n = 4;
                let sequence = u32::from_be_bytes([data[3], data[4], data[5], data[6]]);
                n += decimal_into(sequence as i32, &mut out[n..]);
                out[n] = b' ';
                n += 1;
                n += decimal_into(rssi, &mut out[n..]);
            } else {
                out[..2].copy_from_slice(b"R ");
                n = 2 + hex_into(&received.info.src_address, &mut out[2..]);
                out[n] = b' ';
                n += 1;
                n += decimal_into(rssi, &mut out[n..]);
                out[n] = b' ';
                n += 1;
                n += hex_into(data, &mut out[n..]);
            }
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
        let mut rest = &chunk[..n];
        while !rest.is_empty() {
            let (used, ended) = lines.take(rest);
            rest = &rest[used..];
            if !ended {
                break;
            }
            let len = core::mem::take(&mut lines.len);
            let whole = !core::mem::take(&mut lines.overrun);
            let text = lines.line[..len]
                .strip_suffix(b"\r")
                .unwrap_or(&lines.line[..len]);
            if text.is_empty() {
                continue;
            }
            if !whole {
                bad_lines += 1;
                continue;
            }
            if let Some((id, to, n)) = parse_send(text, &mut payload) {
                baud_on_trial = None;
                know(&manager, &to, rate);
                let ok = sender.send_async(&to, &payload[..n]).await.is_ok();
                if ok {
                    sent += 1;
                } else {
                    failed += 1;
                }
                let mut verdict = *b"K 00 0\r\n";
                hex_into(&[id], &mut verdict[2..4]);
                verdict[5] = b'0' + u8::from(ok);
                Printer::write_bytes(&verdict);
            } else if text == b"?" {
                // a board with no reset line is asked rather than restarted
                baud_on_trial = None;
                hello(channel, channel_set, baud, rate_mbps, power);
            } else if let Some([wanted, _, _]) = parse_numbers(text, b'U') {
                println!("relay: baud {wanted}");
                // the answer leaves at the old speed first
                Timer::after(Duration::from_millis(40)).await;
                if set_baud(wanted) {
                    baud = wanted;
                    baud_on_trial = Some(Instant::now());
                } else {
                    let _ = set_baud(baud);
                    println!("relay: baud {baud} (the UART refused {wanted})");
                }
            } else if let Some([mbps, _, _]) = parse_numbers(text, b'P') {
                match rate_for(mbps) {
                    Some(config) => {
                        rate_mbps = mbps;
                        rate = (mbps != 1).then_some(config);
                        // peers already known take it too
                        let mut from_head = true;
                        while let Ok(peer) = manager.fetch_peer(from_head) {
                            from_head = false;
                            let _ = manager.set_peer_rate(&peer.peer_address, config);
                        }
                        println!("relay: rate {mbps}");
                    }
                    None => println!("relay: rate {rate_mbps} (no such rate: {mbps})"),
                }
            } else if let Some([count, gap_us, length]) = parse_numbers(text, b'B') {
                beacons(&mut sender, b'R', count, gap_us, length).await;
            } else if let Some([wanted, _, _]) = parse_numbers(text, b'W') {
                if (8..=84).contains(&wanted) && wifi.set_max_tx_power(wanted as i8).is_ok() {
                    power = wanted as i8;
                    println!("relay: power {power}");
                } else {
                    println!("relay: power {power} (refused {wanted})");
                }
            } else if let Some([wanted, _, _]) = parse_numbers(text, b'C') {
                if (1..=13).contains(&wanted) && manager.set_channel(wanted as u8).is_ok() {
                    channel = wanted as u8;
                    channel_set = true;
                    println!("relay: channel {channel}");
                } else {
                    println!("relay: channel {channel} (refused {wanted})");
                }
            } else {
                bad_lines += 1;
            }
        }
        // a speed the host never spoke at: back to the one a boot reads at
        if baud_on_trial.is_some_and(|since| since.elapsed() > BAUD_PATIENCE) {
            let refused = baud;
            baud = BOOT_BAUD;
            baud_on_trial = None;
            let _ = set_baud(baud);
            println!("relay: baud {baud} (no answer at {refused})");
        }
        if last_report.elapsed() > Duration::from_secs(5) {
            last_report = Instant::now();
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

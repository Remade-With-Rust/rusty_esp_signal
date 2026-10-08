#![no_std]
#![no_main]
//! The experiments' portable code counted on silicon (the optimisation
//! round of 2026-10-07). Each kernel runs `REPS` times with interrupts
//! masked between two reads of the C6's performance counter set to count
//! retired instructions (`mpcer` = instructions, `mpcmr` = on, `mpccr` the
//! count: Espressif's CSRs 0x7E0-0x7E2), so the number is exact and
//! repeatable -- a deterministic counter, not a clock. Every kernel's last
//! output goes into an FNV-1a hash: the byte-identity gate between arms.
//!
//! Lines: `INSN <kernel> reps=<n> per_call=<instructions> total=<n>
//! fnv=<hash>`, then `INSN done kernels=<k>`, repeated every few seconds for
//! a reader that joins late (the DevKitC's bridge).

extern crate alloc;

#[allow(dead_code)]
#[path = "../../espnow-relay/src/hex.rs"]
mod hex;
#[allow(dead_code)]
#[path = "../../espnow-relay/src/ring.rs"]
mod ring;
#[allow(dead_code)]
#[path = "../../c6-open-rx/src/sniff.rs"]
mod sniff;

use alloc::vec;
use alloc::vec::Vec;
use ap_core::elements::Elements;
use ap_core::frames::{self, Bss, Tim};
use ap_core::handshake::{self, Authenticator};
use ap_core::hold::Held;
use ap_core::request;
use ap_core::stations::Stations;
use ap_core::{BROADCAST, qos, rsn, status};
use core::hint::black_box;
use esp_backtrace as _;
use esp_hal::clock::CpuClock;
use esp_println::println;
use ieee80211::crypto::map_passphrase_to_psk;
use ieee80211::element_chain;
use ieee80211::elements::rsn::RsnElement;
use ieee80211::mac_parser::MACAddress;
use ieee80211::scroll::Pwrite;
use sta_handshake::{GroupKey, PairwiseKeys};

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &[u8] = b"janus-e3-test";
const PASSPHRASE: &str = "not-a-real-network-0000";
const AP: [u8; 6] = [0x02, 0xe3, 0, 0, 0, 0xa1];
const STA: [u8; 6] = [0x02, 0xe3, 0, 0, 0, 0x51];
const ANONCE: [u8; 32] = [0xa5; 32];
const SNONCE: [u8; 32] = [0x5a; 32];
const STA_WMM: [u8; 9] = [221, 7, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00];

fn fnv(acc: u32, bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(acc, |h, &b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193))
}

const FNV0: u32 = 0x811c_9dc5;

/// Retired instructions of `reps` calls of `f`, interrupts masked; `f`
/// returns its output's hash, the last one is kept.
fn count(name: &str, reps: u32, mut f: impl FnMut() -> u32) -> (u32, u32) {
    let (insns, hash) = critical_section::with(|_| {
        let mut hash = 0;
        unsafe {
            // count instructions; on; from zero
            core::arch::asm!("csrw 0x7E0, {0}", in(reg) 2u32);
            core::arch::asm!("csrw 0x7E1, {0}", in(reg) 1u32);
            core::arch::asm!("csrw 0x7E2, zero");
        }
        let start: u32;
        unsafe { core::arch::asm!("csrr {0}, 0x7E2", out(reg) start) };
        for _ in 0..reps {
            hash = black_box(f());
        }
        let end: u32;
        unsafe { core::arch::asm!("csrr {0}, 0x7E2", out(reg) end) };
        (end.wrapping_sub(start), hash)
    });
    println!(
        "INSN {name} reps={reps} per_call={} total={insns} fnv={hash:08x}",
        insns / reps
    );
    (insns, hash)
}

/// The relay's ring as it was before the optimisation round: the oracle the
/// new one is checked against, byte for byte, overflow included.
struct OracleRing {
    bytes: [u8; ring::RING],
    head: usize,
    len: usize,
    lost: u32,
}

impl OracleRing {
    fn push(&mut self, data: &[u8]) {
        for &b in data {
            if self.len == ring::RING {
                self.lost += 1;
                continue;
            }
            self.bytes[(self.head + self.len) % ring::RING] = b;
            self.len += 1;
        }
    }
    fn pop(&mut self, out: &mut [u8]) -> usize {
        let n = self.len.min(out.len());
        for slot in &mut out[..n] {
            *slot = self.bytes[self.head];
            self.head = (self.head + 1) % ring::RING;
        }
        self.len -= n;
        n
    }
}

/// 20,000 pushes and pops of pseudo-random sizes (overflow and wrap
/// included) through both rings: every byte out and the lost count equal.
fn ring_oracle() -> bool {
    let mut a = ring::Ring::new();
    let mut b = OracleRing {
        bytes: [0; ring::RING],
        head: 0,
        len: 0,
        lost: 0,
    };
    let mut seed = 0x1234_5678u32;
    let mut data = [0u8; 1500];
    let (mut out_a, mut out_b) = ([0u8; 1500], [0u8; 1500]);
    for (i, d) in data.iter_mut().enumerate() {
        *d = (i as u8).wrapping_mul(29);
    }
    for _ in 0..20_000 {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        let n = (seed % 1500) as usize;
        if seed & 0x8000_0000 != 0 {
            a.push(&data[..n]);
            b.push(&data[..n]);
        } else {
            let (x, y) = (a.pop(&mut out_a[..n]), b.pop(&mut out_b[..n]));
            if x != y || out_a[..x] != out_b[..y] {
                return false;
            }
        }
    }
    a.lost == b.lost
}

/// The relay's line assembly as it was before the optimisation round (a
/// byte at a time): the oracle and the "before" arm.
struct OracleLines {
    line: [u8; 520],
    len: usize,
    overrun: bool,
}

impl OracleLines {
    /// Every finished line to `done`: its text, the CR stripped, and whole.
    fn feed(&mut self, bytes: &[u8], mut done: impl FnMut(&[u8], bool)) {
        for &byte in bytes {
            if byte != b'\n' {
                if self.len < self.line.len() {
                    self.line[self.len] = byte;
                    self.len += 1;
                } else {
                    self.overrun = true;
                }
                continue;
            }
            let text = self.line[..self.len]
                .strip_suffix(b"\r")
                .unwrap_or(&self.line[..self.len]);
            done(text, !self.overrun);
            self.len = 0;
            self.overrun = false;
        }
    }
}

/// The relay's word-at-a-time newline search against `position` on 20,000
/// random buffers: random lengths and alignments, newlines anywhere or
/// nowhere, bytes at and above 0x80 among them.
fn newline_oracle() -> bool {
    let mut buf = [0u8; 300];
    let mut seed = 0x9e37_79b9u32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        seed
    };
    for _ in 0..20_000 {
        for b in buf.iter_mut() {
            let r = next();
            *b = if r % 97 == 0 { 10 } else { (r >> 8) as u8 };
        }
        let start = (next() % 8) as usize;
        let len = (next() % 290) as usize;
        let s = &buf[start..start + len];
        if ring::newline(s) != s.iter().position(|&b| b == 10) {
            return false;
        }
    }
    true
}

fn bss(protected: bool, ht: bool) -> Bss<'static> {
    Bss {
        bssid: AP,
        ssid: SSID,
        channel: 6,
        beacon_interval_tu: 100,
        protected,
        ht,
    }
}

fn mgmt(subtype: u8, from: [u8; 6], to: [u8; 6], bssid: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut f = vec![subtype << 4, 0, 0, 0];
    f.extend_from_slice(&to);
    f.extend_from_slice(&from);
    f.extend_from_slice(&bssid);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(body);
    f
}

fn station_rsn_element() -> Vec<u8> {
    let mut buf = [0u8; 64];
    let n = buf
        .pwrite(element_chain! { RsnElement::WPA2_PERSONAL }, 0)
        .unwrap_or(0);
    buf[..n].to_vec()
}

fn sta_ht(info: u16, rx_mcs: u8) -> [u8; 28] {
    let mut e = [0u8; 28];
    e[0] = 45;
    e[1] = 26;
    e[2..4].copy_from_slice(&info.to_le_bytes());
    e[5] = rx_mcs;
    e
}

/// A station's association request as a WPA2 phone sends it: capability,
/// listen interval, SSID, rates, extended rates, RSN, HT, WMM.
fn assoc_request(rsn: &[u8]) -> Vec<u8> {
    let mut body = vec![0x11, 0x04, 10, 0, 0, SSID.len() as u8];
    body.extend_from_slice(SSID);
    body.extend_from_slice(&[1, 8, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    body.extend_from_slice(&[50, 4, 0x30, 0x48, 0x60, 0x6c]);
    body.extend_from_slice(rsn);
    body.extend_from_slice(&sta_ht(0x016e, 0xff));
    body.extend_from_slice(&STA_WMM);
    mgmt(0, STA, AP, AP, &body)
}

#[esp_hal::main]
fn main() -> ! {
    let _p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    esp_alloc::heap_allocator!(size: 64 * 1024);
    println!("INSN boot c6-insn-bench");
    println!(
        "INSN oracle ring {}",
        if ring_oracle() { "identical" } else { "FAIL" }
    );
    println!(
        "INSN oracle newline {}",
        if newline_oracle() {
            "identical"
        } else {
            "FAIL"
        }
    );

    // the fixtures, outside every count
    let rsn = station_rsn_element();
    let assoc = assoc_request(&rsn);
    let probe_wild = mgmt(
        4,
        STA,
        BROADCAST,
        BROADCAST,
        &[0, 0, 1, 4, 0x82, 0x84, 0x8b, 0x96],
    );
    let probe_named = {
        let mut body = vec![0, SSID.len() as u8];
        body.extend_from_slice(SSID);
        body.extend_from_slice(&[1, 4, 0x82, 0x84, 0x8b, 0x96]);
        body.extend_from_slice(&sta_ht(0x016e, 0xff));
        mgmt(4, STA, BROADCAST, BROADCAST, &body)
    };
    let auth = mgmt(11, STA, AP, AP, &[0, 0, 1, 0, 0, 0]);
    let mut pmk = [0u8; 32];
    map_passphrase_to_psk(PASSPHRASE, "janus-e3-test", &mut pmk);
    let gtk = GroupKey {
        key: [0x61; 16],
        key_id: 1,
        rsc: 0x0102_0304_0506,
        replay_counter: 0,
    };
    let sta_keys = PairwiseKeys::derive(&pmk, &AP, &STA, &ANONCE, &SNONCE);
    let (mut out, mut scratch) = (vec![0u8; 1024], vec![0u8; 1024]);
    // message 2 and 4 as our station sends them, for the reads
    let n2 = sta_handshake::write_message_2(
        &mut out,
        &mut scratch,
        MACAddress::new(AP),
        MACAddress::new(STA),
        &sta_keys,
        &SNONCE,
        1,
    )
    .unwrap_or(0);
    let msg2 = out[..n2].to_vec();
    let n4 = sta_handshake::write_message_4(
        &mut out,
        &mut scratch,
        MACAddress::new(AP),
        MACAddress::new(STA),
        &sta_keys,
        2,
    )
    .unwrap_or(0);
    let msg4 = out[..n4].to_vec();
    let mut held_frames: Vec<Vec<u8>> = Vec::new();
    for i in 0..6u8 {
        let mut eth = vec![0u8; 14 + 60 + usize::from(i) * 100];
        eth[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1 + (i % 3)]);
        eth[6..12].copy_from_slice(&AP);
        eth[12] = 0x08;
        held_frames.push(eth);
    }
    let mut group_frame = vec![0u8; 14 + 28];
    group_frame[..6].copy_from_slice(&BROADCAST);
    group_frame[12] = 0x08;
    group_frame[13] = 0x06;
    let mut beacon_air = [0u8; 512];
    let beacon_tim = Tim {
        dtim_count: 0,
        dtim_period: 2,
        group_buffered: true,
        buffered_aids: 0b110,
    };
    let beacon_len = frames::beacon(&mut beacon_air, &bss(true, true), &beacon_tim)
        .map(|b| b.len)
        .unwrap_or(0);

    loop {
        let mut k = 0u32;
        let mut buf = [0u8; 512];

        // ---- frames --------------------------------------------------
        let b_ht = bss(true, true);
        k += 1;
        count("beacon_wpa2_ht", 2000, || {
            let b = frames::beacon(
                black_box(&mut buf),
                black_box(&b_ht),
                black_box(&beacon_tim),
            );
            b.map_or(0, |b| fnv(FNV0, &buf[..b.len]))
        });
        let b_open = bss(false, false);
        k += 1;
        count("beacon_open", 2000, || {
            let b = frames::beacon(
                black_box(&mut buf),
                black_box(&b_open),
                black_box(&beacon_tim),
            );
            b.map_or(0, |b| fnv(FNV0, &buf[..b.len]))
        });
        // the access point's per-TBTT work from a template: the TIM
        // rewritten in place (its hash must equal the full build's above)
        let mut template = [0u8; 512];
        let tim_at = frames::beacon(&mut template, &b_ht, &Tim::default())
            .map(|b| (b.tim_at, b.len))
            .unwrap_or((0, 0));
        k += 1;
        count("beacon_per_tbtt_template", 2000, || {
            let ok = frames::set_tim(black_box(&mut template), tim_at.0, black_box(&beacon_tim));
            ok.map_or(0, |()| fnv(FNV0, &template[..tim_at.1]))
        });
        k += 1;
        count("probe_response_ht", 2000, || {
            let n = frames::probe_response(black_box(&mut buf), black_box(&b_ht), black_box(STA));
            n.map_or(0, |n| fnv(FNV0, &buf[..n]))
        });
        // a probe response from a template: copied, its receiver set (its
        // hash must equal the full build's above)
        let mut probe_template = [0u8; 512];
        let probe_len = frames::probe_response(&mut probe_template, &b_ht, [0xff; 6]).unwrap_or(0);
        k += 1;
        count("probe_response_template", 2000, || {
            buf[..probe_len].copy_from_slice(black_box(&probe_template[..probe_len]));
            let ok = frames::set_receiver(&mut buf, black_box(STA));
            ok.map_or(0, |()| fnv(FNV0, &buf[..probe_len]))
        });
        // what every management reply paid before building anything: a
        // 1 KB scratch zeroed (only the EAPOL writes use it)
        k += 1;
        count("reply_scratch_zeroed", 2000, || {
            let scratch = [0u8; 1024];
            black_box(&scratch);
            u32::from(scratch[1023])
        });
        k += 1;
        count("association_response_ht", 2000, || {
            let n = frames::association_response(
                black_box(&mut buf),
                black_box(&b_ht),
                black_box(STA),
                status::SUCCESS,
                3,
                false,
            );
            n.map_or(0, |n| fnv(FNV0, &buf[..n]))
        });
        k += 1;
        count("auth_and_deauth", 2000, || {
            let a =
                frames::authentication(black_box(&mut buf), AP, black_box(STA), status::SUCCESS);
            let h = a.map_or(0, |n| fnv(FNV0, &buf[..n]));
            let d = frames::deauthentication(black_box(&mut buf), AP, black_box(STA), 7);
            d.map_or(h, |n| fnv(h, &buf[..n]))
        });

        // ---- requests --------------------------------------------------
        k += 1;
        count("parse_probes", 2000, || {
            let mut h = FNV0;
            for f in [&probe_wild, &probe_named] {
                if let Some(request::Request::Probe { from, ssid }) =
                    request::parse(black_box(f), black_box(&AP))
                {
                    h = fnv(fnv(h, &from), ssid.unwrap_or(&[0xee]));
                }
            }
            h
        });
        k += 1;
        count("parse_auth", 2000, || {
            match request::parse(black_box(&auth), black_box(&AP)) {
                Some(request::Request::Authentication {
                    from,
                    algorithm,
                    sequence,
                }) => fnv(fnv(FNV0, &from), &[algorithm as u8, sequence as u8]),
                _ => 0,
            }
        });
        k += 1;
        count("parse_assoc_wpa2_ht", 2000, || {
            match request::parse(black_box(&assoc), black_box(&AP)) {
                Some(request::Request::Association {
                    from,
                    ssid,
                    rsn_element,
                    reassociation,
                    qos,
                    ht,
                }) => {
                    let h = fnv(fnv(FNV0, &from), ssid.unwrap_or(&[]));
                    let h = fnv(h, rsn_element.unwrap_or(&[]));
                    let ht = ht.map_or([9, 9], |c| [u8::from(c.short_gi_20), c.rx_mcs]);
                    fnv(h, &[u8::from(reassociation), u8::from(qos), ht[0], ht[1]])
                }
                _ => 0,
            }
        });
        k += 1;
        let assoc_elements = &assoc[24 + 4..];
        count("qos_and_ht_read", 2000, || {
            let e = Elements::new(black_box(assoc_elements));
            let q = qos::station_is_qos(e);
            let ht = qos::station_ht(e).map_or([9, 9], |c| [u8::from(c.short_gi_20), c.rx_mcs]);
            fnv(FNV0, &[u8::from(q), ht[0], ht[1]])
        });
        k += 1;
        let rsn_body = &rsn[2..];
        count("rsn_check", 2000, || {
            let r = rsn::check_station(black_box(rsn_body));
            fnv(FNV0, &r.err().unwrap_or(0xffff).to_le_bytes())
        });
        k += 1;
        count("elements_first_whole", 2000, || {
            let e = Elements::new(black_box(assoc_elements));
            let a = e.first_whole(221).map_or(0, |w| w.len());
            let b = e.first(48).map_or(0, |w| w.len());
            fnv(FNV0, &[a as u8, b as u8])
        });

        // ---- the station table and the hold pool ------------------------
        k += 1;
        count("stations_join_four", 500, || {
            let mut s = Stations::new();
            let mut h = FNV0;
            for n in 1..=4u8 {
                let a = [2, 0, 0, 0, 0, n];
                let st = s.authenticate(black_box(a), 0, 1);
                let aid = s.associate(a, true, Some(&rsn), true).unwrap_or(0);
                h = fnv(h, &[st as u8, aid as u8]);
            }
            h
        });
        let mut table = Stations::new();
        for n in 1..=4u8 {
            let a = [2, 0, 0, 0, 0, n];
            table.authenticate(a, 0, 1);
            let _ = table.associate(a, true, Some(&rsn), true);
        }
        k += 1;
        let mut now = 0u64;
        count("stations_per_frame", 2000, || {
            // a frame from each station, its queue, then the beacon's TIM and
            // the sweep's inactivity check
            now += 1000;
            let mut h = FNV0;
            for n in 1..=4u8 {
                let a = [2, 0, 0, 0, 0, n];
                let ok = table.heard(black_box(&a), now, n & 1 == 0);
                table.set_queued(&a, u16::from(n & 1));
                h = fnv(h, &[u8::from(ok)]);
            }
            let tim = table.tim(1, 2, false);
            let gone = table.inactive(now, 300_000_000).map_or(0, |a| a[5]);
            fnv(
                h,
                &[
                    tim.buffered_aids as u8,
                    (tim.buffered_aids >> 8) as u8,
                    gone,
                ],
            )
        });
        // a data frame's lookups at the access point: `get` then `heard`
        // (before), `heard_was` (after); the same answers, hashed
        k += 1;
        let mut t_old = table.clone();
        count("data_frame_lookup_get_heard", 2000, || {
            now += 1000;
            let mut h = FNV0;
            for n in 1..=4u8 {
                let a = [2, 0, 0, 0, 0, n];
                let (state, was) = match t_old.get(black_box(&a)) {
                    Some(s) => (Some(s.state), s.power_save),
                    None => (None, false),
                };
                let ok = t_old.heard(&a, now, n & 1 == 0);
                h = fnv(
                    h,
                    &[u8::from(ok), state.map_or(9, |s| s as u8), u8::from(was)],
                );
            }
            h
        });
        k += 1;
        let mut t_new = table.clone();
        let mut now2 = 0u64;
        count("data_frame_lookup_heard_was", 2000, || {
            now2 += 1000;
            let mut h = FNV0;
            for n in 1..=4u8 {
                let a = [2, 0, 0, 0, 0, n];
                let r = t_new.heard_was(black_box(&a), now2, n & 1 == 0);
                let (ok, state, was) = match r {
                    Some((s, w)) => (true, Some(s), w),
                    None => (false, None, false),
                };
                h = fnv(
                    h,
                    &[u8::from(ok), state.map_or(9, |s| s as u8), u8::from(was)],
                );
            }
            h
        });
        // the access point's per-TBTT work: the TIM from the table, whether
        // group frames wait, the template's TIM rewritten (a group frame and
        // two stations' frames held)
        let mut tbtt_pool = Held::new();
        let _ = tbtt_pool.push(&held_frames[0], false);
        let _ = tbtt_pool.push(&held_frames[1], false);
        let _ = tbtt_pool.push(&group_frame, true);
        let mut tbtt_beacon = template;
        let mut dtim = 0u8;
        k += 1;
        count("per_tbtt_work", 2000, || {
            dtim ^= 1;
            let group = black_box(&tbtt_pool).group_count() > 0;
            let tim = table.tim(dtim, 2, group);
            let ok = frames::set_tim(&mut tbtt_beacon, tim_at.0, &tim);
            ok.map_or(0, |()| fnv(FNV0, &tbtt_beacon[tim_at.0..tim_at.0 + 7]))
        });
        k += 1;
        let mut pool = Held::new();
        count("hold_cycle", 1000, || {
            let mut h = FNV0;
            for f in &held_frames {
                let _ = pool.push(black_box(f), false);
            }
            let _ = pool.push(&group_frame, true);
            for n in 1..=3u8 {
                let a = [2, 0, 0, 0, 0, n];
                h = fnv(h, &pool.count(&a).to_le_bytes());
            }
            h = fnv(h, &pool.group_count().to_le_bytes());
            while let Some((t, more)) = pool.pop_group() {
                h = fnv(h, &[t.frame.len() as u8, u8::from(more)]);
            }
            for n in 1..=3u8 {
                let a = [2, 0, 0, 0, 0, n];
                while let Some((t, more)) = pool.pop(&a) {
                    h = fnv(h, &[t.frame.len() as u8, u8::from(more)]);
                }
            }
            fnv(h, &[pool.free() as u8])
        });

        // the access point's per-frame copies removed (2026-10-07): each Ethernet
        // frame from the stack copied into a 1,600-byte buffer before delivery,
        // and a 1,514-byte array zeroed per held frame released
        let eth = &held_frames[5];
        let mut frame_buf = [0u8; 1600];
        k += 1;
        count("deliver_extra_copy_600b", 2000, || {
            frame_buf[..eth.len()].copy_from_slice(black_box(eth));
            u32::from(black_box(&frame_buf)[eth.len() - 1])
        });
        k += 1;
        count("release_zeroed_1514b", 2000, || {
            let copy = [0u8; ap_core::hold::HELD_FRAME_BYTES];
            black_box(&copy);
            u32::from(copy[1])
        });

        k += 1;
        count("forward_zeroed_1600b", 2000, || {
            let eth = [0u8; 1600];
            black_box(&eth);
            u32::from(eth[1])
        });

        // ---- the handshake ------------------------------------------------
        let mut auth = Authenticator::new(ANONCE);
        k += 1;
        count("handshake_write_1", 300, || {
            let r = auth.next_replay_counter();
            let n =
                handshake::write_message_1(&mut out, &mut scratch, AP, STA, &ANONCE, black_box(r));
            n.map_or(0, |n| fnv(FNV0, &out[..n]))
        });
        let mut m2 = msg2.clone();
        k += 1;
        count("handshake_read_2", 100, || {
            m2.copy_from_slice(&msg2);
            match handshake::read_message_2(&mut m2, &pmk, &AP, &STA, &ANONCE, 1, &rsn) {
                Ok(keys) => fnv(FNV0, &keys.ptk),
                Err(_) => 1,
            }
        });
        let ap_keys = {
            m2.copy_from_slice(&msg2);
            handshake::read_message_2(&mut m2, &pmk, &AP, &STA, &ANONCE, 1, &rsn).ok()
        };
        if let Some(ap_keys) = ap_keys {
            k += 1;
            count("handshake_write_3", 100, || {
                let n = handshake::write_message_3(
                    &mut out,
                    &mut scratch,
                    AP,
                    STA,
                    &ap_keys,
                    &ANONCE,
                    black_box(2),
                    &gtk,
                );
                n.map_or(0, |n| fnv(FNV0, &out[..n]))
            });
            let mut m4 = msg4.clone();
            k += 1;
            count("handshake_read_4", 100, || {
                m4.copy_from_slice(&msg4);
                match handshake::read_message_4(&mut m4, &ap_keys, black_box(2)) {
                    Ok(()) => 7,
                    Err(_) => 1,
                }
            });
            k += 1;
            count("handshake_group_1", 100, || {
                let n = handshake::write_group_message_1(
                    &mut out,
                    &mut scratch,
                    AP,
                    STA,
                    &ap_keys,
                    black_box(3),
                    &gtk,
                    5,
                    0,
                );
                n.map_or(0, |n| fnv(FNV0, &out[..n]))
            });
        } else {
            println!("INSN handshake: message 2 was refused (fixture)");
        }

        // ---- the sniffer -------------------------------------------------
        let mut sn = sniff::Sniffer::default();
        k += 1;
        // one beacon per interval, as on the air: its timestamp advanced by
        // 102,400 us each call
        let mut air = beacon_air;
        let mut local = 0u32;
        let mut tsf = 3_000_000_000u64;
        count("sniff_beacon", 2000, || {
            local = local.wrapping_add(102_400);
            tsf += 102_400;
            air[24..32].copy_from_slice(&tsf.to_le_bytes());
            sn.beacon(black_box(&air[..beacon_len]), SSID, local);
            fnv(FNV0, &local.to_le_bytes())
        });
        // the sniffer's own verdicts, hashed: the gate for its arithmetic
        k += 1;
        count("sniff_report_state", 1, || {
            let mut h = FNV0;
            for _ in 0..1 {
                h = fnv(h, &sn.digest());
            }
            h
        });

        // ---- the relay's line codec (E4), per frame -----------------------
        let payload: [u8; 250] =
            core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
        let mut line = [0u8; 600];
        k += 1;
        count("relay_hex_250b", 1000, || {
            let n = hex::hex_into(black_box(&payload), &mut line);
            fnv(FNV0, &line[..n])
        });
        let mut text = [0u8; 500];
        let tn = hex::hex_into(&payload, &mut text);
        let mut back = [0u8; 250];
        k += 1;
        count("relay_unhex_250b", 1000, || {
            let n = hex::unhex(black_box(&text[..tn]), &mut back).unwrap_or(0);
            fnv(FNV0, &back[..n])
        });
        k += 1;
        count("relay_decimals", 1000, || {
            let mut h = FNV0;
            for v in [-61i32, 0, 7, 1_234_567, -2_147_483_648] {
                let n = hex::decimal_into(black_box(v), &mut line);
                h = fnv(h, &line[..n]);
            }
            h
        });

        // the relay's receive ring: 600 bytes in the UART's 64-byte pieces,
        // out in the loop's 128-byte reads, wrapping round the ring
        let mut rx_ring = ring::Ring::new();
        let mut piece = [0u8; 128];
        k += 1;
        count("relay_ring_600b", 500, || {
            let mut h = FNV0;
            for chunk in line[..600].chunks(64) {
                rx_ring.push(black_box(chunk));
            }
            loop {
                let n = rx_ring.pop(&mut piece);
                if n == 0 {
                    break;
                }
                h = fnv(h, &piece[n - 1..n]);
            }
            h
        });

        // the relay's line assembly: a 'T' line of 519 bytes and a short
        // command, fed in the UART's 128-byte pieces; before and after
        let mut stream = [0u8; 560];
        stream[..2].copy_from_slice(b"T ");
        stream[2..517].fill(b'a');
        stream[517] = 13;
        stream[518] = 10;
        stream[519..527].copy_from_slice(b"U 921600");
        stream[527] = 13;
        stream[528] = 10;
        let stream = &stream[..529];
        let mut old_lines = OracleLines {
            line: [0; 520],
            len: 0,
            overrun: false,
        };
        k += 1;
        count("relay_lines_before", 500, || {
            let mut h = FNV0;
            for piece in stream.chunks(128) {
                old_lines.feed(black_box(piece), |text, whole| {
                    h = fnv(fnv(h, text), &[u8::from(whole)]);
                });
            }
            h
        });
        let mut new_lines = ring::Lines::<520>::new();
        k += 1;
        count("relay_lines_after", 500, || {
            let mut h = FNV0;
            for piece in stream.chunks(128) {
                let mut rest = black_box(piece);
                while !rest.is_empty() {
                    let (used, ended) = new_lines.take(rest);
                    rest = &rest[used..];
                    if !ended {
                        break;
                    }
                    let len = core::mem::take(&mut new_lines.len);
                    let whole = !core::mem::take(&mut new_lines.overrun);
                    let text = new_lines.line[..len]
                        .strip_suffix(b"\r")
                        .unwrap_or(&new_lines.line[..len]);
                    h = fnv(fnv(h, text), &[u8::from(whole)]);
                }
            }
            h
        });

        // E4's raw link: an ESP-NOW frame written, parsed, checked for a
        // retransmission, per frame
        let mut air_frame = [0u8; espnow_frame::MAX_FRAME];
        k += 1;
        count("espnow_write_250b", 1000, || {
            let n = espnow_frame::write(
                &mut air_frame,
                black_box(&STA),
                &AP,
                [1, 2, 3, 4],
                black_box(&payload),
            );
            n.map_or(0, |n| fnv(FNV0, &air_frame[n - 8..n]))
        });
        let air_n =
            espnow_frame::write(&mut air_frame, &STA, &AP, [1, 2, 3, 4], &payload).unwrap_or(0);
        k += 1;
        count("espnow_parse_250b", 1000, || {
            match espnow_frame::parse(black_box(&air_frame[..air_n])) {
                Some(f) => fnv(
                    fnv(fnv(FNV0, &f.to), &f.from),
                    &[f.version, f.body.len() as u8, u8::from(f.more_data)],
                ),
                None => 1,
            }
        });
        // E4's sealed send: before, sealed into a zeroed 250-byte buffer and
        // copied into the frame (`write`); after, sealed in place and only
        // the header laid (`write_header`). The seal itself is the same in
        // both and left out; the frames are hashed whole.
        let mut sealed = [0u8; 250];
        sealed.copy_from_slice(&payload);
        k += 1;
        count("link_send_before", 1000, || {
            let mut scratch = [0u8; 250];
            scratch.copy_from_slice(black_box(&sealed));
            let n = espnow_frame::write(&mut air_frame, &STA, &AP, [1, 2, 3, 4], &scratch);
            n.map_or(0, |n| fnv(FNV0, &air_frame[n - 8..n]))
        });
        let mut in_place = [0u8; espnow_frame::MAX_FRAME];
        in_place[espnow_frame::OVERHEAD..].copy_from_slice(&sealed);
        k += 1;
        count("link_send_after", 1000, || {
            let n =
                espnow_frame::write_header(black_box(&mut in_place), &STA, &AP, [1, 2, 3, 4], 250);
            n.map_or(0, |n| fnv(FNV0, &in_place[n - 8..n]))
        });
        // the gate: the two frames, whole
        let before =
            espnow_frame::write(&mut air_frame, &STA, &AP, [1, 2, 3, 4], &sealed).unwrap_or(0);
        let after =
            espnow_frame::write_header(&mut in_place, &STA, &AP, [1, 2, 3, 4], 250).unwrap_or(1);
        println!(
            "INSN oracle link_send {}",
            if before == after && air_frame[..before] == in_place[..after] {
                "identical"
            } else {
                "FAIL"
            }
        );
        let mut dups = espnow_frame::Duplicates::new();
        let mut seq = 0u16;
        k += 1;
        count("espnow_is_duplicate", 1000, || {
            seq = seq.wrapping_add(16);
            air_frame[22..24].copy_from_slice(&seq.to_le_bytes());
            u32::from(dups.is_duplicate(black_box(&air_frame[..air_n])))
        });

        println!("INSN done kernels={k}");
        let t = esp_hal::time::Instant::now();
        while t.elapsed() < esp_hal::time::Duration::from_secs(4) {}
    }
}

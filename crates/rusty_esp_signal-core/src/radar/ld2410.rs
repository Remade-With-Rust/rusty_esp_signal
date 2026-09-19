//! HLK-LD2410 / LD2410B / LD2410C 24 GHz mmWave presence module: the UART
//! serial protocol as a streaming, resynchronising report parser
//! ([`Parser`]) and an allocation-free command encoder ([`Command`]).
//!
//! Source: "HLK-LD2410 Serial Communication Protocol" V1.02 (Hi-Link,
//! 2022-07-01) and the LD2410C edition V1.00 (2022-11-07). Every fixture in
//! the tests is a byte sequence printed in one of those documents.
//!
//! # Wire format
//!
//! All multi-byte integers are **little-endian**. The module talks at 256000
//! baud, 8N1, by default.
//!
//! Two frame families share one shape: `header(4)` `len: u16` `data(len)`
//! `tail(4)`, where `len` counts only the `data` bytes.
//!
//! | Family | Direction | Header | Tail |
//! |---|---|---|---|
//! | report | module → host | `F4 F3 F2 F1` | `F8 F7 F6 F5` |
//! | command / ACK | both | `FD FC FB FA` | `04 03 02 01` |
//!
//! **Command** data is `word: u16` then the command value. **ACK** data is
//! `word | 0x0100: u16`, `status: u16` (0 success, 1 failure), then any
//! returned values. Every configuration command must be preceded by
//! [`Command::EnableConfig`] and followed by [`Command::EndConfig`].
//!
//! **Report** data is `data_type: u8` (`0x01` engineering, `0x02` basic),
//! `head 0xAA`, `target_state: u8` (bit 0 moving, bit 1 stationary),
//! `moving_distance_cm: u16`, `moving_energy: u8` (0..=100),
//! `stationary_distance_cm: u16`, `stationary_energy: u8`,
//! `detection_distance_cm: u16`, then in engineering mode
//! `max_moving_gate: u8`, `max_stationary_gate: u8`,
//! `moving_gate_energy: [u8; max_moving_gate + 1]`,
//! `stationary_gate_energy: [u8; max_stationary_gate + 1]` and `M` reserved
//! bytes (light level and OUT pin state on LD2410B/C firmware), and finally
//! `tail 0x55`, `check 0x00`. Gates are `0..=8`, 0.75 m each.
//!
//! # Use
//!
//! Feed every received byte to [`Parser::feed`]; garbage between frames is
//! skipped and counted, a corrupted frame costs at most the bytes up to the
//! next header. Build outgoing frames with [`Command::encode`] into a
//! caller-owned buffer of at least [`Command::encoded_len`] bytes.

use core::fmt;

use rusty_esp_core::prelude::{Error, Result};

/// Number of distance gates the module reports: gates `0..=8`, 0.75 m each.
pub const GATES: usize = 9;

/// Largest frame the parser accepts, header to tail inclusive. The largest
/// documented frame is the engineering report (43 bytes plus reserved
/// bytes); the read-parameters ACK is 38 bytes.
pub const MAX_FRAME: usize = 64;

/// Bytes of framing around the data: header (4) + length (2) + tail (4).
const FRAMING: usize = 10;

/// Largest `len` field the parser accepts; a longer one triggers a resync.
pub const MAX_DATA: usize = MAX_FRAME - FRAMING;

/// Smallest `len` field the parser accepts: a bare command word.
const MIN_DATA: usize = 2;

/// Reserved bytes kept from an engineering report (see
/// [`Engineering::extra`]).
pub const MAX_EXTRA: usize = 8;

/// Report frame header, module → host.
pub const REPORT_HEADER: [u8; 4] = [0xF4, 0xF3, 0xF2, 0xF1];
/// Report frame tail.
pub const REPORT_TAIL: [u8; 4] = [0xF8, 0xF7, 0xF6, 0xF5];
/// Command and ACK frame header.
pub const COMMAND_HEADER: [u8; 4] = [0xFD, 0xFC, 0xFB, 0xFA];
/// Command and ACK frame tail.
pub const COMMAND_TAIL: [u8; 4] = [0x04, 0x03, 0x02, 0x01];
/// The bit the module sets in an ACK's command word.
pub const ACK_BIT: u16 = 0x0100;

/// Report data: the fixed head byte after `data_type`.
const REPORT_HEAD: u8 = 0xAA;
/// Report data: the byte before the check byte.
const REPORT_END: u8 = 0x55;
/// Report data: the final check byte.
const REPORT_CHECK: u8 = 0x00;
/// Report `data_type` for engineering mode.
const DATA_TYPE_ENGINEERING: u8 = 0x01;
/// Report `data_type` for basic (target) mode.
const DATA_TYPE_BASIC: u8 = 0x02;
/// Bytes of the basic target block: `state md md me sd sd se dd dd`.
const BASIC_LEN: usize = 9;

/// Command words, as sent by the host (the ACK carries `word | ACK_BIT`).
pub mod word {
    /// Enable configuration; value `0x0001`. ACK returns protocol version and
    /// buffer size.
    pub const ENABLE_CONFIG: u16 = 0x00FF;
    /// End configuration; no value.
    pub const END_CONFIG: u16 = 0x00FE;
    /// Set maximum gates and no-one duration; three `(u16, u32)` records.
    pub const SET_MAX_GATES: u16 = 0x0060;
    /// Read parameters; ACK returns the [`super::Parameters`] block.
    pub const READ_PARAMETERS: u16 = 0x0061;
    /// Enable engineering mode; no value.
    pub const ENGINEERING_ON: u16 = 0x0062;
    /// End engineering mode; no value.
    pub const ENGINEERING_OFF: u16 = 0x0063;
    /// Set gate sensitivity; three `(u16, u32)` records.
    pub const SET_SENSITIVITY: u16 = 0x0064;
    /// Read firmware version; ACK returns [`super::FirmwareVersion`].
    pub const READ_FIRMWARE: u16 = 0x00A0;
    /// Set serial baud rate; value is a [`super::Baud`] index.
    pub const SET_BAUD: u16 = 0x00A1;
    /// Restore factory settings; no value.
    pub const FACTORY_RESET: u16 = 0x00A2;
    /// Restart the module; no value.
    pub const RESTART: u16 = 0x00A3;
    /// Bluetooth on/off; value `0x0001` on, `0x0000` off.
    pub const BLUETOOTH: u16 = 0x00A4;
    /// Get MAC address; value `0x0001`. ACK returns six bytes.
    pub const READ_MAC: u16 = 0x00A5;
}

/// Little-endian `u16` at `at`, or `None` when the slice is too short.
fn le16(bytes: &[u8], at: usize) -> Option<u16> {
    let lo = *bytes.get(at)?;
    let hi = *bytes.get(at.checked_add(1)?)?;
    Some(u16::from_le_bytes([lo, hi]))
}

/// Little-endian `u32` at `at`, or `None` when the slice is too short.
fn le32(bytes: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    let b: [u8; 4] = bytes.get(at..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

/// Saturating counter bump.
fn bump(counter: &mut u32, by: usize) {
    let by = u32::try_from(by).unwrap_or(u32::MAX);
    *counter = counter.saturating_add(by);
}

/// Copy as much of `src` as fits into the front of `dst`.
fn copy_prefix(dst: &mut [u8], src: &[u8]) {
    let n = dst.len().min(src.len());
    if let (Some(d), Some(s)) = (dst.get_mut(..n), src.get(..n)) {
        d.copy_from_slice(s);
    }
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// What the module currently sees: the `target_state` byte of a report.
///
/// Bit 0 is a moving target, bit 1 a stationary one; the document lists the
/// values `0x00` none, `0x01` moving, `0x02` stationary, `0x03` both. Higher
/// bits are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetState {
    /// No target.
    None,
    /// A moving target only.
    Moving,
    /// A stationary target only.
    Stationary,
    /// Both a moving and a stationary target.
    Both,
}

impl TargetState {
    /// Decode the `target_state` byte (bits 0 and 1).
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte & 0x03 {
            0 => Self::None,
            1 => Self::Moving,
            2 => Self::Stationary,
            _ => Self::Both,
        }
    }

    /// The byte the module sends for this state.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Moving => 1,
            Self::Stationary => 2,
            Self::Both => 3,
        }
    }

    /// Whether a moving target is present.
    #[must_use]
    pub const fn moving(self) -> bool {
        matches!(self, Self::Moving | Self::Both)
    }

    /// Whether a stationary target is present.
    #[must_use]
    pub const fn stationary(self) -> bool {
        matches!(self, Self::Stationary | Self::Both)
    }

    /// Whether any target is present.
    #[must_use]
    pub const fn present(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// One detected target: its distance and energy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target {
    /// Distance in centimetres.
    pub distance_cm: u16,
    /// Energy `0..=100`; a target counts when it exceeds the gate sensitivity.
    pub energy: u8,
}

/// The engineering-mode part of a report: per-gate energies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Engineering {
    /// Number of moving gates reported (`max_moving_gate + 1`, at most
    /// [`GATES`]); `moving_energy[..moving_gates]` is valid.
    pub moving_gates: u8,
    /// Number of stationary gates reported (`max_stationary_gate + 1`, at most
    /// [`GATES`]); `stationary_energy[..stationary_gates]` is valid.
    pub stationary_gates: u8,
    /// Moving-target energy per gate, gate 0 first.
    pub moving_energy: [u8; GATES],
    /// Stationary-target energy per gate, gate 0 first.
    pub stationary_energy: [u8; GATES],
    /// The first [`MAX_EXTRA`] reserved bytes that followed the gate
    /// energies ("retain data, store additional information" in the
    /// document). LD2410B/C firmware puts the light level at index 0 and the
    /// OUT pin state at index 1.
    pub extra: [u8; MAX_EXTRA],
    /// How many reserved bytes the frame carried (may exceed [`MAX_EXTRA`];
    /// only the first [`MAX_EXTRA`] are kept).
    pub extra_len: u8,
}

impl Engineering {
    /// Valid moving-gate energies, gate 0 first.
    #[must_use]
    pub fn moving(&self) -> &[u8] {
        self.moving_energy
            .get(..usize::from(self.moving_gates))
            .unwrap_or(&self.moving_energy)
    }

    /// Valid stationary-gate energies, gate 0 first.
    #[must_use]
    pub fn stationary(&self) -> &[u8] {
        self.stationary_energy
            .get(..usize::from(self.stationary_gates))
            .unwrap_or(&self.stationary_energy)
    }

    /// The reserved bytes that were kept.
    #[must_use]
    pub fn extra(&self) -> &[u8] {
        self.extra
            .get(..usize::from(self.extra_len).min(MAX_EXTRA))
            .unwrap_or(&self.extra)
    }

    /// Light-sensor level (`0..=255`) on LD2410B/C firmware that reports it;
    /// on other firmware this is the first reserved byte.
    #[must_use]
    pub fn light(&self) -> Option<u8> {
        self.extra().first().copied()
    }

    /// OUT pin state on LD2410B/C firmware that reports it (`0x01` = high);
    /// on other firmware this is the second reserved byte.
    #[must_use]
    pub fn out_pin(&self) -> Option<u8> {
        self.extra().get(1).copied()
    }

    /// Parse the bytes after the basic block and before `0x55 0x00`:
    /// `max_moving_gate`, `max_stationary_gate`, the two energy arrays, then
    /// reserved bytes.
    fn parse(bytes: &[u8]) -> Result<Self> {
        let (&max_moving, rest) = bytes.split_first().ok_or(Error::InvalidFormat)?;
        let (&max_stationary, rest) = rest.split_first().ok_or(Error::InvalidFormat)?;
        let moving_gates = usize::from(max_moving) + 1;
        let stationary_gates = usize::from(max_stationary) + 1;
        if moving_gates > GATES || stationary_gates > GATES {
            return Err(Error::InvalidFormat);
        }
        let moving = rest.get(..moving_gates).ok_or(Error::InvalidFormat)?;
        let rest = rest.get(moving_gates..).ok_or(Error::InvalidFormat)?;
        let stationary = rest.get(..stationary_gates).ok_or(Error::InvalidFormat)?;
        let extra = rest.get(stationary_gates..).ok_or(Error::InvalidFormat)?;

        let mut out = Self {
            moving_gates: max_moving + 1,
            stationary_gates: max_stationary + 1,
            moving_energy: [0; GATES],
            stationary_energy: [0; GATES],
            extra: [0; MAX_EXTRA],
            extra_len: u8::try_from(extra.len()).unwrap_or(u8::MAX),
        };
        copy_prefix(&mut out.moving_energy, moving);
        copy_prefix(&mut out.stationary_energy, stationary);
        copy_prefix(&mut out.extra, extra);
        Ok(out)
    }
}

/// One periodic report from the module.
///
/// The basic fields are always present; [`Report::engineering`] is `Some`
/// only while engineering mode is on ([`Command::EngineeringMode`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Report {
    /// The target state byte.
    pub state: TargetState,
    /// Moving target distance in centimetres (meaningful when
    /// `state.moving()`).
    pub moving_distance_cm: u16,
    /// Moving target energy `0..=100`.
    pub moving_energy: u8,
    /// Stationary target distance in centimetres (meaningful when
    /// `state.stationary()`).
    pub stationary_distance_cm: u16,
    /// Stationary target energy `0..=100`.
    pub stationary_energy: u8,
    /// Detection distance in centimetres.
    pub detection_distance_cm: u16,
    /// Per-gate energies, present in engineering mode.
    pub engineering: Option<Engineering>,
}

impl Report {
    /// Parse the data bytes of a report frame (everything between `len` and
    /// the tail): `data_type`, `0xAA`, the target block, the engineering
    /// block when `data_type == 0x01`, then `0x55 0x00`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] when a marker, length or gate count does not
    /// fit the layout above; [`Error::Unsupported`] for an unknown
    /// `data_type`.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let (&data_type, rest) = data.split_first().ok_or(Error::InvalidFormat)?;
        let (&head, rest) = rest.split_first().ok_or(Error::InvalidFormat)?;
        if head != REPORT_HEAD {
            return Err(Error::InvalidFormat);
        }
        let body_len = rest.len().checked_sub(2).ok_or(Error::InvalidFormat)?;
        let body = rest.get(..body_len).ok_or(Error::InvalidFormat)?;
        let trailer = rest.get(body_len..).ok_or(Error::InvalidFormat)?;
        if trailer != [REPORT_END, REPORT_CHECK] {
            return Err(Error::InvalidFormat);
        }

        let basic: [u8; BASIC_LEN] = body
            .get(..BASIC_LEN)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::InvalidFormat)?;
        let after_basic = body.get(BASIC_LEN..).ok_or(Error::InvalidFormat)?;

        let engineering = match data_type {
            DATA_TYPE_BASIC => {
                if !after_basic.is_empty() {
                    return Err(Error::InvalidFormat);
                }
                None
            }
            DATA_TYPE_ENGINEERING => Some(Engineering::parse(after_basic)?),
            _ => return Err(Error::Unsupported),
        };

        Ok(Self {
            state: TargetState::from_byte(basic[0]),
            moving_distance_cm: u16::from_le_bytes([basic[1], basic[2]]),
            moving_energy: basic[3],
            stationary_distance_cm: u16::from_le_bytes([basic[4], basic[5]]),
            stationary_energy: basic[6],
            detection_distance_cm: u16::from_le_bytes([basic[7], basic[8]]),
            engineering,
        })
    }

    /// The moving target, when one is present.
    #[must_use]
    pub const fn moving(&self) -> Option<Target> {
        if self.state.moving() {
            Some(Target {
                distance_cm: self.moving_distance_cm,
                energy: self.moving_energy,
            })
        } else {
            None
        }
    }

    /// The stationary target, when one is present.
    #[must_use]
    pub const fn stationary(&self) -> Option<Target> {
        if self.state.stationary() {
            Some(Target {
                distance_cm: self.stationary_distance_cm,
                energy: self.stationary_energy,
            })
        } else {
            None
        }
    }

    /// Whether any target is present.
    #[must_use]
    pub const fn present(&self) -> bool {
        self.state.present()
    }

    /// Whether this report came from engineering mode.
    #[must_use]
    pub const fn is_engineering(&self) -> bool {
        self.engineering.is_some()
    }
}

// ---------------------------------------------------------------------------
// ACKs
// ---------------------------------------------------------------------------

/// An acknowledgement frame from the module.
///
/// Data layout: `word | 0x0100: u16`, `status: u16` (0 success, 1 failure),
/// then the command's return value. [`Ack::word`] is the request word with
/// the ACK bit cleared, so it compares directly with [`word`] constants and
/// [`Command::word`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ack<'a> {
    /// The acknowledged command word (ACK bit cleared).
    pub word: u16,
    /// `status == 0`.
    pub ok: bool,
    /// The raw status word.
    pub status: u16,
    /// Returned values after the status word (empty for most commands).
    pub payload: &'a [u8],
}

/// What [`Command::EnableConfig`] returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnableConfig {
    /// Protocol version (`0x0001` on all documented firmware).
    pub protocol_version: u16,
    /// Module receive buffer size in bytes (`0x0040` on documented firmware).
    pub buffer_size: u16,
}

/// What [`Command::ReadFirmware`] returns: `firmware_type: u16`,
/// `major: u16`, `minor: u32`.
///
/// The printed form is `V<major.hi>.<major.lo:02>.<minor:08X>`, so major
/// `0x0102` and minor `0x2206_2416` display as `V1.02.22062416` (the
/// document's example).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FirmwareVersion {
    /// Firmware type word (`0x0000` on LD2410, `0x0100` on LD2410C).
    pub firmware_type: u16,
    /// Major version: high byte `.` low byte.
    pub major: u16,
    /// Minor version, printed as eight hex digits (a build date).
    pub minor: u32,
}

impl fmt::Display for FirmwareVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [hi, lo] = self.major.to_be_bytes();
        write!(f, "V{hi}.{lo:02}.{:08X}", self.minor)
    }
}

/// What [`Command::ReadParameters`] returns.
///
/// Payload: `0xAA`, `max_gate: u8` (N, 8 on this module),
/// `max_moving_gate: u8`, `max_stationary_gate: u8`,
/// `moving_sensitivity: [u8; N + 1]`, `stationary_sensitivity: [u8; N + 1]`,
/// `no_one_secs: u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Parameters {
    /// Highest gate index the module has (N); `gates()` is `N + 1`.
    pub max_gate: u8,
    /// Configured farthest moving-detection gate.
    pub max_moving_gate: u8,
    /// Configured farthest stationary-detection gate.
    pub max_stationary_gate: u8,
    /// Moving sensitivity per gate, gate 0 first; `[..gates()]` is valid.
    pub moving_sensitivity: [u8; GATES],
    /// Stationary sensitivity per gate, gate 0 first; `[..gates()]` is valid.
    pub stationary_sensitivity: [u8; GATES],
    /// No-one (unmanned) duration in seconds.
    pub no_one_secs: u16,
}

impl Parameters {
    /// Number of gates (`max_gate + 1`, at most [`GATES`]).
    #[must_use]
    pub fn gates(&self) -> usize {
        (usize::from(self.max_gate) + 1).min(GATES)
    }

    /// Valid moving sensitivities, gate 0 first.
    #[must_use]
    pub fn moving(&self) -> &[u8] {
        self.moving_sensitivity
            .get(..self.gates())
            .unwrap_or(&self.moving_sensitivity)
    }

    /// Valid stationary sensitivities, gate 0 first.
    #[must_use]
    pub fn stationary(&self) -> &[u8] {
        self.stationary_sensitivity
            .get(..self.gates())
            .unwrap_or(&self.stationary_sensitivity)
    }
}

/// What [`Command::ReadMac`] returns: six address bytes in transmission
/// order (the document prints them as `8F 27 2E B8 0F 65`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mac(pub [u8; 6]);

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl<'a> Ack<'a> {
    /// Parse the data bytes of a command-family frame as an ACK.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] when shorter than four bytes or when the
    /// ACK bit is not set (a host → module command, not an ACK).
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let raw = le16(data, 0).ok_or(Error::InvalidFormat)?;
        let status = le16(data, 2).ok_or(Error::InvalidFormat)?;
        if raw & ACK_BIT == 0 {
            return Err(Error::InvalidFormat);
        }
        Ok(Self {
            word: raw & !ACK_BIT,
            ok: status == 0,
            status,
            payload: data.get(4..).unwrap_or(&[]),
        })
    }

    /// The payload, once this ACK is confirmed to answer `word` with success.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] for another command's ACK,
    /// [`Error::Hardware`] when the module reported failure.
    pub const fn expect(&self, word: u16) -> Result<&'a [u8]> {
        if self.word != word {
            return Err(Error::InvalidFormat);
        }
        if !self.ok {
            return Err(Error::Hardware);
        }
        Ok(self.payload)
    }

    /// Decode the [`Command::EnableConfig`] reply: `protocol_version: u16`,
    /// `buffer_size: u16`.
    ///
    /// # Errors
    ///
    /// As [`Ack::expect`], plus [`Error::InvalidFormat`] for a short payload.
    pub fn enable_config(&self) -> Result<EnableConfig> {
        let p = self.expect(word::ENABLE_CONFIG)?;
        Ok(EnableConfig {
            protocol_version: le16(p, 0).ok_or(Error::InvalidFormat)?,
            buffer_size: le16(p, 2).ok_or(Error::InvalidFormat)?,
        })
    }

    /// Decode the [`Command::ReadFirmware`] reply.
    ///
    /// # Errors
    ///
    /// As [`Ack::expect`], plus [`Error::InvalidFormat`] for a short payload.
    pub fn firmware_version(&self) -> Result<FirmwareVersion> {
        let p = self.expect(word::READ_FIRMWARE)?;
        Ok(FirmwareVersion {
            firmware_type: le16(p, 0).ok_or(Error::InvalidFormat)?,
            major: le16(p, 2).ok_or(Error::InvalidFormat)?,
            minor: le32(p, 4).ok_or(Error::InvalidFormat)?,
        })
    }

    /// Decode the [`Command::ReadParameters`] reply.
    ///
    /// # Errors
    ///
    /// As [`Ack::expect`], plus [`Error::InvalidFormat`] when the `0xAA`
    /// head is missing, the gate count exceeds [`GATES`], or the payload is
    /// short.
    pub fn parameters(&self) -> Result<Parameters> {
        let p = self.expect(word::READ_PARAMETERS)?;
        let fixed: [u8; 4] = p
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::InvalidFormat)?;
        if fixed[0] != REPORT_HEAD {
            return Err(Error::InvalidFormat);
        }
        let max_gate = fixed[1];
        let gates = usize::from(max_gate) + 1;
        if gates > GATES {
            return Err(Error::InvalidFormat);
        }
        let rest = p.get(4..).ok_or(Error::InvalidFormat)?;
        let moving = rest.get(..gates).ok_or(Error::InvalidFormat)?;
        let rest = rest.get(gates..).ok_or(Error::InvalidFormat)?;
        let stationary = rest.get(..gates).ok_or(Error::InvalidFormat)?;
        let no_one_secs = le16(rest, gates).ok_or(Error::InvalidFormat)?;

        let mut out = Parameters {
            max_gate,
            max_moving_gate: fixed[2],
            max_stationary_gate: fixed[3],
            moving_sensitivity: [0; GATES],
            stationary_sensitivity: [0; GATES],
            no_one_secs,
        };
        copy_prefix(&mut out.moving_sensitivity, moving);
        copy_prefix(&mut out.stationary_sensitivity, stationary);
        Ok(out)
    }

    /// Decode the [`Command::ReadMac`] reply: six address bytes.
    ///
    /// # Errors
    ///
    /// As [`Ack::expect`], plus [`Error::InvalidFormat`] for a short payload.
    pub fn mac(&self) -> Result<Mac> {
        let p = self.expect(word::READ_MAC)?;
        let bytes: [u8; 6] = p
            .get(..6)
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::InvalidFormat)?;
        Ok(Mac(bytes))
    }
}

// ---------------------------------------------------------------------------
// Frames and the streaming parser
// ---------------------------------------------------------------------------

/// Which frame family a header announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Report,
    Command,
}

impl Kind {
    const fn header(self) -> &'static [u8; 4] {
        match self {
            Self::Report => &REPORT_HEADER,
            Self::Command => &COMMAND_HEADER,
        }
    }

    const fn tail(self) -> &'static [u8; 4] {
        match self {
            Self::Report => &REPORT_TAIL,
            Self::Command => &COMMAND_TAIL,
        }
    }

    /// The family whose header starts with `byte`, if any.
    const fn starting_with(byte: u8) -> Option<Self> {
        match byte {
            0xF4 => Some(Self::Report),
            0xFD => Some(Self::Command),
            _ => None,
        }
    }
}

/// One complete, decoded frame from the module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A periodic report.
    Report(Report),
    /// An acknowledgement; borrows the parser's buffer until the next feed.
    Ack(Ack<'a>),
}

impl<'a> Frame<'a> {
    /// Decode one whole frame held in `bytes`: header, `len`, data and tail,
    /// with nothing before or after.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidFormat`] for a bad header, length or tail, or an
    /// undecodable body; [`Error::Unsupported`] for an unknown report type.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let header = bytes.get(..4).ok_or(Error::InvalidFormat)?;
        let kind = if header == REPORT_HEADER {
            Kind::Report
        } else if header == COMMAND_HEADER {
            Kind::Command
        } else {
            return Err(Error::InvalidFormat);
        };
        let len = usize::from(le16(bytes, 4).ok_or(Error::InvalidFormat)?);
        let data_start = FRAMING - 4;
        let data_end = data_start + len;
        let data = bytes
            .get(data_start..data_end)
            .ok_or(Error::InvalidFormat)?;
        let tail = bytes.get(data_end..).ok_or(Error::InvalidFormat)?;
        if tail != kind.tail() {
            return Err(Error::InvalidFormat);
        }
        Self::decode(kind, data)
    }

    fn decode(kind: Kind, data: &'a [u8]) -> Result<Self> {
        match kind {
            Kind::Report => Report::parse(data).map(Frame::Report),
            Kind::Command => Ack::parse(data).map(Frame::Ack),
        }
    }
}

/// Parser counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Complete, decoded frames delivered.
    pub frames: u32,
    /// Times an in-progress frame was abandoned (header mismatch after a
    /// partial match, out-of-range length, tail mismatch) and header hunting
    /// restarted.
    pub resyncs: u32,
    /// Bytes discarded: garbage between frames plus abandoned frames.
    pub dropped: u32,
    /// Correctly framed bodies that failed to decode (bad `0xAA`/`0x55`
    /// markers, impossible gate counts, a command frame without the ACK bit).
    pub malformed: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// Matching header bytes; `matched` counts them.
    Header,
    /// Collecting the two length bytes; `matched` counts them.
    Len,
    /// Collecting `len` data bytes into the buffer.
    Data,
    /// Matching tail bytes; `matched` counts them.
    Tail,
}

/// A streaming parser for the module's UART output.
///
/// Feed bytes one at a time ([`Parser::feed`]) or a slice at a time
/// ([`Parser::feed_slice`]); a decoded [`Frame`] comes back when its last
/// tail byte arrives. Bytes that do not belong to a frame are skipped and
/// counted in [`Stats::dropped`]. When a candidate frame turns out to be
/// corrupt the parser abandons it and re-examines only the offending byte,
/// so a frame whose header began inside the corrupt span is lost too; the
/// module re-reports every 100 ms, so the stream heals by the next frame.
///
/// Owns a `[u8; MAX_FRAME]` buffer and nothing else.
#[derive(Debug, Clone)]
pub struct Parser {
    buf: [u8; MAX_FRAME],
    state: State,
    kind: Kind,
    matched: usize,
    len: usize,
    pos: usize,
    stats: Stats,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    /// A parser hunting for a header.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: [0; MAX_FRAME],
            state: State::Header,
            kind: Kind::Report,
            matched: 0,
            len: 0,
            pos: 0,
            stats: Stats {
                frames: 0,
                resyncs: 0,
                dropped: 0,
                malformed: 0,
            },
        }
    }

    /// The counters so far.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }

    /// Forget any partial frame and go back to hunting for a header. The
    /// counters are kept.
    pub const fn reset(&mut self) {
        self.state = State::Header;
        self.matched = 0;
        self.len = 0;
        self.pos = 0;
    }

    /// Feed one received byte; returns a frame when this byte completed one.
    pub fn feed(&mut self, byte: u8) -> Option<Frame<'_>> {
        if self.step(byte) { self.emit() } else { None }
    }

    /// Feed bytes until a frame completes. Returns how many bytes were
    /// consumed and the frame, if any; when fewer than `bytes.len()` were
    /// consumed (a frame was delivered, or a malformed body discarded), call
    /// again with the remainder.
    pub fn feed_slice(&mut self, bytes: &[u8]) -> (usize, Option<Frame<'_>>) {
        let mut i = 0;
        while i < bytes.len() {
            // The DATA phase is the bulk of a frame -- 35 of an engineering
            // report's 45 bytes -- and it is INVARIANT for `len - pos`
            // consecutive bytes: every one of them is copied and nothing else.
            // Re-entering `step` for each costs a load of `self.state`, a
            // four-way branch, and a read-modify-write of `self.pos` through
            // `&mut self`, to move one byte. Taking the whole run at once does
            // the same thing with one `copy_from_slice`.
            if self.state == State::Data {
                let n = (self.len - self.pos).min(bytes.len() - i);
                if n > 1 {
                    // `step` writes only while `pos < MAX_FRAME` and silently
                    // drops the rest; mirror that exactly, including the
                    // advance past the end.
                    if self.pos < MAX_FRAME {
                        let m = n.min(MAX_FRAME - self.pos);
                        self.buf[self.pos..self.pos + m].copy_from_slice(&bytes[i..i + m]);
                    }
                    self.pos += n;
                    i += n;
                    if self.pos >= self.len {
                        self.state = State::Tail;
                        self.matched = 0;
                    }
                    continue;
                }
            }
            if self.step(bytes[i]) {
                return (i + 1, self.emit());
            }
            i += 1;
        }
        (bytes.len(), None)
    }

    /// Decode the frame that just completed.
    fn emit(&mut self) -> Option<Frame<'_>> {
        let data = self.buf.get(..self.len).unwrap_or(&[]);
        if let Ok(frame) = Frame::decode(self.kind, data) {
            bump(&mut self.stats.frames, 1);
            Some(frame)
        } else {
            bump(&mut self.stats.malformed, 1);
            None
        }
    }

    /// Advance the state machine by one byte; `true` when a frame is
    /// complete in `buf[..len]`.
    fn step(&mut self, byte: u8) -> bool {
        match self.state {
            State::Header => {
                if self.matched == 0 {
                    self.start(byte);
                    return false;
                }
                let expected = self.kind.header().get(self.matched).copied();
                if expected == Some(byte) {
                    self.matched += 1;
                    if self.matched == 4 {
                        self.state = State::Len;
                        self.matched = 0;
                        self.len = 0;
                    }
                } else {
                    self.abandon(self.matched);
                    self.start(byte);
                }
                false
            }
            State::Len => {
                self.len |= usize::from(byte) << (8 * self.matched);
                self.matched += 1;
                if self.matched == 2 {
                    if (MIN_DATA..=MAX_DATA).contains(&self.len) {
                        self.state = State::Data;
                        self.pos = 0;
                    } else {
                        // Header plus the first length byte; `start` accounts for this one.
                        self.abandon(4 + 1);
                        self.start(byte);
                    }
                }
                false
            }
            State::Data => {
                if let Some(slot) = self.buf.get_mut(self.pos) {
                    *slot = byte;
                }
                self.pos += 1;
                if self.pos >= self.len {
                    self.state = State::Tail;
                    self.matched = 0;
                }
                false
            }
            State::Tail => {
                let expected = self.kind.tail().get(self.matched).copied();
                if expected != Some(byte) {
                    self.abandon(4 + 2 + self.len + self.matched);
                    self.start(byte);
                    return false;
                }
                self.matched += 1;
                if self.matched < 4 {
                    return false;
                }
                self.state = State::Header;
                self.matched = 0;
                true
            }
        }
    }

    /// Treat `byte` as a possible first header byte.
    fn start(&mut self, byte: u8) {
        self.state = State::Header;
        if let Some(kind) = Kind::starting_with(byte) {
            self.kind = kind;
            self.matched = 1;
        } else {
            self.matched = 0;
            bump(&mut self.stats.dropped, 1);
        }
    }

    /// Give up on the candidate frame whose first `consumed` bytes were
    /// already accepted.
    fn abandon(&mut self, consumed: usize) {
        bump(&mut self.stats.resyncs, 1);
        bump(&mut self.stats.dropped, consumed);
        self.reset();
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Which gate a [`Command::SetSensitivity`] addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gate {
    /// One gate, `0..=8`.
    Index(u8),
    /// Every gate at once (the module's `0xFFFF` gate value).
    All,
}

impl Gate {
    /// The 32-bit gate value the command carries.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::Index(i) => i as u32,
            Self::All => 0xFFFF,
        }
    }
}

/// Serial baud rate, by the module's selection index (table 6 of the
/// document). The factory default is [`Baud::B256000`]; a change takes
/// effect after [`Command::Restart`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Baud {
    /// Index 1.
    B9600,
    /// Index 2.
    B19200,
    /// Index 3.
    B38400,
    /// Index 4.
    B57600,
    /// Index 5.
    B115200,
    /// Index 6.
    B230400,
    /// Index 7, the factory default.
    B256000,
    /// Index 8.
    B460800,
}

impl Baud {
    /// The selection index the command carries.
    #[must_use]
    pub const fn index(self) -> u16 {
        match self {
            Self::B9600 => 1,
            Self::B19200 => 2,
            Self::B38400 => 3,
            Self::B57600 => 4,
            Self::B115200 => 5,
            Self::B230400 => 6,
            Self::B256000 => 7,
            Self::B460800 => 8,
        }
    }

    /// The rate for a selection index, if it is one the module knows.
    #[must_use]
    pub const fn from_index(index: u16) -> Option<Self> {
        Some(match index {
            1 => Self::B9600,
            2 => Self::B19200,
            3 => Self::B38400,
            4 => Self::B57600,
            5 => Self::B115200,
            6 => Self::B230400,
            7 => Self::B256000,
            8 => Self::B460800,
            _ => return None,
        })
    }

    /// Bits per second.
    #[must_use]
    pub const fn bits_per_second(self) -> u32 {
        match self {
            Self::B9600 => 9600,
            Self::B19200 => 19200,
            Self::B38400 => 38400,
            Self::B57600 => 57600,
            Self::B115200 => 115_200,
            Self::B230400 => 230_400,
            Self::B256000 => 256_000,
            Self::B460800 => 460_800,
        }
    }
}

/// Highest gate index accepted in a command.
const MAX_GATE: u8 = 8;
/// Highest sensitivity accepted in a command.
const MAX_SENSITIVITY: u8 = 100;

/// A command to the module, encoded by [`Command::encode`].
///
/// Every command except [`Command::EnableConfig`] itself must be sent inside
/// an enable-configuration / end-configuration bracket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Command {
    /// `0x00FF`, value `0x0001`. Enter configuration mode; the ACK carries
    /// [`EnableConfig`].
    EnableConfig,
    /// `0x00FE`. Leave configuration mode and resume reporting.
    EndConfig,
    /// `0x0060`. Farthest moving and stationary gates (`2..=8`) and the
    /// no-one duration in seconds. Persists across power cycles.
    SetMaxGates {
        /// Farthest moving-detection gate, `2..=8`.
        moving: u8,
        /// Farthest stationary-detection gate, `2..=8`.
        stationary: u8,
        /// Seconds a target stays reported after it leaves.
        no_one_secs: u16,
    },
    /// `0x0061`. The ACK carries [`Parameters`].
    ReadParameters,
    /// `0x0062` (`true`) or `0x0063` (`false`). Engineering mode adds
    /// per-gate energies to every report; it is off after power-up.
    EngineeringMode(bool),
    /// `0x0064`. Sensitivity (`0..=100`) of one gate or all gates; 100
    /// disables a gate. Persists across power cycles.
    SetSensitivity {
        /// The gate, or [`Gate::All`].
        gate: Gate,
        /// Moving sensitivity, `0..=100`.
        moving: u8,
        /// Stationary sensitivity, `0..=100`.
        stationary: u8,
    },
    /// `0x00A0`. The ACK carries [`FirmwareVersion`].
    ReadFirmware,
    /// `0x00A1`. Persists; takes effect after [`Command::Restart`].
    SetBaud(Baud),
    /// `0x00A2`. Restore factory defaults; takes effect after restart.
    FactoryReset,
    /// `0x00A3`. The module restarts after acknowledging.
    Restart,
    /// `0x00A4`. Bluetooth on (`0x0001`) or off (`0x0000`); LD2410B/C.
    /// Takes effect after restart.
    Bluetooth(bool),
    /// `0x00A5`, value `0x0001`. The ACK carries [`Mac`]; LD2410B/C.
    ReadMac,
}

/// Bounded writer over a caller buffer; every write is range-checked.
struct Cursor<'a> {
    out: &'a mut [u8],
    pos: usize,
    needed: usize,
}

impl Cursor<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self.pos + bytes.len();
        let dst = self
            .out
            .get_mut(self.pos..end)
            .ok_or(Error::BufferTooSmall {
                needed: self.needed,
            })?;
        dst.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }

    fn u16(&mut self, v: u16) -> Result<()> {
        self.put(&v.to_le_bytes())
    }

    fn u32(&mut self, v: u32) -> Result<()> {
        self.put(&v.to_le_bytes())
    }

    /// One `(param_word, value)` record of the `0x0060` / `0x0064` commands.
    fn record(&mut self, param: u16, value: u32) -> Result<()> {
        self.u16(param)?;
        self.u32(value)
    }
}

impl Command {
    /// The command word.
    #[must_use]
    pub const fn word(&self) -> u16 {
        match self {
            Self::EnableConfig => word::ENABLE_CONFIG,
            Self::EndConfig => word::END_CONFIG,
            Self::SetMaxGates { .. } => word::SET_MAX_GATES,
            Self::ReadParameters => word::READ_PARAMETERS,
            Self::EngineeringMode(true) => word::ENGINEERING_ON,
            Self::EngineeringMode(false) => word::ENGINEERING_OFF,
            Self::SetSensitivity { .. } => word::SET_SENSITIVITY,
            Self::ReadFirmware => word::READ_FIRMWARE,
            Self::SetBaud(_) => word::SET_BAUD,
            Self::FactoryReset => word::FACTORY_RESET,
            Self::Restart => word::RESTART,
            Self::Bluetooth(_) => word::BLUETOOTH,
            Self::ReadMac => word::READ_MAC,
        }
    }

    /// Bytes of command value after the word.
    const fn value_len(self) -> usize {
        match self {
            Self::EnableConfig | Self::SetBaud(_) | Self::Bluetooth(_) | Self::ReadMac => 2,
            Self::SetMaxGates { .. } | Self::SetSensitivity { .. } => 3 * (2 + 4),
            Self::EndConfig
            | Self::ReadParameters
            | Self::EngineeringMode(_)
            | Self::ReadFirmware
            | Self::FactoryReset
            | Self::Restart => 0,
        }
    }

    /// Size of the encoded frame, header to tail.
    #[must_use]
    pub const fn encoded_len(&self) -> usize {
        FRAMING + 2 + self.value_len()
    }

    /// Encode the frame into `out`; returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// [`Error::BufferTooSmall`] (with `needed`) when `out` is shorter than
    /// [`Command::encoded_len`]; [`Error::Unsupported`] for a gate above 8 or
    /// a sensitivity above 100.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        self.validate()?;
        let needed = self.encoded_len();
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        let mut c = Cursor {
            out,
            pos: 0,
            needed,
        };
        c.put(&COMMAND_HEADER)?;
        let len = u16::try_from(2 + self.value_len()).map_err(|_| Error::Unsupported)?;
        c.u16(len)?;
        c.u16(self.word())?;
        match *self {
            Self::EnableConfig | Self::ReadMac => c.u16(0x0001)?,
            Self::SetMaxGates {
                moving,
                stationary,
                no_one_secs,
            } => {
                c.record(0x0000, u32::from(moving))?;
                c.record(0x0001, u32::from(stationary))?;
                c.record(0x0002, u32::from(no_one_secs))?;
            }
            Self::SetSensitivity {
                gate,
                moving,
                stationary,
            } => {
                c.record(0x0000, gate.value())?;
                c.record(0x0001, u32::from(moving))?;
                c.record(0x0002, u32::from(stationary))?;
            }
            Self::SetBaud(baud) => c.u16(baud.index())?,
            Self::Bluetooth(on) => c.u16(u16::from(on))?,
            Self::EndConfig
            | Self::ReadParameters
            | Self::EngineeringMode(_)
            | Self::ReadFirmware
            | Self::FactoryReset
            | Self::Restart => {}
        }
        c.put(&COMMAND_TAIL)?;
        Ok(c.pos)
    }

    /// Reject values the module cannot take.
    const fn validate(self) -> Result<()> {
        match self {
            Self::SetMaxGates {
                moving, stationary, ..
            } if moving > MAX_GATE || stationary > MAX_GATE => Err(Error::Unsupported),
            Self::SetSensitivity {
                gate,
                moving,
                stationary,
            } => {
                let gate_ok = match gate {
                    Gate::Index(i) => i <= MAX_GATE,
                    Gate::All => true,
                };
                if gate_ok && moving <= MAX_SENSITIVITY && stationary <= MAX_SENSITIVITY {
                    Ok(())
                } else {
                    Err(Error::Unsupported)
                }
            }
            _ => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: every frame below is printed in the Hi-Link protocol document
// (V1.02 for the LD2410, V1.00 for the LD2410C); section numbers cite it.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 2.3.2 "Report data in normal working mode": stationary target,
    /// moving 81 cm / energy 0, stationary 0 cm / energy 59, detection 0 cm.
    const BASIC_REPORT: [u8; 23] = [
        0xF4, 0xF3, 0xF2, 0xF1, 0x0D, 0x00, 0x02, 0xAA, 0x02, 0x51, 0x00, 0x00, 0x00, 0x00, 0x3B,
        0x00, 0x00, 0x55, 0x00, 0xF8, 0xF7, 0xF6, 0xF5,
    ];

    /// 2.3.2 "Report data in engineering mode": both targets, moving 30 cm /
    /// energy 60, stationary 0 cm / energy 57, gates 8 and 8, nine energies
    /// each, two reserved bytes.
    const ENGINEERING_REPORT: [u8; 45] = [
        0xF4, 0xF3, 0xF2, 0xF1, 0x23, 0x00, 0x01, 0xAA, 0x03, 0x1E, 0x00, 0x3C, 0x00, 0x00, 0x39,
        0x00, 0x00, 0x08, 0x08, 0x3C, 0x22, 0x05, 0x03, 0x03, 0x04, 0x03, 0x06, 0x05, 0x00, 0x00,
        0x39, 0x10, 0x13, 0x06, 0x06, 0x08, 0x04, 0x03, 0x05, 0x55, 0x00, 0xF8, 0xF7, 0xF6, 0xF5,
    ];

    /// 2.2.1 enable configuration, send and ACK.
    const ENABLE_CONFIG_CMD: [u8; 14] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xFF, 0x00, 0x01, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    const ENABLE_CONFIG_ACK: [u8; 18] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x08, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00, 0x04,
        0x03, 0x02, 0x01,
    ];
    /// 2.2.2 end configuration, send and ACK.
    const END_CONFIG_CMD: [u8; 12] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0xFE, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    const END_CONFIG_ACK: [u8; 14] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xFE, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.3 "maximum distance gate 8 (movement & stillness), unmanned
    /// duration 5 seconds".
    const SET_MAX_GATES_CMD: [u8; 30] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x14, 0x00, 0x60, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.4 read parameters, send.
    const READ_PARAMETERS_CMD: [u8; 12] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0x61, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.4 read parameters ACK: max gate 8, moving 8, stationary 8, motion
    /// sensitivity 20 and static sensitivity 25 on gates 0..=8, no-one
    /// duration 5 s. The V1.02 document prints the length as `18 00`, which
    /// does not match its own 28 data bytes; the LD2410C document prints the
    /// same ACK with the correct `1C 00`, used here.
    const READ_PARAMETERS_ACK: [u8; 38] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x1C, 0x00, 0x61, 0x01, 0x00, 0x00, 0xAA, 0x08, 0x08, 0x08, 0x14,
        0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19,
        0x19, 0x19, 0x05, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.5 / 2.2.6 engineering mode on and off, send.
    const ENGINEERING_ON_CMD: [u8; 12] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0x62, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    const ENGINEERING_OFF_CMD: [u8; 12] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0x63, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.7 "motion sensitivity of distance gate 3 to 40, and the static
    /// sensitivity of 40" (LD2410C edition; the V1.02 table for this example
    /// is garbled).
    const SET_SENSITIVITY_GATE3_CMD: [u8; 30] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x14, 0x00, 0x64, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x28, 0x00, 0x00, 0x00, 0x02, 0x00, 0x28, 0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.7 "motion sensitivity of all distance gates to 40, and the static
    /// sensitivity to 40".
    const SET_SENSITIVITY_ALL_CMD: [u8; 30] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x14, 0x00, 0x64, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x01,
        0x00, 0x28, 0x00, 0x00, 0x00, 0x02, 0x00, 0x28, 0x00, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.8 read firmware version, send.
    const READ_FIRMWARE_CMD: [u8; 12] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0xA0, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.8 (LD2410C edition) firmware ACK, "V1.07.22091615"; the bytes
    /// decode to minor `0x2209_1516`.
    const READ_FIRMWARE_ACK_C: [u8; 22] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x0C, 0x00, 0xA0, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x16,
        0x15, 0x09, 0x22, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.8 (V1.02) firmware ACK, "V1.02.22062416". The document prints the
    /// length as `0B 00` for 12 data bytes; corrected to `0C 00`.
    const READ_FIRMWARE_ACK: [u8; 22] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x0C, 0x00, 0xA0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x16,
        0x24, 0x06, 0x22, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.9 set baud to index 7 (256000), send.
    const SET_BAUD_CMD: [u8; 14] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xA1, 0x00, 0x07, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.10 factory reset and 2.2.11 restart, send.
    const FACTORY_RESET_CMD: [u8; 12] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0xA2, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    const RESTART_CMD: [u8; 12] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0xA3, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.12 (LD2410C) Bluetooth on, send.
    const BLUETOOTH_ON_CMD: [u8; 14] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xA4, 0x00, 0x01, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    /// 2.2.13 (LD2410C) get MAC, send and ACK ("8F 27 2E B8 0F 65").
    const READ_MAC_CMD: [u8; 14] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xA5, 0x00, 0x01, 0x00, 0x04, 0x03, 0x02, 0x01,
    ];
    const READ_MAC_ACK: [u8; 20] = [
        0xFD, 0xFC, 0xFB, 0xFA, 0x0A, 0x00, 0xA5, 0x01, 0x00, 0x00, 0x8F, 0x27, 0x2E, 0xB8, 0x0F,
        0x65, 0x04, 0x03, 0x02, 0x01,
    ];

    /// An owned summary of a frame, so the parser borrow can end.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Summary {
        Report(Report),
        Ack(u16, bool, usize),
    }

    /// Feed a whole slice byte by byte, collecting up to eight frames.
    fn drive(parser: &mut Parser, bytes: &[u8]) -> ([Option<Summary>; 8], usize) {
        let mut out = [None; 8];
        let mut n = 0;
        for &b in bytes {
            if let Some(frame) = parser.feed(b) {
                let summary = match frame {
                    Frame::Report(r) => Summary::Report(r),
                    Frame::Ack(a) => Summary::Ack(a.word, a.ok, a.payload.len()),
                };
                if let Some(slot) = out.get_mut(n) {
                    *slot = Some(summary);
                }
                n += 1;
            }
        }
        (out, n)
    }

    fn basic_expected() -> Report {
        Report {
            state: TargetState::Stationary,
            moving_distance_cm: 81,
            moving_energy: 0,
            stationary_distance_cm: 0,
            stationary_energy: 59,
            detection_distance_cm: 0,
            engineering: None,
        }
    }

    /// A tiny fixed-capacity string so `Display` can be checked without
    /// `alloc`.
    struct Buf {
        bytes: [u8; 32],
        len: usize,
    }

    impl Buf {
        fn new() -> Self {
            Self {
                bytes: [0; 32],
                len: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.bytes[..self.len]).expect("ascii")
        }
    }

    impl fmt::Write for Buf {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.len + s.len();
            let dst = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
            dst.copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    fn display(value: &dyn fmt::Display) -> Buf {
        let mut s = Buf::new();
        fmt::write(&mut s, format_args!("{value}")).expect("fits");
        s
    }

    #[test]
    fn basic_report_fixture_parses_from_body() {
        let report = Report::parse(&BASIC_REPORT[6..19]).expect("document fixture");
        assert_eq!(report, basic_expected());
        assert_eq!(report.moving(), None);
        assert_eq!(
            report.stationary(),
            Some(Target {
                distance_cm: 0,
                energy: 59
            })
        );
        assert!(report.present());
        assert!(!report.is_engineering());
    }

    #[test]
    fn basic_report_streams_byte_by_byte_after_garbage() {
        let mut p = Parser::new();
        // Seven junk bytes: two plain, a lone F4, a byte, a partial FD FC,
        // a byte.
        let garbage = [0x13, 0x37, 0xF4, 0x00, 0xFD, 0xFC, 0x99];
        let (_, n) = drive(&mut p, &garbage);
        assert_eq!(n, 0);
        let (frames, n) = drive(&mut p, &BASIC_REPORT);
        assert_eq!(n, 1);
        assert_eq!(frames[0], Some(Summary::Report(basic_expected())));
        let s = p.stats();
        assert_eq!(s.frames, 1);
        assert_eq!(s.resyncs, 2, "the lone F4 and the FD FC pair");
        assert_eq!(s.dropped, 7, "every garbage byte");
        assert_eq!(s.malformed, 0);
    }

    #[test]
    fn basic_report_split_across_two_feed_slice_calls() {
        let mut p = Parser::new();
        let (head, tail) = BASIC_REPORT.split_at(9);
        let (consumed, frame) = p.feed_slice(head);
        assert_eq!(consumed, head.len());
        assert!(frame.is_none());
        let (consumed, frame) = p.feed_slice(tail);
        assert_eq!(consumed, tail.len());
        assert_eq!(frame, Some(Frame::Report(basic_expected())));
    }

    #[test]
    fn feed_slice_stops_after_each_frame() {
        let mut p = Parser::new();
        let mut stream = [0u8; 46];
        stream[..23].copy_from_slice(&BASIC_REPORT);
        stream[23..].copy_from_slice(&BASIC_REPORT);
        let (consumed, frame) = p.feed_slice(&stream);
        assert_eq!(consumed, 23);
        assert!(frame.is_some());
        let (consumed, frame) = p.feed_slice(&stream[23..]);
        assert_eq!(consumed, 23);
        assert!(frame.is_some());
        assert_eq!(p.stats().frames, 2);
    }

    #[test]
    fn engineering_report_fixture_parses() {
        let mut p = Parser::new();
        let (frames, n) = drive(&mut p, &ENGINEERING_REPORT);
        assert_eq!(n, 1);
        let Some(Summary::Report(r)) = frames[0] else {
            panic!("expected a report");
        };
        assert_eq!(r.state, TargetState::Both);
        assert_eq!(
            r.moving(),
            Some(Target {
                distance_cm: 30,
                energy: 60
            })
        );
        assert_eq!(
            r.stationary(),
            Some(Target {
                distance_cm: 0,
                energy: 57
            })
        );
        assert_eq!(r.detection_distance_cm, 0);
        let e = r.engineering.expect("engineering block");
        assert_eq!(e.moving_gates, 9);
        assert_eq!(e.stationary_gates, 9);
        assert_eq!(
            e.moving(),
            &[0x3C, 0x22, 0x05, 0x03, 0x03, 0x04, 0x03, 0x06, 0x05]
        );
        assert_eq!(
            e.stationary(),
            &[0x00, 0x00, 0x39, 0x10, 0x13, 0x06, 0x06, 0x08, 0x04]
        );
        assert_eq!(e.extra(), &[0x03, 0x05]);
        assert_eq!(e.extra_len, 2);
        assert_eq!(e.light(), Some(0x03));
        assert_eq!(e.out_pin(), Some(0x05));
    }

    #[test]
    fn engineering_report_with_fewer_gates_and_no_extras() {
        // Constructed from table 13: max gates 2 and 3, so 3 + 4 energies.
        let body = [
            0x01, 0xAA, 0x01, 0x10, 0x00, 0x32, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0x03, 0x0A,
            0x0B, 0x0C, 0x14, 0x15, 0x16, 0x17, 0x55, 0x00,
        ];
        let r = Report::parse(&body).expect("constructed body");
        let e = r.engineering.expect("engineering");
        assert_eq!(e.moving(), &[0x0A, 0x0B, 0x0C]);
        assert_eq!(e.stationary(), &[0x14, 0x15, 0x16, 0x17]);
        assert!(e.extra().is_empty());
        assert_eq!(e.light(), None);
        assert_eq!(e.out_pin(), None);
        assert_eq!(r.moving_distance_cm, 16);
        assert_eq!(r.detection_distance_cm, 16);
    }

    #[test]
    fn report_parse_rejects_bad_markers_and_counts() {
        // Wrong head byte.
        let mut bad = BASIC_REPORT;
        bad[7] = 0xAB;
        assert_eq!(Report::parse(&bad[6..19]), Err(Error::InvalidFormat));
        // Wrong 0x55 tail marker.
        let mut bad = BASIC_REPORT;
        bad[17] = 0x54;
        assert_eq!(Report::parse(&bad[6..19]), Err(Error::InvalidFormat));
        // Unknown data type.
        let mut bad = BASIC_REPORT;
        bad[6] = 0x03;
        assert_eq!(Report::parse(&bad[6..19]), Err(Error::Unsupported));
        // Gate count that cannot fit.
        let mut bad = ENGINEERING_REPORT;
        bad[17] = 9;
        assert_eq!(Report::parse(&bad[6..41]), Err(Error::InvalidFormat));
        // Basic frame with stray bytes before the marker.
        let mut bad = ENGINEERING_REPORT;
        bad[6] = 0x02;
        assert_eq!(Report::parse(&bad[6..41]), Err(Error::InvalidFormat));
        // Too short for the basic block.
        assert_eq!(
            Report::parse(&[0x02, 0xAA, 0x55, 0x00]),
            Err(Error::InvalidFormat)
        );
        assert_eq!(Report::parse(&[]), Err(Error::InvalidFormat));

        // Through the parser the framed-but-bad body is counted, not
        // delivered, and the next good frame still arrives.
        let mut p = Parser::new();
        let mut bad = BASIC_REPORT;
        bad[7] = 0xAB;
        let (_, n) = drive(&mut p, &bad);
        assert_eq!(n, 0);
        assert_eq!(p.stats().malformed, 1);
        assert_eq!(p.stats().frames, 0);
        let (_, n) = drive(&mut p, &BASIC_REPORT);
        assert_eq!(n, 1);
    }

    #[test]
    fn truncated_frame_is_abandoned_and_next_frame_recovers() {
        let mut p = Parser::new();
        // A report missing its last two tail bytes, immediately followed by
        // a complete one.
        let (_, n) = drive(&mut p, &BASIC_REPORT[..21]);
        assert_eq!(n, 0);
        let (frames, n) = drive(&mut p, &BASIC_REPORT);
        assert_eq!(n, 1);
        assert_eq!(frames[0], Some(Summary::Report(basic_expected())));
        let s = p.stats();
        assert_eq!(s.resyncs, 1);
        assert_eq!(s.dropped, 21, "the whole truncated candidate");
        assert_eq!(s.frames, 1);
    }

    #[test]
    fn overlong_length_resets_without_panic() {
        let mut p = Parser::new();
        let overlong = [0xF4, 0xF3, 0xF2, 0xF1, 0xFF, 0xFF, 0x01, 0x02, 0x03];
        let (_, n) = drive(&mut p, &overlong);
        assert_eq!(n, 0);
        let s = p.stats();
        assert_eq!(s.resyncs, 1);
        assert_eq!(s.dropped, 9);
        // A zero length is rejected the same way.
        let short = [0xFD, 0xFC, 0xFB, 0xFA, 0x00, 0x00];
        let (_, n) = drive(&mut p, &short);
        assert_eq!(n, 0);
        assert_eq!(p.stats().resyncs, 2);
        // The longest documented frame still works end to end afterwards.
        let (frames, n) = drive(&mut p, &ENGINEERING_REPORT);
        assert_eq!(n, 1);
        assert!(matches!(frames[0], Some(Summary::Report(_))));
    }

    #[test]
    fn header_byte_inside_garbage_restarts_the_match() {
        // F4 F4 F3 F2 F1: the second F4 must start a fresh header.
        let mut p = Parser::new();
        let (_, n) = drive(&mut p, &[0xF4]);
        assert_eq!(n, 0);
        let (frames, n) = drive(&mut p, &BASIC_REPORT);
        assert_eq!(n, 1);
        assert!(matches!(frames[0], Some(Summary::Report(_))));
        assert_eq!(p.stats().dropped, 1);
        assert_eq!(p.stats().resyncs, 1);
    }

    #[test]
    fn interleaved_reports_and_acks_stream() {
        let mut p = Parser::new();
        let mut stream = [0u8; 23 + 18 + 45];
        stream[..23].copy_from_slice(&BASIC_REPORT);
        stream[23..41].copy_from_slice(&ENABLE_CONFIG_ACK);
        stream[41..].copy_from_slice(&ENGINEERING_REPORT);
        let (frames, n) = drive(&mut p, &stream);
        assert_eq!(n, 3);
        assert_eq!(frames[0], Some(Summary::Report(basic_expected())));
        assert_eq!(frames[1], Some(Summary::Ack(word::ENABLE_CONFIG, true, 4)));
        assert!(matches!(frames[2], Some(Summary::Report(r)) if r.is_engineering()));
        assert_eq!(p.stats().frames, 3);
        assert_eq!(p.stats().dropped, 0);
    }

    #[test]
    fn ack_enable_config_decodes() {
        let Frame::Ack(ack) = Frame::parse(&ENABLE_CONFIG_ACK).expect("document ACK") else {
            panic!("expected an ACK");
        };
        assert_eq!(ack.word, word::ENABLE_CONFIG);
        assert!(ack.ok);
        assert_eq!(ack.status, 0);
        assert_eq!(ack.payload, &[0x01, 0x00, 0x40, 0x00]);
        assert_eq!(
            ack.enable_config(),
            Ok(EnableConfig {
                protocol_version: 1,
                buffer_size: 0x40
            })
        );
        // The wrong typed decoder refuses it.
        assert_eq!(ack.firmware_version(), Err(Error::InvalidFormat));
        // The end-config ACK has an empty payload.
        let Frame::Ack(end) = Frame::parse(&END_CONFIG_ACK).expect("document ACK") else {
            panic!("expected an ACK");
        };
        assert_eq!(end.word, word::END_CONFIG);
        assert!(end.ok);
        assert!(end.payload.is_empty());
    }

    #[test]
    fn ack_firmware_version_decodes() {
        let Frame::Ack(ack) = Frame::parse(&READ_FIRMWARE_ACK_C).expect("document ACK") else {
            panic!("expected an ACK");
        };
        let v = ack.firmware_version().expect("firmware");
        assert_eq!(
            v,
            FirmwareVersion {
                firmware_type: 0x0100,
                major: 0x0107,
                minor: 0x2209_1516
            }
        );
        assert_eq!(display(&v).as_str(), "V1.07.22091516");

        let Frame::Ack(ack) = Frame::parse(&READ_FIRMWARE_ACK).expect("document ACK") else {
            panic!("expected an ACK");
        };
        let v = ack.firmware_version().expect("firmware");
        assert_eq!(v.firmware_type, 0);
        assert_eq!(v.major, 0x0102);
        assert_eq!(v.minor, 0x2206_2416);
        assert_eq!(display(&v).as_str(), "V1.02.22062416");
    }

    #[test]
    fn ack_parameters_decodes() {
        let Frame::Ack(ack) = Frame::parse(&READ_PARAMETERS_ACK).expect("document ACK") else {
            panic!("expected an ACK");
        };
        let p = ack.parameters().expect("parameters");
        assert_eq!(p.max_gate, 8);
        assert_eq!(p.gates(), 9);
        assert_eq!(p.max_moving_gate, 8);
        assert_eq!(p.max_stationary_gate, 8);
        assert_eq!(p.moving(), &[20; 9]);
        assert_eq!(p.stationary(), &[25; 9]);
        assert_eq!(p.no_one_secs, 5);
    }

    #[test]
    fn ack_mac_decodes() {
        let Frame::Ack(ack) = Frame::parse(&READ_MAC_ACK).expect("document ACK") else {
            panic!("expected an ACK");
        };
        let mac = ack.mac().expect("mac");
        assert_eq!(mac, Mac([0x8F, 0x27, 0x2E, 0xB8, 0x0F, 0x65]));
        assert_eq!(display(&mac).as_str(), "8F:27:2E:B8:0F:65");
    }

    #[test]
    fn ack_failure_status_and_short_payloads() {
        // Status 1 = failure (constructed: the document shows only successes).
        let nack = [
            0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xFF, 0x01, 0x01, 0x00, 0x04, 0x03, 0x02, 0x01,
        ];
        let Frame::Ack(ack) = Frame::parse(&nack).expect("framed") else {
            panic!("expected an ACK");
        };
        assert!(!ack.ok);
        assert_eq!(ack.status, 1);
        assert_eq!(ack.enable_config(), Err(Error::Hardware));
        // A success ACK whose payload is too short for the decoder.
        let Frame::Ack(ack) = Frame::parse(&END_CONFIG_ACK).expect("framed") else {
            panic!("expected an ACK");
        };
        let short = Ack {
            word: word::READ_MAC,
            ..ack
        };
        assert_eq!(short.mac(), Err(Error::InvalidFormat));
        // A host command (no ACK bit) is not an ACK.
        assert_eq!(Frame::parse(&ENABLE_CONFIG_CMD), Err(Error::InvalidFormat));
        assert_eq!(Ack::parse(&[0xFF, 0x01, 0x00]), Err(Error::InvalidFormat));
    }

    #[test]
    fn frame_parse_rejects_bad_framing() {
        let mut bad = BASIC_REPORT;
        bad[0] = 0xF5;
        assert_eq!(Frame::parse(&bad), Err(Error::InvalidFormat));
        let mut bad = BASIC_REPORT;
        bad[22] = 0xF4;
        assert_eq!(Frame::parse(&bad), Err(Error::InvalidFormat));
        assert_eq!(Frame::parse(&BASIC_REPORT[..20]), Err(Error::InvalidFormat));
        assert_eq!(Frame::parse(&[]), Err(Error::InvalidFormat));
    }

    fn check(cmd: Command, expected: &[u8]) {
        let mut buf = [0u8; MAX_FRAME];
        let n = cmd.encode(&mut buf).expect("encode");
        assert_eq!(n, expected.len(), "{cmd:?} length");
        assert_eq!(&buf[..n], expected, "{cmd:?} bytes");
        assert_eq!(cmd.encoded_len(), n, "{cmd:?} encoded_len");
        // An exactly-sized buffer works too.
        let mut exact = [0u8; 30];
        let exact = exact.get_mut(..n).expect("fixture fits");
        assert_eq!(cmd.encode(exact), Ok(n));
    }

    #[test]
    fn command_encodings_match_document_examples() {
        check(Command::EnableConfig, &ENABLE_CONFIG_CMD);
        check(Command::EndConfig, &END_CONFIG_CMD);
        check(
            Command::SetMaxGates {
                moving: 8,
                stationary: 8,
                no_one_secs: 5,
            },
            &SET_MAX_GATES_CMD,
        );
        check(Command::ReadParameters, &READ_PARAMETERS_CMD);
        check(Command::EngineeringMode(true), &ENGINEERING_ON_CMD);
        check(Command::EngineeringMode(false), &ENGINEERING_OFF_CMD);
        check(
            Command::SetSensitivity {
                gate: Gate::Index(3),
                moving: 40,
                stationary: 40,
            },
            &SET_SENSITIVITY_GATE3_CMD,
        );
        check(
            Command::SetSensitivity {
                gate: Gate::All,
                moving: 40,
                stationary: 40,
            },
            &SET_SENSITIVITY_ALL_CMD,
        );
        check(Command::ReadFirmware, &READ_FIRMWARE_CMD);
        check(Command::SetBaud(Baud::B256000), &SET_BAUD_CMD);
        check(Command::FactoryReset, &FACTORY_RESET_CMD);
        check(Command::Restart, &RESTART_CMD);
        check(Command::Bluetooth(true), &BLUETOOTH_ON_CMD);
        check(Command::ReadMac, &READ_MAC_CMD);
    }

    #[test]
    fn command_encode_reports_needed_size_and_rejects_bad_values() {
        let mut small = [0u8; 13];
        assert_eq!(
            Command::EnableConfig.encode(&mut small),
            Err(Error::BufferTooSmall { needed: 14 })
        );
        assert_eq!(
            Command::Restart.encode(&mut []),
            Err(Error::BufferTooSmall { needed: 12 })
        );
        let mut buf = [0u8; MAX_FRAME];
        assert_eq!(
            Command::SetMaxGates {
                moving: 9,
                stationary: 8,
                no_one_secs: 0
            }
            .encode(&mut buf),
            Err(Error::Unsupported)
        );
        assert_eq!(
            Command::SetSensitivity {
                gate: Gate::Index(9),
                moving: 1,
                stationary: 1
            }
            .encode(&mut buf),
            Err(Error::Unsupported)
        );
        assert_eq!(
            Command::SetSensitivity {
                gate: Gate::All,
                moving: 101,
                stationary: 1
            }
            .encode(&mut buf),
            Err(Error::Unsupported)
        );
        // Bluetooth off carries 0x0000.
        let n = Command::Bluetooth(false).encode(&mut buf).expect("encode");
        assert_eq!(n, 14);
        assert_eq!(&buf[6..10], &[0xA4, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn baud_table_round_trips() {
        for (index, bps) in [
            (1, 9600),
            (2, 19200),
            (3, 38400),
            (4, 57600),
            (5, 115_200),
            (6, 230_400),
            (7, 256_000),
            (8, 460_800),
        ] {
            let baud = Baud::from_index(index).expect("documented index");
            assert_eq!(baud.index(), index);
            assert_eq!(baud.bits_per_second(), bps);
        }
        assert_eq!(Baud::from_index(0), None);
        assert_eq!(Baud::from_index(9), None);
    }

    #[test]
    fn target_state_bits() {
        assert_eq!(TargetState::from_byte(0), TargetState::None);
        assert_eq!(TargetState::from_byte(1), TargetState::Moving);
        assert_eq!(TargetState::from_byte(2), TargetState::Stationary);
        assert_eq!(TargetState::from_byte(3), TargetState::Both);
        assert_eq!(TargetState::from_byte(0x83), TargetState::Both);
        for s in [
            TargetState::None,
            TargetState::Moving,
            TargetState::Stationary,
            TargetState::Both,
        ] {
            assert_eq!(TargetState::from_byte(s.to_byte()), s);
        }
    }

    #[test]
    fn random_stream_never_panics_and_still_finds_frames() {
        // xorshift32 junk with the two document reports spliced in.
        let mut x = 0x2545_F491u32;
        let mut p = Parser::new();
        let mut found = 0u32;
        for round in 0..64 {
            for _ in 0..200 {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                if p.feed(x.to_le_bytes()[0]).is_some() {
                    found += 1;
                }
            }
            let frame: &[u8] = if round % 2 == 0 {
                &BASIC_REPORT
            } else {
                &ENGINEERING_REPORT
            };
            let (_, n) = drive(&mut p, frame);
            found += u32::try_from(n).unwrap_or(0);
        }
        // A frame spliced in right after junk that opened a candidate may be
        // eaten by it; most must still be found.
        assert!(found >= 48, "found {found}");
        assert_eq!(p.stats().frames, found);
        assert!(p.stats().dropped > 0);
    }
}

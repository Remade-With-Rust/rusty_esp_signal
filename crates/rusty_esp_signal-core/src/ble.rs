//! The Janus GATT table as data: three services (provisioning, manifest,
//! telemetry), their characteristics, and the 128-bit UUIDs they live under.
//!
//! No BLE stack here. A backend walks [`GATT_TABLE`] to register the
//! attributes with whatever host it has (NimBLE, Bluedroid, `trouble`) and
//! uses [`GattTable::find`] to route a write or read back to the
//! characteristic it names. Property bits follow the Bluetooth Core
//! Specification 5.4, Vol 3 Part G §3.3.1.1 so [`Props::bits`] can be
//! programmed into a characteristic declaration as is.

use core::fmt;
use core::ops::{BitOr, BitOrAssign};

use rusty_esp_core::error::{Error, Result};

/// A 128-bit UUID in big-endian (display) byte order: byte 0 is the first
/// pair of hex digits of the hyphenated form.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uuid128([u8; 16]);

impl Uuid128 {
    /// Length of the hyphenated text form, `8-4-4-4-12` (RFC 9562 §4).
    pub const HYPHENATED_LEN: usize = 36;

    /// Wrap 16 bytes in display order.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Uuid128(bytes)
    }

    /// The bytes, display order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The bytes by value, display order.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Write the lowercase hyphenated form (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`,
    /// 36 characters) into `out` and return it as text.
    ///
    /// `BufferTooSmall { needed: 36 }` when `out` is shorter.
    pub fn write_hyphenated<'a>(&self, out: &'a mut [u8]) -> Result<&'a str> {
        let Some(out) = out.get_mut(..Uuid128::HYPHENATED_LEN) else {
            return Err(Error::BufferTooSmall {
                needed: Uuid128::HYPHENATED_LEN,
            });
        };
        let mut pos = 0;
        for (i, byte) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                if let Some(c) = out.get_mut(pos) {
                    *c = b'-';
                }
                pos += 1;
            }
            if let Some(c) = out.get_mut(pos) {
                *c = hex_digit(byte >> 4);
            }
            if let Some(c) = out.get_mut(pos + 1) {
                *c = hex_digit(byte & 0x0f);
            }
            pos += 2;
        }
        core::str::from_utf8(out).map_err(|_| Error::InvalidFormat)
    }
}

/// Lowercase hex digit of the low nibble of `n`.
const fn hex_digit(n: u8) -> u8 {
    match n & 0x0f {
        d @ 0..=9 => b'0' + d,
        d => b'a' + d - 10,
    }
}

impl fmt::Display for Uuid128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; Uuid128::HYPHENATED_LEN];
        match self.write_hyphenated(&mut buf) {
            Ok(text) => f.write_str(text),
            Err(_) => Err(fmt::Error),
        }
    }
}

impl fmt::Debug for Uuid128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The Janus base UUID, `4a616e75-7300-4d41-5441-000000000000`: the ASCII
/// of `Janus` followed by `MATA`, with the last two bytes reserved for the
/// 16-bit short id of each service and characteristic.
pub const JANUS_BASE: [u8; 16] = [
    0x4a, 0x61, 0x6e, 0x75, // "Janu"
    0x73, 0x00, // "s", pad
    0x4d, 0x41, // "MA"
    0x54, 0x41, // "TA"
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// [`JANUS_BASE`] with `short` in the last two bytes, big-endian.
///
/// Services are `0xNN00`, their characteristics `0xNN01..`.
#[must_use]
pub const fn janus_uuid(short: u16) -> Uuid128 {
    let mut bytes = JANUS_BASE;
    let [hi, lo] = short.to_be_bytes();
    bytes[14] = hi;
    bytes[15] = lo;
    Uuid128(bytes)
}

/// Provisioning service, `…-000000000100`: Wi-Fi credentials in, status out.
pub const SERVICE_PROVISIONING: Uuid128 = janus_uuid(0x0100);
/// `credentials`, `…-0101`: WRITE, the `wifi::Credentials` TLV.
pub const CHAR_CREDENTIALS: Uuid128 = janus_uuid(0x0101);
/// `status`, `…-0102`: READ|NOTIFY, the `wifi::Phase` as one byte.
pub const CHAR_STATUS: Uuid128 = janus_uuid(0x0102);
/// `scan`, `…-0103`: READ, visible SSIDs as TLV tag-1 entries.
pub const CHAR_SCAN: Uuid128 = janus_uuid(0x0103);

/// Manifest service, `…-000000000200`: who this device is.
pub const SERVICE_MANIFEST: Uuid128 = janus_uuid(0x0200);
/// `manifest`, `…-0201`: READ, the signed capability manifest bytes.
pub const CHAR_MANIFEST: Uuid128 = janus_uuid(0x0201);
/// `did`, `…-0202`: READ, the `did:mata:` string.
pub const CHAR_DID: Uuid128 = janus_uuid(0x0202);
/// `ticket`, `…-0203`: READ, the `janus1…` ticket string.
pub const CHAR_TICKET: Uuid128 = janus_uuid(0x0203);

/// Telemetry service, `…-000000000300`: link and presence readings.
pub const SERVICE_TELEMETRY: Uuid128 = janus_uuid(0x0300);
/// `rssi`, `…-0301`: READ|NOTIFY, one `i8` dBm.
pub const CHAR_RSSI: Uuid128 = janus_uuid(0x0301);
/// `uptime`, `…-0302`: READ, `u32` seconds big-endian.
pub const CHAR_UPTIME: Uuid128 = janus_uuid(0x0302);
/// `presence`, `…-0303`: READ|NOTIFY, verdict tag then level.
pub const CHAR_PRESENCE: Uuid128 = janus_uuid(0x0303);

/// Characteristic property bits, Core Spec Vol 3 Part G §3.3.1.1 Table 3.5.
///
/// Combine with `|` or, in a `const`, with [`Props::union`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Props(u8);

impl Props {
    /// No properties.
    pub const NONE: Props = Props(0);
    /// 0x02: the value can be read.
    pub const READ: Props = Props(0x02);
    /// 0x04: Write Command, no ATT response.
    pub const WRITE_WITHOUT_RESPONSE: Props = Props(0x04);
    /// 0x08: Write Request with response.
    pub const WRITE: Props = Props(0x08);
    /// 0x10: the server may push the value without acknowledgement.
    pub const NOTIFY: Props = Props(0x10);
    /// 0x20: the server may push the value and require acknowledgement.
    pub const INDICATE: Props = Props(0x20);

    /// Every bit this type knows.
    const ALL_BITS: u8 = 0x02 | 0x04 | 0x08 | 0x10 | 0x20;

    /// The raw bit field, as it appears in a characteristic declaration.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Bits back to `Props`, or `None` if any bit is not one of the five
    /// (Broadcast 0x01, Authenticated Signed Writes 0x40 and Extended
    /// Properties 0x80 are not modelled).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Props> {
        if bits & !Props::ALL_BITS == 0 {
            Some(Props(bits))
        } else {
            None
        }
    }

    /// `true` when every bit of `other` is set here.
    #[must_use]
    pub const fn contains(self, other: Props) -> bool {
        self.0 & other.0 == other.0
    }

    /// `true` when no bit is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Both sets of bits (`|`, usable in `const`).
    #[must_use]
    pub const fn union(self, other: Props) -> Props {
        Props(self.0 | other.0)
    }
}

impl BitOr for Props {
    type Output = Props;

    fn bitor(self, rhs: Props) -> Props {
        self.union(rhs)
    }
}

impl BitOrAssign for Props {
    fn bitor_assign(&mut self, rhs: Props) {
        *self = self.union(rhs);
    }
}

impl fmt::Debug for Props {
    /// `READ | NOTIFY`, or `NONE`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(Props, &str); 5] = [
            (Props::READ, "READ"),
            (Props::WRITE_WITHOUT_RESPONSE, "WRITE_WITHOUT_RESPONSE"),
            (Props::WRITE, "WRITE"),
            (Props::NOTIFY, "NOTIFY"),
            (Props::INDICATE, "INDICATE"),
        ];
        if self.is_empty() {
            return f.write_str("NONE");
        }
        let mut first = true;
        for (flag, name) in NAMES {
            if self.contains(flag) {
                if !first {
                    f.write_str(" | ")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}

/// One attribute value under a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Characteristic {
    /// The 128-bit UUID.
    pub uuid: Uuid128,
    /// What clients may do with it.
    pub props: Props,
    /// Largest value in bytes. At most [`ATT_MAX_VALUE_LEN`].
    pub max_len: u16,
    /// A short name for logs and the backend's attribute table.
    pub name: &'static str,
}

/// A primary service and its characteristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    /// The 128-bit UUID.
    pub uuid: Uuid128,
    /// A short name for logs.
    pub name: &'static str,
    /// The characteristics, in declaration order.
    pub characteristics: &'static [Characteristic],
}

/// The whole table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GattTable {
    /// The primary services, in declaration order.
    pub services: &'static [Service],
}

impl GattTable {
    /// The characteristic with `uuid`, if the table has one.
    #[must_use]
    pub fn find(&self, uuid: Uuid128) -> Option<&'static Characteristic> {
        self.characteristics().find(|c| c.uuid == uuid)
    }

    /// The service with `uuid`, if the table has one.
    #[must_use]
    pub fn find_service(&self, uuid: Uuid128) -> Option<&'static Service> {
        self.services.iter().find(|s| s.uuid == uuid)
    }

    /// Every characteristic of every service, in table order.
    pub fn characteristics(&self) -> impl Iterator<Item = &'static Characteristic> {
        self.services.iter().flat_map(|s| s.characteristics.iter())
    }

    /// Number of characteristics across all services.
    #[must_use]
    pub fn characteristic_count(&self) -> usize {
        self.characteristics().count()
    }
}

/// The longest attribute value ATT allows (Core Spec Vol 3 Part F §3.2.9).
pub const ATT_MAX_VALUE_LEN: u16 = 512;

/// Characteristics of [`SERVICE_PROVISIONING`].
pub const PROVISIONING_CHARACTERISTICS: [Characteristic; 3] = [
    Characteristic {
        uuid: CHAR_CREDENTIALS,
        props: Props::WRITE,
        max_len: 100,
        name: "credentials",
    },
    Characteristic {
        uuid: CHAR_STATUS,
        props: Props::READ.union(Props::NOTIFY),
        max_len: 1,
        name: "status",
    },
    Characteristic {
        uuid: CHAR_SCAN,
        props: Props::READ,
        max_len: 240,
        name: "scan",
    },
];

/// Characteristics of [`SERVICE_MANIFEST`].
pub const MANIFEST_CHARACTERISTICS: [Characteristic; 3] = [
    Characteristic {
        uuid: CHAR_MANIFEST,
        props: Props::READ,
        max_len: 512,
        name: "manifest",
    },
    Characteristic {
        uuid: CHAR_DID,
        props: Props::READ,
        max_len: 55,
        name: "did",
    },
    Characteristic {
        uuid: CHAR_TICKET,
        props: Props::READ,
        max_len: 128,
        name: "ticket",
    },
];

/// Characteristics of [`SERVICE_TELEMETRY`].
pub const TELEMETRY_CHARACTERISTICS: [Characteristic; 3] = [
    Characteristic {
        uuid: CHAR_RSSI,
        props: Props::READ.union(Props::NOTIFY),
        max_len: 1,
        name: "rssi",
    },
    Characteristic {
        uuid: CHAR_UPTIME,
        props: Props::READ,
        max_len: 4,
        name: "uptime",
    },
    Characteristic {
        uuid: CHAR_PRESENCE,
        props: Props::READ.union(Props::NOTIFY),
        max_len: 2,
        name: "presence",
    },
];

/// The three Janus services.
pub const SERVICES: [Service; 3] = [
    Service {
        uuid: SERVICE_PROVISIONING,
        name: "provisioning",
        characteristics: &PROVISIONING_CHARACTERISTICS,
    },
    Service {
        uuid: SERVICE_MANIFEST,
        name: "manifest",
        characteristics: &MANIFEST_CHARACTERISTICS,
    },
    Service {
        uuid: SERVICE_TELEMETRY,
        name: "telemetry",
        characteristics: &TELEMETRY_CHARACTERISTICS,
    },
];

/// How many bytes a legacy BLE advertisement (or one scan response) can
/// carry: Bluetooth Core Specification 5.4, Vol 6 Part B §2.3.1.3.
pub const LEGACY_ADV_CAPACITY: usize = 31;

/// The bytes an advertising structure costs: one length byte, one type byte,
/// and the value (Vol 3 Part C §11).
#[must_use]
pub const fn adv_structure_len(value_len: usize) -> usize {
    2 + value_len
}

/// What an advertisement carrying the flags, a 128-bit service UUID and a
/// device name of `name_len` bytes would cost.
///
/// A Janus device advertises the provisioning service so a browser can
/// filter on it, and 3 + 18 of the 31 bytes are gone before the name is
/// considered: a name longer than [`LEGACY_ADV_NAME_BUDGET`] does not fit,
/// and a stack asked for it anyway drops part of what it was given (ESP-IDF's
/// Bluedroid logs `BTM_BleWriteAdvData, Partial data write into ADV` and the
/// service UUID can be what goes). The name belongs in the scan response,
/// which a scanner reads before it shows the device.
#[must_use]
pub const fn provisioning_adv_len(name_len: usize) -> usize {
    adv_structure_len(1) + adv_structure_len(16) + adv_structure_len(name_len)
}

/// The longest device name that still fits in the advertisement beside the
/// flags and the 128-bit provisioning service UUID: 31 - 3 - 18 - 2.
pub const LEGACY_ADV_NAME_BUDGET: usize =
    LEGACY_ADV_CAPACITY - adv_structure_len(1) - adv_structure_len(16) - 2;

/// The Janus GATT table.
///
/// | service      | characteristic | props        | max | value |
/// |--------------|----------------|--------------|-----|-------|
/// | provisioning | credentials    | WRITE        | 100 | `wifi::Credentials` TLV |
/// | provisioning | status         | READ, NOTIFY | 1   | `wifi::Phase` as u8 |
/// | provisioning | scan           | READ         | 240 | SSIDs as TLV tag 1 entries |
/// | manifest     | manifest       | READ         | 512 | signed capability manifest |
/// | manifest     | did            | READ         | 55  | `did:mata:` string |
/// | manifest     | ticket         | READ         | 128 | `janus1…` ticket string |
/// | telemetry    | rssi           | READ, NOTIFY | 1   | `i8` dBm |
/// | telemetry    | uptime         | READ         | 4   | `u32` seconds, big-endian |
/// | telemetry    | presence       | READ, NOTIFY | 2   | verdict tag, level |
pub const GATT_TABLE: GattTable = GattTable {
    services: &SERVICES,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_name_does_not_fit_beside_the_service_uuid() {
        // flags (3) + the 128-bit service UUID (18) = 21 of 31 bytes, so a
        // name has 8 bytes of value left — shorter than every model name we
        // advertise. This is why the name goes in the scan response.
        assert_eq!(LEGACY_ADV_NAME_BUDGET, 8);
        assert!(provisioning_adv_len(8) <= LEGACY_ADV_CAPACITY);
        assert!(provisioning_adv_len(9) > LEGACY_ADV_CAPACITY);
        // the name a generated camera advertises under
        assert_eq!(provisioning_adv_len("janus/esp32-cam-ble".len()), 42);
        // …and it fits a scan response of its own with room to spare
        assert!(adv_structure_len("janus/esp32-cam-ble".len()) <= LEGACY_ADV_CAPACITY);
    }
    use core::fmt::Write;

    /// A fixed-capacity `fmt::Write` sink, so the tests need no allocator.
    struct Sink {
        buf: [u8; 128],
        len: usize,
    }

    impl Sink {
        fn new() -> Self {
            Sink {
                buf: [0; 128],
                len: 0,
            }
        }

        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap_or("<not utf-8>")
        }
    }

    impl Write for Sink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.len + s.len();
            let Some(dst) = self.buf.get_mut(self.len..end) else {
                return Err(fmt::Error);
            };
            dst.copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    #[test]
    fn provisioning_service_hyphenates_to_the_documented_string() {
        let mut buf = [0u8; 36];
        assert_eq!(
            SERVICE_PROVISIONING.write_hyphenated(&mut buf),
            Ok("4a616e75-7300-4d41-5441-000000000100")
        );
        assert_eq!(
            Uuid128::new(JANUS_BASE).write_hyphenated(&mut buf),
            Ok("4a616e75-7300-4d41-5441-000000000000")
        );
        assert_eq!(
            CHAR_PRESENCE.write_hyphenated(&mut buf),
            Ok("4a616e75-7300-4d41-5441-000000000303")
        );
        assert_eq!(&JANUS_BASE[..5], b"Janus");
        assert_eq!(&JANUS_BASE[6..10], b"MATA");
    }

    #[test]
    fn hyphenated_needs_36_bytes_and_uses_every_digit() {
        let mut short = [0u8; 35];
        assert_eq!(
            SERVICE_PROVISIONING.write_hyphenated(&mut short),
            Err(Error::BufferTooSmall { needed: 36 })
        );
        let all = Uuid128::new([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]);
        let mut long = [b'!'; 40];
        assert_eq!(
            all.write_hyphenated(&mut long),
            Ok("01234567-89ab-cdef-fedc-ba9876543210")
        );
        assert_eq!(&long[36..], b"!!!!");
        let mut sink = Sink::new();
        assert!(write!(sink, "{all} {all:?}").is_ok());
        assert_eq!(
            sink.as_str(),
            "01234567-89ab-cdef-fedc-ba9876543210 01234567-89ab-cdef-fedc-ba9876543210"
        );
    }

    #[test]
    fn janus_uuid_places_the_short_id_big_endian() {
        let u = janus_uuid(0x1234);
        assert_eq!(&u.as_bytes()[..14], &JANUS_BASE[..14]);
        assert_eq!(u.as_bytes()[14], 0x12);
        assert_eq!(u.as_bytes()[15], 0x34);
        assert_eq!(u.to_bytes(), *u.as_bytes());
        assert_eq!(SERVICE_MANIFEST, janus_uuid(0x0200));
        assert_eq!(SERVICE_TELEMETRY, janus_uuid(0x0300));
    }

    #[test]
    fn every_uuid_in_the_table_is_unique() {
        let mut seen = [Uuid128::new([0; 16]); 16];
        let mut n = 0;
        let mut record = |uuid: Uuid128| {
            assert!(!seen[..n].contains(&uuid), "duplicate {uuid}");
            seen[n] = uuid;
            n += 1;
        };
        for service in GATT_TABLE.services {
            record(service.uuid);
            for characteristic in service.characteristics {
                record(characteristic.uuid);
            }
        }
        assert_eq!(n, 12);
        assert_eq!(GATT_TABLE.characteristic_count(), 9);
        assert_eq!(GATT_TABLE.services.len(), 3);
    }

    #[test]
    fn table_contents_match_the_contract() {
        let expect = |uuid: Uuid128, name: &str, props: Props, max_len: u16| {
            let c = GATT_TABLE.find(uuid);
            assert!(c.is_some(), "{name} missing");
            if let Some(c) = c {
                assert_eq!(c.name, name);
                assert_eq!(c.props, props, "{name} props");
                assert_eq!(c.max_len, max_len, "{name} max_len");
            }
        };
        expect(CHAR_CREDENTIALS, "credentials", Props::WRITE, 100);
        expect(CHAR_STATUS, "status", Props::READ | Props::NOTIFY, 1);
        expect(CHAR_SCAN, "scan", Props::READ, 240);
        expect(CHAR_MANIFEST, "manifest", Props::READ, 512);
        expect(CHAR_DID, "did", Props::READ, 55);
        expect(CHAR_TICKET, "ticket", Props::READ, 128);
        expect(CHAR_RSSI, "rssi", Props::READ | Props::NOTIFY, 1);
        expect(CHAR_UPTIME, "uptime", Props::READ, 4);
        expect(CHAR_PRESENCE, "presence", Props::READ | Props::NOTIFY, 2);
        // The credentials characteristic carries the largest wifi TLV.
        assert_eq!(
            usize::from(PROVISIONING_CHARACTERISTICS[0].max_len),
            crate::wifi::MAX_ENCODED_LEN
        );
        // No value exceeds what ATT can carry.
        for c in GATT_TABLE.characteristics() {
            assert!(c.max_len <= ATT_MAX_VALUE_LEN, "{}", c.name);
            assert!(c.max_len > 0, "{}", c.name);
        }
    }

    #[test]
    fn find_misses_services_and_strangers() {
        assert_eq!(GATT_TABLE.find(SERVICE_PROVISIONING), None);
        assert_eq!(GATT_TABLE.find(janus_uuid(0x0104)), None);
        assert_eq!(GATT_TABLE.find(Uuid128::new([0xff; 16])), None);
        assert_eq!(
            GATT_TABLE.find_service(SERVICE_TELEMETRY).map(|s| s.name),
            Some("telemetry")
        );
        assert_eq!(GATT_TABLE.find_service(CHAR_RSSI), None);
    }

    #[test]
    fn props_bits_follow_the_core_spec() {
        assert_eq!(Props::READ.bits(), 0x02);
        assert_eq!(Props::WRITE_WITHOUT_RESPONSE.bits(), 0x04);
        assert_eq!(Props::WRITE.bits(), 0x08);
        assert_eq!(Props::NOTIFY.bits(), 0x10);
        assert_eq!(Props::INDICATE.bits(), 0x20);
        let rw = Props::READ | Props::WRITE;
        assert_eq!(rw.bits(), 0x0a);
        assert!(rw.contains(Props::READ));
        assert!(rw.contains(Props::WRITE));
        assert!(rw.contains(rw));
        assert!(!rw.contains(Props::NOTIFY));
        assert!(!rw.contains(Props::READ | Props::NOTIFY));
        assert!(Props::NONE.is_empty());
        assert!(rw.contains(Props::NONE));
        let mut acc = Props::default();
        acc |= Props::NOTIFY;
        acc |= Props::INDICATE;
        assert_eq!(acc, Props::NOTIFY.union(Props::INDICATE));
        assert_eq!(Props::from_bits(0x12), Some(Props::READ | Props::NOTIFY));
        assert_eq!(Props::from_bits(0x01), None);
        assert_eq!(Props::from_bits(0x80), None);

        let mut sink = Sink::new();
        assert!(write!(sink, "{:?}|{:?}|{:?}", Props::NONE, rw, acc).is_ok());
        assert_eq!(sink.as_str(), "NONE|READ | WRITE|NOTIFY | INDICATE");
    }
}

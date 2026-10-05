use crate::sys::include::esp_phy_init_data_t;

/// The maximum transmit power, in quarter dBm, for every rate: the
/// `phy_max_tx_power` option (Janus's E6). Upstream fixes this at 20 dBm
/// (`CONFIG_ESP_PHY_MAX_TX_POWER = 20`, times four); here it defaults to 20
/// quarter dBm, 5 dBm, the cap esp-radio sets at start
/// (`esp_wifi_set_max_tx_power(20)`), so a firmware moving from esp-radio to
/// the open MAC transmits as it did. Each rate's own ceiling below still
/// applies.
const MAX_TX_POWER_QDBM: u8 = parse_u8(env!("ESP_PHY_CONFIG_PHY_MAX_TX_POWER"));

const fn parse_u8(s: &str) -> u8 {
    let b = s.as_bytes();
    let mut n: u32 = 0;
    let mut i = 0;
    assert!(!b.is_empty(), "phy_max_tx_power is a number");
    while i < b.len() {
        assert!(b[i].is_ascii_digit(), "phy_max_tx_power is a number");
        n = n * 10 + (b[i] - b'0') as u32;
        i += 1;
    }
    assert!(n >= 8 && n <= 84, "phy_max_tx_power is 8 to 84 (quarter dBm)");
    n as u8
}

const fn limit(val: u8, low: u8, high: u8) -> u8 {
    if val < low {
        low
    } else if val > high {
        high
    } else {
        val
    }
}

pub(crate) static PHY_INIT_DATA_DEFAULT: esp_phy_init_data_t = esp_phy_init_data_t {
    params: [
        0x00,
        0x00,
        limit(MAX_TX_POWER_QDBM, 0, 0x50),
        limit(MAX_TX_POWER_QDBM, 0, 0x50),
        limit(MAX_TX_POWER_QDBM, 0, 0x50),
        limit(MAX_TX_POWER_QDBM, 0, 0x4c),
        limit(MAX_TX_POWER_QDBM, 0, 0x4c),
        limit(MAX_TX_POWER_QDBM, 0, 0x48),
        limit(MAX_TX_POWER_QDBM, 0, 0x4c),
        limit(MAX_TX_POWER_QDBM, 0, 0x48),
        limit(MAX_TX_POWER_QDBM, 0, 0x48),
        limit(MAX_TX_POWER_QDBM, 0, 0x44),
        limit(MAX_TX_POWER_QDBM, 0, 0x4a),
        limit(MAX_TX_POWER_QDBM, 0, 0x46),
        limit(MAX_TX_POWER_QDBM, 0, 0x46),
        limit(MAX_TX_POWER_QDBM, 0, 0x42),
        0x00,
        0x00,
        0x00,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0x74,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ],
};

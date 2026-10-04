"""E3's independent check: WPA2-PSK's 4-way and group-key handshakes laid
out from 802.11-2020 (12.7.2, 12.7.6, 12.7.7) in Python, with nothing
shared with the `ieee80211` crate the Rust side builds on: the PRF and the
MIC from hashlib/hmac, the PBKDF2 from hashlib, the AES key wrap (RFC 3394)
from `cryptography`. A test that runs one crate against itself agrees with
itself even where the crate is wrong (E2's F13); this is the second
implementation.

stdin: `name=value` lines (hex unless noted) from host-tests/air's
`interop.rs`: the passphrase and SSID (text), the addresses, the nonces,
the access point's RSN element, the station's, its messages 1 and 3 and its
group message 1 (as the station reads it, decrypted), the GTKs and key IDs,
the RSCs (decimal), the replay counters (decimal).

stdout: `check_<what>=ok` or `check_<what>=fail <why>` for each check of the
access point's frames, then `ptk=`, and the station's replies laid out the
same way: `message_2=`, `message_4=`, `group_message_2=` (hex).
"""
import hashlib
import hmac
import sys

from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

LLC_EAPOL = bytes.fromhex("aaaa03000000888e")
# Key Information bits (12.7.2): the descriptor version is the low 3 bits
V2, PAIRWISE, INSTALL, ACK, MIC, SECURE, ENCRYPTED = 2, 1 << 3, 1 << 6, 1 << 7, 1 << 8, 1 << 9, 1 << 12


def prf(key, label, data, n):
    """PRF-n (12.7.1.2): HMAC-SHA1 over label, 0, data, counter."""
    out = b""
    i = 0
    while len(out) < n:
        out += hmac.new(key, label.encode() + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:n]


def derive_ptk(pmk, aa, spa, anonce, snonce):
    """12.7.1.3: the PTK from the PMK, both addresses and both nonces."""
    data = min(aa, spa) + max(aa, spa) + min(anonce, snonce) + max(anonce, snonce)
    return prf(pmk, "Pairwise key expansion", data, 48)


def parse(frame):
    """A non-QoS data frame carrying an EAPOL-Key frame (Figure 12-32)."""
    if frame[0] != 0x08:
        raise ValueError("not a data frame")
    if frame[24:32] != LLC_EAPOL:
        raise ValueError("not LLC/SNAP EAPOL")
    e = frame[32:]
    if e[1] != 3:
        raise ValueError("not EAPOL-Key")
    length = int.from_bytes(e[2:4], "big")
    body = e[4 : 4 + length]
    if len(body) != length or body[0] != 2:
        raise ValueError("length or descriptor")
    kdl = int.from_bytes(body[93:95], "big")
    return {
        "fc1": frame[1],
        "a1": frame[4:10],
        "a2": frame[10:16],
        "a3": frame[16:22],
        "eapol": e[: 4 + length],
        "info": int.from_bytes(body[1:3], "big"),
        "replay": int.from_bytes(body[5:13], "big"),
        "nonce": body[13:45],
        "rsc": int.from_bytes(body[61:69], "little"),
        "mic": body[77:93],
        "key_data": body[95 : 95 + kdl],
    }


def mic(kck, eapol):
    """The EAPOL-Key MIC (HMAC-SHA1-128) over the frame with the MIC zeroed."""
    z = bytearray(eapol)
    z[4 + 77 : 4 + 93] = bytes(16)
    return hmac.new(kck, bytes(z), hashlib.sha1).digest()[:16]


def gtk_kde(plain):
    """The GTK KDE in unwrapped key data: (key ID, GTK)."""
    i = 0
    while i + 2 <= len(plain):
        t, n = plain[i], plain[i + 1]
        if t == 0xDD and n >= 6 and plain[i + 2 : i + 6] == bytes([0x00, 0x0F, 0xAC, 0x01]):
            return plain[i + 6] & 3, plain[i + 8 : i + 2 + n]
        if t == 0xDD and n == 0:
            break  # padding
        i += 2 + n
    raise ValueError("no GTK KDE")


def station_frame(bssid, sta, info, replay, nonce, key_data, kck):
    """A station's EAPOL-Key frame to the access point, MIC'd under the KCK."""
    body = (
        bytes([2])
        + info.to_bytes(2, "big")
        + (0).to_bytes(2, "big")
        + replay.to_bytes(8, "big")
        + nonce
        + bytes(16 + 8 + 8 + 16)
        + len(key_data).to_bytes(2, "big")
        + key_data
    )
    eapol = bytearray(bytes([1, 3]) + len(body).to_bytes(2, "big") + body)
    eapol[4 + 77 : 4 + 93] = mic(kck, bytes(eapol))
    header = bytes([0x08, 0x01, 0, 0]) + bssid + sta + bssid + bytes(2)
    return header + LLC_EAPOL + bytes(eapol)


def main():
    v = dict(line.strip().split("=", 1) for line in sys.stdin if "=" in line)
    h = lambda k: bytes.fromhex(v[k])
    bssid, sta = h("bssid"), h("station")
    anonce, snonce = h("anonce"), h("snonce")
    pmk = hashlib.pbkdf2_hmac("sha1", v["passphrase"].encode(), v["ssid"].encode(), 4096, 32)
    ptk = derive_ptk(pmk, bssid, sta, anonce, snonce)
    kck, kek = ptk[:16], ptk[16:32]
    out = []

    def check(name, cond, why=""):
        out.append(f"check_{name}=" + ("ok" if cond else f"fail {why}"))

    m1 = parse(h("message_1"))
    check("m1_addresses", (m1["a1"], m1["a2"], m1["a3"], m1["fc1"] & 3) == (sta, bssid, bssid, 2))
    check("m1_key_information", m1["info"] == V2 | PAIRWISE | ACK, hex(m1["info"]))
    check("m1_replay", m1["replay"] == int(v["replay_1"]), m1["replay"])
    check("m1_nonce", m1["nonce"] == anonce)
    check("m1_no_mic", m1["mic"] == bytes(16) and m1["key_data"] == b"")

    m3 = parse(h("message_3"))
    check("m3_key_information", m3["info"] == V2 | PAIRWISE | INSTALL | ACK | MIC | SECURE | ENCRYPTED, hex(m3["info"]))
    check("m3_replay", m3["replay"] == int(v["replay_3"]), m3["replay"])
    check("m3_mic", m3["mic"] == mic(kck, m3["eapol"]))
    check("m3_rsc_little_endian", m3["rsc"] == int(v["rsc_1"]), m3["rsc"])
    plain = aes_key_unwrap(kek, m3["key_data"])
    ap_rsn = h("ap_rsn_element")
    check("m3_rsn_element_is_the_beacons", plain.startswith(ap_rsn))
    key_id, gtk = gtk_kde(plain)
    check("m3_gtk", (key_id, gtk) == (int(v["key_id_1"]), h("gtk_1")), f"{key_id} {gtk.hex()}")

    g1 = parse(h("group_message_1"))
    check("g1_key_information", g1["info"] == V2 | ACK | MIC | SECURE | ENCRYPTED, hex(g1["info"]))
    check("g1_replay", g1["replay"] == int(v["replay_g"]), g1["replay"])
    check("g1_mic", g1["mic"] == mic(kck, g1["eapol"]))
    check("g1_rsc_little_endian", g1["rsc"] == int(v["rsc_2"]), g1["rsc"])
    key_id, gtk = gtk_kde(aes_key_unwrap(kek, g1["key_data"]))
    check("g1_gtk", (key_id, gtk) == (int(v["key_id_2"]), h("gtk_2")), f"{key_id} {gtk.hex()}")

    out.append("ptk=" + ptk.hex())
    m2 = station_frame(bssid, sta, V2 | PAIRWISE | MIC, int(v["replay_1"]), snonce, h("station_rsn_element"), kck)
    m4 = station_frame(bssid, sta, V2 | PAIRWISE | MIC | SECURE, int(v["replay_3"]), bytes(32), b"", kck)
    g2 = station_frame(bssid, sta, V2 | MIC | SECURE, int(v["replay_g"]), bytes(32), b"", kck)
    out.append("message_2=" + m2.hex())
    out.append("message_4=" + m4.hex())
    out.append("group_message_2=" + g2.hex())
    print("\n".join(out))


if __name__ == "__main__":
    main()

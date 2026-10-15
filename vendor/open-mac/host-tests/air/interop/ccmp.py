"""P2's independent check: CCMP encapsulation (802.11-2020 clause 12.5.3)
laid out from the standard in Python, with nothing shared with the Rust in
`ap_core::ccmp` -- the additional data and the nonce built here by hand, and
the AEAD itself AES-CCM from `cryptography` (OpenSSL), not our CCM. A test
that runs one implementation against itself agrees with itself even where it
is wrong (E2's F13); this is the second implementation.

What agreement here does prove: the field order of the additional data, every
mask, the packet number's byte order in both the header and the nonce, the
nonce's shape, and all of CCM's own construction -- B0, the length-prefixed
additional data, the padding, the counter blocks, and which octets the MIC
takes. What it cannot prove: that two readings of the masking rules in
12.5.3.3.3 are both the standard's. The frames being accepted by a chip's own
hardware decryption on the air is that check.

stdin: `name=value` hex lines from host-tests/air's `ccmp.rs`: `tk`, and
`frame_<n>` -- a whole MPDU with its CCMP header written, its body in the
clear, and 8 octets of room for the MIC.

stdout: `frame_<n>=<hex>`, the same MPDU encapsulated.
"""
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

MIC = 8
CCMP_HEADER = 8


def is_qos(frame):
    """A QoS data frame: the top bit of the subtype."""
    return bool(frame[0] & 0x80)


def has_addr4(frame):
    """A fourth address is present when both DS bits are set."""
    return frame[1] & 0x03 == 0x03


def qos_control(frame):
    """Where the QoS Control field sits: after the fourth address if there
    is one."""
    return 30 if has_addr4(frame) else 24


def header_length(frame):
    """The MAC header: the 24 fixed octets, the fourth address, the QoS
    Control field."""
    return 24 + (6 if has_addr4(frame) else 0) + (2 if is_qos(frame) else 0)


def additional_data(frame):
    """The AAD (12.5.3.3.3): FC, A1, A2, A3, SC, then A4 and QoS Control when
    they are there -- with every field a relay may legitimately change masked
    to 0, and the Protected bit set."""
    fc0 = frame[0] & ~0x70  # the subtype's bits 4, 5 and 6
    fc1 = (frame[1] & ~0x38) | 0x40  # Retry, Power Management, More Data; Protected
    if is_qos(frame):
        fc1 &= ~0x80  # Order
    aad = bytes([fc0, fc1])
    aad += frame[4:22]  # A1, A2, A3
    aad += bytes([frame[22] & 0x0F, 0])  # the fragment number kept, the sequence masked
    if has_addr4(frame):
        aad += frame[24:30]
    if is_qos(frame):
        aad += bytes([frame[qos_control(frame)] & 0x0F, 0])  # the TID kept
    return aad


def nonce(frame):
    """The nonce (12.5.3.3.4): the priority, then A2, then the packet number
    most significant octet first. The CCMP header holds it as PN0, PN1, a
    reserved octet, the key id, then PN2 to PN5 (12.5.3.2)."""
    priority = frame[qos_control(frame)] & 0x0F if is_qos(frame) else 0
    at = header_length(frame)
    ccmp = frame[at : at + CCMP_HEADER]
    pn = bytes([ccmp[7], ccmp[6], ccmp[5], ccmp[4], ccmp[1], ccmp[0]])
    return bytes([priority]) + frame[10:16] + pn


def encapsulate(frame, tk):
    """The body replaced by its ciphertext, with the MIC after it. AES-CCM
    with an 8-octet tag is CCMP's cipher (12.5.3.1), and it returns exactly
    the ciphertext and then the MIC."""
    at = header_length(frame) + CCMP_HEADER
    body = frame[at : len(frame) - MIC]
    sealed = AESCCM(tk, tag_length=MIC).encrypt(nonce(frame), body, additional_data(frame))
    return frame[:at] + sealed


def main():
    values = {}
    for line in sys.stdin.read().splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            values[name] = bytes.fromhex(value)
    tk = values["tk"]
    out = [
        f"{name}={encapsulate(frame, tk).hex()}"
        for name, frame in sorted(values.items())
        if name.startswith("frame_")
    ]
    print("\n".join(out))


if __name__ == "__main__":
    main()

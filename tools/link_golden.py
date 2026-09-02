"""Independent oracle for the `link` wire format: Python's hmac/hashlib, no
Rust in the loop. Prints the constants `link::tests::golden_*` assert.

    python tools/link_golden.py
"""
import hashlib
import hmac


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def hexlist(b: bytes) -> str:
    return ", ".join(f"0x{x:02x}" for x in b)


# Envelope tag: HMAC-SHA256(k_send, ver | session BE | seq BE | payload)[:16]
key = bytes(range(1, 33))
frame_head = bytes([1]) + (0xBEEF).to_bytes(2, "big") + (7).to_bytes(4, "big") + b"janus"
tag = hmac.new(key, frame_head, hashlib.sha256).digest()[:16]
print("ENVELOPE_TAG =", "[" + hexlist(tag) + "]")

# Key schedule: HKDF-SHA256(salt = nonce_i || nonce_r, ikm = ss_static || ss_eph,
# info = "janus-link-v1") -> k_i2r (32) | k_r2i (32) | k_confirm (32) | id (2)
nonce_i = bytes([0xA0 + i for i in range(16)])
nonce_r = bytes([0xB0 + i for i in range(16)])
ikm = bytes([0x11] * 32) + bytes([0x22] * 32)
okm = hkdf_sha256(nonce_i + nonce_r, ikm, b"janus-link-v1", 98)
print("K_I2R     =", "[" + hexlist(okm[0:32]) + "]")
print("K_R2I     =", "[" + hexlist(okm[32:64]) + "]")
print("K_CONFIRM =", "[" + hexlist(okm[64:96]) + "]")
print("SESSION_ID = 0x%02x%02x" % (okm[96], okm[97]))

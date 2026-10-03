"""Independent oracle for the setup protocol (docs/setup-protocol.md in the
Janus umbrella; enc-ble M1): pure Python, no Rust and no third-party package
in the loop. Every primitive is checked against its own RFC before it is
used, then one fixed session is computed end to end and written as
`key = hex` lines for `tests/session_vectors.rs`.

    python tools/setup_golden.py            # writes the fixture
    python tools/setup_golden.py --check    # exits 1 if the fixture differs

Primitives: P-256 (affine, exact integers), SHA-256 / HMAC / HKDF / PBKDF2
(hashlib, hmac), SPAKE2+ (RFC 9383), deterministic ECDSA (RFC 6979, low-s),
ChaCha20-Poly1305 (RFC 8439).
"""
import os
import sys

from setup_v1 import *  # noqa: F401,F403 -- the primitives, checked on import

# ---- one fixed session ---------------------------------------------------------
def scalar(label):
    return int.from_bytes(sha256(label), "big") % n


CODE_AS_TYPED = "7kxq3-m9prt"
pw = normalise(CODE_AS_TYPED)
salt = sha256(b"janus-setup-v1 test salt")[:16]
iterations = 1000
w0, w1 = derive(pw, salt, iterations)
assert w0 and w1
L = mul(w1, G)
setup_v = bytes([1]) + i2b(w0) + enc(L) + salt + iterations.to_bytes(4, "big")
assert len(setup_v) == 118

dev_secret = scalar(b"janus-setup-v1 test device key")
devpub = compressed(mul(dev_secret, G))
label = b"ble"
context = b"janus-setup-v1" + bytes([len(label)]) + label + devpub
x = scalar(b"janus-setup-v1 test x")
y = scalar(b"janus-setup-v1 test y")
s = spake2plus(context, b"", b"", w0, w1, x, y)

reply_prehash = sha256(b"janus-setup-v1/reply\n", len(context).to_bytes(2, "big"), context,
                       s["shareP"], s["shareV"], s["confirmV"])
sig = ecdsa_sign_prehash(dev_secret, reply_prehash)
assert ecdsa_verify_prehash(mul(dev_secret, G), reply_prehash, sig)

k_b2d = hkdf(s["K_shared"], b"janus-setup-v1 b2d", 32)
k_d2b = hkdf(s["K_shared"], b"janus-setup-v1 d2b", 32)


def nonce(seq):
    return b"\x00" * 4 + seq.to_bytes(8, "big")


# Ready: phase Unprovisioned (0), one scan entry "bench-net", -51 dBm, secured
ready_pt = bytes([0]) + bytes([1, 9]) + b"bench-net" + bytes([3, 1, (-51) & 0xFF]) + bytes([4, 1, 1])
ready = aead_seal(k_d2b, nonce(0), bytes([1, 0x04]), ready_pt)


def tlv(tag, value):
    return bytes([tag]) + len(value).to_bytes(2, "big") + value


settings_pt = (tlv(0x01, b"bench-net") + tlv(0x02, b"example-pass-1") + tlv(0x03, b"porch camera")
               + tlv(0x05, (250).to_bytes(4, "big")))
settings = aead_seal(k_b2d, nonce(0), bytes([1, 0x05]), settings_pt)
result_pt = bytes([0x00, 1])  # Applied, phase Connecting
result = aead_seal(k_d2b, nonce(1), bytes([1, 0x06]), result_pt)

hdr = lambda kind: bytes([1, kind])
discover = hdr(0x00) + bytes([1]) + devpub + salt + iterations.to_bytes(4, "big") + (0xFFFF).to_bytes(2, "big") + bytes([5])
messages = {
    "msg_discover": discover,
    "msg_start": hdr(0x01) + bytes([1]) + s["shareP"],
    "msg_reply": hdr(0x02) + s["shareV"] + s["confirmV"] + sig,
    "msg_confirm": hdr(0x03) + s["confirmP"],
    "msg_ready": hdr(0x04) + ready,
    "msg_settings": hdr(0x05) + settings,
    "msg_result": hdr(0x06) + result,
}
assert [len(m) for m in messages.values()] == [59, 68, 163, 34, 2 + len(ready_pt) + 16, 2 + len(settings_pt) + 16, 20]

out = [
    "# The setup protocol v1, one fixed session (tools/setup_golden.py; do not edit).",
    f"code_as_typed = {CODE_AS_TYPED.encode().hex()}",
    f"pw = {pw.hex()}",
    f"salt = {salt.hex()}",
    f"iterations = {iterations:08x}",
    f"w0 = {i2b(w0).hex()}",
    f"w1 = {i2b(w1).hex()}",
    f"L = {enc(L).hex()}",
    f"setup_v = {setup_v.hex()}",
    f"device_secret = {i2b(dev_secret).hex()}",
    f"devpub = {devpub.hex()}",
    f"label = {label.hex()}",
    f"context = {context.hex()}",
    f"x = {i2b(x).hex()}",
    f"y = {i2b(y).hex()}",
]
for k in ["shareP", "shareV", "Z", "V", "K_main", "K_confirmP", "K_confirmV", "confirmP", "confirmV", "K_shared"]:
    out.append(f"{k} = {s[k].hex()}")
out += [
    f"reply_prehash = {reply_prehash.hex()}",
    f"reply_sig = {sig.hex()}",
    f"k_b2d = {k_b2d.hex()}",
    f"k_d2b = {k_d2b.hex()}",
    f"ready_plain = {ready_pt.hex()}",
    f"settings_plain = {settings_pt.hex()}",
    f"result_plain = {result_pt.hex()}",
]
out += [f"{k} = {v.hex()}" for k, v in messages.items()]
text = "\n".join(out) + "\n"

dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "crates", "rusty_esp_signal-core", "tests",
                   "fixtures", "setup", "session-v1.txt")
dst = os.path.normpath(dst)
if "--check" in sys.argv:
    same = os.path.exists(dst) and open(dst, encoding="utf-8").read() == text
    print("fixture", "matches" if same else "DIFFERS", dst)
    sys.exit(0 if same else 1)
os.makedirs(os.path.dirname(dst), exist_ok=True)
tmp = dst + ".tmp"
with open(tmp, "w", encoding="utf-8", newline="\n") as f:
    f.write(text)
os.replace(tmp, dst)
print("RFC 8439, RFC 6979 and RFC 9383 self-checks passed; wrote", dst, len(text), "bytes")

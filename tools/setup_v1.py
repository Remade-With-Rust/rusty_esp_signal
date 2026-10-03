"""The setup protocol v1 in pure Python (docs/setup-protocol.md in the Janus
umbrella): the independent implementation behind `setup_golden.py`'s fixture
and the scripted central (`setup_central.py`) that drives a board. No Rust
and no third-party package in the loop. Every primitive is checked against
its own RFC on import.

Primitives: P-256 (affine, exact integers), SHA-256 / HMAC / HKDF / PBKDF2
(hashlib, hmac), SPAKE2+ (RFC 9383), deterministic ECDSA (RFC 6979, low-s),
ChaCha20-Poly1305 (RFC 8439). The browser's side of a session is at the end.
"""
import hashlib
import hmac
import os
import sys

# ---- P-256 ----------------------------------------------------------------
p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    if P[0] == Q[0]:
        if (P[1] + Q[1]) % p == 0:
            return None
        lam = (3 * P[0] * P[0] + a) * pow(2 * P[1], -1, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (lam * lam - P[0] - Q[0]) % p
    return (x, (lam * (P[0] - x) - P[1]) % p)


def mul(k, P):
    R = None
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R


def neg(P):
    return (P[0], (-P[1]) % p)


def decompress(raw):
    x = int.from_bytes(raw[1:], "big")
    y = pow((x ** 3 + a * x + b) % p, (p + 1) // 4, p)
    if y % 2 != raw[0] - 2:
        y = p - y
    assert (y * y - (x ** 3 + a * x + b)) % p == 0
    return (x, y)


def enc(P):
    return b"\x04" + P[0].to_bytes(32, "big") + P[1].to_bytes(32, "big")


def compressed(P):
    return bytes([2 + (P[1] & 1)]) + P[0].to_bytes(32, "big")


def i2b(v):
    return v.to_bytes(32, "big")


# ---- hashes --------------------------------------------------------------
def sha256(*parts):
    h = hashlib.sha256()
    for x in parts:
        h.update(x)
    return h.digest()


def hkdf(ikm, info, length, salt=None):
    prk = hmac.new(salt if salt is not None else b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + t, i + 1
    return out[:length]


def lp8(s):
    return len(s).to_bytes(8, "little") + s


# ---- ChaCha20-Poly1305 (RFC 8439) ----------------------------------------
def _rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _qr(s, a_, b_, c_, d_):
    s[a_] = (s[a_] + s[b_]) & 0xFFFFFFFF; s[d_] = _rotl(s[d_] ^ s[a_], 16)
    s[c_] = (s[c_] + s[d_]) & 0xFFFFFFFF; s[b_] = _rotl(s[b_] ^ s[c_], 12)
    s[a_] = (s[a_] + s[b_]) & 0xFFFFFFFF; s[d_] = _rotl(s[d_] ^ s[a_], 8)
    s[c_] = (s[c_] + s[d_]) & 0xFFFFFFFF; s[b_] = _rotl(s[b_] ^ s[c_], 7)


def chacha20_block(key, counter, nonce):
    const = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    st = const + [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)] + [counter] + \
        [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    w = list(st)
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return b"".join(((w[i] + st[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(16))


def chacha20(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[i:i + 64], ks))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s = int.from_bytes(key[16:], "little")
    acc, P = 0, (1 << 130) - 5
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b"\x01", "little")) * r % P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(x):
    return b"\x00" * (-len(x) % 16)


def aead_seal(key, nonce, aad, pt):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, pt)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    return ct + poly1305(otk, mac_data)


# RFC 8439 section 2.8.2
_k = bytes(range(0x80, 0xa0))
_nonce = bytes.fromhex("070000004041424344454647")
_aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
_pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
_sealed = aead_seal(_k, _nonce, _aad, _pt)
assert _sealed[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", "RFC 8439 2.8.2 tag"
assert _sealed[:16].hex() == "d31a8d34648e60db7b86afbc53ef7ec2", "RFC 8439 2.8.2 ciphertext"


# ---- ECDSA P-256, RFC 6979 deterministic, low-s ---------------------------
def rfc6979_k(x, h1):
    qlen = 32
    bx = i2b(x) + i2b(int.from_bytes(h1, "big") % n)
    V, K = b"\x01" * 32, b"\x00" * 32
    K = hmac.new(K, V + b"\x00" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = int.from_bytes(V[:qlen], "big")
        if 1 <= k < n:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def ecdsa_sign_prehash(x, h1, low_s=True):
    k = rfc6979_k(x, h1)
    r = mul(k, G)[0] % n
    e = int.from_bytes(h1, "big") % n
    s = pow(k, -1, n) * (e + r * x) % n
    if low_s and s > n // 2:
        s = n - s
    return i2b(r) + i2b(s)


def ecdsa_verify_prehash(Q, h1, sig):
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < n and 1 <= s < n):
        return False
    e = int.from_bytes(h1, "big") % n
    w = pow(s, -1, n)
    R = add(mul(e * w % n, G), mul(r * w % n, Q))
    return R is not None and R[0] % n == r


# RFC 6979 A.2.5, P-256, SHA-256, message "sample" (the RFC's s, not low-s)
_x = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
_sig = ecdsa_sign_prehash(_x, sha256(b"sample"), low_s=False)
assert _sig.hex().upper() == ("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
                              "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"), "RFC 6979 A.2.5"

# ---- SPAKE2+ (RFC 9383), checked against its first P-256 vector ------------
M = decompress(bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"))
N = decompress(bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"))


def spake2plus(context, id_p, id_v, w0, w1, x, y):
    L = mul(w1, G)
    X = add(mul(x, G), mul(w0, M))
    Y = add(mul(y, G), mul(w0, N))
    Z = mul(y, add(X, neg(mul(w0, M))))
    V = mul(y, L)
    assert Z == mul(x, add(Y, neg(mul(w0, N)))) and V == mul(w1, add(Y, neg(mul(w0, N))))
    TT = (lp8(context) + lp8(id_p) + lp8(id_v) + lp8(enc(M)) + lp8(enc(N)) + lp8(enc(X)) + lp8(enc(Y))
          + lp8(enc(Z)) + lp8(enc(V)) + lp8(i2b(w0)))
    k_main = sha256(TT)
    ck = hkdf(k_main, b"ConfirmationKeys", 64)
    k_shared = hkdf(k_main, b"SharedKey", 32)
    return {
        "L": enc(L), "shareP": enc(X), "shareV": enc(Y), "Z": enc(Z), "V": enc(V), "TT": TT,
        "K_main": k_main, "K_confirmP": ck[:32], "K_confirmV": ck[32:], "K_shared": k_shared,
        "confirmP": hmac.new(ck[:32], enc(Y), hashlib.sha256).digest(),
        "confirmV": hmac.new(ck[32:], enc(X), hashlib.sha256).digest(),
    }


_v = spake2plus(b"SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors", b"client", b"server",
                0xbb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3,
                0x7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba,
                0xd1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539,
                0x717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3)
assert _v["K_main"].hex() == "4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29"
assert _v["confirmP"].hex() == "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527"
assert _v["confirmV"].hex() == "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68"
assert _v["K_shared"].hex() == "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7"

# ---- the setup code ----------------------------------------------------------
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def normalise(code):
    out = []
    for ch in code.upper():
        if ch in "- ":
            continue
        ch = {"O": "0", "I": "1", "L": "1"}.get(ch, ch)
        if ch not in ALPHABET:
            raise ValueError(f"not a code symbol: {ch!r}")
        out.append(ch)
    if len(out) != 10:
        raise ValueError("a code is ten symbols")
    return "".join(out).encode()


def derive(pw, salt, iterations):
    ws = hashlib.pbkdf2_hmac("sha256", lp8(pw) + lp8(b"") + lp8(b""), salt, iterations, 80)
    return int.from_bytes(ws[:40], "big") % n, int.from_bytes(ws[40:], "big") % n


# ---- the browser's side of one session (the prover) ---------------------------
def aead_open(key, nonce, aad, sealed):
    """ChaCha20-Poly1305 open; None when the tag does not verify."""
    if len(sealed) < 16:
        return None
    ct, tag = sealed[:-16], sealed[-16:]
    otk = chacha20_block(key, 0, nonce)[:32]
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + len(aad).to_bytes(8, "little") + len(ct).to_bytes(8, "little")
    if not hmac.compare_digest(poly1305(otk, mac_data), tag):
        return None
    return chacha20(key, 1, nonce, ct)


def seq_nonce(seq):
    return bytes(4) + seq.to_bytes(8, "big")


def context_for(label, devpub):
    return b"janus-setup-v1" + bytes([len(label)]) + label + devpub


def read_discover(msg):
    """Discover's fields, or ValueError."""
    if len(msg) != 59 or msg[0] != 1 or msg[1] != 0x00:
        raise ValueError(f"not a Discover: {msg.hex()}")
    return {
        "suites": msg[2], "devpub": msg[3:36], "salt": msg[36:52],
        "iterations": int.from_bytes(msg[52:56], "big"),
        "window_s": int.from_bytes(msg[56:58], "big"), "attempts_left": msg[58],
    }


REPLY_DOMAIN = b"janus-setup-v1/reply" + bytes([0x0A])


class Prover:
    """One session from the browser's side: `start()` is Start; `reply()`
    checks the device's Reply (its confirmation and its signature) and returns
    Confirm; then `open_ready`, `seal_settings`, `open_result`."""

    def __init__(self, discover, code, label=b"ble", x=None):
        d = read_discover(discover)
        if not d["suites"] & 1:
            raise ValueError("the device offers no setup code")
        if not 1000 <= d["iterations"] <= 2_000_000:
            raise ValueError(f"iterations {d['iterations']} outside the protocol's bounds")
        self.devpub = d["devpub"]
        self.context = context_for(label, self.devpub)
        self.w0, self.w1 = derive(normalise(code), d["salt"], d["iterations"])
        self.x = x if x is not None else int.from_bytes(os.urandom(32), "big") % (n - 1) + 1
        self.X = add(mul(self.x, G), mul(self.w0, M))
        self.recv_seq = 0
        self.send_seq = 0

    def start(self):
        return bytes([1, 0x01, 1]) + enc(self.X)

    def reply(self, msg):
        """Confirm, or ValueError naming what failed ("confirmV": a wrong
        code; "signature": another device)."""
        if len(msg) >= 3 and msg[1] == 0x7F:
            raise ValueError(f"device error {msg[2]:#04x}")
        if len(msg) != 163 or msg[1] != 0x02:
            raise ValueError(f"not a Reply: {msg[:4].hex()}")
        share_v, confirm_v, sig = msg[2:67], msg[67:99], msg[99:163]
        Y = (int.from_bytes(share_v[1:33], "big"), int.from_bytes(share_v[33:65], "big"))
        if share_v[0] != 4 or (Y[1] * Y[1] - Y[0] ** 3 - a * Y[0] - b) % p:
            raise ValueError("shareV is not a point")
        T = add(Y, neg(mul(self.w0, N)))
        Z, V = mul(self.x, T), mul(self.w1, T)
        TT = (lp8(self.context) + lp8(b"") + lp8(b"") + lp8(enc(M)) + lp8(enc(N)) + lp8(enc(self.X))
              + lp8(share_v) + lp8(enc(Z)) + lp8(enc(V)) + lp8(i2b(self.w0)))
        k_main = sha256(TT)
        ck = hkdf(k_main, b"ConfirmationKeys", 64)
        k_shared = hkdf(k_main, b"SharedKey", 32)
        expect_v = hmac.new(ck[32:], enc(self.X), hashlib.sha256).digest()
        if not hmac.compare_digest(expect_v, confirm_v):
            raise ValueError("confirmV")
        prehash = sha256(REPLY_DOMAIN, len(self.context).to_bytes(2, "big"), self.context,
                         enc(self.X), share_v, confirm_v)
        if int.from_bytes(sig[32:], "big") > n // 2 or not ecdsa_verify_prehash(decompress(self.devpub), prehash, sig):
            raise ValueError("signature")
        self.k_b2d = hkdf(k_shared, b"janus-setup-v1 b2d", 32)
        self.k_d2b = hkdf(k_shared, b"janus-setup-v1 d2b", 32)
        return bytes([1, 0x03]) + hmac.new(ck[:32], share_v, hashlib.sha256).digest()

    def _open(self, msg, kind):
        if len(msg) >= 3 and msg[1] == 0x7F:
            raise ValueError(f"device error {msg[2]:#04x}")
        if msg[:2] != bytes([1, kind]):
            raise ValueError(f"expected kind {kind:#04x}, got {msg[:2].hex()}")
        plain = aead_open(self.k_d2b, seq_nonce(self.recv_seq), msg[:2], msg[2:])
        if plain is None:
            raise ValueError("a sealed message did not open")
        self.recv_seq += 1
        return plain

    def open_ready(self, msg):
        plain = self._open(msg, 0x04)
        return plain[0], plain[1:]

    def seal_settings(self, record):
        sealed = aead_seal(self.k_b2d, seq_nonce(self.send_seq), bytes([1, 0x05]), record)
        self.send_seq += 1
        return bytes([1, 0x05]) + sealed

    def open_result(self, msg):
        plain = self._open(msg, 0x06)
        return plain[0], plain[1]


def record_tlv(tag, value):
    return bytes([tag]) + len(value).to_bytes(2, "big") + value

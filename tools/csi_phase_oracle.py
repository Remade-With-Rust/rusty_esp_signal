"""Float replica of `radar::phase` for the host oracle side: `atan2` per live
subcarrier, unwrap across subcarriers, a least-squares line removed per
frame, circular variance over a sliding window, mean across subcarriers, in
permille. No numpy, no Rust, none of the fixed-point tricks. Writes one
value per judged frame next to each fixture so the chip's integer pipeline
can be checked against an independent implementation:

    python tools/csi_phase_oracle.py          # regenerate the golden files
    python tools/csi_phase_oracle.py --luts   # print the two tables phase.rs embeds
"""
import cmath
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "crates", "rusty_esp_signal-core", "tests", "fixtures", "csi")
VALID = list(range(4, 32)) + list(range(33, 61))  # Layout::C6_HT20_NATURAL
WINDOW = 50


def rows(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            v = list(map(int, line.strip().split(",")[3:3 + 128]))
            out.append([math.atan2(v[2 * k], v[2 * k + 1]) for k in VALID])  # (imag, real)
    return out


def sanitise(raw):
    # unwrap across subcarriers: cumulative shortest arc
    u = [raw[0]]
    for k in range(1, len(raw)):
        d = raw[k] - raw[k - 1]
        d = (d + math.pi) % (2 * math.pi) - math.pi
        u.append(u[-1] + d)
    n = len(u)
    ks = list(range(n))
    sk, skk = sum(ks), sum(k * k for k in ks)
    su, sku = sum(u), sum(k * x for k, x in zip(ks, u))
    slope = (n * sku - sk * su) / (n * skk - sk * sk)
    icpt = (su - slope * sk) / n
    return [x - slope * k - icpt for k, x in zip(ks, u)]


def wander(frames):
    out = []
    for n in range(WINDOW - 1, len(frames)):
        win = frames[n - WINDOW + 1:n + 1]
        vs = []
        for sc in range(len(VALID)):
            m = sum(cmath.exp(1j * f[sc]) for f in win) / WINDOW
            vs.append(1000.0 * (1.0 - abs(m)))
        out.append(sum(vs) / len(vs))
    return out


def luts():
    atan = [round(math.atan(i / 256) / (2 * math.pi) * 65536) for i in range(257)]
    sin = [round(math.sin(i / 256 * math.pi / 2) * 1024) for i in range(257)]
    print("ATAN_OCTANT", atan)
    print("SIN_QUARTER", sin)


def main():
    if "--luts" in sys.argv:
        luts()
        return
    for name in ("c6_empty_room_iter1", "c6_walking_person_iter1"):
        frames = [sanitise(r) for r in rows(os.path.join(FIX, name + ".csv"))]
        ws = wander(frames)
        golden = os.path.join(FIX, name + ".phase.txt")
        with open(golden, "w", encoding="utf-8", newline="\n") as f:
            f.write("# float phase wander (permille) per judged frame, window %d, from tools/csi_phase_oracle.py\n" % WINDOW)
            for w in ws:
                f.write("%.3f\n" % w)
        s = sorted(ws)
        print("wrote", golden, len(ws), "values; p50 %.1f p95 %.1f max %.1f" % (s[len(s) // 2], s[len(s) * 95 // 100], s[-1]))


if __name__ == "__main__":
    main()

"""Synthetic CSI captures with KNOWN rates, and a float replica of
`radar::vitals` -- the host oracle for breathing and heart-rate estimation.

The Cuenca dataset has no vitals labels and there is no recording of our
own yet, so the algorithm is checked two ways: it must recover the rate it
was given from a synthetic capture (this file writes two, in the exact row
format of the real fixtures), and the chip's integer pipeline must agree
with this float implementation of the same steps, frame by frame. Neither
is an accuracy claim about a person; the ledger says so.

    python tools/csi_vitals_oracle.py     # (re)generate the captures and goldens

Determinism: a seeded xorshift, so every machine writes the same bytes.
"""
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "crates", "rusty_esp_signal-core", "tests", "fixtures", "csi")
VALID = list(range(4, 32)) + list(range(33, 61))  # Layout::C6_HT20_NATURAL
FRAME_HZ = 50
SECONDS = 25
N = 200  # decimated samples in the window (both configs)


class XorShift:
    def __init__(self, seed):
        self.s = seed & 0xFFFFFFFF

    def next(self):
        s = self.s
        s ^= (s << 13) & 0xFFFFFFFF
        s ^= s >> 17
        s ^= (s << 5) & 0xFFFFFFFF
        self.s = s & 0xFFFFFFFF
        return self.s

    def uniform(self):
        return self.next() / 0xFFFFFFFF

    def gauss(self):
        # Box-Muller, one sample
        u1 = max(self.uniform(), 1e-12)
        u2 = self.uniform()
        return math.sqrt(-2.0 * math.log(u1)) * math.cos(2 * math.pi * u2)


def synth(name, rhythms, seed):
    """rhythms: list of (hz, depth). Each subcarrier modulates with its own
    depth (0.5-1.5x) and sign, because a changing path is frequency-selective."""
    rng = XorShift(seed)
    gains = []
    for k in range(len(VALID)):
        amp = 20.0 + 20.0 * rng.uniform()
        ph = 2 * math.pi * rng.uniform()
        mods = []
        for i, (hz, depth) in enumerate(rhythms):
            sign = -1.0 if rng.uniform() < 0.4 else 1.0
            d = depth * (0.5 + rng.uniform())
            psi = 2 * math.pi * rng.uniform()
            mods.append((hz, sign * d, psi))
        gains.append((amp, ph, mods))
    rows = []
    frames = FRAME_HZ * SECONDS
    for n in range(frames):
        t = n / FRAME_HZ
        drift = 1.0 + 0.003 * t / SECONDS
        entries = [0] * 128
        for k, (amp, ph, mods) in zip(VALID, gains):
            m = 1.0
            for hz, d, psi in mods:
                m *= 1.0 + d * math.sin(2 * math.pi * hz * t + psi)
            a = amp * m * drift
            re = a * math.cos(ph) + rng.gauss()
            im = a * math.sin(ph) + rng.gauss()
            entries[2 * k] = max(-128, min(127, round(im)))
            entries[2 * k + 1] = max(-128, min(127, round(re)))
        rows.append("CSI_DATA,-40,128," + ",".join(str(v) for v in entries))
    path = os.path.join(FIX, name + ".csv")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(rows) + "\n")
    print("wrote", path, frames, "rows")
    return path


def features_normalised(path):
    """Per frame: amplitude per live subcarrier, divided by the frame mean and
    scaled to 1024 -- what `Features::normalised` does, in float."""
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            v = list(map(int, line.strip().split(",")[3:3 + 128]))
            amps = [math.hypot(v[2 * k + 1], v[2 * k]) for k in VALID]
            m = sum(amps) / len(amps)
            out.append([a / m * 1024.0 for a in amps])
    return out


def highpass(x, m):
    """x minus a centred moving average of m samples (edges shrink the window)."""
    half = max(m // 2, 1)
    n = len(x)
    out = []
    for i in range(n):
        lo, hi = max(0, i - half), min(n, i + half + 1)
        out.append(x[i] - sum(x[lo:hi]) / (hi - lo))
    return out


def estimate(frames, decim, rate_hz, lo_mhz, hi_mhz, every, hp=0):
    """The float replica of VitalsEstimator::estimate, at every update."""
    # decimate
    samples = []
    for i in range(0, len(frames) - decim + 1, decim):
        block = frames[i:i + decim]
        samples.append([sum(b[k] for b in block) / decim for k in range(len(VALID))])
    lo = (rate_hz * 1000) // hi_mhz
    hi = (rate_hz * 1000 + lo_mhz - 1) // lo_mhz
    lo = max(lo, 2)
    hi = min(hi, N - 2)
    out = []
    since = every  # the first full window estimates at once, like the chip
    for end in range(N, len(samples) + 1):
        since += 1
        if since < every:
            continue
        since = 0
        win = samples[end - N:end]
        summed = {}
        used = 0
        for sc in range(len(VALID)):
            col = [w[sc] for w in win]
            mean = sum(col) / N
            x = [c - mean for c in col]
            if hp > 1:
                x = highpass(x, hp)
            energy = sum(v * v for v in x)
            if energy <= 0:
                continue
            used += 1
            for lag in range(1, hi + 2):
                r = sum(x[i] * x[i + lag] for i in range(N - lag))
                rho = r * N / ((N - lag) * energy)
                summed[lag] = summed.get(lag, 0.0) + max(-2.0, min(2.0, rho))
        # the first significant peak from lag 2, not the global one
        # (sub-harmonics below, harmonics of a faster rhythm above)
        g = max(summed[l] for l in range(2, hi + 1))
        floor = g - abs(g) * 0.15 if g > 0 else g
        best = None
        for l in range(2, hi + 1):
            if summed[l] >= floor and summed[l] >= summed[l - 1] and summed[l] >= summed[l + 1]:
                best = l
                break
        if best is None:
            best = max(range(2, hi + 1), key=lambda l: summed[l])
        conf = summed[best] / used if used else 0.0
        a, b, c = summed[best - 1], summed[best], summed[best + 1]
        denom = a - 2 * b + c
        delta = (a - c) / (2 * denom) if denom < 0 else 0.0
        delta = max(-0.5, min(0.5, delta))
        lag = best + delta
        bpm = 60.0 * rate_hz / lag
        out.append((bpm, max(0.0, min(1.0, conf))))
    return out


def golden(path, suffix, decim, rate, lo, hi, every, hp=0):
    frames = features_normalised(path)
    est = estimate(frames, decim, rate, lo, hi, every, hp)
    g = path[:-4] + suffix
    with open(g, "w", encoding="utf-8", newline="\n") as f:
        f.write("# float vitals per estimate: bpm confidence -- decim %d, %d Hz, band %d-%d mHz, window %d, from tools/csi_vitals_oracle.py\n"
                % (decim, rate, lo, hi, N))
        for bpm, conf in est:
            f.write("%.3f %.4f\n" % (bpm, conf))
    print("wrote", g, len(est), "estimates; last bpm %.2f conf %.3f" % est[-1] if est else "none")


def main():
    b = synth("synth_breathing_15bpm", [(0.25, 0.03)], seed=0xB0B0_0001)
    v = synth("synth_vitals_12_72bpm", [(0.20, 0.03), (1.20, 0.006)], seed=0xB0B0_0002)
    # breathing band, 10 Hz
    golden(b, ".breath.txt", 5, 10, 150, 550, 10)
    golden(v, ".breath.txt", 5, 10, 150, 550, 10)
    # heart band, 25 Hz, a one-second high-pass, on the two-rate file
    golden(v, ".heart.txt", 2, 25, 700, 2200, 25, hp=25)
    # the real captures through the breathing band: no rate must appear in
    # the empty room; the walk is printed, not asserted
    for name in ("c6_empty_room_iter1", "c6_walking_person_iter1"):
        golden(os.path.join(FIX, name + ".csv"), ".breath.txt", 5, 10, 150, 550, 10)


if __name__ == "__main__":
    main()

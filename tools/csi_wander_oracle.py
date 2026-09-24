"""Float replica of `radar::csi` for the host oracle side: amplitude per live
subcarrier (`hypot`), coefficient of variation over a sliding window, mean
across subcarriers, in permille. No numpy, no Rust. Writes one wander value
per judged frame next to each fixture so the fixed-point chip code can be
checked against an independent implementation:

    python tools/csi_wander_oracle.py    # regenerate the golden files
"""
import math
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "crates", "rusty_esp_signal-core", "tests", "fixtures", "csi")
VALID = list(range(4, 32)) + list(range(33, 61))  # Layout::C6_HT20_NATURAL
WINDOW = 50


def rows(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            v = list(map(int, line.strip().split(",")[3:3 + 128]))
            out.append([math.hypot(v[2 * k + 1], v[2 * k]) for k in VALID])  # (real, imag)
    return out


def normalised(rows_):
    """Each frame's amplitudes divided by that frame's mean (the gain cancels)."""
    out = []
    for r in rows_:
        m = sum(r) / len(r)
        out.append([a / m for a in r] if m else list(r))
    return out


def wander(rows_):
    out = []
    for n in range(WINDOW - 1, len(rows_)):
        win = rows_[n - WINDOW + 1:n + 1]
        cvs = []
        for sc in range(len(VALID)):
            col = [r[sc] for r in win]
            m = sum(col) / WINDOW
            if m == 0:
                continue
            var = max(sum(x * x for x in col) / WINDOW - m * m, 0.0)
            cvs.append(1000.0 * math.sqrt(var) / m)
        out.append(sum(cvs) / len(cvs) if cvs else 0.0)
    return out


def main():
    for name in ("c6_empty_room_iter1", "c6_walking_person_iter1"):
        raw = rows(os.path.join(FIX, name + ".csv"))
        for suffix, series in ((".wander.txt", raw), (".nwander.txt", normalised(raw))):
            ws = wander(series)
            golden = os.path.join(FIX, name + suffix)
            with open(golden, "w", encoding="utf-8", newline="\n") as f:
                f.write("# float %swander (permille) per judged frame, window %d, from tools/csi_wander_oracle.py\n"
                        % ("gain-normalised " if suffix == ".nwander.txt" else "", WINDOW))
                for w in ws:
                    f.write("%.3f\n" % w)
            print("wrote", golden, len(ws), "values; p50 %.1f max %.1f" % (sorted(ws)[len(ws) // 2], max(ws)))


if __name__ == "__main__":
    main()

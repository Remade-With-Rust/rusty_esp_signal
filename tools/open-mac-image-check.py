"""E6's gate where signal's CI can run it: an open-MAC image transmits at
esp-radio's cap and carries none of esp-radio.

    python tools/open-mac-image-check.py ELF [--map MAP] [--allow-power QDBM]

Reads the ELF's symbol table (standard library only): the PHY init data's
fourteen per-rate power limits must be at most 20 quarter dBm (5 dBm, the
cap esp-radio sets; `--allow-power` names another cap a firmware chose with
`ESP_PHY_CONFIG_PHY_MAX_TX_POWER`), and no symbol of esp-radio's blob API
(`esp_wifi_*`, `esp_now_*`, `ieee80211_*`, `ppTxPkt`) may be defined. With
`--map` (the linker map of the same link, GNU ld's), every C archive that
put bytes in the image is listed by member, and anything but `libphy.a`
fails. The umbrella's `tools/e6-phy.py` is the full gate (the census's
classification, and the PHY functions our code calls).
"""
import re
import struct
import sys

CAP = 20
ACCEPTED = {"libphy.a"}
# an input section from an archive member: its address, its size, the
# archive and the member (a long section name puts these on the next line)
MAP_PIECE = re.compile(r"0x[0-9a-f]+\s+0x([0-9a-f]+)\s+(\S+\.a)\(([^)]+)\)")
FORBIDDEN_PREFIXES = ("esp_wifi_", "esp_now_", "ieee80211_")
FORBIDDEN = {"ppTxPkt", "ppRxPkt", "wDev_ProcessFiq"}


def symbols(path):
    b = open(path, "rb").read()
    assert b[:4] == b"\x7fELF" and b[4] == 1, "a 32-bit ELF"
    shoff, = struct.unpack_from("<I", b, 0x20)
    shentsize, shnum, = struct.unpack_from("<HH", b, 0x2E)
    secs = []
    for i in range(shnum):
        name, kind, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
            "<IIIIIIIIII", b, shoff + i * shentsize)
        secs.append(dict(kind=kind, addr=addr, off=off, size=size, link=link, entsize=entsize))
    out = []
    for s in secs:
        if s["kind"] != 2:  # SHT_SYMTAB
            continue
        strtab = secs[s["link"]]["off"]
        for j in range(s["size"] // 16):
            name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", b, s["off"] + j * 16)
            end = b.index(b"\0", strtab + name)
            out.append((b[strtab + name:end].decode("utf-8", "replace"), value, size, shndx))
    return b, secs, out


def archives(map_path):
    """{archive: {member: bytes}} for the C archives in a GNU ld map."""
    got = {}
    started = False
    for line in open(map_path, encoding="utf-8", errors="replace"):
        if not started:
            started = line.startswith("Linker script and memory map")
            continue
        m = MAP_PIECE.search(line)
        if not m:
            continue
        size = int(m.group(1), 16)
        name = m.group(2).replace("\\", "/").rsplit("/", 1)[-1]
        if size:
            got.setdefault(name, {}).setdefault(m.group(3), 0)
            got[name][m.group(3)] += size
    return got


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cap = int(sys.argv[sys.argv.index("--allow-power") + 1]) if "--allow-power" in sys.argv else CAP
    b, secs, syms = symbols(sys.argv[1])
    failed = []
    table = [s for s in syms if "PHY_INIT_DATA_DEFAULT" in s[0] and s[2] >= 16]
    if not table:
        failed.append("the PHY's init data is not in the image")
    else:
        name, value, size, shndx = table[0]
        sec = secs[shndx]
        limits = list(b[sec["off"] + value - sec["addr"] + 2:][:14])
        print(f"transmit power limits (quarter dBm): {limits}")
        if max(limits) > cap:
            failed.append(f"a rate above the cap: {max(limits)} > {cap}")
    # defined in the image's own sections: the linker script names every
    # mask-ROM routine as an absolute symbol (SHN_ABS), present or not
    blob = sorted({n for n, value, size, shndx in syms
                   if 0 < shndx < len(secs) and (n.startswith(FORBIDDEN_PREFIXES) or n in FORBIDDEN)})
    if blob:
        failed.append(f"esp-radio's blob API is in the image: {', '.join(blob[:8])}")
    if "--map" in sys.argv:
        got = archives(sys.argv[sys.argv.index("--map") + 1])
        for name in sorted(got):
            total = sum(got[name].values())
            print(f"C archive {name}: {len(got[name])} members, {total:,} B")
        extra = sorted(set(got) - ACCEPTED)
        if extra:
            failed.append(f"C beside the PHY: {', '.join(extra)}")
        if "libphy.a" not in got:
            failed.append("no libphy.a in the map: is this the open MAC's image?")
    if failed:
        sys.exit("open-MAC image check FAILED: " + "; ".join(failed))
    print(f"open-MAC image check: at most {cap / 4:g} dBm, no esp-radio"
          + (", no C but the PHY" if "--map" in sys.argv else ""))


if __name__ == "__main__":
    main()

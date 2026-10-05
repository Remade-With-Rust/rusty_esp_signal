"""E6's gate where signal's CI can run it: an open-MAC image transmits at
esp-radio's cap and carries none of esp-radio.

    python tools/open-mac-image-check.py ELF [--allow-power QDBM]

Reads the ELF's symbol table (standard library only): the PHY init data's
fourteen per-rate power limits must be at most 20 quarter dBm (5 dBm, the
cap esp-radio sets; `--allow-power` names another cap a firmware chose with
`ESP_PHY_CONFIG_PHY_MAX_TX_POWER`), and no symbol of esp-radio's blob API
(`esp_wifi_*`, `esp_now_*`, `ieee80211_*`, `ppTxPkt`) may be defined. The
umbrella's `tools/e6-phy.py` is the full gate (archives and members from the
linker map, the PHY functions our code calls); this is the part that needs
nothing but the image.
"""
import struct
import sys

CAP = 20
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
    if failed:
        sys.exit("open-MAC image check FAILED: " + "; ".join(failed))
    print(f"open-MAC image check: at most {cap / 4:g} dBm, no esp-radio")


if __name__ == "__main__":
    main()

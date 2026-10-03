"""The open MAC's host tests (experiments plan E1): upstream's S3
regressions (opensensor/esp-wifi-hal f159fcf, docs/esp32s3/tests/
run-rust-tests.sh), run against the vendored and ported sources on this
machine. No board, no SDK.

    python tools/open-mac-host-tests.py

What runs, as upstream's script runs it:

- the C regressions of the reviewed C reference (`test_hal.c`, which
  includes `src/hal_mac.c`);
- `rust_init.rs`: the Rust MAC initialization (`s3_mac.rs`) against that C
  reference, register access by register access;
- `rustc --test` on four of the crate's own sources (`s3_mac_helpers.rs`,
  `s3_phy.rs`, `ht20.rs`, `rx.rs`);
- `rust_dma.rs`: the DMA list, S3 configuration (the C3 variant is
  upstream's and not ours).

On Windows the C is compiled with clang (LLVM's), and `host-tests/win/`
supplies the one POSIX call the C test makes (`mmap` below 4 GiB). The
upstream files are unchanged.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR = os.path.normpath(os.path.join(HERE, "..", "vendor", "open-mac"))
TESTS = os.path.join(VENDOR, "host-tests", "esp32s3", "tests")
SRC = os.path.join(VENDOR, "esp-wifi-hal", "src")
WIN = os.path.join(VENDOR, "host-tests", "win")


def clang():
    for c in ("clang", "cc", "C:/Program Files/LLVM/bin/clang.exe"):
        found = shutil.which(c) or (c if os.path.exists(c) else None)
        if found:
            return found
    raise SystemExit("no C compiler (clang or cc) for the C reference")


def run(cmd, what):
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode:
        print(out[-3000:])
        raise SystemExit(f"FAILED: {what}")
    return out


def main():
    cc = clang()
    windows = os.name == "nt"
    cflags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", f"-I{TESTS}"]
    if windows:
        # the shim first; MSVC's CRT spells some POSIX names with underscores
        cflags = cflags[:-1] + [f"-I{WIN}", f"-I{TESTS}", "-D_CRT_SECURE_NO_WARNINGS",
                                "-Wno-deprecated-declarations"]
    exe = ".exe" if windows else ""
    results = []
    with tempfile.TemporaryDirectory() as out:
        # the C regressions of the reference
        c_test = os.path.join(out, "c-regressions" + exe)
        run([cc, *cflags, os.path.join(TESTS, "test_hal.c"), "-o", c_test], "compile test_hal.c")
        results.append(("C reference (test_hal.c)", run([c_test], "test_hal.c")))

        # the Rust initialization against the C reference
        obj = os.path.join(out, "init-reference" + (".obj" if windows else ".o"))
        run([cc, *cflags, "-c", os.path.join(TESTS, "rust_init_reference.c"), "-o", obj],
            "compile rust_init_reference.c")
        t = os.path.join(out, "rust-init" + exe)
        run(["rustc", "+stable", "--edition", "2024", "--test", os.path.join(TESTS, "rust_init.rs"),
             "-C", f"link-arg={obj}", "-o", t], "build rust_init.rs")
        results.append(("Rust MAC init vs the C reference (rust_init.rs)", run([t], "rust_init.rs")))

        for name in ("s3_mac_helpers", "s3_phy", "ht20", "rx"):
            t = os.path.join(out, name + exe)
            run(["rustc", "+stable", "--edition", "2024", "--test", os.path.join(SRC, name + ".rs"),
                 "-o", t], f"build {name}.rs")
            results.append((f"{name}.rs", run([t], f"{name}.rs")))

        t = os.path.join(out, "rust-dma" + exe)
        run(["rustc", "+stable", "--edition", "2024", "--test", "--cfg", 'feature="esp32s3"',
             os.path.join(TESTS, "rust_dma.rs"), "-o", t], "build rust_dma.rs")
        results.append(("DMA list, S3 (rust_dma.rs)", run([t], "rust_dma.rs")))

    for what, text in results:
        lines = [l for l in text.splitlines() if l.startswith(("test result", "PASS"))]
        print(f"{what}: " + ("; ".join(lines[-3:]) if lines else "ran"))
    print("all host tests passed")


if __name__ == "__main__":
    sys.exit(main())

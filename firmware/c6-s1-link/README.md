# `c6-s1-link` — the S1 kill test, self-driving

One source, two images. The same code built twice with one feature different,
so the two halves of the link are comparable by construction:

```
cargo build --release --no-default-features --features role-responder
cargo build --release --no-default-features --features role-initiator
```

Track B, stable RISC-V — no espup, no Xtensa toolchain. The C6 target is
`riscv32imac-unknown-none-elf`.

## What it asserts

The S1 row: **1,000 frames each way over an mID-authenticated ESP-NOW link;
loss, replay-rejected and bad-tag counters recorded; a third unadopted
identity cannot join.**

Counters come from `Session::counters()` — the core's own judgement — not
from this firmware restating them.

## Two boards, not three

The row reads "a third unadopted **C6** cannot join", which sounds like three
boards. What must be refused is an unadopted **identity**, not a particular
piece of silicon. After the frame run the initiator mints a second
`DeviceKey` the responder has never seen and tries again; the responder pins
the first DID it accepted and refuses the rest.

That is the stronger test: same radio, same antenna, same distance. Only the
identity differs, so a refusal cannot be put down to range or interference.

## Every wait is bounded

`EspNowLink::recv` awaits a datagram, and a lost frame would otherwise hang
the run — which on someone else's bench is indistinguishable from a crash.
Every receive is wrapped in a timeout and a timeout is **counted as loss**
rather than being fatal. A lossy run still produces numbers, and numbers are
what S1 is for.

## Chips: the harness is not only for the C6

`esp-radio` carries ESP-NOW on the esp32, esp32s3 and esp32c6 alike, and
`rusty_esp_signal-esp` takes its chip feature from the firmware rather than
pinning one — so the only per-chip surface is the `chip-*` feature block.

| chip | toolchain | target | state |
|---|---|---|---|
| **C6** (the S1 row) | stable | `riscv32imac-unknown-none-elf` | builds |
| **S3** (XIAO) | `esp` | `xtensa-esp32s3-none-elf` | **builds and RUNS** — reaches `S1 waiting for peer`, DID minted |
| **ESP32** (the CAM) | `esp` | `xtensa-esp32-none-elf` | **builds**; never reached on hardware — see below |

The ESP32 link error was `Main stack is smaller than 8192 bytes`, which reads
like a stack setting and is a **heap** one: the assert
(`ESP_HAL_CONFIG_ENSURE_MAIN_STACK_MINIMUM`, in esp-hal's `ld/sections/stack.x`)
compares the stack the linker could *fit* against a minimum, and the 96 KB
`heap_allocator!` was consuming the ESP32's much smaller contiguous DRAM. The
heap is chip-dependent now: 32 KB there, 96 KB elsewhere.

**The AI-Thinker ESP32-CAM was not reachable on this bench.** Its CH340
enumerated (COM3, port opens, nothing holding it) but the board never
responded to anything: no auto-reset (DTR/RTS toggle produced zero bytes,
so those lines are not wired to EN/IO0 on this adapter), no response with
`--before no-reset` after a manual IO0-to-GND power-cycle, and no boot
output at all while listening at 115200. No data path was ever established,
so the failure is upstream of anything this firmware controls. Recorded
rather than retried: a second XIAO S3 pairs with the first immediately and
carries none of the CAM's quirks (no native USB, no auto-reset, brownouts
on 3.3V once the radio starts).

```
cargo +esp build --release --target xtensa-esp32s3-none-elf       --no-default-features --features role-responder,chip-esp32s3
```

**Why this matters more than portability.** S1 is a C6 row and an S3 run is
not S1. But without it, a colleague with two new boards would be the first
person ever to execute this code on hardware — and if it fell over, they
would burn a day and we would learn nothing about S1. Proving the bring-up
on a board we own reduces their run to "only the chip differs".

What the S3 run establishes: boot, heap, TRNG, `DeviceKey` generation,
Wi-Fi station bring-up, the ESP-NOW split and the link. What it cannot:
the handshake, the frame loop, the counters and the rejection arm all need a
second radio.

## Running it

Reset the **responder first**, then the initiator. Both print `S1 ...` lines
and finish with one `RESULT:`.

The runbook written for someone else's bench — what to buy, what to flash,
what to send back — is `docs/plans/s1-c6-runbook.md` in the Janus umbrella.

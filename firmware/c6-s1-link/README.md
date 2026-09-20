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

## Running it

Reset the **responder first**, then the initiator. Both print `S1 ...` lines
and finish with one `RESULT:`.

The runbook written for someone else's bench — what to buy, what to flash,
what to send back — is `docs/plans/s1-c6-runbook.md` in the Janus umbrella.

# c6-mesh-node-kairos — the K5 comparison arm (not buildable yet)

This directory is the **sibling firmware dir** Kairos K5 calls for: the mesh
node rebuilt on `rusty_rtos` while `../c6-mesh-node` stays on `esp-rtos` as
the comparison arm. A before/after with only an "after" is not a comparison,
so the two live side by side rather than one replacing the other.

**It is empty on purpose.** Writing the firmware now would produce something
that cannot build, and a firmware that cannot build is worse than an absent
one because it looks like progress.

## What it is waiting for

`esp-radio` reaches a scheduler through the `esp-radio-rtos-driver`
interface. `rusty_rtos_port-riscv` **documents** that interface and does not
implement it — that is Kairos's half of K5. Until it lands, this firmware
has no kernel to run on, because the mesh node's whole job is ESP-NOW and
ESP-NOW is the radio blob.

Tracked from the Janus side in `janus/docs/plans/k5-prep.md`; the contract
written for the Kairos side is `docs/plans/janus-rtos.md` in the Kairos
umbrella.

## What is already done so this is a port problem, not a dependency problem

- `../c6-mesh-node` runs on esp-hal 1.2.0 / esp-radio 1.0.0-beta.1 /
  esp-rtos 0.4.0 — the companion set `esp-rtos` 0.4 requires, and therefore
  the set the Kairos port has to sit in.
- `rusty_esp_rtos` (in `rusty_esp_core`) pins the ports and compiles against
  the published 0.1.0 releases on both `xtensa-esp32s3-none-elf` and
  `riscv32imac-unknown-none-elf`.
- The Xtensa half of K5 is **already proven on silicon** — see
  `rusty_esp_mid/firmware/xiao-s3-keys`, feature `kairos`.

## And the thing that blocks the kill test, which is not Kairos's fault

K5's kill test is Janus **S1**: two C6s, ESP-NOW authenticated link, 1 000
frames each way, counters, a third C6 refused — matching the numbers from
`esp-rtos`. Those numbers **do not exist yet**. S1 has to be taken on
`esp-rtos` first, on two C6s, and neither is on the bench.

So the order is fixed: S1 on esp-rtos → the driver in `-riscv` → this
firmware → S1 again.

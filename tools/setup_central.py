"""A scripted BLE central for the setup session (enc-ble M6/M7): the browser's
half in pure Python (`setup_v1.Prover`, independent of the Rust it tests)
over the laptop's Bluetooth with `bleak`.

    python tools/setup_central.py SCENARIO --code-file FILE [--expect-did DID] [--name NAME]

The code is read from FILE and never printed. Each scenario prints one JSON
line: what was sent, what came back, the verdict, and the central's round
trip per message (the device's own time is in its serial log).

Scenarios:
    discover        read `discover`: the DID, the window, the attempts left
    ready           unlock and open Ready: the networks the device scanned
    provision       a network (--ssid, the passphrase from --psk-env VAR, never
                    printed), sealed; then the join watched on `status`
    wrong-code      a session with a wrong code: refused at Reply, nothing applied
    wrong-device    a session expecting another DID: refused before any write
    session         a whole session (a name, and a fresh verifier for the SAME
                    code, which makes Settings a long write), recorded for replay
    replay          the recorded writes of `session` written again, in order
    second-writer   while a session is in flight: is anyone else let in?
    lockout         wrong codes until the device closes its window

Needs bleak (a venv: F:/coding/janus-scratch/venv-ble).
"""
import argparse
import asyncio
import json
import os
import sys
import time

from bleak import BleakClient, BleakScanner

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import setup_v1 as v1  # noqa: E402

JANUS = "4a616e75-7300-4d41-5441-00000000{:04x}"
SERVICE = JANUS.format(0x0100)
STATUS = JANUS.format(0x0102)
SETUP = JANUS.format(0x0104)
DISCOVER = JANUS.format(0x0105)
ERRORS = {0x01: "Malformed", 0x02: "Version", 0x03: "Busy", 0x04: "WindowClosed", 0x05: "Backoff",
          0x06: "NoVerifier", 0x07: "Order", 0x08: "Confirm", 0x09: "Seal", 0x20: "BadNetwork",
          0x21: "BadName", 0x22: "BadMaker", 0x23: "BadVerifier", 0x24: "BadAdoption",
          0x25: "UnknownTag", 0x26: "StoreFailed"}
PHASES = {0: "Unprovisioned", 1: "Connecting", 2: "Connected", 3: "Backoff", 4: "Fallback"}
RECORDING = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "setup-central-recording.json")


def did_of(devpub):
    """did:mata of a compressed key: base58 (bitcoin alphabet) of the 33
    bytes, as rusty_esp_mid_core::did writes it."""
    raw = devpub
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(raw, "big")
    out = ""
    while num:
        num, r = divmod(num, 58)
        out = alphabet[r] + out
    out = "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out
    return "did:mata:" + out


def parse_scan(scan):
    """The scan list's TLV (tag 1 name, 3 RSSI, 4 secured) as (name, dBm, secured)."""
    nets, i, cur = [], 0, None
    while i + 2 <= len(scan):
        tag, n = scan[i], scan[i + 1]
        val = scan[i + 2:i + 2 + n]
        if tag == 1:
            cur = [val.decode("utf-8", "replace"), None, False]
            nets.append(cur)
        elif tag == 3 and cur and n == 1:
            cur[1] = int.from_bytes(val, "big", signed=True)
        elif tag == 4 and cur and n == 1:
            cur[2] = val[0] != 0
        i += 2 + n
    return [tuple(x) for x in nets]


def error_of(msg):
    if len(msg) == 3 and msg[1] == 0x7F:
        return ERRORS.get(msg[2], hex(msg[2]))
    return None


class Link:
    """One connection: `exchange` writes a message to `setup`, waits for the
    header's notification, and reads the answer."""

    def __init__(self, client):
        self.client = client
        self.notified = asyncio.Event()
        self.trips = []

    async def open(self):
        await self.client.start_notify(SETUP, lambda _c, _d: self.notified.set())

    async def discover(self):
        return bytes(await self.client.read_gatt_char(DISCOVER))

    async def exchange(self, message, label):
        self.notified.clear()
        t0 = time.perf_counter()
        await self.client.write_gatt_char(SETUP, message, response=True)
        await asyncio.wait_for(self.notified.wait(), 30)
        answer = bytes(await self.client.read_gatt_char(SETUP))
        self.trips.append({"msg": label, "bytes_out": len(message), "bytes_in": len(answer),
                           "round_trip_ms": round((time.perf_counter() - t0) * 1000, 1)})
        return answer


async def find(name, timeout=30):
    device = await BleakScanner.find_device_by_filter(
        lambda d, ad: SERVICE in [u.lower() for u in ad.service_uuids] and (not name or d.name == name),
        timeout=timeout)
    return device


async def connected(args):
    """Find, connect, subscribe. A failure after the connection disconnects
    before it is raised: Windows otherwise keeps the link open, and a device
    that holds one peer at a time stops advertising (seen on C13, M6). One
    retry, since Windows' first service discovery can come back short."""
    for attempt in (1, 2):
        device = await find(args.name)
        if device is None:
            raise SystemExit(json.dumps({"verdict": "not found", "note": "nothing advertising the provisioning service"}))
        client = BleakClient(device)
        await client.connect()
        link = Link(client)
        try:
            await link.open()
            return device, client, link
        except Exception:
            await client.disconnect()
            if attempt == 2:
                raise
            await asyncio.sleep(2)


def code(args):
    with open(args.code_file, encoding="utf-8") as f:
        return f.read().strip()


def offer(discover):
    d = v1.read_discover(discover)
    return {"did": did_of(d["devpub"]), "takes_code": bool(d["suites"] & 1),
            "window_s": None if d["window_s"] == 0xFFFF else d["window_s"], "attempts_left": d["attempts_left"],
            "iterations": d["iterations"]}


async def scenario(args):
    out = {"scenario": args.scenario}
    if args.scenario == "wrong-device":
        # the page's check: the DID it was sent to set up against Discover's
        device, client, link = await connected(args)
        try:
            o = offer(await link.discover())
            # a device that is not this one: the curve's generator as a key
            other = did_of(v1.compressed(v1.G))
            out.update(offer=o, expected=other,
                       verdict="refused before any write" if o["did"] != other else "MATCHED")
        finally:
            await client.disconnect()
        return out

    device, client, link = await connected(args)
    out["mtu"] = getattr(client, "mtu_size", None)
    try:
        disc = await link.discover()
        out["offer"] = offer(disc)
        if args.expect_did and out["offer"]["did"] != args.expect_did:
            out["verdict"] = "another device"
            return out
        if args.scenario == "discover":
            out["verdict"] = "read"
            return out

        if args.scenario in ("wrong-code", "lockout"):
            attempts = []
            while True:
                pr = v1.Prover(disc, "AAAAA-AAAAA")
                reply = await link.exchange(pr.start(), "Start")
                err = error_of(reply)
                if err:
                    attempts.append({"start": err})
                    if err == "Backoff":
                        await asyncio.sleep(2)
                        continue
                    break
                try:
                    pr.reply(reply)
                    attempts.append({"reply": "ACCEPTED A WRONG CODE"})
                    break
                except ValueError as e:
                    attempts.append({"reply": str(e)})
                if args.scenario == "wrong-code":
                    break
                # the device keeps the session until the carrier closes
                await client.disconnect()
                _, client, link = await connected(args)
                disc = await link.discover()
                attempts[-1]["attempts_left_after"] = v1.read_discover(disc)["attempts_left"]
                if len(attempts) > 12:
                    break
            out["attempts"] = attempts
            out["verdict"] = attempts[-1].get("start") or attempts[-1].get("reply")
            return out

        if args.scenario == "ready":
            # unlock and open Ready: the networks the device sent, sealed;
            # nothing applied (the session ends with the connection)
            pr = v1.Prover(disc, code(args))
            reply = await link.exchange(pr.start(), "Start")
            ready = await link.exchange(pr.reply(reply), "Confirm")
            phase, scan = pr.open_ready(ready)
            out["ready"] = {"phase": phase, "scan_bytes": len(scan), "networks": parse_scan(scan)}
            out["verdict"] = f"{len(out['ready']['networks'])} networks in Ready"
            return out

        if args.scenario == "provision":
            # a network, sealed: the passphrase from the environment, never
            # printed; then the join watched on `status`
            psk = os.environ.get(args.psk_env or "", "")
            if not args.ssid or not psk:
                raise SystemExit(json.dumps({"verdict": "refused", "note": "--ssid and --psk-env (a set variable) are needed"}))
            phases = []
            t0 = time.perf_counter()
            await link.client.start_notify(STATUS, lambda _c, d: phases.append(
                (round(time.perf_counter() - t0, 1), PHASES.get(bytes(d)[0], bytes(d)[0]))))
            pr = v1.Prover(disc, code(args))
            reply = await link.exchange(pr.start(), "Start")
            ready = await link.exchange(pr.reply(reply), "Confirm")
            phase, scan = pr.open_ready(ready)
            out["ready"] = {"phase": PHASES.get(phase, phase), "networks": len(parse_scan(scan))}
            record = v1.record_tlv(0x01, args.ssid.encode()) + v1.record_tlv(0x02, psk.encode())
            if args.set_name:
                record += v1.record_tlv(0x03, args.set_name.encode())
            t0 = time.perf_counter()
            result = await link.exchange(pr.seal_settings(record), "Settings")
            record = b""
            code_byte, phase = pr.open_result(result)
            out["result"] = {"code": "Applied" if code_byte == 0 else ERRORS.get(code_byte, hex(code_byte)),
                             "phase": PHASES.get(phase, phase)}
            if code_byte == 0:
                end = time.perf_counter() + args.watch
                while time.perf_counter() < end and link.client.is_connected:
                    if phases and phases[-1][1] in ("Connected", "Fallback"):
                        break
                    await asyncio.sleep(0.2)
            out["status"] = phases
            out["verdict"] = phases[-1][1] if phases else out["result"]["code"]
            return out

        if args.scenario == "session":
            pr = v1.Prover(disc, code(args))
            recorded = {"start": pr.start().hex()}
            reply = await link.exchange(pr.start(), "Start")
            confirm = pr.reply(reply)
            recorded["confirm"] = confirm.hex()
            ready = await link.exchange(confirm, "Confirm")
            phase, scan = pr.open_ready(ready)
            out["ready"] = {"phase": phase, "scan_bytes": len(scan)}
            # a fresh verifier for the same code (a new salt): the code still
            # works, and the record outgrows one ATT packet (a long write)
            d = v1.read_discover(disc)
            salt = os.urandom(16)
            w0, w1 = v1.derive(v1.normalise(code(args)), salt, d["iterations"])
            setup_v = bytes([1]) + v1.i2b(w0) + v1.enc(v1.mul(w1, v1.G)) + salt + d["iterations"].to_bytes(4, "big")
            # 64 bytes, the most a name may be: with the maker and the verifier
            # the sealed Settings is 264 bytes, past one packet at MTU 247
            name = (args.set_name or "c13 m6 bench: a long write of the setup session's Settings record").encode()[:64]
            maker = did_of(v1.read_discover(disc)["devpub"]).encode()
            record = (v1.record_tlv(0x03, name) + v1.record_tlv(0x04, maker) + v1.record_tlv(0x10, setup_v))
            sealed = pr.seal_settings(record)
            recorded["settings"] = sealed.hex()
            result = await link.exchange(sealed, "Settings")
            code_byte, phase = pr.open_result(result)
            out["settings_bytes"] = len(sealed)
            out["result"] = {"code": "Applied" if code_byte == 0 else ERRORS.get(code_byte, hex(code_byte)), "phase": phase}
            out["verdict"] = out["result"]["code"]
            os.makedirs(os.path.dirname(RECORDING), exist_ok=True)
            with open(RECORDING + ".tmp", "w", encoding="utf-8") as f:
                json.dump(recorded, f)
            os.replace(RECORDING + ".tmp", RECORDING)
            return out

        if args.scenario == "replay":
            with open(RECORDING, encoding="utf-8") as f:
                rec = json.load(f)
            steps = []
            reply = await link.exchange(bytes.fromhex(rec["start"]), "Start (replayed)")
            steps.append({"start": error_of(reply) or "a Reply (fresh shareV)"})
            if not error_of(reply):
                answer = await link.exchange(bytes.fromhex(rec["confirm"]), "Confirm (replayed)")
                steps.append({"confirm": error_of(answer) or "ACCEPTED"})
                answer = await link.exchange(bytes.fromhex(rec["settings"]), "Settings (replayed)")
                steps.append({"settings": error_of(answer) or "ACCEPTED"})
            out["steps"] = steps
            out["verdict"] = "refused" if all(v not in ("ACCEPTED",) for s in steps for v in s.values()) else "REPLAY ACCEPTED"
            return out

        if args.scenario == "second-writer":
            pr = v1.Prover(disc, code(args))
            reply = await link.exchange(pr.start(), "Start")
            confirm = pr.reply(reply)
            # a second session on the same connection: Busy, the first undisturbed
            second = await link.exchange(v1.Prover(disc, code(args)).start(), "Start (second)")
            out["second_start"] = error_of(second) or "ANSWERED"
            # a second central: the device stops advertising while connected
            seen = await find(args.name, timeout=8)
            out["advertising_while_connected"] = seen is not None
            # the first session still completes its Confirm
            ready = await link.exchange(confirm, "Confirm (first)")
            out["first_session_after"] = error_of(ready) or "Ready"
            out["verdict"] = ("refused" if out["second_start"] == "Busy" and not out["advertising_while_connected"]
                              and out["first_session_after"] == "Ready" else "NOT AS SPECIFIED")
            return out
        raise SystemExit(f"unknown scenario {args.scenario}")
    finally:
        out["trips"] = link.trips
        if client.is_connected:
            await client.disconnect()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scenario")
    ap.add_argument("--code-file", required=False)
    ap.add_argument("--expect-did")
    ap.add_argument("--name", default="janus-s3", help="the advertised name ('' for any)")
    ap.add_argument("--set-name", help="the device name the session sets")
    ap.add_argument("--ssid", help="provision: the network's name")
    ap.add_argument("--psk-env", help="provision: the environment variable holding its passphrase")
    ap.add_argument("--watch", type=float, default=40, help="provision: seconds to watch the join")
    args = ap.parse_args()
    if args.scenario in ("session", "second-writer", "ready", "provision") and not args.code_file:
        ap.error("this scenario needs --code-file")
    out = asyncio.run(scenario(args))
    out["at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    print(json.dumps(out))


if __name__ == "__main__":
    main()

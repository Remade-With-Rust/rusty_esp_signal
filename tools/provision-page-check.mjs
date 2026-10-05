// enc-ble M5: docs/provision.html completes a setup session against the
// device half, on the host.
//
// The page's own inlined wasm and its `session` script run as they stand;
// the device is rusty_esp_signal-web's `sim` build, which is the firmware's
// GATT router (`provision::Provisioner`) over in-memory stores. The fake Web
// Bluetooth characteristics move bytes and nothing else, the way a carrier is
// trusted with nothing.
//
//     python tools/build-provision-page.py && node tools/provision-page-check.mjs

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const target = process.env.CARGO_TARGET_DIR ?? path.join(root, 'target');
const page = readFileSync(path.join(root, 'docs', 'provision.html'), 'utf8');
const script = (id) => {
  const m = page.match(new RegExp(`<script id="${id}">([\\s\\S]*?)</script>`));
  assert.ok(m, `the page has a <script id="${id}">`);
  return m[1];
};

// the page's wasm and session, in one scope, as the browser runs them
const api = new Function(
  `${script('setup-wasm')}\n${script('session')}\n` +
    'return { wasm_bindgen, PAGE_WASM, openSetup, readOffer, openPage, readPageOffer, SESSION_HEADER, unlock, sendSettings, provision, parseScan, CHAR_STATUS, CHAR_SETUP, CHAR_DISCOVER };',
)();
assert.ok(api.PAGE_WASM.length > 0, 'the page carries its wasm: run tools/build-provision-page.py');
await api.wasm_bindgen({ module_or_path: Buffer.from(api.PAGE_WASM, 'base64') });

const { SimDevice, SimPageDevice } = createRequire(import.meta.url)(path.join(target, 'provision-sim', 'rusty_esp_signal_web.js'));
const [STATUS, SETUP, DISCOVER] = SimDevice.uuids();
assert.deepEqual([STATUS, SETUP, DISCOVER], [api.CHAR_STATUS, api.CHAR_SETUP, api.CHAR_DISCOVER], 'the page names the table the router serves');

/** A Web Bluetooth characteristic over the device: bytes in, bytes out. */
class FakeCharacteristic extends EventTarget {
  constructor(device, uuid, { notifyFirst = false } = {}) {
    super();
    this.device = device;
    this.uuid = uuid;
    this.notifyFirst = notifyFirst;
    this.subscribed = false;
    this.writes = 0;
  }
  async startNotifications() { this.subscribed = true; return this; }
  async readValue() {
    const b = this.device.read(this.uuid);
    return new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  async writeValueWithResponse(value) {
    this.writes += 1;
    const header = this.device.write(this.uuid, new Uint8Array(value));
    if (!header.length || !this.subscribed) return;
    const notify = () => {
      this.value = new DataView(header.buffer, header.byteOffset, header.byteLength);
      this.dispatchEvent(new Event('characteristicvaluechanged'));
    };
    // a stack may deliver the notification before or after the write's response
    if (this.notifyFirst) notify(); else setTimeout(notify, 0);
  }
}

const CODE = '7KXQ3-M9PRT';
const results = [];
async function test(name, body) {
  try {
    await body();
    results.push(['ok', name]);
  } catch (e) {
    results.push(['FAILED', name, e]);
  }
}

async function connect(device, options) {
  const setup = new FakeCharacteristic(device, SETUP, options);
  const exchange = await api.openSetup(setup);
  const { bytes, offer } = await api.readOffer(new FakeCharacteristic(device, DISCOVER));
  return { setup, exchange, bytes, offer };
}

for (const notifyFirst of [false, true]) {
  await test(`a session provisions the device (notification ${notifyFirst ? 'before' : 'after'} the write's response)`, async () => {
    const device = new SimDevice(CODE, 1000, 'home,cafe');
    const { setup, exchange, bytes, offer } = await connect(device, { notifyFirst });
    assert.equal(offer.did, device.did);
    assert.equal(offer.takes_code, true);
    assert.equal(offer.window_s, -1, 'unprovisioned: open until it is');
    assert.equal(offer.attempts_left, 5);

    // typed as a person types it: lower case, no hyphen
    const session = await api.unlock(exchange, bytes, '7kxq3m9prt', device.did);
    assert.deepEqual(api.parseScan(session.scan).map((n) => n.ssid), ['home', 'cafe'], 'the networks arrive sealed in Ready');
    assert.equal(session.phase, 0);

    const phase = await api.sendSettings(exchange, session, 'home', 'a-home-passphrase', 'porch camera');
    assert.equal(phase, 0, 'Result carries the phase the record was applied in');
    const status = await new FakeCharacteristic(device, STATUS).readValue();
    assert.equal(status.getUint8(0), 1, 'then status moves to Connecting');
    assert.equal(device.network(), 'home');
    assert.ok(device.passphrase_is('a-home-passphrase'));
    assert.equal(device.action(), 'Connect');
    assert.equal(setup.writes, 3, 'Start, Confirm, Settings');
  });
}

await test('a wrong code fails at Reply; after the peer leaves and the backoff the right one works', async () => {
  const device = new SimDevice(CODE, 1000, '');
  let c = await connect(device);
  await assert.rejects(api.unlock(c.exchange, c.bytes, 'AAAAA-AAAAA', device.did), /code is wrong/);
  device.disconnect();
  device.advance_ms(2000);
  c = await connect(device);
  assert.equal(c.offer.attempts_left, 4, 'the wrong code cost one attempt');
  const session = await api.unlock(c.exchange, c.bytes, CODE, device.did);
  assert.deepEqual(api.parseScan(session.scan), []);
});

await test('another device is refused before a guess is spent', async () => {
  const device = new SimDevice(CODE, 1000, '');
  const other = new SimDevice(CODE, 1000, '');
  const c = await connect(device);
  const elsewhere = 'did:mata:29qcqKb5kMT529GSNgfcUU2gSf4bpd7EWUDEj2Mq7cb9J';
  assert.notEqual(elsewhere, device.did);
  await assert.rejects(api.unlock(c.exchange, c.bytes, CODE, elsewhere), /not the device you were sent/);
  await assert.rejects(api.unlock(c.exchange, c.bytes, 'hello', ''), /ten letters and digits/);
  assert.equal(c.setup.writes, 0, 'nothing reached the device');
  assert.equal((await connect(device)).offer.attempts_left, 5);
  void other;
});

await test('the settings are checked before they are sealed', async () => {
  const device = new SimDevice(CODE, 1000, '');
  const c = await connect(device);
  const session = await api.unlock(c.exchange, c.bytes, CODE, '');
  assert.throws(() => session.settings('home', 'short', ''), /8 to 63/);
  assert.throws(() => session.settings('home', '', ''), /both its name and its passphrase/);
  assert.throws(() => session.settings('', '', ''), /nothing to send/);
});

for (const idle_ms of [5_000, 61_000]) {
  await test(`Provision after ${idle_ms / 1000} s at the network form (the device drops a session idle for 60 s)`, async () => {
    const device = new SimDevice(CODE, 1000, 'home');
    const c = await connect(device);
    const session = await api.unlock(c.exchange, c.bytes, CODE, device.did);
    device.advance_ms(idle_ms);
    const phase = await api.provision(c.exchange, session, c.bytes, CODE, device.did, 'home', 'a-home-passphrase', '');
    assert.equal(phase, 0);
    assert.equal(device.network(), 'home');
    assert.equal(c.setup.writes, idle_ms > 60_000 ? 6 : 3, 'a fresh session only when the first expired');
  });
}

await test("a device's refusal comes back in words", async () => {
  const device = new SimDevice(CODE, 1000, '');
  const c = await connect(device);
  const session = await api.unlock(c.exchange, c.bytes, CODE, '');
  // a name over the device's 64-byte limit
  await assert.rejects(api.sendSettings(c.exchange, session, '', '', 'n'.repeat(65)), /refused its name/);
  assert.equal(device.network(), undefined);
});

await test('the page names no retired characteristic and never logs a passphrase', async () => {
  assert.ok(!page.includes('4a616e75-7300-4d41-5441-000000000101'), 'credentials is retired');
  assert.ok(!page.includes('4a616e75-7300-4d41-5441-000000000103'), 'scan is retired');
  assert.ok(!/log\([^)]*psk/i.test(page), 'no log line takes the passphrase');
});

// E7: the device's own page (protocol section 11.2). `fetch` is the page's
// own call; here it reaches SimPageDevice, which is the firmware's
// `setup::page` over in-memory stores. The status and the bytes come back as
// a server would send them, and nothing else.
function serve(device) {
  const seen = [];
  globalThis.fetch = async (url, init = {}) => {
    const method = init.method ?? 'GET';
    assert.ok(url.endsWith('/setup'), `the page asks for /setup, not ${url}`);
    let body;
    if (method === 'GET') body = device.get();
    else {
      const name = init.headers?.[api.SESSION_HEADER] ?? '';
      seen.push(name);
      body = device.post(name, new Uint8Array(init.body));
    }
    const status = device.last_status;
    return { status, ok: status === 200, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) };
  };
  return seen;
}

await test('page: a device is set up over its own page', async () => {
  const device = new SimPageDevice(CODE, 1000, 'bench-net,next-door');
  const names = serve(device);
  const { bytes, offer } = await api.readPageOffer('');
  assert.equal(offer.did, device.did);
  const exchange = api.openPage('');
  const session = await api.unlock(exchange, bytes, CODE, device.did, 'page');
  assert.deepEqual(api.parseScan(session.scan).map((n) => n.ssid), ['bench-net', 'next-door']);
  await api.provision(exchange, session, bytes, CODE, device.did, 'bench-net', 'example-pass-1', 'porch', 'page');
  assert.equal(device.network(), 'bench-net');
  assert.ok(device.passphrase_is('example-pass-1'));
  assert.ok(names.length >= 3 && names.every((n) => n === names[0] && /^[0-9a-f]{16}$/.test(n)),
    'one session name, sixteen hex digits, on every message');
});

await test('page: a second browser is Busy and the first goes on', async () => {
  const device = new SimPageDevice(CODE, 1000, 'bench-net');
  serve(device);
  const { bytes } = await api.readPageOffer('');
  const first = api.openPage('');
  const session = await api.unlock(first, bytes, CODE, '', 'page');
  const second = api.openPage('');
  await assert.rejects(api.unlock(second, bytes, CODE, '', 'page'), /another setup session/);
  await api.provision(first, session, bytes, CODE, '', 'bench-net', 'example-pass-1', '', 'page');
  assert.equal(device.network(), 'bench-net');
});

await test('page: a session computed for Bluetooth is refused on the page', async () => {
  const device = new SimPageDevice(CODE, 1000, 'bench-net');
  serve(device);
  const { bytes } = await api.readPageOffer('');
  await assert.rejects(api.unlock(api.openPage(''), bytes, CODE, '', 'ble'));
  assert.equal(device.network(), undefined);
});

await test('page: a wrong code fails, and nothing is applied', async () => {
  const device = new SimPageDevice(CODE, 1000, 'bench-net');
  serve(device);
  const { bytes } = await api.readPageOffer('');
  await assert.rejects(api.unlock(api.openPage(''), bytes, '8KXQ3-M9PRT', '', 'page'));
  assert.equal(device.network(), undefined);
});

let failed = 0;
for (const [verdict, name, e] of results) {
  console.log(`${verdict.padEnd(6)} ${name}`);
  if (e) { failed += 1; console.log(`       ${e.stack ?? e}`); }
}
console.log(`${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);

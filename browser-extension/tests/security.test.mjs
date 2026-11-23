import test from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { canonicalOrigin, sameOrigin } from '../dist/origin.js'
import { b64, unb64 } from '../dist/noise.js'

async function abi(random = (bytes) => { crypto.getRandomValues(bytes); return 1 }) {
  const wasm = await readFile(new URL('../dist/noise.wasm', import.meta.url))
  let api
  const instance = await WebAssembly.instantiate(wasm, { fluxlock: { random_fill(ptr, len) { return random(new Uint8Array(api.memory.buffer, ptr, len)) } } })
  api = instance.instance.exports
  const run = (op, bytes = new Uint8Array()) => {
    const pointer = api.input_ptr()
    new Uint8Array(api.memory.buffer, pointer, bytes.length).set(bytes)
    assert.equal(api.execute(op, bytes.length), 1)
    return new Uint8Array(api.memory.buffer, api.output_ptr(), api.output_len()).slice()
  }
  return { api, run }
}

test('WASM destroys pending state on oversized input and fails closed without entropy', async () => {
  const { api, run } = await abi()
  try {
    run(0, new Uint8Array(64).fill(1))
    assert.equal(api.output_len(), 32)
    assert.equal(api.execute(1, 65537), 0)
    assert.equal(api.output_len(), 0)
    assert.equal(api.execute(1, 0), 0, 'Oversized input must have destroyed the handshake')
  } finally { api.clear() }
  const failedRandom = await abi(() => 0)
  try {
    const pointer = failedRandom.api.input_ptr()
    new Uint8Array(failedRandom.api.memory.buffer, pointer, 64).fill(1)
    const initialized = failedRandom.api.execute(0, 64)
    // Snow may request ephemeral entropy at initialization or first write.
    if (initialized === 1) assert.equal(failedRandom.api.execute(1, 0), 0)
    else assert.equal(initialized, 0)
    assert.equal(failedRandom.api.output_len(), 0)
    assert.equal(failedRandom.api.execute(5, 0), 0)
  } finally { failedRandom.api.clear() }
})

test('b64 handles large 40KB frames without call stack overflow', () => {
  const large = new Uint8Array(40000)
  for (let i = 0; i < large.length; i++) large[i] = i & 0xff
  const encoded = b64(large)
  const decoded = unb64(encoded)
  assert.deepEqual(decoded, large)
})

test('exact origin matching: IDNA, ports, subdomains and ambiguous inputs', () => {
  assert.equal(canonicalOrigin('https://PAYPAL.COM:443/login'), 'https://paypal.com')
  assert.equal(canonicalOrigin('https://bücher.de'), 'https://xn--bcher-kva.de')
  for (const wrong of ['https://www.paypal.com', 'https://paypal.com.evil.test', 'http://paypal.com', 'https://pаypal.com', 'https://paypal.com:8443']) assert.equal(sameOrigin('https://paypal.com', wrong), false)
  assert.equal(sameOrigin('https://faß.de', 'https://fass.de'), false)
  for (const bad of ['https://user@paypal.com', 'https://paypal.com.', 'https://paypal.com\\@evil.test', 'data:text/html,x']) assert.throws(() => canonicalOrigin(bad))
})
test('packaged manifest has minimal permissions and no page-facing bridge', async () => {
  const manifest = JSON.parse(await readFile(new URL('../dist/manifest.json', import.meta.url), 'utf8'))
  assert.deepEqual(manifest.permissions.sort(), ['activeTab', 'nativeMessaging', 'scripting'].sort())
  assert.equal(manifest.host_permissions, undefined)
  assert.equal(manifest.externally_connectable, undefined)
  assert.equal(manifest.web_accessible_resources, undefined)
  assert.equal(manifest.content_scripts, undefined)
  assert.ok(!manifest.content_security_policy.extension_pages.includes("'unsafe-eval'"))
})
test('packaged WASM and native Rust interoperate, authenticate and reject replay', async () => {
  const { api, run } = await abi()
  const executable = new URL(`../../autofill-protocol/target/debug/examples/interop${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url)
  const child = spawn(fileURLToPath(executable), [], { stdio: ['pipe', 'pipe', 'pipe'] })
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]()
  const send = (b) => child.stdin.write(Buffer.from(b).toString('hex') + '\n')
  const line = async () => { const { value, done } = await lines.next(); assert.equal(done, false); return value }
  try {
    run(0, new Uint8Array(64).fill(1))
    send(run(1)); run(2, Buffer.from(await line(), 'hex')); send(run(1))
    const fingerprint = await line(), peer = await line()
    assert.equal(new TextDecoder().decode(run(4)), fingerprint)
    assert.equal(Buffer.from(run(3)).toString('hex'), peer)
    run(5)
    const plaintext = new TextEncoder().encode('SYNTHETIC_SELECTED_CREDENTIAL')
    send(run(6, plaintext))
    const encrypted = Buffer.from(await line(), 'hex')
    assert.equal(Buffer.from(run(7, encrypted)).toString(), 'SYNTHETIC_SELECTED_CREDENTIAL')
    new Uint8Array(api.memory.buffer, api.input_ptr(), encrypted.length).set(encrypted)
    assert.equal(api.execute(7, encrypted.length), 0)
    assert.equal(api.output_len(), 0)
  } finally { api.clear(); child.kill(); }
})

test('WASM identity agrees with the NIST ML-DSA vector and refuses legacy 32-byte identities', async () => {
  const { api, run } = await abi()
  const seed = await readFile(new URL('../../autofill-protocol/test-vectors/mldsa-seed.bin', import.meta.url))
  const publicKey = await readFile(new URL('../../autofill-protocol/test-vectors/mldsa-public.bin', import.meta.url))
  const privateKey = new Uint8Array(64).fill(1); privateKey.set(seed, 32)
  const expected = createHash('sha256').update('fluxlock-autofill-v2/ML-DSA-65/identity').update(publicKey).digest()
  try {
    assert.deepEqual(Buffer.from(run(0, privateKey)), expected)
    new Uint8Array(api.memory.buffer, api.input_ptr(), 32).fill(1)
    assert.equal(api.execute(0, 32), 0)
    assert.equal(api.output_len(), 0)
    assert.equal(api.execute(5, 0), 0)
  } finally { privateKey.fill(0); api.clear() }
})

test('WASM rejects an altered ML-DSA server proof before exporting any channel', async () => {
  const { api, run } = await abi()
  const executable = new URL(`../../autofill-protocol/target/debug/examples/interop${process.platform === 'win32' ? '.exe' : ''}`, import.meta.url)
  const child = spawn(fileURLToPath(executable), [], { stdio: ['pipe', 'pipe', 'pipe'] })
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]()
  try {
    run(0, new Uint8Array(64).fill(1))
    child.stdin.write(Buffer.from(run(1)).toString('hex') + '\n')
    const { value, done } = await lines.next(); assert.equal(done, false)
    const packet = Buffer.from(value, 'hex'); packet[packet.length - 1] ^= 1
    new Uint8Array(api.memory.buffer, api.input_ptr(), packet.length).set(packet)
    assert.equal(api.execute(2, packet.length), 0)
    assert.equal(api.output_len(), 0)
    assert.equal(api.execute(5, 0), 0)
  } finally { api.clear(); child.kill() }
})

import test from 'node:test'
import assert from 'node:assert/strict'
import { Channel } from '../dist/channel.js'
let listener, connectListener, documentId = 'doc-one', nativeAuthenticated = false, nativeCalls = [], inserted = [], connections = 0
const extensionId = 'a'.repeat(32), origin = 'https://login.example.test'
globalThis.chrome = {
  runtime: { id: extensionId, getURL: (p) => `chrome-extension://${extensionId}/${p}`, onMessage: { addListener: (fn) => { listener = fn } }, onConnect: { addListener: (fn) => { connectListener = fn } } },
  tabs: { query: async () => [{ id: 1, active: true, url: origin }], get: async () => ({ id: 1, active: true, url: origin }), onRemoved: { addListener() {} }, onUpdated: { addListener() {} } },
  scripting: { executeScript: async (args) => {
    if (args.target.documentIds && args.target.documentIds[0] !== documentId) return []
    if (!args.args) return [{ frameId: 0, documentId, result: { origin } }]
    if (args.args.length > 1) { inserted.push(structuredClone(args.args[1])); return [{ documentId, result: { filled: true } }] }
    return [{ documentId, result: { mode: 'password' } }]
  } },
}
Channel.prototype.open = async function () { connections++; this.welcome = { state: 'connected' }; this.fingerprint = 'test' }
Channel.prototype.request = async function (message) {
  nativeCalls.push(structuredClone(message))
  switch (message.op) {
    case 'begin_fill': return { state: 'auth_required', request_id: 'native-request' }
    case 'status': return { state: nativeAuthenticated ? 'ready' : 'auth_required' }
    case 'list_candidates': assert.ok(nativeAuthenticated); return { state: 'ready', entries: [{ handle: '1'.repeat(64), username: 'one@example.test' }, { handle: '2'.repeat(64), username: 'two@example.test' }], total: 2 }
    case 'select_and_fill': assert.ok(nativeAuthenticated); return { state: 'fill_once', request_id: 'native-request', username: 'two@example.test', password: 'ONLY_SELECTED_SECRET' }
    case 'cancel': return { state: 'cancelled' }
    default: throw new Error('Unknown request')
  }
}
await import('../dist/worker.js')
const sender = { id: extensionId, url: chrome.runtime.getURL('popup.html') }
const call = (message) => new Promise((resolve) => listener(message, sender, resolve))
test('opening the popup previews the site without opening a native channel or querying credentials', async () => {
  const preview = await call({ op: 'status' })
  assert.equal(preview.state, 'idle'); assert.equal(preview.origin, origin)
  assert.deepEqual(preview.entries, []); assert.equal(connections, 0); assert.deepEqual(nativeCalls, [])
})
test('popup receives no password, then only its explicit selection is injected', async () => {
  await call({ op: 'start' })
  const before = await call({ op: 'status' })
  assert.equal(before.state, 'auth_required'); assert.deepEqual(before.entries, [])
  assert.equal(nativeCalls.filter((c) => c.op === 'list_candidates').length, 0)
  nativeAuthenticated = true
  const list = await call({ op: 'status' })
  assert.equal(list.entries.length, 2); assert.ok(!JSON.stringify(list).includes('password'))
  const result = await call({ op: 'fill', handle: '2'.repeat(64) })
  assert.equal(result.state, 'filled'); assert.ok(!JSON.stringify(result).includes('SECRET'))
  assert.deepEqual(inserted, [{ username: 'two@example.test', password: 'ONLY_SELECTED_SECRET' }])
  assert.equal(nativeCalls.filter((c) => c.op === 'select_and_fill').length, 1)
  assert.equal((await call({ op: 'fill', handle: '1'.repeat(64) })).ok, false)
  assert.equal(nativeCalls.filter((c) => c.op === 'select_and_fill').length, 1)
})
test('a navigation between listing and selection prevents retrieving any password', async () => {
  nativeCalls = []; inserted = []; nativeAuthenticated = false
  await call({ op: 'start' }); nativeAuthenticated = true; await call({ op: 'status' })
  documentId = 'doc-two'
  const result = await call({ op: 'fill', handle: '1'.repeat(64) })
  assert.equal(result.ok, false); assert.equal(inserted.length, 0)
  assert.equal(nativeCalls.filter((c) => c.op === 'select_and_fill').length, 0)
})
test('site/content scripts cannot call privileged worker operations or declare auth success', async () => {
  assert.equal(listener({ op: 'start' }, { id: extensionId, tab: { id: 1 }, url: origin }, () => assert.fail()), false)
  assert.equal(listener({ op: 'start' }, { id: 'b'.repeat(32), url: chrome.runtime.getURL('popup.html') }, () => assert.fail()), false)
  assert.equal((await call({ op: 'authenticated', authenticated: true })).ok, false)
})
test('popup closure preserves native authentication but cancels a displayed selection', async () => {
  nativeCalls = []; nativeAuthenticated = false
  let disconnected
  connectListener({ name: 'popup-lifecycle', sender, onDisconnect: { addListener(fn) { disconnected = fn } } })
  await call({ op: 'start' }); disconnected()
  assert.equal((await call({ op: 'status' })).state, 'auth_required')
  nativeAuthenticated = true; assert.equal((await call({ op: 'status' })).state, 'ready')
  disconnected()
  assert.equal((await call({ op: 'status' })).state, 'idle')
  assert.equal(nativeCalls.filter((c) => c.op === 'cancel').length, 1)
  assert.equal(nativeCalls.filter((c) => c.op === 'select_and_fill').length, 0)
})

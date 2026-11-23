// Load the actual MV3 package in a fresh browser profile, without registering a
// native host or touching personal browser data. Requires full Chromium/Brave.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const require = createRequire(import.meta.url)
const { chromium } = require(process.env.FLUXLOCK_PLAYWRIGHT || 'playwright')
const profile = await mkdtemp(path.join(tmpdir(), 'fluxlock-extension-test-'))
const extension = fileURLToPath(new URL('../dist', import.meta.url))
let context
try {
  context = await chromium.launchPersistentContext(profile, {
    headless: true, ...(process.env.FLUXLOCK_BROWSER_EXECUTABLE ? { executablePath: process.env.FLUXLOCK_BROWSER_EXECUTABLE } : { channel: 'chromium' }),
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  })
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 15000 })
  assert.match(worker.url(), /^chrome-extension:\/\/[a-p]{32}\/worker\.js$/u)
  // Dynamic imports are forbidden in ServiceWorkerGlobalScope. Exercise these
  // statically worker-imported modules from a real extension page instead.
  const page = await context.newPage()
  await page.goto(worker.url().replace(/worker\.js$/u, 'popup.html'))
  const result = await page.evaluate(async () => {
    const { identity, resetIdentity } = await import(chrome.runtime.getURL('identity.js'))
    const { Noise } = await import(chrome.runtime.getURL('noise.js'))
    // A legacy record must never become a trusted PQ identity implicitly.
    const legacy = await new Promise((resolve, reject) => {
      const request = indexedDB.open('fluxlock-browser-identity', 1)
      request.onupgradeneeded = () => request.result.createObjectStore('identity')
      request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error)
    })
    await new Promise((resolve, reject) => {
      const transaction = legacy.transaction('identity', 'readwrite')
      transaction.objectStore('identity').put({ peer: '0'.repeat(64), legacy: true }, 'local')
      transaction.oncomplete = resolve; transaction.onerror = reject
    })
    legacy.close()
    const first = await identity(), second = await identity()
    let noise
    try {
      const same = first.privateKey.every((v, i) => v === second.privateKey[i])
      noise = await Noise.create(first.privateKey)
      const handshake = noise.run(1)
      const database = await new Promise((resolve, reject) => {
        const request = indexedDB.open('fluxlock-browser-identity-v2', 1)
        request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error)
      })
      const stored = await new Promise((resolve, reject) => {
        const request = database.transaction('identity').objectStore('identity').get('local')
        request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error)
      })
      database.close()
      return { same, unpaired: first.peer === undefined && second.peer === undefined, privateLength: first.privateKey.length, handshakeLength: handshake.length, extractable: stored.key.extractable, algorithm: stored.key.algorithm.name, wrappedLength: stored.wrapped.byteLength, manifest: chrome.runtime.getManifest().manifest_version }
    } finally { noise?.clear(); first.privateKey.fill(0); second.privateKey.fill(0); await resetIdentity() }
  })
  assert.deepEqual(result, { same: true, unpaired: true, privateLength: 64, handshakeLength: 1240, extractable: false, algorithm: 'AES-GCM', wrappedLength: 80, manifest: 3 })
  console.log('Paquet MV3 chargé : worker réel, CSP/WASM, aléa Web Crypto et identité chiffrée sous clé IndexedDB non exportable vérifiés dans un profil jetable.')
} finally { await context?.close(); await rm(profile, { recursive: true, force: true }) }

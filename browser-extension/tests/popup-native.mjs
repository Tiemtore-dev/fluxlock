// Measures the actual toolbar-action popup, not a tab displaying popup.html.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const require = createRequire(import.meta.url)
const { chromium } = require(process.env.FLUXLOCK_PLAYWRIGHT || 'playwright')
const profile = await mkdtemp(path.join(tmpdir(), 'fluxlock-native-popup-'))
const extension = fileURLToPath(new URL('../dist', import.meta.url))
const output = process.env.FLUXLOCK_UI_OUTPUT || '/private/tmp/fluxlock-extension-wide'
let context
try {
  context = await chromium.launchPersistentContext(profile, {
    headless: process.env.FLUXLOCK_HEADED !== '1',
    ...(process.env.FLUXLOCK_BROWSER_EXECUTABLE ? { executablePath: process.env.FLUXLOCK_BROWSER_EXECUTABLE } : { channel: 'chromium' }),
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  })
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker', { timeout: 15000 })
  const backgroundPage = context.pages()[0] || await context.newPage()
  await backgroundPage.bringToFront()
  const cdp = await context.newCDPSession(backgroundPage)
  await worker.evaluate(() => chrome.action.openPopup())
  const nativeContexts = await worker.evaluate(() => chrome.runtime.getContexts({ contextTypes: ['POPUP'] }))
  assert.equal(nativeContexts.length, 1, 'The toolbar action must create one actual POPUP context')
  const targets = await cdp.send('Target.getTargets')
  const target = targets.targetInfos.find((t) => t.url === nativeContexts[0].documentUrl)
  assert.ok(target, 'Native popup DevTools target missing')
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId: target.targetId, flatten: false })
  let commandId = 0
  const command = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++commandId
    const timer = setTimeout(() => { cdp.off('Target.receivedMessageFromTarget', receive); reject(new Error(`Popup ${method} timeout`)) }, 10000)
    const receive = (event) => {
      if (event.sessionId !== sessionId) return
      const message = JSON.parse(event.message)
      if (message.id !== id) return
      clearTimeout(timer); cdp.off('Target.receivedMessageFromTarget', receive)
      if (message.error) reject(new Error(message.error.message)); else resolve(message.result)
    }
    cdp.on('Target.receivedMessageFromTarget', receive)
    cdp.send('Target.sendMessageToTarget', { sessionId, message: JSON.stringify({ id, method, params }) }).catch(reject)
  })
  const evaluated = await command('Runtime.evaluate', {
    expression: `new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve({width: innerWidth, height: innerHeight, contentWidth: document.documentElement.scrollWidth, contentHeight: document.documentElement.scrollHeight, clientWidth: document.documentElement.clientWidth, rootWidth: document.documentElement.getBoundingClientRect().width, state: document.body.dataset.state}))))`,
    awaitPromise: true, returnByValue: true,
  })
  const size = evaluated.result.value
  assert.equal(size.width, 520, JSON.stringify(size))
  assert.equal(size.rootWidth, 520, JSON.stringify(size))
  assert.equal(size.contentWidth, 520, JSON.stringify(size))
  assert.equal(size.clientWidth, 520, JSON.stringify(size))
  assert.ok(size.contentHeight <= size.height, JSON.stringify(size))
  assert.ok(size.height <= 340, JSON.stringify(size))
  assert.equal(size.state, 'idle')
  const screenshot = await command('Page.captureScreenshot', { format: 'png' })
  await mkdir(output, { recursive: true })
  await writeFile(path.join(output, 'actual-toolbar-popup.png'), Buffer.from(screenshot.data, 'base64'))
  console.log(JSON.stringify({ context: 'POPUP', size, screenshot: path.join(output, 'actual-toolbar-popup.png') }, null, 2))
} finally { await context?.close(); await rm(profile, { recursive: true, force: true }) }

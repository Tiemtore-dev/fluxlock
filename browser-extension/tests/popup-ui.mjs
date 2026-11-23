// Real DOM/CSS with a simulated extension API. No vault or native authentication
// is mocked as successful outside this isolated UI fixture.
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { readFile, mkdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
const require = createRequire(import.meta.url)
const { chromium } = require(process.env.FLUXLOCK_PLAYWRIGHT || 'playwright')
const root = fileURLToPath(new URL('../dist/', import.meta.url))
const output = process.env.FLUXLOCK_UI_OUTPUT || '/private/tmp/fluxlock-extension-redesign'
await mkdir(output, { recursive: true })
const browser = await chromium.launch({ headless: true })
const states = ['idle', 'connecting', 'pairing', 'paired', 'auth_required', 'ready', 'filled', 'empty', 'expired', 'error']
const errors = [], contrastResults = [], dimensions = []
try {
  const context = await browser.newContext({ reducedMotion: 'reduce' })
  await context.route('https://fluxlock-ui.test/**', async (route) => {
    const name = new URL(route.request().url()).pathname.slice(1) || 'popup.html'
    if (!/^[a-z0-9/.-]+$/u.test(name) || name.includes('..')) return route.abort()
    try {
      const type = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png' }[path.extname(name)]
      await route.fulfill({ body: await readFile(path.join(root, name)), contentType: type })
    } catch { await route.abort() }
  })
  await context.addInitScript(() => {
    const state = new URL(location.href).searchParams.get('state') || 'idle'
    const preview = new URL(location.href).searchParams.get('preview') === '1'
    const all = Array.from({ length: 23 }, (_, i) => ({ handle: (i + 1).toString(16).padStart(64, '0'), username: i === 0 ? 'alice@example.test' : i === 1 ? (preview ? 'equipe@example.test' : '<img src=x onerror="window.INJECTED=1">@example.test') : i === 2 ? (preview ? 'personnel@example.test' : `${'identifiant-long-'.repeat(12)}@example.test`) : `compte.${i + 1}@example.test` }))
    window.calls = []
    window.view = { ok: state !== 'error', state, origin: 'https://xn--bcher-kva.example.test', entries: state === 'ready' ? all.slice(0, 10) : [], total: state === 'ready' ? 23 : 0,
      fingerprint: 'A19E2D4F-809B164C-3A7DE20F-91B5C604-A19E2D4F-809B164C-3A7DE20F-91B5C604', error: state === 'error' ? 'Le relais local est introuvable. Vérifiez son installation pour ce navigateur.' : undefined }
    window.chrome = { runtime: { connect: () => ({ onDisconnect: { addListener() {} } }), sendMessage: async (message) => {
      window.calls.push(structuredClone(message))
      if (message.op === 'list') window.view.entries = all.slice(message.offset, message.offset + 10)
      if (message.op === 'fill') window.view = { ok: true, state: 'filled' }
      if (message.op === 'reset' || message.op === 'cancel') window.view = { ok: true, state: 'idle' }
      return structuredClone(window.view)
    } } }
  })
  const page = await context.newPage()
  page.on('pageerror', (e) => errors.push(e.message))
  const load = async (state, width = 520, scheme = 'light', preview = false) => {
    await page.setViewportSize({ width, height: 900 })
    await page.emulateMedia({ colorScheme: scheme })
    await page.goto(`https://fluxlock-ui.test/popup.html?state=${state}&preview=${preview ? '1' : '0'}`)
    await page.waitForFunction(() => document.querySelector('#main').getAttribute('aria-busy') === 'false')
  }
  for (const scheme of ['light', 'dark']) {
    for (const width of [320, 375, 520, 768, 1280]) {
      for (const state of states) {
        await load(state, width, scheme)
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${state}/${scheme}/${width}: horizontal overflow`)
        assert.equal(await page.locator('input[type=password]').count(), 0)
        assert.equal(await page.locator('.brand img').evaluate((img) => img.complete && img.naturalWidth > 0), true)
        assert.equal(await page.locator('#origin').innerText(), 'https://xn--bcher-kva.example.test')
        if (state === 'ready') {
          assert.equal(await page.locator('.account-button').count(), 10)
          assert.equal(await page.locator('#accounts img').count(), 0)
          assert.equal(await page.evaluate(() => window.INJECTED), undefined)
        }
        if (width === 520) {
          const size = await page.locator('body').boundingBox()
          dimensions.push({ scheme, state, width: size.width, height: size.height })
          assert.equal(size.width, 520)
          assert.ok(size.height <= 500, `${state}: popup too tall (${size.height})`)
          if (state === 'idle') assert.ok(size.height <= 340, `idle: ${size.height}`)
        }
      }
    }
    for (const state of ['idle', 'ready', 'pairing', 'error']) {
      await load(state, 520, scheme, true)
      await page.locator('body').screenshot({ path: path.join(output, `${state}-${scheme}.png`) })
      // Check actual computed foreground/background pairs, including inherited
      // backgrounds. Decorative SVGs and disabled controls are excluded.
      const ratios = await page.evaluate(() => {
        const rgb = (v) => (v.match(/[\d.]+/g) || []).map(Number)
        const luminance = (v) => v.slice(0, 3).map((x) => { x /= 255; return x <= .04045 ? x / 12.92 : ((x + .055) / 1.055) ** 2.4 }).reduce((sum, x, i) => sum + x * [.2126, .7152, .0722][i], 0)
        const results = []
        for (const el of document.querySelectorAll('p,h1,h2,h3,button,summary,.eyebrow,.account-name,.account-kind,.count,.steps li')) {
          if (!el.getBoundingClientRect().width || el.closest('[hidden],button:disabled,dialog:not([open])')) continue
          const style = getComputedStyle(el), fg = rgb(style.color)
          let parent = el, bg
          while (parent) { const color = rgb(getComputedStyle(parent).backgroundColor); if (color.length === 3 || color[3] === 1) { bg = color; break }; parent = parent.parentElement }
          if (!bg) continue
          const ls = [luminance(fg), luminance(bg)].sort((a, b) => b - a)
          results.push({ element: el.id || el.className || el.tagName, ratio: (ls[0] + .05) / (ls[1] + .05) })
        }
        return results
      })
      for (const pair of ratios) assert.ok(pair.ratio >= 4.5, `${scheme}/${state}/${pair.element}: ${pair.ratio.toFixed(2)} contrast`)
      contrastResults.push({ scheme, state, minimum: Math.min(...ratios.map((p) => p.ratio)) })
      if (process.env.FLUXLOCK_AXE) {
        await page.addScriptTag({ path: process.env.FLUXLOCK_AXE })
        const result = await page.evaluate(() => axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'] } }))
        assert.deepEqual(result.violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target) })), [], `${scheme}/${state}: axe`)
      }
    }
  }
  await load('ready')
  await page.locator('#next').click(); await page.waitForFunction(() => document.querySelector('#page-label').textContent === '11–20 sur 23')
  await page.locator('#next').click(); await page.waitForFunction(() => document.querySelector('#page-label').textContent === '21–23 sur 23')
  assert.equal(await page.locator('#next').isDisabled(), true)
  await page.locator('#previous').click(); await page.waitForFunction(() => document.querySelector('#page-label').textContent === '11–20 sur 23')
  await page.locator('.account-button').first().focus()
  await page.waitForTimeout(1200)
  assert.equal(await page.locator('.account-button').first().evaluate((el) => el === document.activeElement), true)
  await page.keyboard.press('Enter'); await page.locator('#state-title').filter({ hasText: 'Formulaire rempli' }).waitFor()
  assert.equal(await page.evaluate(() => window.calls.filter((c) => c.op === 'fill').length), 1)
  assert.deepEqual(await page.evaluate(() => Object.keys(window.calls.find((c) => c.op === 'fill')).sort()), ['handle', 'op'])
  await load('idle')
  await page.locator('#connection > summary').click(); await page.locator('.advanced > summary').click()
  await page.locator('#reset').click(); assert.equal(await page.locator('#reset-dialog').evaluate((el) => el.open), true)
  await page.keyboard.press('Escape')
  assert.equal(await page.evaluate(() => window.calls.some((c) => c.op === 'reset')), false)
  assert.equal(await page.locator('#reset').evaluate((el) => el === document.activeElement), true)
  await page.locator('#reset').click(); await page.locator('#reset-confirm').click()
  await page.waitForFunction(() => window.calls.some((c) => c.op === 'reset'))
  await load('idle', 320)
  // Classic scrollbars reserve layout width on Linux; macOS normally overlays
  // them. Force that geometry so the same reflow regression is caught locally.
  await page.addStyleTag({ content: 'html::-webkit-scrollbar { width: 16px; } body { min-height: 1200px; }' })
  await page.evaluate(() => document.documentElement.style.fontSize = '200%')
  for (const font of ['system', 'monospace']) {
    await page.evaluate((font) => {
      if (font === 'system') document.documentElement.style.removeProperty('--font-body')
      else document.documentElement.style.setProperty('--font-body', font)
    }, font)
    for (const open of [false, true]) {
      await page.locator('#connection').evaluate((el, open) => { el.open = open }, open)
      const reflow = await page.evaluate(() => ({
        viewport: innerWidth, width: document.documentElement.scrollWidth,
        overflow: [...document.querySelectorAll('body *')].filter((el) => {
          const r = el.getBoundingClientRect()
          return r.width && (r.right > innerWidth + 1 || r.left < -1)
        }).map((el) => ({ tag: el.tagName, id: el.id, class: el.className.baseVal ?? el.className, text: el.textContent.trim().slice(0, 80) })),
      }))
      await page.locator('body').screenshot({ path: path.join(output, `reflow-200-${font}-${open ? 'help' : 'idle'}.png`) })
      assert.ok(reflow.width <= reflow.viewport, `200% text reflow (${font}/help=${open}): ${JSON.stringify(reflow)}`)
    }
  }
  await page.keyboard.press('Tab')
  assert.ok(await page.evaluate(() => parseFloat(getComputedStyle(document.activeElement).outlineWidth) >= 2))
  assert.deepEqual(errors, [])
  console.log(JSON.stringify({ layouts: states.length * 5 * 2, themes: ['light', 'dark'], widths: [320, 375, 520, 768, 1280], dimensions, contrastResults, keyboard: true, pagination: true, resetConfirmation: true, reducedMotion: true, axe: Boolean(process.env.FLUXLOCK_AXE), output }, null, 2))
} finally { await browser.close() }

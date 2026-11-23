import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { formAction } from '../dist/form.js'
const require = createRequire(import.meta.url)
const { chromium } = require(process.env.FLUXLOCK_PLAYWRIGHT || 'playwright')
const browser = await chromium.launch({ headless: true })
try {
  const page = await browser.newPage()
  const origin = 'https://login.example.test'
  let action = '/session', hidden = false, newPassword = false, passwordOnly = false, method = 'post', buttonOverride = '', parentStyle = ''
  await page.route(`${origin}/**`, (route) => route.fulfill({ contentType: 'text/html', body: `<!doctype html><html><body>
    <form ${method ? `method="${method}"` : ''} action="${action}" style="${parentStyle}">${passwordOnly ? '' : '<label>Email <input name="email" type="email" autocomplete="username"></label>'}
    <label>Mot de passe <input name="password" type="password" autocomplete="${newPassword ? 'new-password' : 'current-password'}" ${hidden ? 'style="display:none"' : ''}></label>
    <button type="submit" ${buttonOverride}>Connexion</button></form><script>window.submitted=false;window.seen=[];document.querySelector('form').onsubmit=e=>{e.preventDefault();window.submitted=true};
    document.querySelector('input[type=password]').addEventListener('input',e=>window.seen.push(e.target.value));</script></body></html>` }))
  await page.goto(origin)
  const cdp = await page.context().newCDPSession(page)
  const run = async (...args) => {
    const tree = await cdp.send('Page.getFrameTree')
    const world = await cdp.send('Page.createIsolatedWorld', { frameId: tree.frameTree.frame.id, worldName: 'fluxlock-form-test' })
    const result = await cdp.send('Runtime.evaluate', { contextId: world.executionContextId, expression: `(${formAction.toString()})(...${JSON.stringify(args)})`, returnByValue: true })
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text)
    return result.result.value
  }
  assert.equal((await run(origin)).mode, 'password')
  await run(origin, { username: 'chosen@example.test', password: 'SYNTHETIC_CHOSEN_PASSWORD' })
  assert.equal(await page.locator('input[type=email]').inputValue(), 'chosen@example.test')
  assert.equal(await page.locator('input[type=password]').inputValue(), 'SYNTHETIC_CHOSEN_PASSWORD')
  assert.deepEqual(await page.evaluate(() => window.seen), ['SYNTHETIC_CHOSEN_PASSWORD'])
  assert.equal(await page.evaluate(() => window.submitted), false)
  passwordOnly = true; await page.reload()
  assert.equal((await run(origin)).mode, 'password')
  await run(origin, { username: 'chosen@example.test', password: 'SYNTHETIC_SECOND_STEP' })
  assert.equal(await page.locator('input[type=password]').inputValue(), 'SYNTHETIC_SECOND_STEP')
  passwordOnly = false; method = 'get'; await page.reload(); await assert.rejects(() => run(origin))
  method = ''; await page.reload(); await assert.rejects(() => run(origin))
  method = 'post'
  action = 'https://different.example.test/session'; await page.reload(); await assert.rejects(() => run(origin))
  action = '/session'; buttonOverride = 'formaction="https://different.example.test/steal"'; await page.reload(); await assert.rejects(() => run(origin))
  buttonOverride = 'formmethod="get"'; await page.reload(); await assert.rejects(() => run(origin))
  buttonOverride = ''; parentStyle = 'opacity:0'; await page.reload(); await assert.rejects(() => run(origin))
  parentStyle = ''; newPassword = true; await page.reload(); await assert.rejects(() => run(origin))
  newPassword = false; hidden = true; await page.reload(); assert.equal((await run(origin)).mode, 'username')
  await assert.rejects(() => run('https://different.example.test'))
  console.log('Formulaires : monde isolé, seul compte choisi, événements, absence de soumission automatique, destination externe, inscription et origine différente vérifiés.')
} finally { await browser.close() }

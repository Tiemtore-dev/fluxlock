import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const { chromium } = require(process.env.FLUXLOCK_PLAYWRIGHT || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.FLUXLOCK_BROWSER, headless: true })
const url = process.env.FLUXLOCK_TEST_URL || 'http://127.0.0.1:5173'
try {
  for (const width of [320, 768, 1280]) {
    const page = await browser.newPage({ viewport: { width, height: 960 }, reducedMotion: 'reduce', colorScheme: 'dark' })
    const errors = []
    page.on('pageerror', (e) => errors.push(e.message))
    await page.addInitScript(() => {
      const personal = { id: 'legacy', name: 'Personnel', schema_version: 1, created_at: '2026-11-22' }
      const vaults = [personal]
      let selected = personal
      let token = null
      let generation = 0
      let delayLogout = false
      window.__calls = []
      window.__clipboard = ''
      window.__deletedAliases = []
      window.AndroidBiometric = {
        isAvailable: () => false,
        hasStoredKey: () => false,
        storeKey: () => {},
        deleteKey: (account) => { window.__deletedAliases.push(account); return true },
      }
      Object.defineProperty(navigator, 'clipboard', { value: { writeText: async (text) => { window.__clipboard = text } } })
      window.__delayLogout = () => { delayLogout = true }
      window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} }
      window.__TAURI_INTERNALS__ = { transformCallback: () => 1, invoke: async (command, args = {}) => {
        window.__calls.push([command, args])
        const globals = ['list_vaults', 'init_local_db', 'create_vault', 'select_vault', 'plugin:app|version']
        if (!command.startsWith('plugin:') && !globals.includes(command)) {
          if (args.context?.vault_id !== selected.id) throw new Error('Wrong vault context')
          if (token && args.context?.token !== token) throw new Error('Wrong session context')
        }
        switch (command) {
          case 'init_local_db': return 'ready'
          case 'list_vaults': return { vaults, selected_vault_id: selected.id, unlocked_vault_id: token ? selected.id : null }
          case 'has_existing_user': return true
          case 'check_login_delay': return 0
          case 'check_biometric': return { available: false, enrolled: false, failed_attempts: 0, requires_password: true }
          case 'local_login': {
            if (token) throw new Error('A vault is already unlocked')
            const password = selected.id === 'legacy' ? 'personal password' : 'work password'
            if (args.credentials.password !== password) return { success: false, message: 'Mot de passe incorrect' }
            token = `session-${++generation}`
            return { success: true, token, user_id: 1, username: 'same-user', email: 'fixture@example.org' }
          }
          case 'local_logout':
            if (delayLogout) {
              await new Promise((resolve) => { window.__finishLogout = resolve })
              delayLogout = false
            }
            token = null
            return
          case 'select_vault':
            if (token) throw new Error('A vault is already unlocked')
            selected = vaults.find((v) => v.id === args.vaultId)
            if (!selected) throw new Error('Missing vault')
            return selected
          case 'create_vault':
            if (token) throw new Error('A vault is already unlocked')
            selected = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: args.request.name, schema_version: 1, created_at: '2026-11-22' }
            vaults.push(selected)
            token = `session-${++generation}`
            return { vault: selected, auth: { success: true, token, user_id: 1, username: args.request.username } }
          case 'rename_vault': selected.name = args.name.trim(); return selected
          case 'reset_vault_completely': token = null; return 'reset'
          case 'check_auto_lock': return { locked: !token }
          case 'get_passwords': return [{ id: 1, title: selected.id === 'legacy' ? 'Private Personal Entry' : 'Private Work Entry', password: 'synthetic-secret', created_at: '2026-11-22' }]
          case 'get_secure_files': return [{ id: 1, filename: 'Vault document.txt', file_size: 100, created_at: '2026-11-22' }]
          case 'plugin:dialog|save': return new Promise((resolve) => { window.__finishSave = () => resolve('/synthetic/export.txt') })
          case 'get_secure_keys': case 'get_security_events': return []
          case 'get_security_status': return { is_readonly: false, threat_level: 'none', active_threats: [] }
          case 'get_isolation_mode': return true
          case 'plugin:app|version': return '2.3.4'
          default: return null
        }
      } }
    })
    const nav = async (path) => page.evaluate((path) => { history.pushState(null, '', path); dispatchEvent(new PopStateEvent('popstate')) }, path)
    const unlock = async (password) => {
      await page.getByLabel('Mot de passe maître', { exact: true }).fill(password)
      await page.getByRole('button', { name: 'Déverrouiller', exact: true }).click()
    }
    const lock = async () => {
      await nav('/settings')
      if (width <= 768) {
        await page.getByRole('button', { name: 'Verrouiller le coffre' }).click()
      } else await page.getByRole('button', { name: 'Changer de coffre', exact: true }).click()
      await page.getByRole('heading', { name: 'Déverrouiller le coffre' }).waitFor()
    }
    await page.goto(`${url}/login`)
    assert.equal(await page.getByLabel('Coffre', { exact: true }).inputValue(), 'legacy')
    await unlock('personal password')
    await page.getByRole('heading', { name: 'Votre coffre', exact: true }).waitFor()
    await nav('/passwords')
    await page.getByText('Private Personal Entry', { exact: true }).waitFor()
    await page.getByRole('button', { name: 'Copier', exact: true }).click()
    await page.waitForFunction(() => window.__clipboard === 'synthetic-secret')
    await nav('/files')
    await page.getByRole('button', { name: 'Exporter Vault document.txt', exact: true }).click()
    await page.waitForFunction(() => typeof window.__finishSave === 'function')
    // Hide secret views immediately, but prevent selection until Rust confirms lock.
    await page.evaluate(() => window.__delayLogout())
    await lock()
    assert.ok(await page.getByLabel('Coffre', { exact: true }).isDisabled())
    assert.equal(await page.evaluate(() => window.__clipboard), '')
    assert.equal(await page.getByText('Private Personal Entry', { exact: true }).count(), 0)
    await page.evaluate(() => window.__finishLogout())
    await page.getByRole('link', { name: 'Créer un autre coffre' }).click()
    await page.getByLabel('Nom du coffre', { exact: true }).fill('Travail')
    await page.getByLabel('Nom d’utilisateur').fill('same-user')
    await page.getByLabel('Email', { exact: true }).fill('fixture@example.org')
    await page.getByLabel('Mot de passe maître', { exact: true }).fill('work password')
    await page.getByLabel('Confirmer le mot de passe', { exact: true }).fill('work password')
    await page.getByRole('button', { name: 'Créer le coffre', exact: true }).click()
    await page.getByRole('heading', { name: 'Votre coffre', exact: true }).waitFor()
    await nav('/passwords')
    await page.getByText('Private Work Entry', { exact: true }).waitFor()
    await page.evaluate(() => window.__finishSave())
    await page.getByText(/Le coffre ou la session a changé/).waitFor()
    assert.equal(await page.evaluate(() => window.__calls.filter(([command]) => command === 'decrypt_file_to_path').length), 0)
    assert.equal(await page.getByText('Private Personal Entry', { exact: true }).count(), 0)
    await nav('/settings')
    await page.getByLabel('Nom du coffre', { exact: true }).fill('Travail renommé')
    await page.getByRole('button', { name: 'Enregistrer le nom', exact: true }).click()
    await page.getByText('Nom du coffre enregistré', { exact: true }).waitFor()
    // Rename preserves the session capability and its data access.
    await nav('/passwords')
    await page.getByText('Private Work Entry', { exact: true }).waitFor()
    await lock()
    assert.equal(await page.getByRole('option', { name: 'Travail renommé' }).count(), 1)
    await page.getByLabel('Mot de passe maître', { exact: true }).fill('never carry this to another vault')
    await page.getByLabel('Coffre', { exact: true }).selectOption('legacy')
    await page.getByLabel('Coffre', { exact: true }).and(page.locator(':enabled')).waitFor()
    await page.waitForFunction(() => document.querySelector('input[autocomplete="current-password"]')?.value === '')
    await unlock('work password')
    await page.getByRole('alert').getByText('Mot de passe incorrect').waitFor()
    await unlock('personal password')
    await page.getByRole('heading', { name: 'Votre coffre', exact: true }).waitFor()
    await nav('/passwords')
    await page.getByText('Private Personal Entry', { exact: true }).waitFor()
    assert.equal(await page.getByText('Private Work Entry', { exact: true }).count(), 0)
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth <= 2))
    await nav('/reset-vault')
    await page.getByRole('button', { name: 'Continuer vers la confirmation' }).click()
    await page.getByLabel('Phrase de confirmation').fill('SUPPRIMER TOUT')
    await page.getByLabel('Mot de passe maître', { exact: true }).fill('personal password')
    await page.getByRole('button', { name: 'Effacer définitivement' }).click()
    await page.getByRole('heading', { name: 'Créer votre coffre', exact: true }).waitFor()
    assert.equal(await page.getByLabel('Nom du coffre', { exact: true }).inputValue(), 'Personnel')
    assert.deepEqual(await page.evaluate(() => window.__deletedAliases), ['user_bio_same-user'])
    assert.deepEqual(errors, [])
    await page.close()
  }
  console.log('Multi-coffre : création, verrouillage avant changement, renommage, sessions et caches isolés vérifiés à 320, 768 et 1280 px.')
} finally { await browser.close() }

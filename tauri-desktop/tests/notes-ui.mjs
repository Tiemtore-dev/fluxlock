import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const { chromium } = require(process.env.FLUXLOCK_PLAYWRIGHT || 'playwright')
const browser = await chromium.launch({ executablePath: process.env.FLUXLOCK_BROWSER, headless: true })
const url = process.env.FLUXLOCK_TEST_URL || 'http://127.0.0.1:5173'
try {
  for (const width of [390, 1280]) {
    const page = await browser.newPage({ viewport: { width, height: 960 }, reducedMotion: 'reduce' })
    const errors = []
    page.on('pageerror', (error) => errors.push(error.message))
    await page.addInitScript(() => {
      const vault = { id: 'legacy', name: 'Personnel', schema_version: 1, created_at: '2026-11-22' }
      const records = []
      let token = null, generation = 0, nextId = 1
      window.__calls = []
      window.__readonly = false
      window.__delayRead = false
      window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} }
      window.__TAURI_INTERNALS__ = { transformCallback: () => 1, invoke: async (command, args = {}) => {
        window.__calls.push([command, args])
        const globals = ['list_vaults', 'init_local_db', 'plugin:app|version']
        if (!command.startsWith('plugin:') && !globals.includes(command)) {
          if (args.context?.vault_id !== vault.id) throw new Error('Wrong vault context')
          if (token && args.context?.token !== token) throw new Error('Wrong session context')
        }
        switch (command) {
          case 'init_local_db': return 'ready'
          case 'list_vaults': return { vaults: [vault], selected_vault_id: vault.id, unlocked_vault_id: token ? vault.id : null }
          case 'has_existing_user': return true
          case 'check_biometric': return { available: false, enrolled: false, requires_password: true, failed_attempts: 0 }
          case 'check_login_delay': return 0
          case 'local_login': token = `notes-session-${++generation}`; return { success: true, token, user_id: 1, username: 'fixture' }
          case 'local_logout': token = null; return
          case 'check_auto_lock': return { locked: !token }
          case 'get_secure_files': return [{ id: 7, filename: 'document.txt', file_size: 20, created_at: '2026-11-22' }]
          case 'get_passwords': case 'get_secure_keys': case 'get_security_events': return []
          case 'get_security_status': return { is_readonly: window.__readonly, active_threats: [] }
          case 'list_notes': {
            const filtered = records.filter((note) => note.title.toLowerCase().includes((args.search || '').toLowerCase()))
            return { items: filtered.slice(args.offset || 0, (args.offset || 0) + (args.limit || 50)).map(({ body, attachment, ...note }) => ({ ...note, has_attachment: !!attachment })), total: filtered.length }
          }
          case 'get_note': {
            const note = structuredClone(records.find((note) => note.id === args.id))
            if (window.__delayRead) {
              window.__delayRead = false
              await new Promise((resolve) => { window.__finishRead = resolve })
            }
            return note
          }
          case 'save_note': {
            if (window.__readonly) throw new Error('Lecture seule')
            const request = args.request
            const note = request.id ? records.find((n) => n.id === request.id) : { id: nextId++, revision: 0, created_at: '2026-11-22 10:00:00' }
            if (request.id && note.revision !== request.revision) throw new Error('Conflit')
            Object.assign(note, { title: request.title, body: request.body, revision: note.revision + 1, updated_at: '2026-11-22 10:00:00',
              attachment: request.attachment_path ? { id: 8, filename: 'nouveau.txt', file_size: 20 } : request.attachment_file_id ? { id: request.attachment_file_id, filename: 'document.txt', file_size: 20 } : null })
            if (!request.id) records.push(note)
            return note.id
          }
          case 'delete_note': records.splice(records.findIndex((n) => n.id === args.id), 1); return
          case 'export_note_attachment': return '/synthetic/export.txt'
          case 'plugin:dialog|open': return '/synthetic/nouveau.txt'
          case 'plugin:dialog|save': return '/synthetic/export.txt'
          case 'plugin:fs|stat': return { size: 20, isFile: true, isDirectory: false, isSymlink: false }
          case 'plugin:app|version': return '2.3.4'
          default: return null
        }
      } }
    })
    const nav = (path) => page.evaluate((path) => { history.pushState(null, '', path); dispatchEvent(new PopStateEvent('popstate')) }, path)
    const unlock = async () => {
      await page.getByLabel('Mot de passe maître', { exact: true }).fill('synthetic master password')
      await page.getByRole('button', { name: 'Déverrouiller', exact: true }).click()
      await page.getByRole('heading', { name: 'Votre coffre', exact: true }).waitFor()
    }
    const lock = async () => {
      await nav('/settings')
      await page.getByRole('button', { name: 'Verrouiller le coffre', exact: true }).click()
      await page.getByRole('heading', { name: 'Déverrouiller le coffre', exact: true }).waitFor()
    }
    await page.goto(`${url}/login`)
    await unlock()
    if (width < 768) {
      await page.getByRole('button', { name: 'Plus', exact: true }).click()
      await page.getByRole('navigation', { name: 'Toutes les pages', exact: true }).getByRole('link', { name: 'Notes', exact: true }).click()
    } else await page.getByRole('navigation', { name: 'Navigation principale', exact: true }).getByRole('link', { name: 'Notes', exact: true }).click()
    await page.getByRole('button', { name: 'Nouvelle note', exact: true }).click()
    await page.getByLabel('Titre', { exact: true }).fill('Note sensible')
    const text = 'PRIVATE_NOTE_SENTINEL\n<script>window.__xssSentinel = true</script>'
    await page.getByLabel('Texte de la note', { exact: true }).fill(text)
    await page.getByRole('button', { name: 'Choisir un fichier', exact: true }).click()
    await page.getByText('nouveau.txt', { exact: true }).waitFor()
    assert.equal(await page.evaluate(() => window.__calls.filter(([c]) => c === 'save_note' || c === 'create_secure_file').length), 0)
    await page.getByRole('button', { name: 'Enregistrer la note', exact: true }).click()
    await page.getByRole('button', { name: 'Ouvrir Note sensible', exact: true }).click()
    await page.getByText(text, { exact: true }).waitFor()
    assert.equal(await page.evaluate(() => window.__xssSentinel), undefined)
    await page.getByRole('button', { name: 'Exporter la pièce jointe', exact: true }).click()
    await page.waitForFunction(() => window.__calls.some(([c]) => c === 'export_note_attachment'))
    await page.getByRole('button', { name: 'Fermer', exact: true }).click()
    await page.getByRole('button', { name: 'Modifier Note sensible', exact: true }).click()
    await page.getByLabel('Texte de la note', { exact: true }).fill('PRIVATE_NOTE_SENTINEL_MODIFIED')
    await page.getByRole('button', { name: 'Détacher', exact: true }).click()
    await page.getByRole('button', { name: 'Enregistrer la note', exact: true }).click()
    await page.getByRole('button', { name: 'Modifier Note sensible', exact: true }).waitFor()
    await page.getByLabel('Rechercher dans les titres').fill('absente')
    await page.getByText('Aucune note ne correspond à ce titre.').waitFor()
    await page.getByLabel('Rechercher dans les titres').fill('')
    await page.getByRole('button', { name: 'Modifier Note sensible', exact: true }).click()
    await page.getByLabel('Titre', { exact: true }).fill('Brouillon non enregistré')
    await page.getByRole('button', { name: 'Annuler', exact: true }).click()
    await page.getByRole('button', { name: 'Abandonner', exact: true }).click()
    assert.equal(await page.getByText('Brouillon non enregistré', { exact: true }).count(), 0)
    // A reply from an old session must not reopen a plaintext view after relocking.
    await page.evaluate(() => { window.__delayRead = true })
    await page.getByRole('button', { name: 'Ouvrir Note sensible', exact: true }).click()
    await page.waitForFunction(() => !!window.__finishRead)
    await lock()
    assert.equal(await page.getByText('PRIVATE_NOTE_SENTINEL_MODIFIED', { exact: true }).count(), 0)
    await unlock()
    await nav('/notes')
    await page.evaluate(() => window.__finishRead())
    assert.equal(await page.getByRole('dialog', { name: 'Note sensible', exact: true }).count(), 0)
    assert.ok(!await page.evaluate(() => JSON.stringify([localStorage, sessionStorage])).then((s) => s.includes('PRIVATE_NOTE_SENTINEL')))
    // Read-only controls, deletion confirmation, mobile layout.
    await page.evaluate(() => { window.__readonly = true })
    await nav('/settings'); await nav('/notes')
    await page.getByText('Le coffre est en lecture seule.', { exact: true }).waitFor()
    assert.ok(await page.getByRole('button', { name: 'Nouvelle note', exact: true }).isDisabled())
    await page.evaluate(() => { window.__readonly = false })
    await nav('/settings'); await nav('/notes')
    await page.getByRole('button', { name: 'Supprimer Note sensible', exact: true }).click()
    await page.getByRole('button', { name: 'Supprimer définitivement', exact: true }).click()
    await page.getByText('Aucune note. Créez votre première note chiffrée.').waitFor()
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2))
    assert.deepEqual(errors, [])
    await page.screenshot({ path: `/private/tmp/fluxlock-notes-${width}.png`, fullPage: true })
    await page.close()
  }
  console.log('Notes : navigation, création atomique avec fichier, lecture sans HTML actif, export, modification, détachement, recherche, brouillon, verrouillage, réponse périmée, lecture seule et suppression vérifiés à 390 et 1280 px.')
} finally { await browser.close() }

import assert from 'node:assert/strict'
import { createRequire } from 'node:module'
import { mkdir } from 'node:fs/promises'

const require = createRequire(import.meta.url)
const { chromium } = require(process.env.FLUXLOCK_PLAYWRIGHT || 'playwright-core')
const baseUrl = process.env.FLUXLOCK_TEST_URL || 'http://127.0.0.1:5173'
const screenshots = process.env.FLUXLOCK_SCREENSHOTS

const browser = await chromium.launch({
  executablePath: process.env.FLUXLOCK_BROWSER,
  headless: true,
})
if (screenshots) await mkdir(screenshots, { recursive: true })

try {
  for (const [width, colorScheme] of [[320, 'dark'], [375, 'dark'], [768, 'dark'], [1280, 'dark'], [375, 'light'], [768, 'light'], [1280, 'light']]) {
    const page = await browser.newPage({ viewport: { width, height: 870 }, colorScheme, reducedMotion: 'reduce' })
    const errors = []
    page.on('pageerror', (error) => errors.push(error.message))
    await page.addInitScript(() => {
      let account = sessionStorage.getItem('test-account') !== 'absent'
      let authenticated = false
      let callbacks = 0
      let isolation = false
      let offerStatusChecks = 0
      let pairingStatusChecks = 0
      let paired = false
      const date = '2026-11-19T00:00:00Z'
      window.__calls = []
      window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} }
      window.__TAURI_INTERNALS__ = {
        transformCallback: () => ++callbacks,
        invoke: async (command, args) => {
          window.__calls.push([command, args])
          switch (command) {
            case 'init_local_db': return 'ready'
            case 'has_existing_user': return account
            case 'check_login_delay': return 0
            case 'check_biometric': return {
              enrolled: true, available: true, requires_password: false,
              enrolled_username: 'compte-test', biometric_type: 'touchid', failed_attempts: 0,
            }
            case 'local_register':
              account = true
              sessionStorage.setItem('test-account', 'present')
              authenticated = true
              return { success: true, user_id: 4, token: 'test-session', username: args.credentials.username }
            case 'local_login':
              assertCredentials(args)
              if (args.credentials.password !== 'mot de passe test') {
                return { success: false, message: 'Mot de passe incorrect' }
              }
              authenticated = true
              return { success: true, user_id: 4, token: 'test-session', username: 'compte-test' }
            case 'biometric_login':
              authenticated = true
              return { success: true, user_id: 4, token: 'test-session', username: 'compte-test' }
            case 'local_logout': authenticated = false; return
            case 'check_auto_lock': return { locked: !authenticated }
            case 'get_passwords': return [{
              id: 7, title: 'Messagerie de test', username: 'alice@example.org', password: 'fixture-secret', category: 'Travail', created_at: date,
            }]
            case 'get_secure_files': return [
              { id: 8, filename: 'Facture de test.pdf', file_size: 1248, mime_type: 'application/pdf', created_at: date },
              { id: 9, filename: 'Archive volumineuse.zip', file_size: 40 * 1024 * 1024, created_at: date },
            ]
            case 'get_secure_keys': return [
              { id: 12, key_name: 'Clé de test', key_type: 'encryption', algorithm: 'AES-256-GCM', created_at: date },
            ]
            case 'decrypt_key': return 'fixture-key'
            case 'get_user_shares': return [
              { id: 1, file_id: 8, filename: 'Lien à garder', recipient_email: 'alice@example.org', expires_at: '2100-01-01', access_count: 0, share_token: 'fixture-share-secret' },
              { id: 2, file_id: 9, filename: 'Lien expiré', recipient_email: 'bob@example.org', expires_at: '2000-01-01', access_count: 1 },
            ]
            case 'get_security_events': return [
              { id: 1, event_type: 'login', description: 'Connexion réussie', severity: 'info', timestamp: date },
              { id: 2, event_type: 'anomaly', description: 'Alerte de test', severity: 'warning', timestamp: date },
            ]
            case 'transfer_get_sync_settings': return {
              enabled: false, devices: paired ? [{ name: 'Appareil de test', verifying_key: 'peer-key', last_sync: date }] : [],
              device_verifying_key: 'key',
            }
            case 'transfer_create_offer': return { transfer_id: 'send-fixture', wormhole_code: 'code-fixture-envoi' }
            case 'transfer_start_sync_pairing': return { pairing_id: 'pair-fixture', wormhole_code: 'code-fixture-appairage' }
            case 'transfer_join_sync_pairing':
              paired = true
              return { success: true, device_name: 'Appareil de test' }
            case 'transfer_get_status':
              if (args.transferId === 'pair-fixture') {
                return { state: ++pairingStatusChecks < 2 ? 'WaitingForPeer' : 'Completed', peer_name: 'Appareil de test' }
              }
              return ++offerStatusChecks < 2 ? { state: 'WaitingForPeer' } : {
                state: 'ConfirmingSafetyNumber', safety_number: '123 456', peer_name: 'Destinataire de test',
              }
            case 'transfer_connect':
              if (args.request.wormhole_code !== 'code-fixture-réception') throw new Error('Code de test invalide')
              return { transfer_id: 'receive-fixture', safety_number: '321 654', items: [{ name: 'Facture de test.pdf' }] }
            case 'transfer_confirm_and_execute': return args.confirmed
            case 'transfer_cancel': return true
            case 'get_security_status': return { is_readonly: false, is_locked: false, threat_level: 'none', active_threats: [] }
            case 'get_filesystem_stats': return {
              total_events: 0, modifications: 0, creations: 0, deletions: 0,
              renames: 0, suspicious_extensions: 0, rapid_changes: 0,
              threat_level: 'none', monitored_paths: [], active_threats: [], monitoring_enabled: false,
            }
            case 'search_backups': return {
              backups: [{ path: '/test/archive.svbackup', metadata: { created_at: date, username: 'compte-test', device_name: 'Mac de test' } }],
            }
            case 'restore_backup': throw new Error('Mot de passe de la sauvegarde incorrect')
            case 'transfer_get_visibility': return false
            case 'get_system_security_status': return {}
            case 'get_isolation_mode': return isolation
            case 'toggle_isolation_mode': isolation = args.enabled; return 'Mode isolation modifié'
            case 'plugin:app|version': return '2.3.3'
            case 'plugin:event|listen': return 1
            default: return []
          }
        },
      }
      function assertCredentials(args) {
        if ('username' in args.credentials) throw new Error('Le login ne doit envoyer que le mot de passe')
      }
    })
    await page.goto(`${baseUrl}/login`)
    const login = page.getByRole('heading', { name: 'Déverrouiller le coffre' })
    await login.waitFor()
    const biometricButton = page.getByRole('button', { name: 'Déverrouiller avec la biométrie' })
    await biometricButton.waitFor()
    const identity = page.locator('.auth-identity')
    assert.equal(await identity.getByRole('button').count(), 1)
    assert.equal(await page.evaluate(() => document.documentElement.classList.contains('dark')), colorScheme === 'dark')
    const mark = page.locator('img[src="/fluxlock-mark.png"]')
    await mark.waitFor()
    await mark.evaluate((image) => image.decode())
    assert.ok(await mark.evaluate((image) => image.complete && image.naturalWidth > 0))
    const password = page.getByLabel('Mot de passe maître', { exact: true })
    await password.waitFor()
    if (screenshots) await page.screenshot({ path: `${screenshots}/login-${width}-${colorScheme}.png` })
    assert.equal(await page.getByLabel("Nom d'utilisateur").count(), 0)
    assert.equal(await page.getByText(/passkey/i).count(), 0)
    await password.fill('incorrect')
    await page.getByRole('button', { name: 'Déverrouiller', exact: true }).click()
    await page.getByRole('alert').getByText('Mot de passe incorrect').waitFor()
    await password.fill('mot de passe test')
    await page.getByRole('button', { name: 'Afficher le mot de passe' }).click()
    assert.equal(await password.getAttribute('type'), 'text')
    await page.getByRole('button', { name: 'Masquer le mot de passe' }).click()
    await password.fill('mot de passe test')
    await page.getByRole('button', { name: 'Déverrouiller', exact: true }).click()
    await page.getByRole('heading', { name: 'Votre coffre' }).waitFor()
    if (screenshots) await page.screenshot({ path: `${screenshots}/coffre-${width}-${colorScheme}.png` })
    if (width <= 768) {
      await page.getByRole('button', { name: 'Plus', exact: true }).click()
      await page.getByRole('dialog', { name: 'Navigation' }).waitFor()
      await page.keyboard.press('Escape')
      await page.getByRole('dialog').waitFor({ state: 'hidden' })
    }
    const routes = [
      ['/passwords', 'Mots de passe'], ['/files', 'Fichiers chiffrés'],
      ['/keys', 'Clés cryptographiques'], ['/security', 'Journal de sécurité'],
      ['/system-security', 'Protection du coffre'], ['/shares', 'Fichiers partagés'],
      ['/backup', 'Sauvegardes'], ['/transfer', 'Transférer des données'],
      ['/settings', 'Paramètres'], ['/reset-vault', 'Réinitialiser le coffre'],
    ]
    const navigate = async (route) => {
      await page.evaluate((url) => {
        history.pushState(null, '', url)
        window.dispatchEvent(new PopStateEvent('popstate'))
      }, route)
    }
    for (const [route, title] of routes) {
      await navigate(route)
      await page.getByRole('heading', { level: 1, name: title, exact: true }).waitFor({ timeout: 4000 })
        .catch((error) => { throw new Error(`${width}px ${route}. ${errors.join(' ')}. ${error.message}`) })
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)
      assert.ok(overflow <= 2, `${width}px ${route} déborde de ${overflow}px`)
    }
    await navigate('/passwords')
    await page.getByRole('button', { name: 'Modifier Messagerie de test' }).click()
    const edit = page.getByRole('dialog', { name: 'Modifier le mot de passe' })
    assert.equal(await edit.getByLabel('Mot de passe', { exact: true }).getAttribute('type'), 'password')
    await page.keyboard.press('Escape')
    await edit.waitFor({ state: 'hidden' })
    assert.ok(await page.getByRole('button', { name: 'Modifier Messagerie de test' }).evaluate((button) => button === document.activeElement))

    await navigate('/keys')
    await page.getByRole('button', { name: 'Consulter Clé de test' }).click()
    await page.getByRole('dialog', { name: 'Détails de la clé' }).waitFor()
    await page.keyboard.press('Escape')
    await page.getByRole('button', { name: 'Importer une clé', exact: true }).click()
    await page.getByLabel('Données de la clé').waitFor()
    await page.keyboard.press('Escape')

    await navigate('/files')
    await page.getByRole('button', { name: 'Exporter Facture de test.pdf' }).waitFor()
    await page.getByRole('button', { name: 'Ajouter un fichier' }).click()
    await page.getByRole('dialog', { name: 'Ajouter un fichier' }).waitFor()
    await page.keyboard.press('Escape')
    await page.locator('.workspace-header').getByRole('link', { name: 'Fichiers partagés' }).click()
    await page.getByRole('button', { name: 'Expirés', exact: true }).click()
    await page.getByText('Lien expiré', { exact: true }).waitFor()
    assert.equal(await page.getByText('Lien à garder', { exact: true }).count(), 0)
    assert.equal(await page.getByRole('button', { name: 'Copier le lien' }).count(), 0)
    assert.equal(await page.getByText(/fixture-share-secret/).count(), 0)

    await navigate('/security')
    await page.getByRole('button', { name: 'Alertes (1)' }).click()
    await page.getByText('Alerte de test', { exact: true }).waitFor()
    assert.equal(await page.getByText('Connexion réussie', { exact: true }).count(), 0)
    await page.locator('.workspace-header').getByRole('link', { name: 'Protection du coffre' }).click()
    await page.getByRole('button', { name: 'Activer la surveillance' }).waitFor()

    await navigate('/backup')
    await page.getByRole('button', { name: 'Restaurer archive.svbackup' }).click()
    const restore = page.getByRole('dialog', { name: 'Restaurer une sauvegarde' })
    await restore.getByLabel('Mot de passe de la sauvegarde').fill('mot de passe archive')
    assert.ok(await restore.getByRole('button', { name: 'Restaurer et remplacer' }).isDisabled())
    await restore.getByLabel('Mot de passe du coffre actuel').fill('mot de passe actuel')
    await restore.getByRole('button', { name: 'Restaurer et remplacer' }).click()
    await restore.getByRole('alert').waitFor()
    assert.equal(await restore.getByLabel('Mot de passe de la sauvegarde').inputValue(), '')
    assert.ok(await page.evaluate(() => window.__calls.some(([name, args]) => name === 'restore_backup' &&
      args.request.backup_path === '/test/archive.svbackup' && args.request.current_password === 'mot de passe actuel')))
    await page.keyboard.press('Escape')
    await restore.waitFor({ state: 'hidden' })
    if (screenshots) await page.screenshot({ path: `${screenshots}/sauvegardes-${width}-${colorScheme}.png` })

    await navigate('/transfer')
    assert.ok(await page.getByRole('button', { name: 'Générer le code' }).isDisabled())
    await page.locator('.workspace-panel').getByRole('button', { name: 'Fichiers', exact: true }).click()
    assert.ok(await page.getByRole('checkbox', { name: /Archive volumineuse/ }).isDisabled())
    await page.getByRole('checkbox', { name: /Facture de test/ }).check()
    await page.getByRole('button', { name: 'Générer le code' }).and(page.locator(':enabled')).waitFor()
    if (screenshots) {
      await page.evaluate(() => window.scrollTo(0, 0))
      await page.screenshot({ path: `${screenshots}/transferts-${width}-${colorScheme}.png` })
    }
    await page.getByRole('button', { name: 'Générer le code' }).click()
    await page.getByText('code-fixture-envoi').waitFor()
    await page.getByText('123 456').waitFor()
    await page.getByRole('button', { name: 'Confirmer et envoyer' }).click()
    await page.getByRole('heading', { name: 'Données envoyées' }).waitFor()
    assert.ok(await page.evaluate(() => window.__calls.some(([name, args]) => name === 'transfer_create_offer' &&
      args.request.item_type === 'files' && args.request.item_ids.join() === '8' && !args.request.cross_network)))

    const pathways = page.getByRole('navigation', { name: 'Parcours de transfert' })
    await pathways.getByRole('button', { name: 'Recevoir' }).click()
    await page.getByLabel('Code de transfert').fill('invalide')
    await page.getByRole('button', { name: 'Rejoindre le transfert' }).click()
    await page.getByRole('alert').getByText(/Code de test invalide/).waitFor()
    await page.getByLabel('Code de transfert').fill('  code-fixture-réception  ')
    await page.getByRole('button', { name: 'Rejoindre le transfert' }).click()
    await page.getByText('321 654').waitFor()
    await page.getByRole('button', { name: 'Confirmer et recevoir' }).click()
    await page.getByRole('heading', { name: 'Données reçues' }).waitFor()

    await pathways.getByRole('button', { name: 'Appareils' }).click()
    await page.getByRole('button', { name: 'Créer un code d’appairage' }).click()
    await page.getByRole('button', { name: 'Créer le code d’appairage' }).click()
    await page.getByText('code-fixture-appairage').waitFor()
    await page.getByText('est appairé.', { exact: false }).waitFor()
    await page.getByRole('button', { name: 'Terminer' }).click()
    await page.getByRole('button', { name: 'Saisir un code d’appairage' }).click()
    await page.getByLabel('Code d’appairage').fill('code-fixture-appairage')
    await page.getByRole('button', { name: 'Rejoindre l’appairage' }).click()
    await page.getByRole('button', { name: 'Retirer', exact: true }).waitFor()

    await navigate('/settings')
    if (colorScheme === 'dark') {
      const contrastBefore = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--accent'))
      await page.getByLabel('Couleur d’accent').selectOption('ocean')
      assert.notEqual(await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--accent')), contrastBefore)
      await page.getByLabel('Couleur d’accent').selectOption('default')
    }
    await page.getByLabel('Verrouiller après une période d’inactivité').uncheck()
    await page.getByRole('button', { name: 'Enregistrer le délai' }).click()
    await page.getByText('Verrouillage automatique enregistré').waitFor()
    assert.ok(await page.evaluate(() => window.__calls.some(([name, args]) => name === 'set_auto_lock_timeout' && args.minutes === 0)))
    const isolationToggle = page.getByLabel('Mode isolation')
    await isolationToggle.evaluate((element) => element.scrollIntoView({ block: 'center' }))
    await isolationToggle.click()
    await page.locator('input[type="checkbox"]:checked').and(isolationToggle).waitFor()
    await page.getByRole('link', { name: 'Gérer les appareils' }).click()
    await page.getByText('Le mode isolation bloque les transferts et l’appairage.').waitFor()
    assert.ok(await page.getByRole('button', { name: 'Créer un code d’appairage' }).isDisabled())

    await navigate('/reset-vault')
    await page.getByRole('button', { name: 'Continuer vers la confirmation' }).click()
    await page.getByLabel('Phrase de confirmation').fill('SUPPRIMER TOUT')
    assert.ok(await page.getByRole('button', { name: 'Effacer définitivement' }).isDisabled())
    await page.evaluate(() => {
      history.pushState(null, '', '/')
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    await page.getByRole('heading', { name: 'Votre coffre' }).waitFor()
    await page.getByRole('button', { name: 'Verrouiller le coffre' }).click()
    await login.waitFor()
    await biometricButton.waitFor()
    await page.getByRole('button', { name: 'Déverrouiller avec la biométrie' }).click()
    await page.getByRole('heading', { name: 'Votre coffre' }).waitFor()
    if (colorScheme === 'dark') {
      const contrast = await page.evaluate(() => {
        const css = getComputedStyle(document.documentElement)
        const luminance = (role) => {
          const hex = css.getPropertyValue(role).trim()
          const values = hex.slice(1).match(/../g).map((pair) => parseInt(pair, 16) / 255)
          const linear = values.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
          return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
        }
        return [
          ['--text-primary', '--bg-surface', 4.5], ['--text-muted', '--bg-surface', 4.5],
          ['--accent', '--text-inverse', 4.5], ['--control-border', '--bg-input', 3],
        ].map(([left, right, minimum]) => {
          const values = [luminance(left), luminance(right)].sort((a, b) => b - a)
          return { left, ratio: (values[0] + 0.05) / (values[1] + 0.05), minimum }
        })
      })
      for (const { left, ratio, minimum } of contrast) assert.ok(ratio >= minimum, `${left} contrast ${ratio}`)
    }
    assert.deepEqual(errors, [])
    await page.close()
  }

  for (const fixture of [
    { android: false, enrolled: true, blocked: false, cancel: true },
    { android: true, enrolled: true, blocked: false },
    { android: true, enrolled: true, blocked: true },
    { android: true, enrolled: false, blocked: false },
    { android: true, enrolled: true, blocked: false, missingKey: true },
    { android: false, enrolled: false, blocked: false },
  ]) {
    const page = await browser.newPage({
      viewport: { width: fixture.android ? 375 : 1280, height: 880 }, colorScheme: 'dark', reducedMotion: 'reduce',
    })
    await page.addInitScript((fixture) => {
      const session = { success: true, token: 'fixture', user_id: 4, username: 'compte-test' }
      let cancelled = false
      let stored = fixture.enrolled && !fixture.missingKey
      window.__authFlow = []
      if (fixture.android) window.AndroidBiometric = {
        isAvailable: () => true,
        hasStoredKey: (account) => stored && account === 'user_bio_compte-test',
        retrieveKey: (account, callback) => {
          window.__authFlow.push(['androidRetrieve', account])
          window.__keystoreResolve(callback, true, '', 'android-vault-key')
        },
        storeKey: (account, key, callback) => {
          window.__authFlow.push(['androidStore', account, key])
          stored = true
          window.__keystoreResolve(callback, true, '', '')
        },
      }
      window.__TAURI_INTERNALS__ = {
        transformCallback: () => 1,
        invoke: async (command, args) => {
          switch (command) {
            case 'has_existing_user': return true
            case 'check_login_delay': return 0
            case 'check_biometric': return {
              available: true, enrolled: fixture.enrolled, enrolled_username: fixture.enrolled ? 'compte-test' : null,
              requires_password: fixture.blocked,
              password_reason: fixture.blocked ? 'Verrouillage d’urgence. Saisissez votre mot de passe maître.' : null,
            }
            case 'biometric_login':
              window.__authFlow.push([command])
              if (fixture.cancel && !cancelled) {
                cancelled = true
                throw new Error('Authentification biométrique annulée.')
              }
              return session
            case 'biometric_login_with_key': window.__authFlow.push([command, args.keyB64]); return session
            case 'local_login':
              window.__authFlow.push([command])
              return args.credentials.password === 'mot de passe test' ? session : { success: false, message: 'Mot de passe incorrect' }
            case 'enable_biometric':
              window.__authFlow.push([command])
              return fixture.android ? JSON.stringify({ key_b64: 'android-vault-key' }) : 'Biométrie activée'
            case 'check_auto_lock': return { locked: false }
            default: return []
          }
        },
      }
    }, fixture)
    await page.goto(`${baseUrl}/login`)
    const canUnlock = fixture.enrolled && !fixture.missingKey
    const icon = page.getByRole('button', { name: canUnlock ? 'Déverrouiller avec la biométrie' : 'Activer la biométrie' })
    await icon.click()
    if (fixture.blocked) {
      await page.getByText(/Verrouillage d’urgence/).waitFor()
      assert.equal(await page.getByLabel('Mot de passe maître').evaluate((field) => field === document.activeElement), true)
      assert.deepEqual(await page.evaluate(() => window.__authFlow), [])
    } else {
      if (!canUnlock) {
        const unlock = page.getByRole('button', { name: 'Déverrouiller et activer' })
        await page.getByLabel('Mot de passe maître').fill('mot de passe inexact')
        await unlock.click()
        await page.getByText('Mot de passe incorrect').waitFor()
        assert.deepEqual(await page.evaluate(() => window.__authFlow), [['local_login']])
        await page.getByLabel('Mot de passe maître').fill('mot de passe test')
        await unlock.click()
      } else if (fixture.cancel) {
        await page.getByText('Authentification biométrique annulée.').waitFor()
        await icon.click()
      }
      await page.getByRole('heading', { name: 'Votre coffre' }).waitFor()
      const expected = canUnlock
        ? fixture.android ? [['androidRetrieve', 'user_bio_compte-test'], ['biometric_login_with_key', 'android-vault-key']]
          : [['biometric_login'], ['biometric_login']]
        : [['local_login'], ['local_login'], ['enable_biometric'],
          ...(fixture.android ? [['androidStore', 'user_bio_compte-test', 'android-vault-key']] : [])]
      assert.deepEqual(await page.evaluate(() => window.__authFlow), expected)
    }
    await page.close()
  }

  const page = await browser.newPage()
  await page.addInitScript(() => {
    window.__TAURI_INTERNALS__ = {
      transformCallback: () => 1,
      invoke: async (command, args) => {
        if (command === 'has_existing_user') return false
        if (command === 'local_register') {
          window.__registration = args.credentials
          return { success: true, token: 'fixture', user_id: 2, username: args.credentials.username }
        }
        return command === 'check_auto_lock' ? { locked: false } : []
      },
    }
  })
  await page.goto(`${baseUrl}/login`)
  await page.getByRole('link', { name: 'Créer mon compte' }).click()
  await page.getByLabel("Nom d'utilisateur").fill('compte-test')
  await page.getByLabel('Email').fill('exemple@example.org')
  await page.getByLabel('Mot de passe', { exact: true }).fill('mot de passe test')
  await page.getByLabel('Confirmer le mot de passe', { exact: true }).fill('mot de passe test')
  await page.getByRole('button', { name: "S'inscrire" }).click()
  await page.getByRole('heading', { name: 'Votre coffre' }).waitFor()
  assert.equal(await page.evaluate(() => window.__registration.username), 'compte-test')
  console.log('Parcours simulés de connexion, inscription, biométrie macOS et Android, restauration, transfert et navigation vérifiés de 320 à 1280 px, en modes clair et sombre.')
} finally {
  await browser.close()
}

type View = {ok: boolean; state?: string; origin?: string; fingerprint?: string; entries?: {handle: string; username: string}[]; total?: number; error?: string}
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T
let busy = false, offset = 0, polling = false, total = 0, current: View = { ok: true, state: 'idle' }
const presence = chrome.runtime.connect({ name: 'popup-lifecycle' })
presence.onDisconnect.addListener(() => { polling = false })
const copy: Record<string, {title: string; description: string; icon: string}> = {
  idle: { title: 'Remplir ce site', description: 'Authentifiez-vous dans FluXlock pour choisir votre compte.', icon: 'lock' },
  connecting: { title: 'Connexion à FluXlock…', description: 'Gardez l’application ouverte sur cet appareil.', icon: 'link' },
  pairing: { title: 'Vérifiez la connexion', description: 'Comparez l’empreinte avec celle de FluXlock, puis confirmez des deux côtés.', icon: 'link' },
  paired: { title: 'Votre navigateur est connecté.', description: 'Vous pouvez maintenant autoriser un remplissage pour ce site.', icon: 'check' },
  auth_required: { title: 'Validez dans FluXlock', description: 'Puis revenez ici pour choisir votre compte.', icon: 'lock' },
  ready: { title: 'Choisissez un compte', description: 'Seul le compte choisi sera rempli sur ce site.', icon: 'user' },
  consuming: { title: 'Remplissage en cours…', description: 'Le seul compte choisi est transmis au formulaire.', icon: 'clock' },
  filled: { title: 'Formulaire rempli', description: 'Le coffre est verrouillé. Vous pouvez vous connecter.', icon: 'check' },
  empty: { title: 'Aucun compte pour ce site', description: 'Ajoutez son URL HTTPS exacte dans FluXlock, puis réessayez.', icon: 'search' },
  expired: { title: 'Le délai est écoulé.', description: 'Pour protéger vos identifiants, autorisez une nouvelle demande dans FluXlock.', icon: 'clock' },
  error: { title: 'Remplissage interrompu', description: 'Vérifiez que FluXlock est ouvert, puis réessayez.', icon: 'alert' },
}
function render(view: View, focusAccounts = false) {
  current = view
  const state = view.ok ? view.state || 'idle' : 'error'
  const content = copy[state] || copy.idle
  document.body.dataset.state = state
  total = view.total || 0
  element('state-title').textContent = content.title
  element('status').textContent = content.description
  element('state-icon').setAttribute('href', `#i-${content.icon}`)
  element('state-symbol').parentElement!.dataset.state = state
  element('origin').textContent = view.origin || 'Ouvrez une page HTTPS'
  element('error').textContent = view.error || ''
  element('error-panel').hidden = !view.error
  const ready = state === 'ready', pairing = state === 'pairing'
  const step = ready ? 2 : ['consuming', 'filled'].includes(state) ? 3 : 1
  element('steps').hidden = pairing
  for (const item of document.querySelectorAll<HTMLElement>('[data-step]')) {
    const index = Number(item.dataset.step), complete = index < step || state === 'filled'
    item.dataset.complete = String(complete)
    item.querySelector('span')!.textContent = complete ? '✓' : String(index)
    if (index === step) item.setAttribute('aria-current', 'step'); else item.removeAttribute('aria-current')
  }
  const accounts = element('accounts'), entries = view.entries || []
  // Polling a ready list must not recreate its controls and steal keyboard focus.
  const signature = JSON.stringify(entries)
  if (accounts.dataset.signature !== signature) {
    accounts.replaceChildren(); accounts.dataset.signature = signature
    const template = element<HTMLTemplateElement>('account-template')
    for (const entry of entries) {
      const fragment = template.content.cloneNode(true) as DocumentFragment
      const button = fragment.querySelector('button')!
      fragment.querySelector('.avatar')!.textContent = Array.from(entry.username.trim())[0]?.toLocaleUpperCase('fr') || '@'
      fragment.querySelector('.account-name')!.textContent = entry.username || 'Compte sans identifiant'
      button.setAttribute('aria-label', `Remplir avec ${entry.username || 'ce compte'}`)
      button.addEventListener('click', () => void call({ op: 'fill', handle: entry.handle }))
      accounts.append(fragment)
    }
  }
  element('account-section').hidden = !ready
  element('count').textContent = `${total} compte${total > 1 ? 's' : ''}`
  element('pagination').hidden = !ready || total <= 10
  element('page-label').textContent = `${offset + 1}–${Math.min(offset + entries.length, total)} sur ${total}`
  element<HTMLButtonElement>('previous').disabled = offset === 0
  element<HTMLButtonElement>('next').disabled = offset + 10 >= total
  element('fingerprint-panel').hidden = !pairing
  element('fingerprint').textContent = pairing ? view.fingerprint || '' : ''
  element('confirm').hidden = !pairing
  element('start').hidden = ['pairing', 'auth_required', 'ready', 'connecting', 'consuming'].includes(state)
  element('cancel').hidden = !['pairing', 'auth_required', 'ready'].includes(state)
  element('start-label').textContent = state === 'filled' ? 'Remplir à nouveau' : ['empty', 'expired', 'error'].includes(state) ? 'Réessayer' : 'Autoriser dans FluXlock'
  element('security-note').querySelector('span')!.textContent = ready ? 'Une utilisation, puis verrouillage.' : 'Authentification dans FluXlock.'
  polling = view.ok && ['pairing', 'auth_required', 'ready'].includes(state)
  element<HTMLButtonElement>('connect').disabled = ['pairing', 'auth_required', 'ready', 'consuming', 'connecting'].includes(state)
  if (focusAccounts && ready) accounts.querySelector('button')?.focus({ preventScroll: true })
}
function setBusy(value: boolean) {
  busy = value
  element('main').setAttribute('aria-busy', String(value))
  for (const button of document.querySelectorAll<HTMLButtonElement>('button')) {
    if (value) button.setAttribute('aria-disabled', 'true'); else button.removeAttribute('aria-disabled')
  }
}
async function call(message: Record<string, unknown>) {
  if (busy) return
  const previousState = current.state, previousOrigin = current.origin
  if (message.op === 'start') { offset = 0; render({ ok: true, state: 'connecting', origin: previousOrigin }) }
  if (message.op === 'fill') render({ ...current, state: 'consuming' })
  setBusy(true)
  try {
    const result = await chrome.runtime.sendMessage(message) as View
    if (result.ok && message.op === 'list') offset = Number(message.offset)
    const keepOrigin = !result.ok || ['filled', 'paired'].includes(result.state || '')
    const view = { ...result, origin: result.origin || (keepOrigin ? previousOrigin : undefined) }
    render(view, view.state === 'ready' && (previousState !== 'ready' || message.op === 'list'))
  } catch { render({ ok: false, origin: previousOrigin, error: 'L’extension est indisponible. Fermez puis rouvrez cette fenêtre.' }) }
  finally { setBusy(false) }
}
document.addEventListener('click', (event) => {
  if (busy && (event.target as Element).closest('button')) { event.preventDefault(); event.stopImmediatePropagation() }
}, true)
element('start').addEventListener('click', () => void call({ op: 'start' }))
element('connect').addEventListener('click', () => void call({ op: 'start' }))
element('confirm').addEventListener('click', () => void call({ op: 'pair_confirm' }))
element('cancel').addEventListener('click', () => void call({ op: 'cancel' }))
element('previous').addEventListener('click', () => void call({ op: 'list', offset: Math.max(0, offset - 10) }))
element('next').addEventListener('click', () => void call({ op: 'list', offset: offset + 10 }))
const resetDialog = element<HTMLDialogElement>('reset-dialog')
element('reset').addEventListener('click', () => resetDialog.showModal())
resetDialog.addEventListener('close', () => {
  element('reset').focus()
  if (resetDialog.returnValue === 'confirm') void call({ op: 'reset' })
})
setInterval(() => { if (polling && !resetDialog.open) void call({ op: 'status' }) }, 1000)
void call({ op: 'status' })

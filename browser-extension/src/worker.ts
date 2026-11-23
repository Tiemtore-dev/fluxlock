import { Channel, type Message } from './channel.js'
import { canonicalOrigin } from './origin.js'
import { hex } from './noise.js'
import { resetIdentity } from './identity.js'
import { formAction } from './form.js'

type Target = {origin: string; tab_id: number; frame_id: number; document_id: string; nonce: string}
type Candidate = {handle: string; username: string}
let channel: Channel | undefined
let requestId: string | undefined
let target: Target | undefined
let entries: Candidate[] = []
let total = 0
let state = 'idle'
let fingerprint = ''
let deadline: ReturnType<typeof setTimeout> | undefined
let queue: Promise<unknown> = Promise.resolve()
function purge() {
  clearTimeout(deadline); deadline = undefined
  channel?.close(); channel = undefined; requestId = undefined; target = undefined; entries = []; total = 0; fingerprint = ''
}
function expire(milliseconds: number) { clearTimeout(deadline); deadline = setTimeout(() => { purge(); state = 'expired' }, milliseconds) }
async function getTarget(): Promise<Target> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
  if (!tab || typeof tab.id !== 'number' || typeof tab.url !== 'string') throw new Error('Ouvrez une page HTTPS')
  const origin = canonicalOrigin(tab.url)
  const results = await chrome.scripting.executeScript({ target: { tabId: tab.id, frameIds: [0] }, world: 'ISOLATED',
    func: () => ({ origin: location.origin }) })
  const result = results?.[0]
  if (!result?.documentId || result.frameId !== 0 || result.result?.origin !== origin) throw new Error('Document non vérifiable')
  return { origin, tab_id: tab.id, frame_id: 0, document_id: result.documentId, nonce: hex(crypto.getRandomValues(new Uint8Array(32))) }
}
async function verifyTarget() {
  if (!target) throw new Error('Demande absente')
  const tab = await chrome.tabs.get(target.tab_id)
  if (!tab.active || canonicalOrigin(tab.url || '') !== target.origin) throw new Error('Le site a changé. Recommencez.')
  const results = await chrome.scripting.executeScript({ target: { tabId: target.tab_id, documentIds: [target.document_id] }, world: 'ISOLATED', func: formAction, args: [target.origin] })
  const result = results?.[0]
  if (result?.documentId !== target.document_id || !['password', 'username'].includes(result.result?.mode)) throw new Error('Formulaire incompatible')
  return result.result.mode as 'password' | 'username'
}
function snapshot() { return { state, fingerprint, origin: target?.origin, entries, total } }
async function start() {
  purge(); state = 'connecting'; target = await getTarget()
  channel = new Channel(); await channel.open()
  fingerprint = channel.fingerprint
  if (channel.welcome.state === 'pairing') { state = 'pairing'; expire(60000); return snapshot() }
  const response = await channel.request({ op: 'begin_fill', target })
  if (typeof response.request_id !== 'string' || response.state !== 'auth_required') throw new Error('Demande native refusée')
  requestId = response.request_id; state = 'auth_required'; expire(60000)
  return snapshot()
}
async function status() {
  if (!channel || !['pairing', 'auth_required', 'ready'].includes(state)) {
    // Preview metadata only; no handshake, authentication or credential lookup.
    let origin: string | undefined
    try { const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); origin = canonicalOrigin(tab?.url || '') } catch { /* non-HTTPS/privileged page */ }
    return { ...snapshot(), origin }
  }
  if (target) {
    const tab = await chrome.tabs.get(target.tab_id)
    if (canonicalOrigin(tab.url || '') !== target.origin) throw new Error('Le site a changé')
  }
  const response = await channel.request({ op: 'status', request_id: requestId ?? null })
  if (state === 'pairing' && response.state === 'paired') {
    await channel.rememberPeer(); purge(); state = 'paired'; return snapshot()
  }
  if (state === 'auth_required' && response.state === 'ready') { state = 'ready'; expire(30000); return list(0) }
  return snapshot()
}
async function list(offset: number) {
  if (!channel || !requestId || state !== 'ready' || !Number.isInteger(offset) || offset < 0 || offset > 128) throw new Error('Demande expirée')
  await verifyTarget()
  const response = await channel.request({ op: 'list_candidates', request_id: requestId, offset })
  if (response.state !== 'ready' || !Array.isArray(response.entries) || response.entries.length > 10 || typeof response.total !== 'number' || response.total > 128) throw new Error('Liste refusée')
  entries = response.entries.map((entry: unknown) => {
    const e = entry as Candidate
    if (!e || Object.keys(e).length !== 2 || !/^[0-9a-f]{64}$/u.test(e.handle) || typeof e.username !== 'string' || e.username.length > 1024) throw new Error('Compte refusé')
    return { handle: e.handle, username: e.username }
  })
  total = response.total
  if (!total) { await cancel(); state = 'empty' }
  return snapshot()
}
async function cancel() {
  try { if (channel && requestId) await channel.request({ op: 'cancel', request_id: requestId }) } finally { purge(); state = 'idle' }
}
async function fill(handle: string) {
  if (!channel || !requestId || !target || state !== 'ready') throw new Error('Authentification requise')
  const candidate = entries.find((entry) => entry.handle === handle)
  if (!candidate) throw new Error('Compte absent de la liste')
  state = 'consuming'
  const mode = await verifyTarget()
  const destination = { ...target }
  let response: Message | undefined
  try {
    if (mode === 'username') {
      // First step of a multi-page login: never request a password that cannot
      // yet be inserted. Cancel the native key before filling the username.
      await channel.request({ op: 'cancel', request_id: requestId })
      response = { username: candidate.username }
    } else {
      response = await channel.request({ op: 'select_and_fill', request_id: requestId, handle, target: destination })
      if (response.state !== 'fill_once' || response.request_id !== requestId || typeof response.password !== 'string' || response.password.length > 16384 || response.username !== candidate.username) throw new Error('Réponse de remplissage refusée')
    }
    await verifyTarget()
    const credentials = { username: String(response.username), ...(typeof response.password === 'string' ? { password: response.password } : {}) }
    try {
      const results = await chrome.scripting.executeScript({ target: { tabId: destination.tab_id, documentIds: [destination.document_id] }, world: 'ISOLATED', func: formAction, args: [destination.origin, credentials] })
      if (!results?.[0]?.result?.filled) throw new Error('Le document n’a pas été rempli')
    } finally { credentials.username = ''; credentials.password = undefined }
    state = 'filled'
  } finally { if (response) { response.password = undefined; response.username = undefined } purge() }
  return snapshot()
}
async function handle(message: Record<string, unknown>) {
  switch (message.op) {
    case 'start': return start()
    case 'status': return status()
    case 'list': return list(Number(message.offset))
    case 'fill': return fill(String(message.handle))
    case 'pair_confirm': if (!channel || state !== 'pairing') throw new Error('Appairage absent'); await channel.request({ op: 'pair_confirm' }); return snapshot()
    case 'cancel': await cancel(); return snapshot()
    case 'reset': await cancel(); await resetIdentity(); return snapshot()
    default: throw new Error('Commande refusée')
  }
}
chrome.runtime.onMessage.addListener((message: unknown, sender: {id?: string; url?: string; tab?: unknown}, respond: (value: unknown) => void) => {
  if (sender.id !== chrome.runtime.id || sender.tab || sender.url !== chrome.runtime.getURL('popup.html')) return false
  const operation = async () => {
    try {
      if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error('Message refusé')
      respond({ ok: true, ...(await handle(message as Record<string, unknown>)) })
    } catch (e) { purge(); state = 'error'; respond({ ok: false, error: e instanceof Error ? e.message : 'Demande refusée' }) }
  }
  queue = queue.then(operation, operation)
  return true
})
chrome.runtime.onConnect.addListener((port: any) => {
  const sender = port.sender
  if (port.name !== 'popup-lifecycle' || sender?.id !== chrome.runtime.id || sender.tab || sender.url !== chrome.runtime.getURL('popup.html')) {
    port.disconnect(); return
  }
  port.onDisconnect.addListener(() => {
    if (state !== 'ready') return // Preserve the bounded native-auth focus handoff.
    const currentChannel = channel, currentRequest = requestId
    const closeSelection = async () => {
      if (channel !== currentChannel || requestId !== currentRequest || state !== 'ready') return
      try { await cancel() } catch { purge(); state = 'expired' }
    }
    queue = queue.then(closeSelection, closeSelection)
  })
})
chrome.tabs.onRemoved.addListener((id: number) => { if (target?.tab_id === id) { purge(); state = 'expired' } })
chrome.tabs.onUpdated.addListener((id: number, info: {url?: string; status?: string}) => { if (target?.tab_id === id && (info.url || info.status === 'loading')) { purge(); state = 'expired' } })

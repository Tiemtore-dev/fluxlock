import { Channel, type Message } from './channel.js'
import { canonicalOrigin } from './origin.js'
import { hex } from './noise.js'
import { resetIdentity } from './identity.js'
import { formAction, cardFormAction, captureFormAction, passkeyFormAction } from './form.js'

type Target = {origin: string; tab_id: number; frame_id: number; document_id: string; nonce: string}
type Candidate = {handle: string; username: string}
let channel: Channel | undefined
let requestId: string | undefined
let target: Target | undefined
let entries: Candidate[] = []
let total = 0
let state = 'idle'
let flowMode: 'login' | 'card' | 'save' | 'passkey' = 'login'
let fingerprint = ''
let deadline: ReturnType<typeof setTimeout> | undefined
let queue: Promise<unknown> = Promise.resolve()
function purge() {
  clearTimeout(deadline); deadline = undefined
  channel?.close(); channel = undefined; requestId = undefined; target = undefined; entries = []; total = 0; fingerprint = ''; flowMode = 'login'
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
  purge(); state = 'connecting'; flowMode = 'login'; target = await getTarget()
  channel = new Channel(); await channel.open()
  fingerprint = channel.fingerprint
  if (channel.welcome.state === 'pairing') { state = 'pairing'; expire(60000); return snapshot() }
  const response = await channel.request({ op: 'begin_fill', target })
  if (typeof response.request_id !== 'string' || response.state !== 'auth_required') throw new Error('Demande native refusée')
  requestId = response.request_id; state = 'auth_required'; expire(60000)
  return snapshot()
}
async function startCard() {
  purge(); state = 'connecting'; flowMode = 'card'; target = await getTarget()
  channel = new Channel(); await channel.open()
  fingerprint = channel.fingerprint
  if (channel.welcome.state === 'pairing') { state = 'pairing'; expire(60000); return snapshot() }
  const response = await channel.request({ op: 'begin_card_fill', target })
  if (typeof response.request_id !== 'string' || response.state !== 'auth_required') throw new Error('Demande native carte refusée')
  requestId = response.request_id; state = 'auth_required'; expire(60000)
  return snapshot()
}
async function saveCaptured() {
  purge(); state = 'connecting'; flowMode = 'save'; target = await getTarget()
  const results = await chrome.scripting.executeScript({
    target: { tabId: target.tab_id, documentIds: [target.document_id] },
    world: 'ISOLATED',
    func: captureFormAction,
    args: [target.origin],
  })
  const captured = results?.[0]?.result
  if (!captured || typeof captured.password !== 'string' || !captured.password) {
    throw new Error('Aucun mot de passe saisi sur cette page HTTPS')
  }
  channel = new Channel(); await channel.open()
  fingerprint = channel.fingerprint
  if (channel.welcome.state === 'pairing') { state = 'pairing'; expire(60000); return snapshot() }
  try {
    const response = await channel.request({
      op: 'propose_save',
      target,
      username: String(captured.username || ''),
      password: captured.password,
    })
    if (typeof response.request_id !== 'string' || response.state !== 'auth_required') throw new Error('Demande d’enregistrement refusée')
    requestId = response.request_id; state = 'auth_required'; expire(60000)
    return snapshot()
  } finally {
    captured.password = ''
  }
}
async function startPasskey() {
  purge(); state = 'connecting'; flowMode = 'passkey'; target = await getTarget()
  const results = await chrome.scripting.executeScript({
    target: { tabId: target.tab_id, documentIds: [target.document_id] },
    world: 'ISOLATED',
    func: passkeyFormAction,
    args: [target.origin],
  })
  const info = results?.[0]?.result
  if (!info || typeof info.rp_id !== 'string' || typeof info.challenge_b64url !== 'string') {
    throw new Error('Contexte WebAuthn Passkey non vérifiable sur cette page HTTPS')
  }
  channel = new Channel(); await channel.open()
  fingerprint = channel.fingerprint
  if (channel.welcome.state === 'pairing') { state = 'pairing'; expire(60000); return snapshot() }
  const response = await channel.request({
    op: 'begin_passkey',
    target,
    rp_id: info.rp_id,
    rp_name: String(info.rp_name || info.rp_id),
    username: String(info.username || ''),
    challenge_b64url: info.challenge_b64url,
  })
  if (typeof response.request_id !== 'string' || response.state !== 'auth_required') {
    throw new Error('Demande Passkey WebAuthn refusée')
  }
  requestId = response.request_id; state = 'auth_required'; expire(60000)
  return snapshot()
}
async function completePasskey() {
  if (!channel || !requestId || !target) throw new Error('Session Passkey expirée')
  const destination = { ...target }
  state = 'consuming'
  try {
    const resp = await channel.request({ op: 'complete_passkey', request_id: requestId, target: destination })
    if (resp.state !== 'passkey_once' || resp.request_id !== requestId || typeof resp.credential_id_b64url !== 'string') {
      throw new Error('Réponse Passkey WebAuthn invalide')
    }
    const payload = {
      mode: (resp.mode === 'create' ? 'create' : 'get') as 'create' | 'get',
      credential_id_b64url: String(resp.credential_id_b64url),
      rp_id: String(resp.rp_id || ''),
      user_name: String(resp.user_name || ''),
      user_handle_b64url: typeof resp.user_handle_b64url === 'string' ? resp.user_handle_b64url : undefined,
      public_key_b64url: typeof resp.public_key_b64url === 'string' ? resp.public_key_b64url : undefined,
      cose_public_key_b64url: typeof resp.cose_public_key_b64url === 'string' ? resp.cose_public_key_b64url : undefined,
      authenticator_data_b64url: String(resp.authenticator_data_b64url || ''),
      client_data_json_b64url: String(resp.client_data_json_b64url || ''),
      signature_b64url: typeof resp.signature_b64url === 'string' ? resp.signature_b64url : undefined,
    }
    const results = await chrome.scripting.executeScript({
      target: { tabId: destination.tab_id, documentIds: [destination.document_id] },
      world: 'ISOLATED',
      func: passkeyFormAction,
      args: [destination.origin, payload],
    })
    if (!results?.[0]?.result?.completed) throw new Error('La cérémonie Passkey n’a pas pu être transmise à la page')
    state = payload.mode === 'create' ? 'passkey_created' : 'passkey_authenticated'
  } finally {
    purge()
  }
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
  if (state === 'auth_required' && response.state === 'saved') {
    purge(); state = 'saved'; return snapshot()
  }
  if (state === 'auth_required' && response.state === 'passkey_ready') {
    return completePasskey()
  }
  if (state === 'auth_required' && response.state === 'ready') { state = 'ready'; expire(30000); return list(0) }
  return snapshot()
}
async function list(offset: number) {
  if (!channel || !requestId || state !== 'ready' || !Number.isInteger(offset) || offset < 0 || offset > 128) throw new Error('Demande expirée')
  if (flowMode === 'card') {
    const tab = await chrome.tabs.get(target!.tab_id)
    if (!tab.active || canonicalOrigin(tab.url || '') !== target!.origin) throw new Error('Le site a changé. Recommencez.')
  } else {
    await verifyTarget()
  }
  const listOp = flowMode === 'card' ? 'list_card_candidates' : 'list_candidates'
  const response = await channel.request({ op: listOp, request_id: requestId, offset })
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
  const destination = { ...target }
  if (flowMode === 'card') {
    let cardResp: Message | undefined
    try {
      cardResp = await channel.request({ op: 'select_and_fill_card', request_id: requestId, handle, target: destination })
      if (cardResp.state !== 'fill_card_once' || cardResp.request_id !== requestId || typeof cardResp.card_number !== 'string') {
        throw new Error('Réponse de remplissage carte refusée')
      }
      const cardData = {
        cardholder_name: String(cardResp.cardholder_name || ''),
        card_number: String(cardResp.card_number),
        exp_month: String(cardResp.exp_month || ''),
        exp_year: String(cardResp.exp_year || ''),
        cvv: String(cardResp.cvv || ''),
        brand: String(cardResp.brand || ''),
      }
      try {
        const results = await chrome.scripting.executeScript({
          target: { tabId: destination.tab_id, documentIds: [destination.document_id] },
          world: 'ISOLATED',
          func: cardFormAction,
          args: [destination.origin, cardData],
        })
        if (!results?.[0]?.result?.filled) throw new Error('Le formulaire de carte n’a pas été rempli')
      } finally {
        cardData.card_number = ''; cardData.cvv = ''; cardData.cardholder_name = ''
      }
      state = 'filled'
    } finally {
      if (cardResp) { cardResp.card_number = undefined; cardResp.cvv = undefined }
      purge()
    }
    return snapshot()
  }
  const mode = await verifyTarget()
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
    case 'start_card': return startCard()
    case 'start_passkey': return startPasskey()
    case 'save_captured': return saveCaptured()
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

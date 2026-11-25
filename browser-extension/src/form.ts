// Serialized by chrome.scripting.executeScript into the isolated world.
// No closure, no page messaging, no secret returned in the result.
export function formAction(expectedOrigin: string, credentials?: { username: string; password?: string }) {
  if (location.origin !== expectedOrigin || window.top !== window.self) throw new Error('Document ou origine différente')
  const visible = (input: HTMLInputElement) => {
    const box = input.getBoundingClientRect()
    if (input.disabled || input.readOnly || box.width < 16 || box.height < 10 || box.bottom <= 0 || box.right <= 0 || box.top >= innerHeight || box.left >= innerWidth) return false
    for (let el: HTMLElement | null = input; el; el = el.parentElement) {
      const style = getComputedStyle(el)
      if (style.visibility !== 'visible' || style.display === 'none' || style.pointerEvents === 'none' || Number(style.opacity) < 0.2) return false
    }
    return true
  }
  // WHATWG HTML §4.10.18.7.1: autocomplete attribute may contain space-separated tokens (e.g. "section-login current-password")
  const tokens = (input: HTMLInputElement) => (input.getAttribute('autocomplete') || input.autocomplete || '').trim().toLowerCase().split(/\s+/).filter(Boolean)
  const hasToken = (input: HTMLInputElement, name: string) => tokens(input).includes(name)
  const isSearchBox = (input: HTMLInputElement) =>
    hasToken(input, 'search') || input.getAttribute('role') === 'searchbox' || /^(q|query|search|s)$/i.test(input.name || '')

  const all = Array.from(document.querySelectorAll<HTMLInputElement>('input')).filter(visible)
  if (all.some((input) => hasToken(input, 'new-password'))) throw new Error('Un formulaire de création de mot de passe ne sera pas rempli')
  const allPasswords = all.filter((input) => input.type === 'password')
  const activePw = allPasswords.find((input) => input === document.activeElement)
  const currentPws = allPasswords.filter((input) => hasToken(input, 'current-password'))
  const passwords = allPasswords.length > 1
    ? (activePw ? [activePw] : currentPws.length === 1 ? currentPws : allPasswords)
    : allPasswords
  if (passwords.length > 1) throw new Error('Plusieurs champs de mot de passe : remplissage refusé')
  const password = passwords[0]
  const form = password?.form
  const usernames = all.filter((input) => ['text', 'email'].includes(input.type) && (!password || input.form === form) &&
    !isSearchBox(input) && !hasToken(input, 'one-time-code') && !hasToken(input, 'new-password'))
  const preferred = usernames.filter((input) => hasToken(input, 'username') || hasToken(input, 'email') || input.type === 'email' || input.inputMode === 'email')
  const matches = preferred.length ? preferred : usernames
  if (matches.length > 1 || (!password && matches.length !== 1)) throw new Error('Champ email ou identifiant ambigu')
  const username = matches[0]
  const effectiveForm = form || username?.form
  if (effectiveForm) {
    if (new URL(effectiveForm.action || location.href, location.href).origin !== expectedOrigin || effectiveForm.method.toLowerCase() !== 'post') {
      throw new Error('Destination de formulaire refusée')
    }
    for (const control of document.querySelectorAll<HTMLButtonElement | HTMLInputElement>('button, input[type="submit"], input[type="image"]')) {
      if (control.form !== effectiveForm) continue
      const overrideAction = control.getAttribute('formaction')
      const overrideMethod = control.getAttribute('formmethod')
      if ((overrideAction && new URL(overrideAction, location.href).origin !== expectedOrigin) || (overrideMethod && overrideMethod.toLowerCase() !== 'post')) {
        throw new Error('Destination de formulaire refusée')
      }
    }
  }
  const mode = password ? 'password' : 'username'
  if (!credentials) return { mode }
  if (mode === 'password' && typeof credentials.password !== 'string') throw new Error('Mot de passe absent')
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
  if (!setter) throw new Error('Champ incompatible')
  const applyValue = (el: HTMLInputElement, val: string) => {
    const tracker = (el as HTMLInputElement & { _valueTracker?: { setValue(v: string): void } })._valueTracker
    if (tracker) tracker.setValue(el.value)
    setter.call(el, val)
    el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true }))
  }
  if (username) applyValue(username, credentials.username)
  if (password && typeof credentials.password === 'string') applyValue(password, credentials.password)
  return { filled: true, mode }
}

// Serialized by chrome.scripting.executeScript into the isolated world.
// Captures a newly created or entered password from a login or registration form on the active HTTPS origin.
export function captureFormAction(expectedOrigin: string) {
  if (location.origin !== expectedOrigin || window.top !== window.self) throw new Error('Document ou origine différente')
  const visible = (input: HTMLInputElement) => {
    const box = input.getBoundingClientRect()
    if (input.disabled || input.readOnly || box.width < 16 || box.height < 10 || box.bottom <= 0 || box.right <= 0 || box.top >= innerHeight || box.left >= innerWidth) return false
    for (let el: HTMLElement | null = input; el; el = el.parentElement) {
      const style = getComputedStyle(el)
      if (style.visibility !== 'visible' || style.display === 'none' || style.pointerEvents === 'none' || Number(style.opacity) < 0.2) return false
    }
    return true
  }
  const tokens = (input: HTMLInputElement) => (input.getAttribute('autocomplete') || input.autocomplete || '').trim().toLowerCase().split(/\s+/).filter(Boolean)
  const hasToken = (input: HTMLInputElement, name: string) => tokens(input).includes(name)
  const isSearchBox = (input: HTMLInputElement) =>
    hasToken(input, 'search') || input.getAttribute('role') === 'searchbox' || /^(q|query|search|s)$/i.test(input.name || '')

  const all = Array.from(document.querySelectorAll<HTMLInputElement>('input')).filter(visible)
  const pwFields = all.filter((input) => input.type === 'password' && input.value.trim().length > 0)
  if (!pwFields.length) throw new Error('Saisissez d’abord votre mot de passe sur la page avant de l’enregistrer dans FluXlock')

  // Priority to registration/password-creation fields (new-password), otherwise current login password
  const newPwFields = pwFields.filter((input) => hasToken(input, 'new-password'))
  let chosenPw = pwFields[0]
  if (newPwFields.length >= 2) {
    if (newPwFields[0].value !== newPwFields[1].value) {
      throw new Error('Les champs de confirmation du nouveau mot de passe ne correspondent pas')
    }
    chosenPw = newPwFields[0]
  } else if (newPwFields.length === 1) {
    chosenPw = newPwFields[0]
  } else if (pwFields.length === 2 && pwFields[0].value === pwFields[1].value) {
    chosenPw = pwFields[0]
  }

  const form = chosenPw.form
  const userCandidates = all.filter((input) =>
    ['text', 'email', 'tel'].includes(input.type) &&
    (!form || input.form === form) &&
    !isSearchBox(input) &&
    !hasToken(input, 'one-time-code') &&
    input.value.trim().length > 0
  )
  const preferred = userCandidates.filter((input) =>
    hasToken(input, 'username') || hasToken(input, 'email') || input.type === 'email' || /user|mail|login|account|id/i.test(input.name || input.id || '')
  )
  const usernameInput = preferred[0] || userCandidates[0]
  return {
    username: usernameInput ? usernameInput.value.trim() : '',
    password: chosenPw.value,
    isNewPassword: newPwFields.length > 0,
  }
}

// Serialized by chrome.scripting.executeScript into the isolated world.
// Detects and fills WHATWG HTML §4.10.18.7.1 payment card fields (cc-name, cc-number, cc-exp, cc-exp-month, cc-exp-year, cc-csc).
export function cardFormAction(
  expectedOrigin: string,
  card?: { cardholder_name: string; card_number: string; exp_month: string; exp_year: string; cvv: string; brand?: string }
) {
  if (location.origin !== expectedOrigin || window.top !== window.self) throw new Error('Document ou origine différente')
  const visible = (el: HTMLElement) => {
    const box = el.getBoundingClientRect()
    if ((el as HTMLInputElement).disabled || (el as HTMLInputElement).readOnly || box.width < 16 || box.height < 10) return false
    for (let cur: HTMLElement | null = el; cur; cur = cur.parentElement) {
      const style = getComputedStyle(cur)
      if (style.visibility !== 'visible' || style.display === 'none' || Number(style.opacity) < 0.2) return false
    }
    return true
  }
  const controls = Array.from(document.querySelectorAll<HTMLInputElement | HTMLSelectElement>('input, select')).filter(visible)
  const tokens = (el: HTMLElement) => (el.getAttribute('autocomplete') || '').trim().toLowerCase().split(/\s+/).filter(Boolean)
  const matchesAttr = (el: HTMLInputElement | HTMLSelectElement, tokenList: string[], regex: RegExp) => {
    const t = tokens(el)
    if (tokenList.some((tk) => t.includes(tk))) return true
    const attr = `${el.name || ''} ${el.id || ''} ${(el as HTMLInputElement).placeholder || ''}`
    return regex.test(attr)
  }

  const ccNumber = controls.find((el): el is HTMLInputElement => el.tagName === 'INPUT' && matchesAttr(el, ['cc-number'], /card.?num|cc.?num|pan|numero.?carte/i))
  if (!ccNumber) throw new Error('Aucun champ de carte bancaire (cc-number) détecté sur cette page HTTPS')
  if (!card) return { mode: 'card' as const }

  const ccName = controls.find((el): el is HTMLInputElement => el.tagName === 'INPUT' && matchesAttr(el, ['cc-name'], /card.?holder|cc.?name|name.?on.?card|titulaire/i))
  const ccExp = controls.find((el): el is HTMLInputElement => el.tagName === 'INPUT' && matchesAttr(el, ['cc-exp'], /cc.?exp|exp.?date|mm\s*\/\s*yy/i) && !matchesAttr(el, ['cc-exp-month', 'cc-exp-year'], /month|year|mois|annee/i))
  const ccMonth = controls.find((el) => matchesAttr(el, ['cc-exp-month'], /cc.?exp.?month|exp.?month|card.?month/i))
  const ccYear = controls.find((el) => matchesAttr(el, ['cc-exp-year'], /cc.?exp.?year|exp.?year|card.?year/i))
  const ccCsc = controls.find((el): el is HTMLInputElement => el.tagName === 'INPUT' && matchesAttr(el, ['cc-csc'], /cvv|cvc|csc|security.?code|cryptogramme/i))

  const inputSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
  const selectSetter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value')?.set
  const apply = (el: HTMLInputElement | HTMLSelectElement, val: string) => {
    const tracker = (el as HTMLElement & { _valueTracker?: { setValue(v: string): void } })._valueTracker
    if (tracker) tracker.setValue(el.value)
    if (el.tagName === 'SELECT' && selectSetter) {
      const sel = el as HTMLSelectElement
      const opt = Array.from(sel.options).find((o) => o.value === val || o.value === val.slice(-2) || o.value === String(Number(val)))
      selectSetter.call(sel, opt ? opt.value : val)
    } else if (inputSetter) {
      inputSetter.call(el, val)
    }
    el.dispatchEvent(new Event('input', { bubbles: true }))
    el.dispatchEvent(new Event('change', { bubbles: true }))
  }

  apply(ccNumber, card.card_number)
  if (ccName) apply(ccName, card.cardholder_name)
  const yy = card.exp_year.slice(-2)
  const yyyy = card.exp_year.length === 2 ? `20${card.exp_year}` : card.exp_year
  if (ccExp) {
    const maxLen = ccExp.maxLength > 0 ? ccExp.maxLength : 5
    apply(ccExp, maxLen >= 7 ? `${card.exp_month}/${yyyy}` : `${card.exp_month}/${yy}`)
  }
  if (ccMonth) apply(ccMonth, card.exp_month)
  if (ccYear) {
    const maxLen = ccYear.tagName === 'INPUT' && (ccYear as HTMLInputElement).maxLength === 2 ? 2 : 4
    apply(ccYear, maxLen === 2 ? yy : yyyy)
  }
  if (ccCsc) apply(ccCsc, card.cvv)
  return { filled: true, mode: 'card' as const }
}

// Serialized by chrome.scripting.executeScript into the isolated world.
// Zero-Friction WebAuthn Level 3 Passkey discovery & assertion/attestation delivery.
export function passkeyFormAction(
  expectedOrigin: string,
  responsePayload?: {
    mode: 'create' | 'get'
    credential_id_b64url: string
    rp_id: string
    user_name: string
    user_handle_b64url?: string
    public_key_b64url?: string
    cose_public_key_b64url?: string
    authenticator_data_b64url: string
    client_data_json_b64url: string
    signature_b64url?: string
  }
) {
  if (location.origin !== expectedOrigin || window.top !== window.self) throw new Error('Document ou origine différente')
  const rpId = location.hostname.toLowerCase()
  if (!rpId) throw new Error('Domaine Relying Party (rp_id) invalide')

  const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input'))
  const userField = inputs.find((el) => {
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase()
    return !el.disabled && !el.readOnly && (ac.includes('webauthn') || ac.includes('username') || el.type === 'email')
  })

  if (!responsePayload) {
    const challengeEl = document.querySelector<HTMLElement>('[data-webauthn-challenge]')
    let challenge = challengeEl?.dataset.webauthnChallenge || ''
    if (!challenge) {
      const rand = crypto.getRandomValues(new Uint8Array(32))
      let bin = ''
      for (let i = 0; i < rand.length; i++) bin += String.fromCharCode(rand[i])
      challenge = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    }
    return {
      rp_id: rpId,
      rp_name: (document.title || rpId).slice(0, 128),
      username: userField ? userField.value.trim() : '',
      challenge_b64url: challenge,
    }
  }

  if (responsePayload.rp_id.toLowerCase() !== rpId) {
    throw new Error('Violation anti-phishing : rp_id Passkey différent du domaine actif')
  }

  if (userField && responsePayload.user_name && !userField.value.trim()) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set
    if (setter) {
      const tracker = (userField as HTMLInputElement & { _valueTracker?: { setValue(v: string): void } })._valueTracker
      if (tracker) tracker.setValue(userField.value)
      setter.call(userField, responsePayload.user_name)
      userField.dispatchEvent(new Event('input', { bubbles: true }))
      userField.dispatchEvent(new Event('change', { bubbles: true }))
    }
  }

  document.dispatchEvent(
    new CustomEvent('fluxlock:webauthn-passkey', {
      detail: {
        mode: responsePayload.mode,
        id: responsePayload.credential_id_b64url,
        rawId: responsePayload.credential_id_b64url,
        type: 'public-key',
        rpId: responsePayload.rp_id,
        response: {
          authenticatorData: responsePayload.authenticator_data_b64url,
          clientDataJSON: responsePayload.client_data_json_b64url,
          signature: responsePayload.signature_b64url,
          userHandle: responsePayload.user_handle_b64url,
          publicKey: responsePayload.public_key_b64url,
          cosePublicKey: responsePayload.cose_public_key_b64url,
        },
      },
    })
  )

  return { completed: true, mode: responsePayload.mode }
}

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
  const all = Array.from(document.querySelectorAll<HTMLInputElement>('input')).filter(visible)
  if (all.some((input) => input.autocomplete === 'new-password')) throw new Error('Un formulaire de création de mot de passe ne sera pas rempli')
  const passwords = all.filter((input) => input.type === 'password')
  if (passwords.length > 1) throw new Error('Plusieurs champs de mot de passe : remplissage refusé')
  const password = passwords[0]
  const form = password?.form
  const usernames = all.filter((input) => ['text', 'email'].includes(input.type) && (!password || input.form === form) &&
    !['search', 'one-time-code', 'new-password'].includes(input.autocomplete))
  const preferred = usernames.filter((input) => ['username', 'email'].includes(input.autocomplete) || input.type === 'email')
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
  if (username) {
    setter.call(username, credentials.username)
    username.dispatchEvent(new Event('input', { bubbles: true })); username.dispatchEvent(new Event('change', { bubbles: true }))
  }
  if (password) {
    setter.call(password, credentials.password)
    password.dispatchEvent(new Event('input', { bubbles: true })); password.dispatchEvent(new Event('change', { bubbles: true }))
  }
  return { filled: true, mode }
}

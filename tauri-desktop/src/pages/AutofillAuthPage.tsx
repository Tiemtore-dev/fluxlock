import { useEffect, useState, type FormEvent } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { Button, Input } from '../design-system/atoms'

export default function AutofillAuthPage() {
  const requestId = new URLSearchParams(location.search).get('request') || ''
  const [prompt, setPrompt] = useState<{ kind: 'fill' | 'pair'; origin?: string; fingerprint: string }>()
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    let active = true
    const refresh = () => invoke<typeof prompt>('autofill_prompt', { requestId }).then((value) => { if (active) setPrompt(value) }).catch((e) => {
      if (active) { setPassword(''); setPrompt(undefined); setError(String(e)) }
    })
    void refresh()
    const timer = setInterval(() => void refresh(), 1000)
    return () => { active = false; clearInterval(timer) }
  }, [requestId])
  async function authenticate(biometric = false) {
    setBusy(true); setError('')
    try { await invoke('autofill_authenticate', { requestId, password: biometric ? null : password }) }
    catch (e) { setError(String(e)) }
    finally { setPassword(''); setBusy(false) }
  }
  async function confirmPair() {
    setBusy(true); setError('')
    try { await invoke('autofill_confirm_pair', { requestId }) }
    catch (e) { setError(String(e)) }
    finally { setBusy(false) }
  }
  async function cancel() { try { await invoke('autofill_cancel_native', { requestId }) } catch (e) { setError(String(e)) } }
  function submit(event: FormEvent) { event.preventDefault(); void authenticate() }
  return <main className="workspace workspace-stack" style={{ padding: 28 }}>
    <h1>FluXlock</h1>
    {prompt?.kind === 'pair' ? <>
      <h2>Connecter un navigateur</h2>
      <p>Comparez cette empreinte avec celle affichée par votre extension. Confirmez seulement si elles sont identiques.</p>
      <code style={{ overflowWrap: 'anywhere', fontSize: 18 }}>{prompt.fingerprint}</code>
      <Button disabled={busy} onClick={() => void confirmPair()}>Les empreintes sont identiques</Button>
    </> : prompt ? <form className="workspace-stack" onSubmit={submit}>
      <h2>Autoriser un remplissage</h2>
      <p>Site exact : <strong style={{ overflowWrap: 'anywhere' }}>{prompt.origin}</strong></p>
      <p>Confirmez votre identité ici, puis choisissez votre compte dans l’extension. Le coffre se verrouillera automatiquement.</p>
      <Input label="Mot de passe maître" type="password" autoComplete="off" autoFocus required value={password}
        disabled={busy} onChange={(event) => setPassword(event.target.value)} />
      <Button type="submit" loading={busy} disabled={!password}>Authentifier cette demande</Button>
      <Button type="button" variant="secondary" disabled={busy} onClick={() => void authenticate(true)}>Utiliser la biométrie de l’appareil</Button>
    </form> : <p role="status">Vérification de la demande…</p>}
    {error && <p role="alert" className="workspace-error">{error}</p>}
    <Button variant="secondary" disabled={busy} onClick={() => void cancel()}>Annuler</Button>
  </main>
}

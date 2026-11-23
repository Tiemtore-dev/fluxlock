import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { invoke } from '../lib/vault-context'
import { Button } from '../design-system/atoms'

export default function BrowserSettings() {
  const client = useQueryClient()
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const status = useQuery({ queryKey: ['browser-settings'], queryFn: () => invoke<{ enabled: boolean; listening: boolean; profiles: { public: string; name: string }[] }>('autofill_settings'), refetchInterval: 3000 })
  async function action(command: string, args?: Record<string, unknown>) {
    setBusy(true); setError(''); setMessage('')
    try {
      await invoke(command, args)
      if (command === 'autofill_start_pairing') setMessage('Pendant 60 secondes, ouvrez l’extension et cliquez sur Connecter. Comparez les empreintes dans les deux fenêtres.')
      await client.invalidateQueries({ queryKey: ['browser-settings'] })
    } catch (e) { setError(String(e)) }
    finally { setBusy(false) }
  }
  return <section className="workspace-panel workspace-stack" aria-labelledby="browser-title">
    <h2 id="browser-title">Extension de navigateur</h2>
    <p>Chaque remplissage demande une nouvelle authentification dans FluXlock. Seuls les comptes du site exact sont proposés dans l’extension.</p>
    <p>Le canal utilise une protection hybride post-quantique. Les anciens profils doivent être reconnectés après cette mise à jour.</p>
    {status.data?.enabled ? <>
      <p>{status.data.listening ? 'Passerelle locale active.' : 'Passerelle locale indisponible.'}</p>
      {!status.data.listening && <Button variant="secondary" disabled={busy} onClick={() => void action('autofill_enable')}>Relancer la passerelle</Button>}
      <Button variant="secondary" disabled={busy || !status.data.listening} onClick={() => void action('autofill_start_pairing')}>Connecter un navigateur</Button>
      {status.data.profiles.map((profile) => <div className="workspace-actions" key={profile.public}>
        <span>{profile.name} · {profile.public.slice(0, 12)}</span>
        <Button variant="secondary" disabled={busy} onClick={() => void action('autofill_revoke', { public: profile.public })}>Révoquer ce profil</Button>
      </div>)}
    </> : <Button variant="secondary" disabled={busy || status.isPending} onClick={() => void action('autofill_enable')}>Activer la passerelle locale</Button>}
    {message && <p role="status">{message}</p>}
    {(error || status.isError) && <p role="alert" className="workspace-error">{error || String(status.error)}</p>}
  </section>
}

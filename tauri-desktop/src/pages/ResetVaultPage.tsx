import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Trash2 } from 'lucide-react'
import { invoke } from '@tauri-apps/api/core'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input } from '../design-system/atoms'
import { useAuthStore } from '../stores/authStore'

const CONFIRMATION = 'SUPPRIMER TOUT'

export default function ResetVaultPage() {
  const navigate = useNavigate()
  const clearAuth = useAuthStore((state) => state.clearAuth)
  const [confirming, setConfirming] = useState(false)
  const [confirmText, setConfirmText] = useState('')
  const [password, setPassword] = useState('')
  const [isResetting, setIsResetting] = useState(false)
  const [error, setError] = useState('')
  const ready = confirmText === CONFIRMATION && !!password && !isResetting

  async function reset(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!ready) return
    setIsResetting(true)
    setError('')
    try {
      await invoke('reset_vault_completely', { password })
      await clearAuth()
      navigate('/register', { replace: true })
    } catch (reason) {
      setError(String(reason))
      setPassword('')
    } finally {
      setIsResetting(false)
    }
  }

  return (
    <WorkspacePage title="Réinitialiser le coffre"
      actions={<Link to="/settings" className="workspace-link">Retour aux paramètres</Link>}>
      {confirming ? (
        <form className="workspace-panel workspace-stack max-w-xl" onSubmit={reset}>
          <h2>Confirmer la suppression</h2>
          <p>Saisissez <strong>{CONFIRMATION}</strong> puis le mot de passe du coffre actuel.</p>
          <Input label="Phrase de confirmation" value={confirmText} onChange={(event) => setConfirmText(event.target.value)}
            autoComplete="off" autoCapitalize="characters" spellCheck={false} disabled={isResetting} required />
          <Input label="Mot de passe maître" type="password" value={password} onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password" disabled={isResetting} required />
          {error && <p className="workspace-error" role="alert">{error}</p>}
          <div className="workspace-actions">
            <Button variant="secondary" disabled={isResetting} onClick={() => {
              setConfirmText('')
              setPassword('')
              setError('')
              setConfirming(false)
            }}>Retour</Button>
            <Button variant="danger" icon={Trash2} type="submit" loading={isResetting} disabled={!ready}>Effacer définitivement</Button>
          </div>
        </form>
      ) : (
        <section className="workspace-panel workspace-stack max-w-xl">
          <h2>Supprimer les données de cet appareil</h2>
          <p className="workspace-danger">Le compte, les identifiants, les fichiers chiffrés, les clés et l’historique local seront supprimés.</p>
          <p>Créez une sauvegarde avant de continuer si vous souhaitez conserver une copie.</p>
          <div className="workspace-actions">
            <Link to="/backup" className="workspace-link">Ouvrir les sauvegardes</Link>
            <Button variant="danger" onClick={() => setConfirming(true)}>Continuer vers la confirmation</Button>
          </div>
        </section>
      )}
    </WorkspacePage>
  )
}

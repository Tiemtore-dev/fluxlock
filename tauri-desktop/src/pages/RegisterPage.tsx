import { useState, type FormEvent } from 'react'
import { useNavigate, Link, useSearchParams } from 'react-router-dom'
import { Lock, Mail, User, Archive, Plus, Eye, EyeOff } from 'lucide-react'
import { auth, vaults } from '../lib/vault-service'
import { useAuthStore } from '../stores/authStore'
import { Button, Input } from '../design-system/atoms'
import { PasswordStrength } from '../design-system/molecules'

export default function RegisterPage() {
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const selectedVault = useAuthStore((state) => state.selectedVault)
  const configure = params.get('configure') === '1' && !!selectedVault
  const { setAuth, setSelectedVault, dbReady, locking } = useAuthStore()
  const [name, setName] = useState(configure ? selectedVault?.name || '' : '')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const [visible, setVisible] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending || locking || !dbReady) return
    setError('')
    if (password !== confirmPassword) { setError('Les mots de passe ne correspondent pas'); return }
    if (Array.from(password).length < 12) { setError('Le mot de passe doit contenir au moins 12 caractères'); return }
    setPending(true)
    try {
      const result = configure && selectedVault
        ? { vault: selectedVault, auth: await auth.register(username, email, password) }
        : await vaults.create({ name, username, email, password })
      const response = result.auth
      if (!response.success || !response.token || response.user_id == null || !response.username) {
        throw new Error(response.message || 'Impossible de créer le coffre')
      }
      setSelectedVault(result.vault)
      setAuth({ id: String(response.user_id), username: response.username, email: response.email || '' }, response.token)
      navigate('/', { replace: true })
    } catch (reason) { setError(String(reason instanceof Error ? reason.message : reason)) }
    finally { setPassword(''); setConfirmPassword(''); setVisible(false); setPending(false) }
  }

  return <main className="auth-page">
    <div className="auth-page-inner">
      <div className="auth-unlock auth-card">
        <div className="auth-brand"><img src="/fluxlock-mark.png" alt="" width={52} height={52} />FluXlock</div>
        <h1>Créer votre coffre</h1>
        <p className="auth-notice">Chaque coffre possède son propre mot de passe maître. Un seul coffre peut être déverrouillé à la fois.</p>
        <form onSubmit={submit} className="workspace-stack">
          <Input label="Nom du coffre" icon={Archive} value={name} onChange={(event) => setName(event.target.value)}
            maxLength={80} placeholder="Personnel, Travail…" autoComplete="off" required autoFocus disabled={pending || locking || configure} />
          <p className="auth-notice">Ce nom est visible dans la liste des coffres verrouillés.</p>
          <Input label="Nom d’utilisateur" icon={User} value={username} onChange={(event) => setUsername(event.target.value)}
            autoComplete="username" maxLength={256} required disabled={pending || locking} />
          <Input label="Email" type="email" icon={Mail} value={email} onChange={(event) => setEmail(event.target.value)}
            autoComplete="email" maxLength={320} required disabled={pending || locking} />
          <div>
            <Input label="Mot de passe maître" type={visible ? 'text' : 'password'} icon={Lock}
              iconRight={visible ? EyeOff : Eye} onIconRightClick={() => setVisible(!visible)}
              iconRightLabel={visible ? 'Masquer le mot de passe' : 'Afficher le mot de passe'}
              value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password"
              required disabled={pending || locking} />
            <PasswordStrength password={password} />
            <p className="auth-notice">Minimum 12 caractères.</p>
          </div>
          <Input label="Confirmer le mot de passe" type="password" icon={Lock} value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" required disabled={pending || locking} />
          {error && <p className="auth-error" role="alert">{error}</p>}
          <Button type="submit" fullWidth size="lg" loading={pending} disabled={!dbReady || locking || pending} icon={Plus}>Créer le coffre</Button>
        </form>
        {!pending && <Link className="auth-primary-link" to="/login">Retour aux coffres</Link>}
      </div>
    </div>
  </main>
}

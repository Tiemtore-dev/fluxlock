import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Lock, Mail, User, AlertTriangle, UserPlus } from 'lucide-react'
import { auth } from '../lib/vault-service'
import { useAuthStore } from '../stores/authStore'
import { Button, Input, Spinner } from '../design-system/atoms'
import { PasswordStrength } from '../design-system/molecules'

export default function RegisterPage() {
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)

  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [hasUser, setHasUser] = useState(false)
  const [checkingUser, setCheckingUser] = useState(true)

  useEffect(() => {
    auth.hasExistingUser().then((exists) => {
      setHasUser(exists)
      setCheckingUser(false)
    })
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (password !== confirmPassword) { setError('Les mots de passe ne correspondent pas'); return }
    if (password.length < 12) { setError('Le mot de passe doit contenir au moins 12 caractères'); return }

    setIsLoading(true)
    try {
      const res = await auth.register(username, email, password)
      if (res.success && res.token) {
        setAuth({ id: res.user_id?.toString() || '1', username, email }, res.token, res.token)
        navigate('/')
      } else {
        setError(res.message || "Erreur lors de l'inscription")
      }
    } catch (err: any) {
      setError(err.message || "Erreur lors de l'inscription")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-page-inner animate-fade-in" style={{ maxWidth: 400 }}>
        {/* Brand */}
        <div style={{ textAlign: 'center', marginBottom: 'var(--space-10)' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: 56, height: 56, borderRadius: 'var(--radius-xl)',
            background: 'var(--accent)', boxShadow: 'var(--shadow-glow)',
            marginBottom: 'var(--space-5)',
          }}>
            <Lock size={24} style={{ color: 'var(--text-inverse)' }} />
          </div>
          <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', letterSpacing: 'var(--tracking-tight)' }}>
            FluXlock
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', marginTop: 'var(--space-1)' }}>
            Créer un nouveau compte
          </p>
        </div>

        {/* Card */}
        <div className="auth-card">
          {checkingUser ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--space-10)' }}>
              <Spinner size={32} />
            </div>
          ) : hasUser ? (
            <div>
              <div style={{
                padding: 'var(--space-5)', borderRadius: 'var(--radius-lg)',
                background: 'var(--warning-muted)', border: '1px solid var(--warning)',
                display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-5)',
              }}>
                <AlertTriangle size={20} style={{ color: 'var(--warning)', flexShrink: 0, marginTop: 2 }} />
                <div>
                  <p style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
                    Appareil déjà enregistré
                  </p>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', marginTop: 'var(--space-2)' }}>
                    Cet appareil possède déjà un compte. Chaque appareil ne peut avoir qu'un seul utilisateur.
                  </p>
                </div>
              </div>
              <Link to="/login" style={{ textDecoration: 'none' }}>
                <Button fullWidth>Retour à la connexion</Button>
              </Link>
            </div>
          ) : (
            <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <Input label="Nom d'utilisateur" icon={User} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="johndoe" required autoFocus />
              <Input label="Email" type="email" icon={Mail} value={email} onChange={(e) => setEmail(e.target.value)} placeholder="john@example.com" required />
              <div>
                <Input label="Mot de passe" type="password" icon={Lock} value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••••••" required />
                <div style={{ marginTop: 'var(--space-2)' }}>
                  <PasswordStrength password={password} />
                </div>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', marginTop: 'var(--space-1)' }}>
                  Minimum 12 caractères
                </p>
              </div>
              <Input label="Confirmer le mot de passe" type="password" icon={Lock} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} placeholder="••••••••••••" required />

              {error && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                  padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                  background: 'var(--danger-muted)', border: '1px solid var(--danger)',
                  fontSize: 'var(--text-sm)', color: 'var(--danger)', fontFamily: 'var(--font-body)',
                }}>
                  <AlertTriangle size={16} />
                  {error}
                </div>
              )}

              <Button type="submit" fullWidth size="lg" loading={isLoading} icon={UserPlus}>
                S'inscrire
              </Button>
            </form>
          )}

          {!checkingUser && !hasUser && (
            <p style={{ textAlign: 'center', marginTop: 'var(--space-5)', fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)' }}>
              Vous avez déjà un compte ?{' '}
              <Link to="/login" style={{ color: 'var(--accent-text)', fontWeight: 500, textDecoration: 'none' }}>Se connecter</Link>
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

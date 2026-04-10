import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Lock, User, AlertTriangle, LogIn, Fingerprint, Info, Loader2 } from 'lucide-react'
import { auth, biometric, type BiometricStatus } from '../lib/vault-service'
import { useAuthStore } from '../stores/authStore'
import { Button, Input } from '../design-system/atoms'
import { hasAndroidBiometric, androidBiometricAvailable, androidAuthenticate, hasAndroidKeystore, androidKeystoreRetrieve } from '../lib/android-biometric'

export default function LoginPage() {
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)
  const dbReady = useAuthStore((state) => state.dbReady)

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loginDelay, setLoginDelay] = useState(0)
  const [remainingTime, setRemainingTime] = useState(0)
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [biometricLoading, setBiometricLoading] = useState(false)
  const [bioStatus, setBioStatus] = useState<BiometricStatus | null>(null)
  const biometricTriggered = useRef(false)

  // Derived: can the user use biometric for this username?
  const canUseBiometric =
    bioStatus?.available &&
    bioStatus?.enrolled &&
    !bioStatus?.requires_password &&
    username.trim().length > 0 &&
    bioStatus?.enrolled_username?.toLowerCase() === username.trim().toLowerCase()

  // Derived: show biometric button but as disabled with reason
  const showBiometricSection =
    bioStatus?.available &&
    bioStatus?.enrolled &&
    username.trim().length > 0 &&
    bioStatus?.enrolled_username?.toLowerCase() === username.trim().toLowerCase()

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`
  }

  useEffect(() => {
    if (remainingTime <= 0) return
    const t = setInterval(() => {
      setRemainingTime((p) => {
        if (p <= 1) { setLoginDelay(0); setError(''); return 0 }
        return p - 1
      })
    }, 1000)
    return () => clearInterval(t)
  }, [remainingTime])

  // Check biometric availability on mount
  useEffect(() => {
    biometric.checkStatus().then((status) => {
      // On Android, override availability from the native BiometricPrompt bridge
      if (hasAndroidBiometric()) {
        status.available = androidBiometricAvailable()
        if (status.available && status.biometric_type === 'none') {
          status.biometric_type = 'fingerprint'
        }
      }
      setBioStatus(status)
    })
  }, [])

  // Pre-fill username if biometric is enrolled
  useEffect(() => {
    if (bioStatus?.enrolled && bioStatus.enrolled_username && !username) {
      setUsername(bioStatus.enrolled_username)
    }
  }, [bioStatus])

  const handleBiometricLogin = useCallback(async () => {
    const trimmed = username.trim()
    if (!trimmed) {
      setError("Entrez votre nom d'utilisateur avant d'utiliser la biométrie.")
      return
    }
    setError('')
    setInfo('')
    setBiometricLoading(true)
    try {
      let res
      // On Android with Keystore: retrieve key from TEE/StrongBox (triggers BiometricPrompt)
      // then pass it to the Rust backend directly — no file-based key storage needed.
      if (hasAndroidKeystore()) {
        const account = `user_bio_${trimmed.toLowerCase()}`
        const keyB64 = await androidKeystoreRetrieve(account)
        res = await biometric.loginWithKey(trimmed, keyB64)
      } else {
        // On Android without Keystore (fallback): show BiometricPrompt then use Rust backend
        if (hasAndroidBiometric()) {
          await androidAuthenticate('Connectez-vous à FluXlock')
        }
        res = await biometric.login(trimmed)
      }
      if (res.success && res.token) {
        if (res.email) localStorage.setItem('userEmail', res.email)
        setAuth(
          { id: res.user_id?.toString() || '1', username: res.message || trimmed, email: res.email || '' },
          res.token,
          res.token,
        )
        navigate('/')
      } else {
        setError(res.message || 'Échec de la connexion biométrique')
      }
    } catch (err: any) {
      const msg = err?.toString() || ''
      setError(msg || 'Échec de la connexion biométrique')
      // Refresh status to get updated failed_attempts / requires_password
      biometric.checkStatus().then(setBioStatus)
    } finally {
      setBiometricLoading(false)
    }
  }, [username, navigate, setAuth])

  // Auto-trigger biometric if enrolled + allowed + username matches (ONCE only)
  useEffect(() => {
    if (
      !biometricTriggered.current &&
      bioStatus?.available &&
      bioStatus?.enrolled &&
      !bioStatus?.requires_password &&
      bioStatus?.enrolled_username &&
      username.trim().toLowerCase() === bioStatus.enrolled_username.toLowerCase() &&
      document.visibilityState === 'visible'
    ) {
      biometricTriggered.current = true
      handleBiometricLogin()
    }
  }, [bioStatus, username])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setInfo('')
    setIsLoading(true)
    try {
      const res = await auth.login(username, password)
      if (res.success && res.token) {
        if (res.email) localStorage.setItem('userEmail', res.email)
        setAuth(
          { id: res.user_id?.toString() || '1', username, email: res.email || `${username}@local.app` },
          res.token,
          res.token,
        )
        navigate('/')
      } else {
        const delay = await auth.checkLoginDelay(username).catch(() => 0)
        if (delay > 0) {
          setLoginDelay(delay)
          setRemainingTime(delay)
          setError(`Trop de tentatives. Attente : ${formatTime(delay)}`)
        } else {
          setError(res.message || 'Identifiants incorrects')
        }
      }
    } catch (err: any) {
      const msg = typeof err === 'string' ? err : (err?.message || 'Erreur de connexion')
      setError(msg)
    } finally {
      setIsLoading(false)
    }
  }

  const locked = loginDelay > 0 && remainingTime > 0

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-void)',
      padding: 'var(--space-6)',
    }}>
      <div className="animate-fade-in" style={{ width: '100%', maxWidth: 400 }}>
        {/* Brand */}
        <div style={{ textAlign: 'center', marginBottom: 'var(--space-10)' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 56,
            height: 56,
            borderRadius: 'var(--radius-xl)',
            background: 'var(--accent)',
            boxShadow: 'var(--shadow-glow)',
            marginBottom: 'var(--space-5)',
          }}>
            <Lock size={24} style={{ color: 'var(--text-inverse)' }} />
          </div>
          <h1 style={{
            fontFamily: 'var(--font-display)',
            fontSize: 'var(--text-3xl)',
            color: 'var(--text-primary)',
            letterSpacing: 'var(--tracking-tight)',
          }}>
            FluXlock
          </h1>
          <p style={{
            fontSize: 'var(--text-sm)',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-body)',
            marginTop: 'var(--space-1)',
          }}>
            Connexion sécurisée à votre coffre-fort
          </p>
        </div>

        {/* Card */}
        <div style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-xl)',
          padding: 'var(--space-8)',
        }}>
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
            {!dbReady ? (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-3)', padding: 'var(--space-6)' }}>
                <Loader2 size={28} style={{ color: 'var(--accent)', animation: 'spin 1s linear infinite' }} />
                <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)', margin: 0 }}>Initialisation du coffre-fort…</p>
              </div>
            ) : (
            <>
            <Input
              label="Nom d'utilisateur"
              icon={User}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Entrez votre nom d'utilisateur"
              required
              autoFocus
              disabled={locked}
            />

            {/* Password field — always shown, user always has the option to type password */}
            <Input
              label="Mot de passe"
              type="password"
              icon={Lock}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              disabled={locked}
            />

            {/* Rate-limit countdown */}
            {locked && (
              <div style={{
                padding: 'var(--space-5)',
                borderRadius: 'var(--radius-lg)',
                background: 'var(--warning-muted)',
                border: '1px solid var(--warning)',
                textAlign: 'center',
              }}>
                <p style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--warning)', fontFamily: 'var(--font-body)' }}>
                  Trop de tentatives échouées
                </p>
                <p style={{
                  fontSize: 'var(--text-2xl)',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  color: 'var(--warning)',
                  margin: 'var(--space-3) 0',
                }}>
                  {formatTime(remainingTime)}
                </p>
                <div style={{ height: 3, borderRadius: 'var(--radius-full)', background: 'var(--bg-hover)', overflow: 'hidden' }}>
                  <div style={{
                    height: '100%',
                    width: `${(remainingTime / loginDelay) * 100}%`,
                    background: 'var(--warning)',
                    transition: 'width 1s linear',
                  }} />
                </div>
              </div>
            )}

            {/* Error */}
            {error && !locked && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                padding: 'var(--space-3)',
                borderRadius: 'var(--radius-md)',
                background: 'var(--danger-muted)',
                border: '1px solid var(--danger)',
                fontSize: 'var(--text-sm)',
                color: 'var(--danger)',
                fontFamily: 'var(--font-body)',
              }}>
                <AlertTriangle size={16} />
                {error}
              </div>
            )}

            {/* Info (password reason from biometric gate) */}
            {info && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-2)',
                padding: 'var(--space-3)',
                borderRadius: 'var(--radius-md)',
                background: 'color-mix(in srgb, var(--accent) 10%, transparent)',
                border: '1px solid var(--accent)',
                fontSize: 'var(--text-sm)',
                color: 'var(--accent-text)',
                fontFamily: 'var(--font-body)',
              }}>
                <Info size={16} />
                {info}
              </div>
            )}

            <Button
              type="submit"
              fullWidth
              size="lg"
              loading={isLoading}
              disabled={locked || !dbReady}
              icon={LogIn}
            >
              Se connecter
            </Button>
            </>
            )}
          </form>

          {/* Biometric login — only shown if enrolled for this username */}
          {showBiometricSection && (
            <div style={{ marginTop: 'var(--space-4)' }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
                marginBottom: 'var(--space-3)',
              }}>
                <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)' }}>ou</span>
                <div style={{ flex: 1, height: 1, background: 'var(--border)' }} />
              </div>

              {bioStatus?.requires_password && (
                <p style={{
                  fontSize: 'var(--text-xs)',
                  color: 'var(--text-muted)',
                  fontFamily: 'var(--font-body)',
                  textAlign: 'center',
                  marginBottom: 'var(--space-2)',
                }}>
                  {bioStatus.password_reason || 'Mot de passe requis'}
                </p>
              )}

              <button
                onClick={handleBiometricLogin}
                disabled={!canUseBiometric || biometricLoading || locked}
                style={{
                  width: '100%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 'var(--space-3)',
                  padding: 'var(--space-3) var(--space-4)',
                  borderRadius: 'var(--radius-lg)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-hover)',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-body)',
                  fontSize: 'var(--text-sm)',
                  fontWeight: 500,
                  cursor: !canUseBiometric || biometricLoading || locked ? 'not-allowed' : 'pointer',
                  opacity: !canUseBiometric || biometricLoading || locked ? 0.4 : 1,
                  transition: 'all var(--transition-fast)',
                }}
              >
                <Fingerprint size={20} style={{ color: canUseBiometric ? 'var(--accent)' : 'var(--text-muted)' }} />
                {biometricLoading
                  ? 'Authentification...'
                  : bioStatus?.biometric_type === 'touchid'
                    ? `Vault · Touch ID${bioStatus?.failed_attempts ? ` (${bioStatus.failed_attempts}/3)` : ''}`
                    : bioStatus?.biometric_type === 'faceid'
                      ? `Vault · Face ID${bioStatus?.failed_attempts ? ` (${bioStatus.failed_attempts}/3)` : ''}`
                      : 'Déverrouiller avec biométrie'}
              </button>
            </div>
          )}

          {/* Links */}
          <div style={{ marginTop: 'var(--space-5)', textAlign: 'center', display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            <Link to="/reset-vault" style={{
              fontSize: 'var(--text-xs)',
              color: 'var(--danger)',
              fontFamily: 'var(--font-body)',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 'var(--space-1)',
              textDecoration: 'none',
            }}>
              <AlertTriangle size={12} />
              Mot de passe oublié ? Réinitialiser le coffre-fort
            </Link>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)' }}>
              Pas encore de compte ?{' '}
              <Link to="/register" style={{ color: 'var(--accent-text)', fontWeight: 500, textDecoration: 'none' }}>
                Créer un compte
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

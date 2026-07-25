import { useState, useEffect, useCallback, useRef } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Lock, User, AlertTriangle, LogIn, Fingerprint, Info, Loader2, Eye, EyeOff, KeyRound } from 'lucide-react'
import { auth, biometric, passkey, type BiometricStatus, type PasskeyStatus } from '../lib/vault-service'
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
  const [showPassword, setShowPassword] = useState(false)
  const [biometricLoading, setBiometricLoading] = useState(false)
  const [bioStatus, setBioStatus] = useState<BiometricStatus | null>(null)
  const biometricTriggered = useRef(false)

  // ─── Passkey state ───
  const [passkeyStatus, setPasskeyStatus] = useState<PasskeyStatus | null>(null)
  const [passkeyLoading, setPasskeyLoading] = useState(false)
  const passkeyTriggered = useRef(false)

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

  // Derived: can the user use passkey for this username?
  const canUsePasskey =
    passkeyStatus?.enrolled &&
    !passkeyStatus?.needs_password_reminder &&
    username.trim().length > 0 &&
    passkeyStatus?.enrolled_username?.toLowerCase() === username.trim().toLowerCase()

  const showPasskeySection =
    passkeyStatus?.enrolled &&
    username.trim().length > 0 &&
    passkeyStatus?.enrolled_username?.toLowerCase() === username.trim().toLowerCase()

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

  // Check biometric and passkey availability on mount
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
    passkey.checkStatus().then(setPasskeyStatus)
  }, [])

  // Pre-fill username if biometric or passkey is enrolled
  useEffect(() => {
    if (bioStatus?.enrolled && bioStatus.enrolled_username && !username) {
      setUsername(bioStatus.enrolled_username)
    } else if (passkeyStatus?.enrolled && passkeyStatus.enrolled_username && !username) {
      setUsername(passkeyStatus.enrolled_username)
    }
  }, [bioStatus, passkeyStatus])

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

  // ─── Passkey login handler ───
  const handlePasskeyLogin = useCallback(async () => {
    const trimmed = username.trim()
    if (!trimmed) {
      setError("Entrez votre nom d'utilisateur avant d'utiliser la passkey.")
      return
    }
    setError('')
    setInfo('')
    setPasskeyLoading(true)
    try {
      let res
      if (hasAndroidKeystore()) {
        const account = `passkey_ed25519_${trimmed.toLowerCase()}`
        const keyB64 = await androidKeystoreRetrieve(account)
        res = await passkey.login(trimmed, keyB64)
      } else {
        res = await passkey.login(trimmed)
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
        setError(res.message || 'Échec de la connexion passkey')
      }
    } catch (err: any) {
      const msg = err?.toString() || ''
      setError(msg || 'Échec de la connexion passkey')
      passkey.checkStatus().then(setPasskeyStatus)
    } finally {
      setPasskeyLoading(false)
    }
  }, [username, navigate, setAuth])

  // Auto-trigger passkey if enrolled + allowed + username matches (ONCE only)
  // Priority: passkey > biometric (passkey has no cold start restriction)
  useEffect(() => {
    if (
      !passkeyTriggered.current &&
      passkeyStatus?.enrolled &&
      !passkeyStatus?.needs_password_reminder &&
      passkeyStatus?.enrolled_username &&
      username.trim().toLowerCase() === passkeyStatus.enrolled_username.toLowerCase() &&
      document.visibilityState === 'visible'
    ) {
      passkeyTriggered.current = true
      biometricTriggered.current = true // prevent biometric from also auto-triggering
      handlePasskeyLogin()
    }
  }, [passkeyStatus, username])

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
    <div className="auth-page flex items-center justify-center min-h-screen p-4 sm:p-6 w-full">
      <div className="auth-page-inner animate-fade-in w-full max-w-md">
        {/* Brand */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-accent shadow-[0_0_30px_rgba(var(--accent-rgb),0.3)] mb-5">
            <Lock size={24} className="text-tx-inverse" />
          </div>
          <h1 className="font-display text-3xl sm:text-4xl text-tx-primary tracking-tight m-0">
            FluXlock
          </h1>
          <p className="text-sm text-tx-muted font-body mt-2 m-0">
            Connexion sécurisée à votre coffre-fort
          </p>
        </div>

        {/* Card */}
        <div className="auth-card bg-surface border border-bd rounded-2xl p-6 sm:p-8 shadow-sm">
          <form onSubmit={handleSubmit} className="flex flex-col gap-5">
            {!dbReady ? (
              <div className="flex flex-col items-center gap-3 p-6">
                <Loader2 size={28} className="text-accent animate-spin" />
                <p className="text-tx-muted text-sm m-0">Initialisation du coffre-fort…</p>
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
              type={showPassword ? 'text' : 'password'}
              icon={Lock}
              iconRight={showPassword ? EyeOff : Eye}
              onIconRightClick={() => setShowPassword((v) => !v)}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              disabled={locked}
            />

            {/* Rate-limit countdown */}
            {locked && (
              <div className="p-5 rounded-lg bg-warning-muted border border-warning text-center">
                <p className="text-sm font-semibold text-warning font-body m-0">
                  Trop de tentatives échouées
                </p>
                <p className="text-2xl font-mono font-bold text-warning my-3">
                  {formatTime(remainingTime)}
                </p>
                <div className="h-1 rounded-full bg-bg-hover overflow-hidden">
                  <div
                    className="h-full bg-warning transition-[width] duration-1000 ease-linear"
                    style={{ width: `${(remainingTime / loginDelay) * 100}%` }}
                  />
                </div>
              </div>
            )}

            {/* Error */}
            {error && !locked && (
              <div className="flex items-center gap-2 p-3 rounded-md bg-danger-muted border border-danger text-sm text-danger font-body">
                <AlertTriangle size={16} className="shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Info (password reason from biometric gate) */}
            {info && (
              <div className="flex items-center gap-2 p-3 rounded-md bg-accent/10 border border-accent text-sm text-accent-text font-body">
                <Info size={16} className="shrink-0" />
                <span>{info}</span>
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
            <div className="mt-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="flex-1 h-px bg-border" />
                <span className="text-xs text-tx-muted font-body">ou</span>
                <div className="flex-1 h-px bg-border" />
              </div>

              {bioStatus?.requires_password && (
                <p className="text-xs text-tx-muted font-body text-center mb-2">
                  {bioStatus.password_reason || 'Mot de passe requis'}
                </p>
              )}

              <button
                onClick={handleBiometricLogin}
                disabled={!canUseBiometric || biometricLoading || locked}
                className={`w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg border border-bd bg-bg-hover text-tx-primary font-body text-sm font-medium transition-all duration-200 ${
                  !canUseBiometric || biometricLoading || locked ? 'cursor-not-allowed opacity-40' : 'cursor-pointer hover:border-bd-hover'
                }`}
              >
                <Fingerprint size={20} className={canUseBiometric ? 'text-accent' : 'text-tx-muted'} />
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

          {/* Passkey login — always available if enrolled (no cold start, no timeout) */}
          {showPasskeySection && (
            <div className={showBiometricSection ? 'mt-2' : 'mt-4'}>
              {!showBiometricSection && (
                <div className="flex items-center gap-3 mb-3">
                  <div className="flex-1 h-px bg-border" />
                  <span className="text-xs text-tx-muted font-body">ou</span>
                  <div className="flex-1 h-px bg-border" />
                </div>
              )}

              {/* 14-day password reminder banner */}
              {passkeyStatus?.needs_password_reminder && (
                <div className="flex items-center gap-2 p-3 rounded-md bg-accent/10 border border-accent text-xs text-accent-text font-body mb-2">
                  <Info size={16} className="shrink-0" />
                  <span>Rappel de sécurité : veuillez taper votre mot de passe pour confirmer que vous le connaissez toujours.</span>
                </div>
              )}

              <button
                onClick={handlePasskeyLogin}
                disabled={!canUsePasskey || passkeyLoading || locked}
                className={`w-full flex items-center justify-center gap-3 px-4 py-3 rounded-lg border border-bd font-body text-sm font-medium transition-all duration-200 ${
                  canUsePasskey ? 'bg-accent/5 hover:bg-accent/10' : 'bg-bg-hover'
                } text-tx-primary ${
                  !canUsePasskey || passkeyLoading || locked ? 'cursor-not-allowed opacity-40' : 'cursor-pointer hover:border-bd-hover'
                }`}
              >
                <KeyRound size={20} className={canUsePasskey ? 'text-accent' : 'text-tx-muted'} />
                {passkeyLoading
                  ? 'Authentification passkey...'
                  : passkeyStatus?.needs_password_reminder
                    ? 'Passkey (mot de passe requis)'
                    : 'Déverrouiller avec Passkey'}
              </button>
            </div>
          )}

          {/* Links */}
          <div className="mt-5 text-center flex flex-col gap-3 border-t border-bd pt-5">
            <Link to="/reset-vault" className="text-xs text-danger font-body inline-flex items-center justify-center gap-1.5 no-underline hover:underline opacity-80 hover:opacity-100 transition-opacity">
              <AlertTriangle size={12} />
              Mot de passe oublié ? Réinitialiser le coffre-fort
            </Link>
            <p className="text-sm text-tx-muted font-body m-0">
              Pas encore de compte ?{' '}
              <Link to="/register" className="text-accent-text font-medium no-underline hover:underline">
                Créer un compte
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

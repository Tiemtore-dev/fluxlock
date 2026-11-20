import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowRight, Eye, EyeOff, Fingerprint } from 'lucide-react'
import { Button, Input, Spinner } from '../design-system/atoms'
import { useToast } from '../design-system/organisms'
import { auth, biometric, type AuthResponse, type BiometricStatus } from '../lib/vault-service'
import { androidBiometricAvailable, androidHasStoredKey, androidKeystoreRetrieve, hasAndroidKeystore } from '../lib/android-biometric'
import { biometricAccount, enrollBiometrics } from '../lib/biometric-enrollment'
import { useAuthStore } from '../stores/authStore'

export default function LoginPage() {
  const navigate = useNavigate()
  const { toast } = useToast()
  const passwordInput = useRef<HTMLInputElement>(null)
  const dbReady = useAuthStore((state) => state.dbReady)
  const locking = useAuthStore((state) => state.locking)
  const setAuth = useAuthStore((state) => state.setAuth)
  const [hasAccount, setHasAccount] = useState<boolean>()
  const [status, setStatus] = useState<BiometricStatus>()
  const [setupBiometrics, setSetupBiometrics] = useState(false)
  const [password, setPassword] = useState('')
  const [visible, setVisible] = useState(false)
  const [pending, setPending] = useState<'password' | 'biometric'>()
  const [retryAt, setRetryAt] = useState(0)
  const [now, setNow] = useState(Date.now)
  const [error, setError] = useState('')
  const android = hasAndroidKeystore()
  const bioAvailable = android ? androidBiometricAvailable() : status?.available
  const enrolled = status?.enrolled && !!status.enrolled_username &&
    (!android || androidHasStoredKey(biometricAccount(status.enrolled_username)))
  const remaining = Math.max(0, Math.ceil((retryAt - now) / 1000))

  function waitForRetry(seconds: number) {
    const timestamp = Date.now()
    setNow(timestamp)
    setRetryAt(timestamp + seconds * 1000)
  }

  useEffect(() => {
    if (!dbReady) return
    let active = true
    auth.hasExistingUser().then((exists) => {
      if (!active) return
      setHasAccount(exists)
      if (exists) {
        auth.checkLoginDelay().then((seconds) => {
          if (active) waitForRetry(seconds)
        }).catch(() => {})
        biometric.checkStatus().then((result) => {
          if (active) setStatus(result)
        })
      }
    }).catch(() => {
      if (active) setError('Impossible d’ouvrir le coffre. Redémarrez FluXlock pour réessayer.')
    })
    return () => { active = false }
  }, [dbReady])

  const retryPending = remaining > 0
  useEffect(() => {
    if (!retryPending) return
    const timer = window.setInterval(() => setNow(Date.now()), 250)
    return () => window.clearInterval(timer)
  }, [retryAt, retryPending])

  function authenticatedUser(response: AuthResponse) {
    if (!response.success || !response.token || response.user_id == null || !response.username) {
      throw new Error(response.message)
    }
    return { id: String(response.user_id), username: response.username, email: response.email || '' }
  }

  function enterVault(user: ReturnType<typeof authenticatedUser>) {
    setAuth(user)
    navigate('/', { replace: true })
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (locking || pending || remaining > 0) return
    setPending('password')
    setError('')
    try {
      const user = authenticatedUser(await auth.login(password))
      if (setupBiometrics && bioAvailable) {
        try {
          await enrollBiometrics(password, user.username)
          toast('Déverrouillage biométrique activé', 'success')
        } catch (reason) {
          toast(reason instanceof Error ? reason.message : String(reason), 'error')
        }
      }
      enterVault(user)
    } catch (reason) {
      setError(String(reason instanceof Error ? reason.message : reason))
      waitForRetry(await auth.checkLoginDelay().catch(() => 0))
    } finally {
      setPassword('')
      setVisible(false)
      setPending(undefined)
    }
  }

  async function unlockWithBiometrics() {
    if (locking || pending || remaining > 0) return
    if (!enrolled) {
      setSetupBiometrics((active) => !active)
      setError('')
      passwordInput.current?.focus()
      return
    }
    if (!status?.enrolled_username || status.requires_password || !bioAvailable) {
      passwordInput.current?.focus()
      return
    }
    setPending('biometric')
    setError('')
    try {
      if (hasAndroidKeystore()) {
        const account = biometricAccount(status.enrolled_username)
        enterVault(authenticatedUser(await biometric.loginWithKey(await androidKeystoreRetrieve(account))))
      } else {
        enterVault(authenticatedUser(await biometric.login()))
      }
    } catch (reason) {
      setError(String(reason instanceof Error ? reason.message : reason))
      setStatus(await biometric.checkStatus())
      window.requestAnimationFrame(() => passwordInput.current?.focus())
    } finally {
      setPending(undefined)
    }
  }

  const showBiometrics = hasAccount && (bioAvailable || enrolled)
  const biometricHint = setupBiometrics
    ? 'Saisissez votre mot de passe maître, puis confirmez avec le capteur de votre appareil.'
    : enrolled && status?.requires_password
      ? status.password_reason || 'Saisissez votre mot de passe maître pour réactiver la biométrie.'
      : enrolled && !bioAvailable ? 'Le capteur est indisponible. Utilisez votre mot de passe maître.' : undefined
  const biometricLabel = enrolled ? 'Déverrouiller avec la biométrie' : 'Activer la biométrie'

  return (
    <main className="auth-page auth-page-login">
      <div className="auth-page-inner">
        <div className="auth-unlock auth-login">
          <div className="auth-identity">
            <img src="/fluxlock-mark.png" alt="FluXlock" width={50} height={50} />
            {showBiometrics && (
              <button type="button" className="auth-biometrics" aria-label={biometricLabel} title={biometricLabel}
                aria-describedby={biometricHint ? 'biometric-hint' : undefined}
                aria-pressed={enrolled ? undefined : setupBiometrics}
                disabled={locking || !!pending || remaining > 0} onClick={unlockWithBiometrics}>
                {pending === 'biometric' ? <Spinner size={20} /> : <Fingerprint size={23} strokeWidth={1.65} aria-hidden="true" />}
              </button>
            )}
          </div>
          <h1>{hasAccount === false ? 'Bienvenue dans FluXlock' : 'Déverrouiller le coffre'}</h1>
          {error && <p className="auth-error" role="alert">{error}</p>}
          {hasAccount === undefined && !error && <p role="status"><Spinner size={20} /> Ouverture du coffre…</p>}
          {hasAccount === false && (
            <Link className="auth-primary-link" to="/register">Créer mon compte <ArrowRight size={18} aria-hidden="true" /></Link>
          )}
          {hasAccount && (
            <>
              <form className="auth-form" onSubmit={submit}>
                <Input ref={passwordInput} label="Mot de passe maître" size="lg" type={visible ? 'text' : 'password'}
                  autoComplete="current-password" value={password} required disabled={locking || !!pending}
                  onChange={(event) => {
                    setPassword(event.target.value)
                    if (error) setError('')
                  }}
                  iconRight={visible ? EyeOff : Eye}
                  onIconRightClick={() => setVisible(!visible)}
                  iconRightLabel={visible ? 'Masquer le mot de passe' : 'Afficher le mot de passe'} />
                {biometricHint && <p id="biometric-hint" className="auth-notice" role="status">{biometricHint}</p>}
                {remaining > 0 && <p className="auth-notice" role="status">Réessayez dans {remaining} s.</p>}
                <Button type="submit" size="lg" fullWidth
                  disabled={locking || !!pending || remaining > 0} loading={pending === 'password'}>
                  {setupBiometrics ? 'Déverrouiller et activer' : 'Déverrouiller'}
                </Button>
              </form>
              <details className="auth-help">
                <summary>Mot de passe oublié ?</summary>
                <p>Le mot de passe maître protège vos données. Saisissez le mot de passe d’origine pour ouvrir le coffre ou restaurer une sauvegarde.</p>
              </details>
            </>
          )}
        </div>
      </div>
    </main>
  )
}

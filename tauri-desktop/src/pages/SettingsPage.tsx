import { useState, useEffect, useRef } from 'react'
import { Settings, Moon, Sun, Bell, Shield, Save, Fingerprint, Info, AlertTriangle, Lock, RefreshCw, Smartphone, Trash2, Copy, Check, Link, Wifi, Globe, ShieldCheck, FileText, Server, KeyRound } from 'lucide-react'
import { AppShell } from '../design-system/layouts'
import { Button, Input } from '../design-system/atoms'
import { useToast } from '../design-system/organisms'
import { biometric, passkey, auth, transfer, isolationMode, signedLogging, enclave, type BiometricStatus, type PasskeyStatus, type SyncSettings, type SyncDeviceInfo, type EnclaveStatus } from '../lib/vault-service'
import { useAuthStore } from '../stores/authStore'
import { hasAndroidBiometric, androidBiometricAvailable, hasAndroidKeystore, androidKeystoreStore, androidKeystoreDelete } from '../lib/android-biometric'

export default function SettingsPage() {
  const { toast } = useToast()
  const user = useAuthStore((s) => s.user)

  const [isDark, setIsDark] = useState(
    localStorage.getItem('theme') === 'dark' ||
    (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)
  )
  const [colorTheme, setColorTheme] = useState(
    localStorage.getItem('color-theme') || 'default'
  )
  const [notifications, setNotifications] = useState(
    localStorage.getItem('notifications') === 'true' || !localStorage.getItem('notifications')
  )
  const [autoLock, setAutoLock] = useState(
    sessionStorage.getItem('autoLock') === 'true' || !sessionStorage.getItem('autoLock')
  )
  const [lockTimeout, setLockTimeout] = useState(
    Math.min(Math.max(parseInt(sessionStorage.getItem('lockTimeout') || '15'), 1), 60)
  )
  const [bioStatus, setBioStatus] = useState<BiometricStatus | null>(null)
  const [bioLoading, setBioLoading] = useState(false)

  // Biometric activation flow states
  const [bioStep, setBioStep] = useState<'idle' | 'info' | 'confirm'>('idle')
  const [bioConsent, setBioConsent] = useState(false)
  const [confirmPassword, setConfirmPassword] = useState('')
  const [confirmError, setConfirmError] = useState('')

  // Passkey activation flow states
  const [passkeyStatus, setPasskeyStatus] = useState<PasskeyStatus | null>(null)
  const [passkeyLoading, setPasskeyLoading] = useState(false)
  const [passkeyStep, setPasskeyStep] = useState<'idle' | 'info' | 'confirm'>('idle')
  const [passkeyConsent, setPasskeyConsent] = useState(false)
  const [passkeyConfirmPassword, setPasskeyConfirmPassword] = useState('')
  const [passkeyConfirmError, setPasskeyConfirmError] = useState('')

  // Sync state
  const [syncSettings, setSyncSettings] = useState<SyncSettings | null>(null)
  const [syncLoading, setSyncLoading] = useState(false)
  const [syncError, setSyncError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  // Pairing flow state
  type PairingStep = 'idle' | 'starting' | 'waiting' | 'joining' | 'success' | 'error'
  const [pairingStep, setPairingStep] = useState<PairingStep>('idle')
  const [pairingCode, setPairingCode] = useState('')
  const [joinCode, setJoinCode] = useState('')
  const [pairingId, setPairingId] = useState('')
  const [crossNetwork, setCrossNetwork] = useState(false)
  const [pairedDeviceName, setPairedDeviceName] = useState('')
  const [pairingError, setPairingError] = useState('')
  const pairingPollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Isolation mode, signed logging, enclave status
  const [isolationEnabled, setIsolationEnabled] = useState(false)
  const [signedLoggingEnabled, setSignedLoggingEnabled] = useState(false)
  const [enclaveStatus, setEnclaveStatus] = useState<EnclaveStatus | null>(null)

  useEffect(() => {
    const saved = localStorage.getItem('theme')
    if (saved === 'dark') { document.documentElement.classList.add('dark'); setIsDark(true) }
    else if (saved === 'light') { document.documentElement.classList.remove('dark'); setIsDark(false) }

    const savedColor = localStorage.getItem('color-theme')
    if (savedColor && savedColor !== 'default') {
      document.documentElement.setAttribute('data-theme', savedColor)
      setColorTheme(savedColor)
    }
  }, [])

  // Load sync settings (with retry)
  const loadSyncSettings = () => {
    setSyncError(null)
    transfer.getSyncSettings()
      .then(setSyncSettings)
      .catch((err) => {
        setSyncError(err?.toString() || 'Erreur chargement synchronisation')
      })
  }

  useEffect(() => {
    loadSyncSettings()
    // Retry once after 2s in case trust store isn't unlocked yet
    const retryTimer = setTimeout(loadSyncSettings, 2000)
    return () => clearTimeout(retryTimer)
  }, [])

  // Load isolation, signed logging, enclave status
  useEffect(() => {
    isolationMode.get().then(setIsolationEnabled)
    signedLogging.getStatus().then(setSignedLoggingEnabled)
    enclave.getStatus().then(setEnclaveStatus).catch(() => { })
  }, [])

  // Check biometric and passkey availability
  useEffect(() => {
    biometric.checkStatus().then((status) => {
      console.log('[Settings] biometric status:', JSON.stringify(status))
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

  const startBiometricActivation = () => {
    setBioStep('info')
    setBioConsent(false)
    setConfirmPassword('')
    setConfirmError('')
  }

  const cancelActivation = () => {
    setBioStep('idle')
    setBioConsent(false)
    setConfirmPassword('')
    setConfirmError('')
  }

  const proceedToConfirm = () => {
    if (!bioConsent) return
    setBioStep('confirm')
    setConfirmError('')
  }

  const confirmAndEnable = async () => {
    if (!confirmPassword.trim()) {
      setConfirmError('Veuillez entrer votre mot de passe maître.')
      return
    }
    setBioLoading(true)
    setConfirmError('')
    try {
      // Verify master password first
      const loginRes = await auth.login(
        user?.username || bioStatus?.enrolled_username || '',
        confirmPassword
      )
      if (!loginRes.success) {
        setConfirmError('Mot de passe incorrect.')
        setBioLoading(false)
        return
      }
      // Now enable biometric (will prompt Touch ID / Face ID)
      const enableResult = await biometric.enable()

      // On Android: Rust returns JSON with key_b64 — store it in Android Keystore (TEE/StrongBox)
      if (hasAndroidKeystore()) {
        try {
          const parsed = JSON.parse(enableResult)
          if (parsed.key_b64) {
            const account = `user_bio_${(user?.username || '').toLowerCase()}`
            await androidKeystoreStore(account, parsed.key_b64)
          }
        } catch {
          // Not JSON = desktop platform, key already stored in OS keychain
        }
      }

      const updated = await biometric.checkStatus()
      setBioStatus(updated)
      setBioStep('idle')
      setConfirmPassword('')
      toast('Biométrie activée avec succès', 'success')
    } catch (err: any) {
      setConfirmError(err?.toString() || 'Erreur lors de l\'activation')
    } finally {
      setBioLoading(false)
    }
  }

  const disableBiometric = async () => {
    setBioLoading(true)
    try {
      // On Android: also delete the key from Android Keystore (TEE/StrongBox)
      if (hasAndroidKeystore()) {
        const account = `user_bio_${(user?.username || '').toLowerCase()}`
        androidKeystoreDelete(account)
      }
      await biometric.disable()
      const updated = await biometric.checkStatus()
      setBioStatus(updated)
      toast('Biométrie désactivée', 'success')
    } catch (err: any) {
      toast(err?.toString() || 'Erreur biométrie', 'error')
    } finally {
      setBioLoading(false)
    }
  }

  const handleEmergencyLock = async () => {
    try {
      await biometric.emergencyLock()
      const updated = await biometric.checkStatus()
      setBioStatus(updated)
      toast('Verrouillage d\'urgence activé — mot de passe requis', 'warning')
    } catch (err: any) {
      toast(err?.toString() || 'Erreur', 'error')
    }
  }

  // ─── Passkey functions ───
  const startPasskeyActivation = () => {
    setPasskeyStep('info')
    setPasskeyConsent(false)
    setPasskeyConfirmPassword('')
    setPasskeyConfirmError('')
  }

  const cancelPasskeyActivation = () => {
    setPasskeyStep('idle')
    setPasskeyConsent(false)
    setPasskeyConfirmPassword('')
    setPasskeyConfirmError('')
  }

  const proceedToPasskeyConfirm = () => {
    if (!passkeyConsent) return
    setPasskeyStep('confirm')
    setPasskeyConfirmError('')
  }

  const confirmAndEnablePasskey = async () => {
    if (!passkeyConfirmPassword.trim()) {
      setPasskeyConfirmError('Veuillez entrer votre mot de passe maître.')
      return
    }
    setPasskeyLoading(true)
    setPasskeyConfirmError('')
    try {
      const loginRes = await auth.login(
        user?.username || passkeyStatus?.enrolled_username || '',
        passkeyConfirmPassword
      )
      if (!loginRes.success) {
        setPasskeyConfirmError('Mot de passe incorrect.')
        setPasskeyLoading(false)
        return
      }
      
      const enableResult = await passkey.register()
      
      // On Android: Rust returns JSON with key_b64 — store it in Android Keystore (TEE/StrongBox)
      if (hasAndroidKeystore()) {
        try {
          const parsed = JSON.parse(enableResult)
          if (parsed.key_b64) {
            const account = `passkey_ed25519_${(user?.username || passkeyStatus?.enrolled_username || '').toLowerCase()}`
            await androidKeystoreStore(account, parsed.key_b64)
          }
        } catch {
          // Fallback if not JSON
        }
      }
      const updated = await passkey.checkStatus()
      setPasskeyStatus(updated)
      setPasskeyStep('idle')
      setPasskeyConfirmPassword('')
      toast('Passkey activée avec succès', 'success')
    } catch (err: any) {
      setPasskeyConfirmError(err?.toString() || 'Erreur lors de l\'activation passkey')
    } finally {
      setPasskeyLoading(false)
    }
  }

  const disablePasskey = async () => {
    setPasskeyLoading(true)
    try {
      if (hasAndroidKeystore()) {
        const account = `passkey_ed25519_${(user?.username || passkeyStatus?.enrolled_username || '').toLowerCase()}`
        androidKeystoreDelete(account)
      }
      await passkey.delete()
      const updated = await passkey.checkStatus()
      setPasskeyStatus(updated)
      toast('Passkey supprimée', 'success')
    } catch (err: any) {
      toast(err?.toString() || 'Erreur passkey', 'error')
    } finally {
      setPasskeyLoading(false)
    }
  }

  const toggleSync = async () => {
    setSyncLoading(true)
    try {
      const newVal = !syncSettings?.enabled
      await transfer.setSyncEnabled(newVal)
      const updated = await transfer.getSyncSettings()
      setSyncSettings(updated)
      toast(newVal ? 'Synchronisation activée' : 'Synchronisation désactivée', 'success')
    } catch (err: any) {
      toast(err?.toString() || 'Erreur sync', 'error')
    } finally {
      setSyncLoading(false)
    }
  }

  // ── Pairing: start (initiator side) ──
  const startPairing = async () => {
    setPairingStep('starting')
    setPairingError('')
    try {
      const result = await transfer.startSyncPairing(crossNetwork)
      setPairingCode(result.wormhole_code)
      setPairingId(result.pairing_id)
      setPairingStep('waiting')

      // Poll for completion (background task will update the transfer state)
      pairingPollRef.current = setInterval(async () => {
        try {
          const status = await transfer.getStatus(result.pairing_id)
          if (status?.state === 'Completed') {
            clearInterval(pairingPollRef.current!)
            pairingPollRef.current = null
            setPairedDeviceName(status.peer_name || 'Appareil')
            setPairingStep('success')
            const updated = await transfer.getSyncSettings()
            setSyncSettings(updated)
            toast('Appairage réussi !', 'success')
          } else if (typeof status?.state === 'object' && 'Failed' in status.state) {
            clearInterval(pairingPollRef.current!)
            pairingPollRef.current = null
            const reason = (status.state as any).Failed?.reason || 'Erreur inconnue'
            setPairingError(reason)
            setPairingStep('error')
          }
        } catch { /* ignore polling errors */ }
      }, 2000)
    } catch (err: any) {
      setPairingError(err?.toString() || 'Erreur lors du démarrage de l\'appairage')
      setPairingStep('error')
    }
  }

  // ── Pairing: join (joiner side) ──
  const joinPairing = async () => {
    if (!joinCode.trim()) {
      toast('Entrez le code wormhole', 'error')
      return
    }
    setPairingStep('joining')
    setPairingError('')
    try {
      const result = await transfer.joinSyncPairing(joinCode.trim())
      if (result.success) {
        setPairedDeviceName(result.device_name)
        setPairingStep('success')
        const updated = await transfer.getSyncSettings()
        setSyncSettings(updated)
        toast(`Appairé avec "${result.device_name}"`, 'success')
      } else {
        setPairingError('L\'autre appareil a refusé l\'appairage')
        setPairingStep('error')
      }
    } catch (err: any) {
      setPairingError(err?.toString() || 'Erreur de connexion')
      setPairingStep('error')
    }
  }

  const cancelPairing = () => {
    if (pairingPollRef.current) {
      clearInterval(pairingPollRef.current)
      pairingPollRef.current = null
    }
    if (pairingId) {
      transfer.cancel(pairingId).catch(() => { })
    }
    setPairingStep('idle')
    setPairingCode('')
    setJoinCode('')
    setPairingId('')
    setPairingError('')
    setPairedDeviceName('')
  }

  const removeSyncDevice = async (vk: string) => {
    setSyncLoading(true)
    try {
      await transfer.removeSyncDevice(vk)
      const updated = await transfer.getSyncSettings()
      setSyncSettings(updated)
      toast('Appareil supprimé', 'success')
    } catch (err: any) {
      toast(err?.toString() || 'Erreur suppression', 'error')
    } finally {
      setSyncLoading(false)
    }
  }

  const copyPairingCode = async () => {
    if (pairingCode) {
      await navigator.clipboard.writeText(pairingCode)
      setCopied(true)
      toast('Code copié', 'success')
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const toggleDarkMode = () => {
    const next = !isDark; setIsDark(next)
    document.documentElement.classList.toggle('dark', next)
    localStorage.setItem('theme', next ? 'dark' : 'light')
  }

  const changeColorTheme = (theme: string) => {
    setColorTheme(theme)
    if (theme === 'default') {
      document.documentElement.removeAttribute('data-theme')
      localStorage.removeItem('color-theme')
    } else {
      document.documentElement.setAttribute('data-theme', theme)
      localStorage.setItem('color-theme', theme)
    }
  }

  const save = () => {
    localStorage.setItem('notifications', notifications.toString())
    sessionStorage.setItem('autoLock', autoLock.toString())
    sessionStorage.setItem('lockTimeout', Math.min(Math.max(lockTimeout, 1), 60).toString())
    toast('Paramètres enregistrés', 'success')
  }

  /* shared styles */
  const card: React.CSSProperties = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', marginBottom: 'var(--space-5)' }
  const cardHeader: React.CSSProperties = { padding: 'var(--space-5)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }
  const cardBody: React.CSSProperties = { padding: 'var(--space-5)' }
  const row = "flex flex-col sm:flex-row sm:items-center justify-between gap-3"

  const Toggle = ({ on, onToggle }: { on: boolean; onToggle: () => void }) => (
    <button onClick={onToggle} style={{
      position: 'relative', width: 44, height: 24, borderRadius: 12, border: 'none', cursor: 'pointer',
      background: on ? 'var(--accent)' : 'var(--bg-hover)', transition: 'background var(--transition-fast)',
    }}>
      <span style={{
        position: 'absolute', top: 2, left: on ? 22 : 2,
        width: 20, height: 20, borderRadius: '50%', background: 'white', transition: 'left var(--transition-fast)',
      }} />
    </button>
  )

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div className="page-header">
          <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)', margin: 0 }}>
            <Settings size={28} style={{ color: 'var(--accent)' }} /> Paramètres
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginTop: 'var(--space-1)' }}>Configuration de FluXlock</p>
        </div>

        {/* Apparence */}
        <div style={card}>
          <div style={cardHeader}>
            {isDark ? <Moon size={20} style={{ color: 'var(--accent)' }} /> : <Sun size={20} style={{ color: 'var(--accent)' }} />}
            <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Apparence</h2>
          </div>
          <div style={{ ...cardBody, display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div className={row}>
              <div>
                <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Mode sombre</p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>Réduire la fatigue oculaire</p>
              </div>
              <Toggle on={isDark} onToggle={toggleDarkMode} />
            </div>
            
            <div className={row}>
              <div>
                <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Thème de couleur</p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>Personnalisez l'accent principal</p>
              </div>
              <select 
                value={colorTheme} 
                onChange={(e) => changeColorTheme(e.target.value)}
                style={{
                  padding: '8px 12px',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--border)',
                  background: 'var(--bg-input)',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-body)',
                  fontSize: 'var(--text-sm)',
                  outline: 'none',
                  cursor: 'pointer'
                }}
              >
                <option value="default">Émeraude (Défaut)</option>
                <option value="ocean">Océan (Bleu)</option>
                <option value="amethyst">Améthyste (Violet)</option>
                <option value="sunset">Crépuscule (Orange)</option>
              </select>
            </div>
          </div>
        </div>

        {/* Notifications */}
        {/* <div style={card}>
          <div style={cardHeader}>
            <Bell size={20} style={{ color: 'var(--accent)' }} />
            <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Notifications</h2>
          </div>
          <div style={cardBody}>
            <div className={row}>
              <div>
                <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Activer les notifications</p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>Alertes événements de sécurité</p>
              </div>
              <Toggle on={notifications} onToggle={() => setNotifications(!notifications)} />
            </div>
          </div>
        </div> */}

        {/* Sécurité */}
        <div style={card}>
          <div style={cardHeader}>
            <Shield size={20} style={{ color: 'var(--accent)' }} />
            <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Sécurité</h2>
          </div>
          <div style={{ ...cardBody, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
            {/* Biometric — always visible */}
            {bioStep === 'idle' && (
              <>
                <div className={row}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <Fingerprint size={18} style={{ color: bioStatus?.available ? 'var(--accent)' : 'var(--text-muted)' }} />
                    <div>
                      <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                        {bioStatus?.biometric_type === 'touchid' ? 'Touch ID'
                          : bioStatus?.biometric_type === 'faceid' ? 'Face ID'
                            : bioStatus?.biometric_type === 'fingerprint' ? 'Empreinte digitale'
                              : 'Biométrie'}
                      </p>
                      <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
                        {!bioStatus
                          ? 'Vérification en cours…'
                          : bioStatus.available && bioStatus.enrolled
                            ? `Activé pour ${bioStatus.enrolled_username || 'cet utilisateur'}`
                            : bioStatus.available
                              ? 'Déverrouillage rapide par empreinte'
                              : 'Non disponible sur cette plateforme'}
                      </p>
                    </div>
                  </div>
                  {bioStatus?.available ? (
                    bioStatus.enrolled ? (
                      <Toggle on={true} onToggle={bioLoading ? () => { } : disableBiometric} />
                    ) : (
                      <Toggle on={false} onToggle={bioLoading ? () => { } : startBiometricActivation} />
                    )
                  ) : (
                    <span style={{
                      fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                      padding: '4px 10px', borderRadius: 'var(--radius-full)',
                      background: 'var(--bg-hover)',
                    }}>
                      {!bioStatus ? '…' : 'Indisponible'}
                    </span>
                  )}
                </div>
                {/* Platform-specific unavailability explanation */}
                {bioStatus && !bioStatus.available && (
                  <div style={{
                    display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)',
                    padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                    background: 'color-mix(in srgb, var(--warning) 8%, transparent)',
                    border: '1px solid color-mix(in srgb, var(--warning) 25%, transparent)',
                    fontSize: 'var(--text-xs)', color: 'var(--text-secondary)',
                    lineHeight: 1.5,
                  }}>
                    <Info size={14} style={{ color: 'var(--warning)', flexShrink: 0, marginTop: 2 }} />
                    <div>
                      {bioStatus.biometric_type === 'none' && (
                        <span>
                          Aucun capteur biométrique détecté. <strong>macOS :</strong> vérifiez que Touch ID est configuré dans
                          Réglages Système &gt; Touch ID. <strong>Windows :</strong> Windows Hello sera supporté dans une prochaine version.
                          <strong> Linux :</strong> la biométrie n'est pas encore disponible.
                        </span>
                      )}
                      {(bioStatus as any)._error && (
                        <span style={{ display: 'block', marginTop: 'var(--space-1)', fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--text-muted)' }}>
                          Diagnostic : {(bioStatus as any)._error}
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {/* Emergency lock button when enrolled */}
                {bioStatus?.available && bioStatus.enrolled && (
                  <button
                    onClick={handleEmergencyLock}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                      padding: 'var(--space-2) var(--space-3)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--danger)',
                      background: 'var(--danger-muted)',
                      color: 'var(--danger)',
                      fontSize: 'var(--text-xs)',
                      fontFamily: 'var(--font-body)',
                      cursor: 'pointer',
                      marginTop: 'var(--space-2)',
                    }}
                  >
                    <AlertTriangle size={14} />
                    Verrouillage d'urgence
                  </button>
                )}
              </>
            )}

            {/* Biometric activation — Step 1: Information screen */}
            {bioStatus?.available && bioStep === 'info' && (
              <div style={{
                padding: 'var(--space-5)',
                borderRadius: 'var(--radius-lg)',
                background: 'color-mix(in srgb, var(--accent) 8%, transparent)',
                border: '1px solid var(--accent)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
                  <Info size={18} style={{ color: 'var(--accent)' }} />
                  <h3 style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0, fontSize: 'var(--text-base)' }}>
                    Activation de la biométrie
                  </h3>
                </div>

                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', lineHeight: 1.6 }}>
                  <p style={{ margin: '0 0 var(--space-3) 0', fontStyle: 'italic', color: 'var(--text-muted)' }}>
                    « Ton empreinte n'est pas la combinaison du coffre. Elle ouvre juste le tiroir qui contient la clé. »
                  </p>
                  <p style={{ margin: '0 0 var(--space-3) 0' }}>
                    <strong>Ce que la biométrie fait :</strong> elle vous permet de déverrouiller rapidement FluXlock
                    sans retaper votre mot de passe à chaque fois, tant que la session est récente.
                  </p>
                  <p style={{ margin: '0 0 var(--space-3) 0' }}>
                    <strong>Ce que la biométrie ne fait PAS :</strong> elle ne remplace jamais votre mot de passe maître.
                    Au premier lancement, après un redémarrage, ou après une longue inactivité, le mot de passe sera toujours demandé.
                  </p>
                  <p style={{ margin: '0 0 var(--space-4) 0' }}>
                    En cas de doute ou de danger, utilisez le <strong>verrouillage d'urgence</strong> pour désactiver
                    instantanément la biométrie jusqu'à la prochaine saisie du mot de passe.
                  </p>
                </div>

                {/* Consent checkbox */}
                <label style={{
                  display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)',
                  cursor: 'pointer', padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-surface)', border: '1px solid var(--border)',
                  marginBottom: 'var(--space-4)',
                }}>
                  <input
                    type="checkbox"
                    checked={bioConsent}
                    onChange={(e) => setBioConsent(e.target.checked)}
                    style={{ marginTop: 2, accentColor: 'var(--accent)' }}
                  />
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
                    J'ai lu et compris les implications de l'activation de la biométrie.
                  </span>
                </label>

                <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'flex-end' }}>
                  <Button variant="ghost" onClick={cancelActivation}>Annuler</Button>
                  <Button onClick={proceedToConfirm} disabled={!bioConsent}>Continuer</Button>
                </div>
              </div>
            )}

            {/* Biometric activation — Step 2: Password confirmation */}
            {bioStatus?.available && bioStep === 'confirm' && (
              <div style={{
                padding: 'var(--space-5)',
                borderRadius: 'var(--radius-lg)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
                  <Lock size={18} style={{ color: 'var(--accent)' }} />
                  <h3 style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0, fontSize: 'var(--text-base)' }}>
                    Confirmez votre identité
                  </h3>
                </div>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', margin: '0 0 var(--space-4) 0' }}>
                  Entrez votre mot de passe maître pour activer la biométrie. Votre empreinte sera ensuite demandée.
                </p>

                <Input
                  label="Mot de passe maître"
                  type="password"
                  icon={Lock}
                  value={confirmPassword}
                  onChange={(e) => { setConfirmPassword(e.target.value); setConfirmError('') }}
                  placeholder="••••••••••••"
                  autoFocus
                />

                {confirmError && (
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                    padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                    background: 'var(--danger-muted)', border: '1px solid var(--danger)',
                    fontSize: 'var(--text-sm)', color: 'var(--danger)',
                    fontFamily: 'var(--font-body)', marginTop: 'var(--space-3)',
                  }}>
                    <AlertTriangle size={14} />
                    {confirmError}
                  </div>
                )}

                <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'flex-end', marginTop: 'var(--space-4)' }}>
                  <Button variant="ghost" onClick={cancelActivation}>Annuler</Button>
                  <Button onClick={confirmAndEnable} loading={bioLoading} icon={Fingerprint}>
                    Activer la biométrie
                  </Button>
                </div>
              </div>
            )}

            {/* ─── Passkey (Always-on) ─── */}
            {passkeyStep === 'idle' && (
              <>
                <div className={row}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <KeyRound size={18} style={{ color: passkeyStatus?.enrolled ? 'var(--accent)' : 'var(--text-muted)' }} />
                    <div>
                      <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                        Authentification Passkey
                      </p>
                      <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
                        {!passkeyStatus
                          ? 'Vérification en cours…'
                          : passkeyStatus.enrolled
                            ? `Activé pour ${passkeyStatus.enrolled_username || 'cet utilisateur'}`
                            : 'Déverrouillage persistant et ultra-rapide'}
                      </p>
                    </div>
                  </div>
                  {passkeyStatus ? (
                    passkeyStatus.enrolled ? (
                      <Toggle on={true} onToggle={passkeyLoading ? () => { } : disablePasskey} />
                    ) : (
                      <Toggle on={false} onToggle={passkeyLoading ? () => { } : startPasskeyActivation} />
                    )
                  ) : (
                    <span style={{
                      fontSize: 'var(--text-xs)', color: 'var(--text-muted)',
                      padding: '4px 10px', borderRadius: 'var(--radius-full)',
                      background: 'var(--bg-hover)',
                    }}>
                      …
                    </span>
                  )}
                </div>
              </>
            )}

            {/* Passkey activation — Step 1: Information screen */}
            {passkeyStep === 'info' && (
              <div style={{
                padding: 'var(--space-5)',
                borderRadius: 'var(--radius-lg)',
                background: 'color-mix(in srgb, var(--accent) 8%, transparent)',
                border: '1px solid var(--accent)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
                  <Info size={18} style={{ color: 'var(--accent)' }} />
                  <h3 style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0, fontSize: 'var(--text-base)' }}>
                    Activation Passkey
                  </h3>
                </div>

                <div style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', lineHeight: 1.6 }}>
                  <p style={{ margin: '0 0 var(--space-3) 0' }}>
                    <strong>Ce que la passkey fait :</strong> Elle remplace la saisie de votre mot de passe à l'ouverture du coffre, 
                    <strong> même au premier lancement de l'application ou après une longue inactivité</strong>.
                  </p>
                  <p style={{ margin: '0 0 var(--space-3) 0' }}>
                    La sécurité est assurée par un chiffrement hybride local post-quantique. 
                    Toutefois, pour votre sécurité, <strong>votre mot de passe maître sera exigé tous les 14 jours</strong> pour s'assurer que vous ne l'avez pas oublié.
                  </p>
                </div>

                {/* Consent checkbox */}
                <label style={{
                  display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)',
                  cursor: 'pointer', padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-surface)', border: '1px solid var(--border)',
                  marginBottom: 'var(--space-4)',
                  marginTop: 'var(--space-3)'
                }}>
                  <input
                    type="checkbox"
                    checked={passkeyConsent}
                    onChange={(e) => setPasskeyConsent(e.target.checked)}
                    style={{ marginTop: 2, accentColor: 'var(--accent)' }}
                  />
                  <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
                    J'ai lu et compris le fonctionnement de la Passkey.
                  </span>
                </label>

                <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'flex-end' }}>
                  <Button variant="ghost" onClick={cancelPasskeyActivation}>Annuler</Button>
                  <Button onClick={proceedToPasskeyConfirm} disabled={!passkeyConsent}>Continuer</Button>
                </div>
              </div>
            )}

            {/* Passkey activation — Step 2: Password confirmation */}
            {passkeyStep === 'confirm' && (
              <div style={{
                padding: 'var(--space-5)',
                borderRadius: 'var(--radius-lg)',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-4)' }}>
                  <Lock size={18} style={{ color: 'var(--accent)' }} />
                  <h3 style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0, fontSize: 'var(--text-base)' }}>
                    Confirmez votre identité
                  </h3>
                </div>
                <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', margin: '0 0 var(--space-4) 0' }}>
                  Entrez votre mot de passe maître pour générer et enregistrer la Passkey.
                </p>

                <Input
                  label="Mot de passe maître"
                  type="password"
                  icon={Lock}
                  value={passkeyConfirmPassword}
                  onChange={(e) => { setPasskeyConfirmPassword(e.target.value); setPasskeyConfirmError('') }}
                  placeholder="••••••••••••"
                  autoFocus
                />

                {passkeyConfirmError && (
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                    padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                    background: 'var(--danger-muted)', border: '1px solid var(--danger)',
                    fontSize: 'var(--text-sm)', color: 'var(--danger)',
                    fontFamily: 'var(--font-body)', marginTop: 'var(--space-3)',
                  }}>
                    <AlertTriangle size={14} />
                    {passkeyConfirmError}
                  </div>
                )}

                <div style={{ display: 'flex', gap: 'var(--space-3)', justifyContent: 'flex-end', marginTop: 'var(--space-4)' }}>
                  <Button variant="ghost" onClick={cancelPasskeyActivation}>Annuler</Button>
                  <Button onClick={confirmAndEnablePasskey} loading={passkeyLoading} icon={KeyRound}>
                    Activer la Passkey
                  </Button>
                </div>
              </div>
            )}

            <div className={row}>
              <div>
                <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Verrouillage automatique</p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>Verrouiller après une période d'inactivité</p>
              </div>
              <Toggle on={autoLock} onToggle={() => setAutoLock(!autoLock)} />
            </div>
            {autoLock && (
              <Input
                label="Délai de verrouillage (minutes)"
                type="number"
                value={lockTimeout.toString()}
                onChange={(e) => setLockTimeout(parseInt(e.target.value) || 15)}
              />
            )}
          </div>
        </div>

        {/* Synchronisation — always visible */}
        <div style={card}>
          <div style={cardHeader}>
            <RefreshCw size={20} style={{ color: 'var(--accent)' }} />
            <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Synchronisation</h2>
          </div>
          {syncError && !syncSettings ? (
            <div style={{ ...cardBody, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-3)' }}>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', margin: 0, textAlign: 'center' }}>
                Impossible de charger les paramètres de synchronisation.
              </p>
              <p style={{ fontSize: 'var(--text-xs)', color: 'var(--danger)', margin: 0 }}>{syncError}</p>
              <Button variant="ghost" size="sm" icon={RefreshCw} onClick={loadSyncSettings}>Réessayer</Button>
            </div>
          ) : !syncSettings ? (
            <div style={{ ...cardBody, display: 'flex', justifyContent: 'center', padding: 'var(--space-6)' }}>
              <RefreshCw size={20} style={{ color: 'var(--accent)', animation: 'spin 1s linear infinite' }} />
            </div>
          ) : (
            <div style={{ ...cardBody, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
              {/* Enable/disable sync */}
              <div className={row}>
                <div>
                  <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Activer la synchronisation</p>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
                    Synchroniser le trust store entre vos appareils (ML-DSA-65 + ML-KEM-768)
                  </p>
                </div>
                <Toggle on={syncSettings.enabled} onToggle={syncLoading ? () => { } : toggleSync} />
              </div>

              {/* ── Pairing section ── */}
              {syncSettings.enabled && pairingStep === 'idle' && (
                <div style={{
                  padding: 'var(--space-4)', borderRadius: 'var(--radius-lg)',
                  background: 'color-mix(in srgb, var(--accent) 6%, transparent)',
                  border: '1px solid color-mix(in srgb, var(--accent) 20%, transparent)',
                  display: 'flex', flexDirection: 'column', gap: 'var(--space-4)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <Link size={16} style={{ color: 'var(--accent)' }} />
                    <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0, fontSize: 'var(--text-sm)' }}>
                      Appairer un appareil
                    </p>
                  </div>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
                    L'appairage utilise un code wormhole + handshake post-quantique (SPAKE2 + ML-KEM-768)
                    pour échanger automatiquement les clés ML-DSA-65 via un canal chiffré.
                  </p>

                  {/* Cross-network toggle */}
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                    cursor: 'pointer', fontSize: 'var(--text-xs)', color: 'var(--text-secondary)',
                  }}>
                    <input
                      type="checkbox"
                      checked={crossNetwork}
                      onChange={(e) => setCrossNetwork(e.target.checked)}
                      style={{ accentColor: 'var(--accent)' }}
                    />
                    <Globe size={14} />
                    Réseaux différents (IPv6 cross-network)
                  </label>

                  <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
                    <Button onClick={startPairing} icon={Wifi} style={{ flex: 1 }}>
                      Générer un code
                    </Button>
                  </div>

                  {/* Join section */}
                  <div style={{ borderTop: '1px solid var(--border)', paddingTop: 'var(--space-3)' }}>
                    <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: '0 0 var(--space-2) 0' }}>
                      Ou entrez le code affiché sur l'autre appareil :
                    </p>
                    <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                      <input
                        value={joinCode}
                        onChange={(e) => setJoinCode(e.target.value)}
                        placeholder="ex: 42-alpha-beacon-drift"
                        style={{
                          flex: 1, padding: 'var(--space-2) var(--space-3)',
                          borderRadius: 'var(--radius-md)', border: '1px solid var(--border)',
                          background: 'var(--bg-base)', color: 'var(--text-primary)',
                          fontFamily: 'var(--font-mono, monospace)', fontSize: 'var(--text-sm)',
                        }}
                      />
                      <Button onClick={joinPairing} disabled={!joinCode.trim()}>
                        Rejoindre
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              {/* Pairing: waiting for joiner (initiator) */}
              {pairingStep === 'starting' && (
                <div style={{
                  padding: 'var(--space-5)', borderRadius: 'var(--radius-lg)',
                  background: 'var(--bg-surface)', border: '1px solid var(--accent)',
                  textAlign: 'center',
                }}>
                  <RefreshCw size={24} style={{ color: 'var(--accent)', animation: 'spin 1s linear infinite' }} />
                  <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 'var(--space-3) 0 0 0' }}>
                    Démarrage de l'appairage...
                  </p>
                </div>
              )}

              {pairingStep === 'waiting' && (
                <div style={{
                  padding: 'var(--space-5)', borderRadius: 'var(--radius-lg)',
                  background: 'var(--bg-surface)', border: '1px solid var(--accent)',
                  display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-4)',
                }}>
                  <Wifi size={28} style={{ color: 'var(--accent)' }} />
                  <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0, fontSize: 'var(--text-base)' }}>
                    En attente de l'autre appareil
                  </p>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0, textAlign: 'center' }}>
                    Entrez ce code sur l'autre appareil pour l'appairer :
                  </p>
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                    padding: 'var(--space-3) var(--space-4)', borderRadius: 'var(--radius-lg)',
                    background: 'var(--bg-base)', border: '2px solid var(--accent)',
                  }}>
                    <code style={{
                      fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--accent)',
                      fontFamily: 'var(--font-mono, monospace)', letterSpacing: '0.05em',
                      wordBreak: 'break-all',
                    }}>
                      {pairingCode}
                    </code>
                    <button
                      onClick={copyPairingCode}
                      style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        width: 32, height: 32, borderRadius: 'var(--radius-md)',
                        border: '1px solid var(--border)', background: 'var(--bg-surface)',
                        cursor: 'pointer', color: 'var(--text-secondary)', flexShrink: 0,
                      }}
                      title="Copier le code"
                    >
                      {copied ? <Check size={14} style={{ color: 'var(--success, green)' }} /> : <Copy size={14} />}
                    </button>
                  </div>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
                    Le code expire dans 5 minutes.
                  </p>
                  <Button variant="ghost" onClick={cancelPairing}>Annuler</Button>
                </div>
              )}

              {/* Pairing: joining (joiner side) */}
              {pairingStep === 'joining' && (
                <div style={{
                  padding: 'var(--space-5)', borderRadius: 'var(--radius-lg)',
                  background: 'var(--bg-surface)', border: '1px solid var(--accent)',
                  textAlign: 'center',
                }}>
                  <RefreshCw size={24} style={{ color: 'var(--accent)', animation: 'spin 1s linear infinite' }} />
                  <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 'var(--space-3) 0 0 0' }}>
                    Connexion et appairage en cours...
                  </p>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 'var(--space-2) 0 0 0' }}>
                    Handshake PQC (SPAKE2 + ML-KEM-768) + échange ML-DSA-65
                  </p>
                </div>
              )}

              {/* Pairing: success */}
              {pairingStep === 'success' && (
                <div style={{
                  padding: 'var(--space-5)', borderRadius: 'var(--radius-lg)',
                  background: 'color-mix(in srgb, var(--success, #22c55e) 10%, transparent)',
                  border: '1px solid var(--success, #22c55e)',
                  textAlign: 'center',
                }}>
                  <Check size={28} style={{ color: 'var(--success, #22c55e)' }} />
                  <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 'var(--space-3) 0 0 0' }}>
                    Appairage réussi !
                  </p>
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', margin: 'var(--space-2) 0 0 0' }}>
                    Appareil « {pairedDeviceName} » ajouté et synchronisation activée.
                  </p>
                  <Button variant="ghost" onClick={cancelPairing} style={{ marginTop: 'var(--space-3)' }}>
                    Fermer
                  </Button>
                </div>
              )}

              {/* Pairing: error */}
              {pairingStep === 'error' && (
                <div style={{
                  padding: 'var(--space-5)', borderRadius: 'var(--radius-lg)',
                  background: 'var(--danger-muted)', border: '1px solid var(--danger)',
                  textAlign: 'center',
                }}>
                  <AlertTriangle size={28} style={{ color: 'var(--danger)' }} />
                  <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 'var(--space-3) 0 0 0' }}>
                    Échec de l'appairage
                  </p>
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)', margin: 'var(--space-2) 0 0 0' }}>
                    {pairingError}
                  </p>
                  <Button variant="ghost" onClick={cancelPairing} style={{ marginTop: 'var(--space-3)' }}>
                    Réessayer
                  </Button>
                </div>
              )}

              {/* Sync devices list
              {syncSettings.enabled && (
                <div>
                  <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 var(--space-3) 0', fontSize: 'var(--text-sm)' }}>
                    Appareils autorisés ({syncSettings.devices.length})
                  </p>

                  {syncSettings.devices.length === 0 && (
                    <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontStyle: 'italic', margin: 0 }}>
                      Aucun appareil appairé. Utilisez le bouton ci-dessus pour appairer un appareil.
                    </p>
                  )}

                  {syncSettings.devices.map((device) => (
                    <div
                      key={device.verifying_key}
                      style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                        border: '1px solid var(--border)', marginBottom: 'var(--space-2)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                        <Smartphone size={18} style={{ color: 'var(--accent)' }} />
                        <div>
                          <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0, fontSize: 'var(--text-sm)' }}>
                            {device.name}
                          </p>
                          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
                            Ajouté le {new Date(device.added_at).toLocaleDateString('fr-FR')}
                            {device.last_sync && ` · Dernière sync: ${new Date(device.last_sync).toLocaleDateString('fr-FR')}`}
                          </p>
                        </div>
                      </div>
                      <button
                        onClick={() => removeSyncDevice(device.verifying_key)}
                        disabled={syncLoading}
                        style={{
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          width: 32, height: 32, borderRadius: 'var(--radius-md)',
                          border: '1px solid var(--danger)', background: 'var(--danger-muted)',
                          cursor: 'pointer', color: 'var(--danger)',
                        }}
                        title="Supprimer"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ))}
                </div>
              )} */}
            </div>
          )}
        </div>

        {/* Mode Isolation */}
        <div style={card}>
          <div style={cardHeader}>
            <ShieldCheck size={20} style={{ color: 'var(--accent)' }} />
            <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Mode Isolation</h2>
          </div>
          <div style={{ ...cardBody, display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div className={row}>
              <div>
                <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Activer le mode isolation</p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
                  Bloque les transferts réseau et désactive la découverte de pairs
                </p>
              </div>
              <Toggle on={isolationEnabled} onToggle={async () => {
                try {
                  const next = !isolationEnabled
                  await isolationMode.toggle(next)
                  setIsolationEnabled(next)
                  toast(next ? 'Mode isolation activé — transferts bloqués' : 'Mode isolation désactivé', next ? 'warning' : 'success')
                } catch (err: any) {
                  toast(err?.toString() || 'Erreur mode isolation', 'error')
                }
              }} />
            </div>
            {isolationEnabled && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
                padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                background: 'var(--warning-muted)', border: '1px solid var(--warning)',
                fontSize: 'var(--text-xs)', color: 'var(--warning)',
              }}>
                <AlertTriangle size={14} />
                Les transferts et la synchronisation sont désactivés en mode isolation.
              </div>
            )}
          </div>
        </div>

        {/* Logs Signés */}
        <div style={card}>
          <div style={cardHeader}>
            <FileText size={20} style={{ color: 'var(--accent)' }} />
            <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Logs Signés</h2>
          </div>
          <div style={cardBody}>
            <div className={row}>
              <div>
                <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>Activer les logs signés</p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }}>
                  Chaque action est signée cryptographiquement (ML-DSA-65) pour garantir l'intégrité de l'audit
                </p>
              </div>
              <Toggle on={signedLoggingEnabled} onToggle={async () => {
                try {
                  const next = !signedLoggingEnabled
                  await signedLogging.toggle(next)
                  setSignedLoggingEnabled(next)
                  toast(next ? 'Logs signés activés' : 'Logs signés désactivés', 'success')
                } catch (err: any) {
                  toast(err?.toString() || 'Erreur logs signés', 'error')
                }
              }} />
            </div>
          </div>
        </div>

        {/* Enclave Sécurisée */}
        {/* {enclaveStatus && (
          <div style={card}>
            <div style={cardHeader}>
              <Server size={20} style={{ color: 'var(--accent)' }} />
              <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Enclave Sécurisée</h2>
            </div>
            <div style={{ ...cardBody, display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 sm:gap-4 text-sm">
                  <span style={{ color: 'var(--text-secondary)' }}>Plateforme</span>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{enclaveStatus.platform}</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 sm:gap-4 text-sm">
                  <span style={{ color: 'var(--text-secondary)' }}>Type d'enclave</span>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 500, textAlign: 'right', maxWidth: '60%' }}>{enclaveStatus.enclave_type}</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 sm:gap-4 text-sm">
                  <span style={{ color: 'var(--text-secondary)' }}>Protection matérielle</span>
                  <span style={{
                    color: enclaveStatus.hardware_backed ? 'var(--success)' : 'var(--warning)',
                    fontWeight: 500,
                  }}>
                    {enclaveStatus.hardware_backed ? 'Oui (Secure Enclave)' : 'Non (logiciel)'}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:justify-between gap-1 sm:gap-4 text-sm">
                  <span style={{ color: 'var(--text-secondary)' }}>Sync iCloud désactivée</span>
                  <span style={{
                    color: enclaveStatus.sync_disabled ? 'var(--success)' : 'var(--warning)',
                    fontWeight: 500,
                  }}>
                    {enclaveStatus.sync_disabled ? 'Oui' : 'Non garanti'}
                  </span>
                </div>
              </div>
              {enclaveStatus.notes && (
                <div style={{
                  padding: 'var(--space-3)', borderRadius: 'var(--radius-md)',
                  background: 'color-mix(in srgb, var(--accent) 6%, transparent)',
                  border: '1px solid color-mix(in srgb, var(--accent) 15%, transparent)',
                  fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)',
                  lineHeight: 1.5,
                }}>
                  {enclaveStatus.notes}
                </div>
              )}
            </div>
          </div>
        )} */}

        {/* Save */}
        <div className="flex justify-end w-full">
          <Button icon={Save} onClick={save} className="w-full sm:w-auto">Enregistrer les paramètres</Button>
        </div>
      </div>
    </AppShell>
  )
}

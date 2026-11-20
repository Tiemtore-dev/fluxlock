import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Fingerprint, Save, Smartphone } from 'lucide-react'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input } from '../design-system/atoms'
import { Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { biometric, isolationMode } from '../lib/vault-service'
import { tauriAPI } from '../lib/tauri-api'
import { useAuthStore } from '../stores/authStore'
import { hasAndroidKeystore, androidBiometricAvailable, androidKeystoreDelete, androidHasStoredKey } from '../lib/android-biometric'
import { biometricAccount, enrollBiometrics } from '../lib/biometric-enrollment'

export default function SettingsPage() {
  const { toast } = useToast()
  const client = useQueryClient()
  const username = useAuthStore((state) => state.user?.username)
  const [dark, setDark] = useState(document.documentElement.classList.contains('dark'))
  const [color, setColor] = useState(localStorage.getItem('color-theme') || 'default')
  const [autoLock, setAutoLock] = useState(sessionStorage.getItem('autoLock') !== 'false')
  const [minutes, setMinutes] = useState(sessionStorage.getItem('lockTimeout') || '15')
  const [enrollMode, setEnrollMode] = useState<'native' | 'compatibility'>()
  const [password, setPassword] = useState('')
  const bio = useQuery({ queryKey: ['biometric-settings'], queryFn: biometric.checkStatus, staleTime: 0 })
  const isolation = useQuery({ queryKey: ['isolation-mode'], queryFn: isolationMode.get, staleTime: 0 })
  const android = hasAndroidKeystore()
  const bioAvailable = android ? androidBiometricAvailable() : bio.data?.available
  const bioAlias = username ? biometricAccount(username) : undefined
  const enrolled = bio.data?.enrolled && (!android || !!bioAlias && androidHasStoredKey(bioAlias))
  const compatibilityAvailable = !android && bio.data?.compatibility_available
  const activationLabel = compatibilityAvailable ? 'Activer Touch ID en mode compatibilité' : 'Activer la biométrie'
  const openEnrollment = () => setEnrollMode(compatibilityAvailable ? 'compatibility' : 'native')

  const refreshBio = () => { void client.invalidateQueries({ queryKey: ['biometric-settings'] }) }
  const closeEnroll = () => {
    setEnrollMode(undefined)
    setPassword('')
    enable.reset()
  }

  const enable = useMutation({
    mutationFn: () => {
      if (!username) throw new Error('Le compte est indisponible.')
      return enrollBiometrics(password, username, enrollMode === 'compatibility')
    },
    onSuccess: () => {
      closeEnroll()
      refreshBio()
      toast('Biométrie activée', 'success')
    },
    onError: () => setPassword(''),
  })
  const disable = useMutation({
    mutationFn: async () => {
      await biometric.disable()
      if (android && bioAlias) androidKeystoreDelete(bioAlias)
    },
    onSuccess: () => { refreshBio(); toast('Biométrie désactivée', 'success') },
  })
  const emergency = useMutation({
    mutationFn: biometric.emergencyLock,
    onSuccess: () => { refreshBio(); toast('Mot de passe requis au prochain déverrouillage', 'success') },
  })
  const toggleIsolation = useMutation({
    mutationFn: (enabled: boolean) => isolationMode.toggle(enabled),
    onSuccess: (_, enabled) => { client.setQueryData(['isolation-mode'], enabled) },
  })
  const saveLock = useMutation({
    mutationFn: async () => {
      const duration = Number(minutes)
      if (autoLock && (!Number.isInteger(duration) || duration < 1 || duration > 60)) {
        throw new Error('Saisissez un délai entre 1 et 60 minutes.')
      }
      await tauriAPI.setAutoLockTimeout(autoLock ? duration : 0)
      sessionStorage.setItem('autoLock', String(autoLock))
      if (autoLock) sessionStorage.setItem('lockTimeout', minutes)
      window.dispatchEvent(new Event('fluxlock:auto-lock-settings'))
    },
    onSuccess: () => toast('Verrouillage automatique enregistré', 'success'),
  })

  function applyTheme(nextDark: boolean) {
    setDark(nextDark)
    document.documentElement.classList.toggle('dark', nextDark)
    localStorage.setItem('theme', nextDark ? 'dark' : 'light')
  }

  function applyColor(nextColor: string) {
    setColor(nextColor)
    if (nextColor === 'default') {
      document.documentElement.removeAttribute('data-theme')
      localStorage.removeItem('color-theme')
    } else {
      document.documentElement.setAttribute('data-theme', nextColor)
      localStorage.setItem('color-theme', nextColor)
    }
  }

  function submitBiometric(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (password && !enable.isPending) enable.mutate()
  }

  return (
    <WorkspacePage title="Paramètres">
      <div className="workspace-columns">
        <section className="workspace-panel workspace-stack" aria-labelledby="appearance-title">
          <h2 id="appearance-title">Apparence</h2>
          <div className="workspace-segments" aria-label="Luminosité">
            <button type="button" aria-pressed={!dark} onClick={() => applyTheme(false)}>Clair</button>
            <button type="button" aria-pressed={dark} onClick={() => applyTheme(true)}>Sombre</button>
          </div>
          <label className="workspace-field">Couleur d’accent
            <select value={color} onChange={(event) => applyColor(event.target.value)}>
              <option value="default">Par défaut</option>
              <option value="ocean">Océan</option>
              <option value="amethyst">Améthyste</option>
              <option value="sunset">Crépuscule</option>
            </select>
          </label>
        </section>

        <form className="workspace-panel workspace-stack" onSubmit={(event) => { event.preventDefault(); saveLock.mutate() }}>
          <h2>Verrouillage automatique</h2>
          <label className="workspace-choice">
            <input type="checkbox" checked={autoLock} onChange={(event) => setAutoLock(event.target.checked)} />
            Verrouiller après une période d’inactivité
          </label>
          {autoLock && <Input type="number" label="Délai en minutes" min={1} max={60} step={1} required
            value={minutes} onChange={(event) => setMinutes(event.target.value)} />}
          {saveLock.isError && <p className="workspace-error" role="alert">{String(saveLock.error)}</p>}
          <div><Button type="submit" variant="secondary" icon={Save} loading={saveLock.isPending}>Enregistrer le délai</Button></div>
        </form>

        <section className="workspace-panel workspace-stack" aria-labelledby="biometric-title">
          <h2 id="biometric-title">Biométrie</h2>
          {bio.isPending ? <p role="status">Vérification du capteur…</p> : enrolled ? (
            <>
              <p>{bio.data?.compatibility_enrolled ? 'Touch ID est activé en mode compatibilité.' : 'Le déverrouillage biométrique est activé.'} {bio.data?.requires_password && (bio.data.password_reason || bio.data.unavailable_reason)}</p>
              <div className="workspace-actions">
                {!bioAvailable && compatibilityAvailable && <Button variant="secondary" icon={Fingerprint}
                  onClick={openEnrollment}>{activationLabel}</Button>}
                <Button variant="secondary" loading={emergency.isPending} disabled={disable.isPending}
                  onClick={() => emergency.mutate()}>Exiger le mot de passe</Button>
                <Button variant="secondary" loading={disable.isPending} disabled={emergency.isPending}
                  onClick={() => disable.mutate()}>Désactiver</Button>
              </div>
            </>
          ) : bioAvailable || compatibilityAvailable ? <>
            <p>Confirmez une fois votre mot de passe maître pour pouvoir déverrouiller le coffre avec le capteur de cet appareil.</p>
            <div><Button variant="secondary" icon={Fingerprint} onClick={openEnrollment}>{activationLabel}</Button></div>
          </> : (
            <p>{(!android && bio.data?.unavailable_reason) || 'Cette option nécessite un capteur biométrique configuré sur cet appareil.'}</p>
          )}
          {(disable.isError || emergency.isError) && <p role="alert" className="workspace-error">{String(disable.error || emergency.error)}</p>}
        </section>

        <section className="workspace-panel workspace-stack" aria-labelledby="network-title">
          <h2 id="network-title">Réseau et appareils</h2>
          <label className="workspace-choice">
            <input type="checkbox" checked={isolation.data === true} disabled={isolation.isPending || toggleIsolation.isPending}
              onChange={(event) => toggleIsolation.mutate(event.target.checked)} />
            Mode isolation
          </label>
          <p>Bloque le transfert, l’appairage et la découverte locale depuis l’application.</p>
          {toggleIsolation.isError && <p role="alert" className="workspace-error">{String(toggleIsolation.error)}</p>}
          <Link className="workspace-link" to="/transfer?vue=devices"><Smartphone size={17} aria-hidden="true" /> Gérer les appareils <ArrowRight size={16} aria-hidden="true" /></Link>
        </section>
      </div>
      <section className="workspace-panel workspace-stack workspace-danger" aria-labelledby="reset-settings">
        <h2 id="reset-settings">Réinitialisation</h2>
        <p>Supprime le compte et les données du coffre sur cet appareil.</p>
        <Link className="workspace-link" to="/reset-vault">Ouvrir la réinitialisation <ArrowRight size={16} aria-hidden="true" /></Link>
      </section>

      <Modal open={!!enrollMode} onClose={() => { if (!enable.isPending) closeEnroll() }}
        title={enrollMode === 'compatibility' ? 'Activer Touch ID en mode compatibilité' : 'Activer la biométrie'}>
        <form className="workspace-stack" onSubmit={submitBiometric}>
          {enrollMode === 'compatibility' && <p>Le trousseau macOS conserve la clé du coffre chiffrée. Seul le Secure Enclave de ce Mac peut la déchiffrer après validation de votre empreinte.</p>}
          <p>Saisissez votre mot de passe maître. L’appareil vous demandera ensuite une vérification biométrique.</p>
          <Input label="Mot de passe maître" type="password" autoComplete="current-password" required autoFocus
            value={password} onChange={(event) => setPassword(event.target.value)} disabled={enable.isPending} />
          {enable.isError && <p role="alert" className="workspace-error">{String(enable.error)}</p>}
          <div className="workspace-actions">
            <Button type="submit" loading={enable.isPending} disabled={!password}>Activer</Button>
            <Button variant="secondary" disabled={enable.isPending} onClick={closeEnroll}>Annuler</Button>
          </div>
        </form>
      </Modal>
    </WorkspacePage>
  )
}

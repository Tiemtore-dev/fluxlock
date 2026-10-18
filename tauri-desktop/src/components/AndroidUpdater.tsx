import { useCallback, useEffect, useRef, useState } from 'react'
import { Download, X } from 'lucide-react'
import { Button, useToast } from '../design-system'
import {
  androidCheckForUpdate,
  androidDownloadStatus,
  androidInstallUpdate,
  androidStartDownload,
  hasAndroidUpdater,
  type AndroidDownloadStatus,
} from '../lib/android-updater'

const STARTUP_DELAY_MS = 8_000
const POLL_INTERVAL_MS = 1_500
const RECHECK_AFTER_MS = 6 * 60 * 60 * 1000 // l'API GitHub non authentifiée est limitée à 60 req/h

/**
 * Mise à jour Android : détecte une nouvelle release GitHub, télécharge l'APK en arrière-plan,
 * puis affiche un bouton « Installer » une fois l'APK prêt et vérifié.
 */
export function AndroidUpdater() {
  const { toast } = useToast()
  const [status, setStatus] = useState<AndroidDownloadStatus>({ state: 'idle' })
  const [dismissed, setDismissed] = useState(false)
  const [hint, setHint] = useState<string | null>(null)
  const lastCheck = useRef(0)
  const announced = useRef<string | null>(null)

  const refreshStatus = useCallback(() => {
    const s = androidDownloadStatus()
    setStatus(s)
    return s
  }, [])

  const checkAndDownload = useCallback(async () => {
    lastCheck.current = Date.now()
    try {
      // Un téléchargement déjà en cours ou prêt (session précédente) est repris tel quel.
      const existing = refreshStatus()
      if (existing.state === 'downloading' || existing.state === 'ready') return

      const info = await androidCheckForUpdate()
      if (!info.available || !info.latestVersion) return

      if (announced.current !== info.latestVersion) {
        announced.current = info.latestVersion
        toast(`Nouvelle version ${info.latestVersion} disponible — téléchargement en arrière-plan…`, 'info')
      }
      const result = androidStartDownload(info)
      if (result.startsWith('error:')) throw new Error(result.slice(6))
      setDismissed(false)
      refreshStatus()
    } catch (e) {
      // Échec réseau silencieux : on réessaiera au prochain retour au premier plan.
      console.warn('[AndroidUpdater]', e)
    }
  }, [refreshStatus, toast])

  // Vérification au démarrage, puis au retour au premier plan (au plus toutes les 6 h).
  useEffect(() => {
    if (!hasAndroidUpdater()) return
    const timer = setTimeout(checkAndDownload, STARTUP_DELAY_MS)
    const onVisible = () => {
      if (document.visibilityState !== 'visible') return
      if (refreshStatus().state === 'idle' && Date.now() - lastCheck.current > RECHECK_AFTER_MS) {
        checkAndDownload()
      }
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [checkAndDownload, refreshStatus])

  // Suivi de la progression tant que le téléchargement est en cours.
  useEffect(() => {
    if (status.state !== 'downloading') return
    const interval = setInterval(() => {
      const s = refreshStatus()
      if (s.state === 'ready') toast(`Mise à jour ${s.version} prête à être installée.`, 'success')
      if (s.state === 'failed') toast(`Échec de la mise à jour : ${s.error ?? 'erreur inconnue'}`, 'error')
    }, POLL_INTERVAL_MS)
    return () => clearInterval(interval)
  }, [status.state, refreshStatus, toast])

  const install = () => {
    const result = androidInstallUpdate()
    if (result === 'needs_permission') {
      setHint('Autorisez FluXlock à installer des applications dans les réglages, puis revenez et appuyez de nouveau sur « Installer ».')
    } else if (result.startsWith('error:')) {
      toast(`Installation impossible : ${result.slice(6)}`, 'error')
      refreshStatus()
    } else {
      setHint(null)
    }
  }

  if (!hasAndroidUpdater() || dismissed) return null
  if (status.state !== 'downloading' && status.state !== 'ready') return null

  const percent = status.total && status.total > 0
    ? Math.min(100, Math.round(((status.downloaded ?? 0) / status.total) * 100))
    : null

  return (
    <div
      role="status"
      className="android-updater-banner"
      style={{
        position: 'fixed',
        left: 12,
        right: 12,
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        padding: '12px 14px',
        borderRadius: 12,
        background: 'var(--bg-elevated, var(--bg-secondary))',
        border: '1px solid var(--info)',
        color: 'var(--text-primary)',
        boxShadow: '0 8px 24px rgba(0,0,0,0.3)',
      }}
    >
      <Download size={20} style={{ flexShrink: 0, color: 'var(--info)' }} />
      <div style={{ flex: 1, minWidth: 0, fontSize: 'var(--text-sm)' }}>
        {status.state === 'downloading' ? (
          <>Téléchargement de la mise à jour {status.version}{percent !== null ? ` — ${percent} %` : '…'}</>
        ) : (
          <>
            <strong>Mise à jour {status.version} prête.</strong>
            {hint && <div style={{ marginTop: 4, color: 'var(--text-secondary)' }}>{hint}</div>}
          </>
        )}
      </div>
      {status.state === 'ready' && <Button size="sm" onClick={install}>Installer</Button>}
      <button
        type="button"
        aria-label="Masquer"
        onClick={() => setDismissed(true)}
        style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
      >
        <X size={16} />
      </button>
    </div>
  )
}

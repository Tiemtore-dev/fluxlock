/**
 * Android updater bridge — appelle AppUpdater.kt (window.AndroidUpdater).
 *
 * Le plugin Tauri updater n'existe pas sur Android : la vérification (API GitHub Releases),
 * le téléchargement (DownloadManager) et l'installation sont faits côté natif.
 * Hors Android (ou si l'interface est absente), toutes les fonctions sont inertes.
 */

export interface AndroidUpdateInfo {
  available: boolean
  currentVersion: string
  latestVersion?: string
  notes?: string
  url?: string
  size?: number
  sha256?: string
  error?: string
}

export interface AndroidDownloadStatus {
  state: 'idle' | 'downloading' | 'ready' | 'failed'
  version?: string
  downloaded?: number
  total?: number
  error?: string
}

export type AndroidInstallResult = 'ok' | 'needs_permission' | `error:${string}`

declare global {
  interface Window {
    AndroidUpdater?: {
      checkForUpdate(callbackId: string): void
      startDownload(url: string, version: string, sha256: string): string
      getDownloadStatus(): string
      installUpdate(): string
    }
    __updaterResolve?: (id: string, payload: string) => void
  }
}

export function hasAndroidUpdater(): boolean {
  return typeof window.AndroidUpdater?.checkForUpdate === 'function'
}

let callbackCounter = 0
const pending = new Map<string, (payload: string) => void>()

window.__updaterResolve = (id, payload) => {
  pending.get(id)?.(payload)
  pending.delete(id)
}

export function androidCheckForUpdate(): Promise<AndroidUpdateInfo> {
  return new Promise((resolve, reject) => {
    if (!window.AndroidUpdater) return reject(new Error('Updater Android indisponible'))
    const id = `upd_${++callbackCounter}`
    const timer = setTimeout(() => {
      pending.delete(id)
      reject(new Error('Délai dépassé'))
    }, 30_000)
    pending.set(id, (payload) => {
      clearTimeout(timer)
      resolve(JSON.parse(payload))
    })
    window.AndroidUpdater.checkForUpdate(id)
  })
}

export function androidStartDownload(info: AndroidUpdateInfo): string {
  if (!window.AndroidUpdater || !info.url || !info.latestVersion) return 'error:Informations manquantes'
  return window.AndroidUpdater.startDownload(info.url, info.latestVersion, info.sha256 ?? '')
}

export function androidDownloadStatus(): AndroidDownloadStatus {
  if (!window.AndroidUpdater) return { state: 'idle' }
  return JSON.parse(window.AndroidUpdater.getDownloadStatus())
}

export function androidInstallUpdate(): AndroidInstallResult {
  if (!window.AndroidUpdater) return 'error:Updater Android indisponible'
  return window.AndroidUpdater.installUpdate() as AndroidInstallResult
}

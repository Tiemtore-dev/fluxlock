import { removeAndroidBiometricEnrollment } from '../lib/biometric-enrollment'
import { useAuthStore } from '../stores/authStore'
import { useState, useEffect, useRef, type FormEvent } from 'react'
import { invoke, captureVaultContext } from '../lib/vault-context'
import { open } from '@tauri-apps/plugin-dialog'
import { FolderOpen, RefreshCw, HardDriveDownload } from 'lucide-react'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner } from '../design-system/atoms'
import { Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { hasAndroidStorage, saveFileToPublic } from '../lib/public-storage'

interface BackupMetadata {
  version: string
  created_at: string
  username: string
  device_name: string
  file_count: number
  password_count: number
  vault_id?: string
  vault_name?: string
}
interface BackupInfo { path: string; metadata: BackupMetadata }
interface CreateBackupResponse { success: boolean; backup_path?: string; message: string }
interface RestoreBackupResponse { success: boolean; message: string; metadata?: BackupMetadata }

const filename = (path: string) => path.split(/[\\/]/).pop() || path

export default function BackupRestorePage() {
  const { toast } = useToast()
  const [backups, setBackups] = useState<BackupInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [restoring, setRestoring] = useState(false)
  const [restoreError, setRestoreError] = useState('')
  const [searchError, setSearchError] = useState('')
  const [searching, setSearching] = useState(false)
  const [masterPw, setMasterPw] = useState('')
  const [showRestore, setShowRestore] = useState(false)
  const [restorePw, setRestorePw] = useState('')
  const [currentPw, setCurrentPw] = useState('')
  const [restorePath, setRestorePath] = useState<string | null>(null)
  const [lastSavedAt, setLastSavedAt] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const isAndroid = hasAndroidStorage()

  const searchBackups = async () => {
    setSearching(true)
    setSearchError('')
    try {
      const r: { backups: BackupInfo[] } = await invoke('search_backups')
      setBackups(r.backups)
    } catch (error) { setSearchError(String(error)) }
    finally { setSearching(false) }
  }

  useEffect(() => { searchBackups() }, [])

  const createBackup = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (loading || restoring) return
    if (!masterPw) { toast('Mot de passe maître requis', 'error'); return }
    setLoading(true)
    try {
      const r: CreateBackupResponse = await invoke('create_backup', { request: { master_password: masterPw } })
      if (r.success) {
        let location = r.backup_path ?? null
        if (isAndroid && r.backup_path) {
          // Copy outside the app sandbox so the backup survives an uninstall.
          const name = r.backup_path.split('/').pop() ?? 'backup.svbackup'
          try {
            location = saveFileToPublic(r.backup_path, name, 'application/octet-stream')
          } catch (e: any) {
            toast('Backup créé, mais copie vers Documents impossible : ' + (e?.message ?? e), 'error')
            location = null
          }
        }
        setLastSavedAt(location)
        if (location) toast(`Backup enregistré : ${location}`, 'success')
        setMasterPw(''); await searchBackups()
      }
      else toast(r.message, 'error')
    } catch (e: any) { toast('Erreur : ' + e, 'error') }
    finally { setLoading(false) }
  }

  const closeRestore = () => {
    if (restoring) return
    setShowRestore(false)
    setRestorePath(null)
    setRestorePw('')
    setCurrentPw('')
    setRestoreError('')
  }

  const confirmRestore = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!restorePath || !restorePw || !currentPw || restoring || loading) return
    setRestoring(true)
    setRestoreError('')
    try {
      const response: RestoreBackupResponse = await invoke('restore_backup', {
        request: { backup_path: restorePath, master_password: restorePw, current_password: currentPw },
      })
      if (response.success) {
        closeRestore()
        toast(response.message, 'success')
        removeAndroidBiometricEnrollment(useAuthStore.getState().user?.username)
        await useAuthStore.getState().clearAuth()
        return
      }
      setRestoreError(response.message)
    } catch (error) {
      setRestoreError(String(error))
    }
    setRestoring(false)
    setRestorePw('')
    setCurrentPw('')
  }

  // Android: the system picker returns content, not a path, so read it and hand it to the backend.
  const onAndroidFilePicked = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    const ensureCurrent = captureVaultContext()
    if (file.size > 64 * 1024 * 1024) { toast('Sauvegarde trop volumineuse', 'error'); return }
    try {
      const content = await file.text()
      ensureCurrent()
      const path: string = await invoke('import_backup_content', { content })
      const meta: BackupMetadata = await invoke('get_backup_metadata', { request: { backup_path: path } })
      setBackups(prev => [{ path, metadata: meta }, ...prev.filter(b => b.path !== path)])
      toast('Backup importé — vous pouvez le restaurer', 'success')
    } catch (err: any) { toast('Erreur fichier : ' + err, 'error') }
  }

  const selectCustom = async () => {
    const ensureCurrent = captureVaultContext()
    if (isAndroid) { fileInputRef.current?.click(); return }
    try {
      const sel = await open({ multiple: false, filters: [{ name: 'SecureVault Backup', extensions: ['svbackup'] }] })
      ensureCurrent()
      if (sel && typeof sel === 'string') {
        try {
          const meta: BackupMetadata = await invoke('get_backup_metadata', { request: { backup_path: sel } })
          if (!backups.some(b => b.path === sel)) setBackups([{ path: sel, metadata: meta }, ...backups])
        } catch (e: any) { toast('Erreur métadonnées : ' + e, 'error') }
      }
    } catch (e: any) { toast('Erreur fichier : ' + e, 'error') }
  }

  return (
    <WorkspacePage title="Sauvegardes" description={`Créez une copie chiffrée du coffre « ${useAuthStore.getState().selectedVault?.name || 'Coffre'} ». Une restauration remplace uniquement son contenu.`}>
      <div className="workspace-columns">
        <form className="workspace-panel workspace-stack" onSubmit={createBackup}>
          <div>
            <h2>Créer une sauvegarde</h2>
            <p>{isAndroid ? 'Une copie sera enregistrée dans Documents sur cet appareil.' : 'Une copie sera enregistrée dans le dossier de sauvegardes du coffre.'}</p>
          </div>
          <Input label="Mot de passe maître" type="password" autoComplete="current-password" value={masterPw}
            onChange={(event) => setMasterPw(event.target.value)} required disabled={loading || restoring} />
          <div><Button type="submit" icon={HardDriveDownload} loading={loading} disabled={!masterPw || restoring}>Créer la sauvegarde</Button></div>
          {lastSavedAt && <p role="status">Sauvegarde enregistrée dans {lastSavedAt}</p>}
        </form>

        <section className="workspace-panel workspace-stack" aria-labelledby="restore-section">
          <div>
            <h2 id="restore-section">Restaurer une sauvegarde</h2>
            <p>Choisissez une archive. La restauration remplacera le contenu du coffre actuel après confirmation.</p>
          </div>
          <div className="workspace-actions">
            <Button variant="secondary" icon={FolderOpen} onClick={selectCustom} disabled={restoring}>Ouvrir un fichier .svbackup</Button>
            <Button variant="ghost" icon={RefreshCw} onClick={searchBackups} loading={searching}>Actualiser</Button>
          </div>
          <input ref={fileInputRef} type="file" hidden onChange={onAndroidFilePicked} />
          {searchError && <p className="workspace-error" role="alert">Impossible de rechercher les sauvegardes. {searchError}</p>}
          {searching && <p role="status" className="workspace-label"><Spinner size={17} /> Recherche des archives…</p>}
          {!searching && !backups.length && <p className="workspace-empty">Aucune archive chargée.</p>}
          {!!backups.length && <ul className="workspace-list">
            {backups.map(({ path, metadata }) => (
              <li key={path} className="workspace-row">
                <div className="workspace-row-copy">
                  <strong>{filename(path)}</strong>
                  <span>{new Date(metadata.created_at).toLocaleString('fr-FR')}</span>
                  <span>{metadata.username} · {metadata.device_name}</span>
                </div>
                <Button variant="secondary" disabled={loading || restoring} onClick={() => {
                  setRestorePath(path)
                  setRestoreError('')
                  setShowRestore(true)
                }} aria-label={`Restaurer ${filename(path)}`}>Restaurer</Button>
              </li>
            ))}
          </ul>}
        </section>
      </div>

      <Modal open={showRestore} onClose={closeRestore} title="Restaurer une sauvegarde">
        <form className="workspace-stack" onSubmit={confirmRestore}>
          <p className="workspace-danger">Le contenu actuel du coffre sera remplacé par celui de <strong>{restorePath && filename(restorePath)}</strong>.</p>
          <Input type="password" label="Mot de passe de la sauvegarde" value={restorePw} required disabled={restoring}
            onChange={(event) => setRestorePw(event.target.value)} />
          <Input type="password" label="Mot de passe du coffre actuel" value={currentPw} required disabled={restoring}
            onChange={(event) => setCurrentPw(event.target.value)} autoComplete="current-password" />
          {restoreError && <p className="workspace-error" role="alert">{restoreError}</p>}
          <div className="workspace-actions">
            <Button variant="secondary" onClick={closeRestore} disabled={restoring}>Annuler</Button>
            <Button variant="danger" type="submit" loading={restoring} disabled={!restorePw || !currentPw}>Restaurer et remplacer</Button>
          </div>
        </form>
      </Modal>
    </WorkspacePage>
  )
}

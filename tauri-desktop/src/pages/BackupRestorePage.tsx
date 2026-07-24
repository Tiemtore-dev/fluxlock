import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { open } from '@tauri-apps/plugin-dialog'
import { HardDrive, Search, FolderOpen, RefreshCw, Upload, AlertTriangle } from 'lucide-react'
import { AppShell } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { Modal, EmptyState } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'

interface BackupMetadata {
  version: string
  created_at: string
  username: string
  device_name: string
  file_count: number
  password_count: number
}
interface BackupInfo { path: string; metadata: BackupMetadata }
interface CreateBackupResponse { success: boolean; backup_path?: string; message: string }
interface RestoreBackupResponse { success: boolean; message: string; metadata?: BackupMetadata }

const fmt = (iso: string) => { try { return new Date(iso).toLocaleString('fr-FR') } catch { return iso } }

export default function BackupRestorePage() {
  const { toast } = useToast()
  const [backups, setBackups] = useState<BackupInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [searching, setSearching] = useState(false)
  const [masterPw, setMasterPw] = useState('')
  const [showRestore, setShowRestore] = useState(false)
  const [restorePw, setRestorePw] = useState('')
  const [restorePath, setRestorePath] = useState<string | null>(null)

  const searchBackups = async () => {
    setSearching(true)
    try {
      const r: { backups: BackupInfo[] } = await invoke('search_backups')
      setBackups(r.backups)
      toast(`${r.backups.length} backup(s) trouvé(s)`, 'success')
    } catch (e: any) { toast('Erreur recherche : ' + e, 'error') }
    finally { setSearching(false) }
  }

  useEffect(() => { searchBackups() }, [])

  const createBackup = async () => {
    if (!masterPw) { toast('Mot de passe maître requis', 'error'); return }
    setLoading(true)
    try {
      const r: CreateBackupResponse = await invoke('create_backup', { request: { master_password: masterPw } })
      if (r.success) { toast('Backup créé avec succès', 'success'); setMasterPw(''); await searchBackups() }
      else toast(r.message, 'error')
    } catch (e: any) { toast('Erreur : ' + e, 'error') }
    finally { setLoading(false) }
  }

  const confirmRestore = async () => {
    if (!restorePath || !restorePw) return
    setShowRestore(false); setLoading(true)
    toast('Restauration en cours…', 'info')
    try {
      const r: RestoreBackupResponse = await invoke('restore_backup', { request: { backup_path: restorePath, master_password: restorePw } })
      if (r.success) { toast(r.message, 'success'); setTimeout(() => window.location.reload(), 3000) }
      else { toast(r.message, 'error'); setLoading(false) }
    } catch (e: any) { toast('Échec restauration : ' + e, 'error'); setLoading(false) }
    setRestorePw(''); setRestorePath(null)
  }

  const selectCustom = async () => {
    try {
      const sel = await open({ multiple: false, filters: [{ name: 'SecureVault Backup', extensions: ['svbackup'] }] })
      if (sel && typeof sel === 'string') {
        try {
          const meta: BackupMetadata = await invoke('get_backup_metadata', { request: { backup_path: sel } })
          if (!backups.some(b => b.path === sel)) setBackups([{ path: sel, metadata: meta }, ...backups])
        } catch (e: any) { toast('Erreur métadonnées : ' + e, 'error') }
      }
    } catch (e: any) { toast('Erreur fichier : ' + e, 'error') }
  }

  const card: React.CSSProperties = { background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 'var(--space-6)' }

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div className="page-header">
          <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)', margin: 0 }}>
            <HardDrive size={28} style={{ color: 'var(--accent)' }} /> Backup & Restauration
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginTop: 'var(--space-1)' }}>Sauvegardez et restaurez votre coffre-fort</p>
        </div>

        {/* Create backup */}
        <div style={card}>
          <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', marginBottom: 'var(--space-4)' }}>Créer un backup</h2>
          <div style={{ display: 'flex', gap: 'var(--space-4)', alignItems: 'flex-end', flexWrap: 'wrap' }}>
            <div style={{ flex: 1 }}>
              <Input label="Mot de passe maître" type="password" value={masterPw} onChange={(e) => setMasterPw(e.target.value)} placeholder="Entrez votre mot de passe" disabled={loading} />
            </div>
            <Button icon={Upload} onClick={createBackup} disabled={loading || !masterPw}>
              {loading ? 'Création…' : 'Créer'}
            </Button>
          </div>
          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', marginTop: 'var(--space-2)' }}>Sauvegardé dans Documents/SecureVault Backups/</p>
        </div>

        {/* Backup list */}
        <div style={card}>
          <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-4 mb-4">
            <h2 style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-lg)', margin: 0 }}>Backups disponibles</h2>
            <div className="flex flex-wrap gap-2 w-full sm:w-auto">
              <Button variant="secondary" icon={FolderOpen} onClick={selectCustom} className="flex-1 sm:flex-initial">Ouvrir .svbackup</Button>
              <Button variant="secondary" icon={RefreshCw} onClick={searchBackups} disabled={searching} className="flex-1 sm:flex-initial">
                {searching ? 'Recherche…' : 'Rechercher'}
              </Button>
            </div>
          </div>

          {backups.length === 0 ? (
            <EmptyState icon={Search} title="Aucun backup trouvé" description="Créez votre premier backup ou ouvrez un fichier .svbackup existant" />
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {backups.map((b, i) => (
                <div key={i} style={{ border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 'var(--space-4)' }} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex-1 min-w-0 w-full">
                    <p style={{ fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                      {b.metadata.username}@{b.metadata.device_name}
                    </p>
                    <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', margin: '4px 0' }}>
                      {fmt(b.metadata.created_at)} · {b.metadata.file_count} fichier(s) · v{b.metadata.version}
                    </p>
                    <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)', margin: 0 }} className="break-all">{b.path}</p>
                  </div>
                  <Button variant="secondary" onClick={() => { setRestorePath(b.path); setRestorePw(''); setShowRestore(true) }} disabled={loading} className="w-full sm:w-auto flex-shrink-0">
                    Restaurer
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Warning */}
        <div style={{ background: 'var(--warning-muted)', borderLeft: '4px solid var(--warning)', borderRadius: 'var(--radius-md)', padding: 'var(--space-4)' }}>
          <div style={{ display: 'flex', gap: 'var(--space-3)', alignItems: 'flex-start' }}>
            <AlertTriangle size={20} style={{ color: 'var(--warning)', flexShrink: 0, marginTop: 2 }} />
            <div>
              <h3 style={{ fontWeight: 700, color: 'var(--warning)', marginBottom: 'var(--space-2)' }}>Important</h3>
              <ul style={{ margin: 0, paddingLeft: 'var(--space-4)', fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                <li>Les backups sont chiffrés avec votre mot de passe maître</li>
                <li>La restauration remplacera toutes vos données actuelles</li>
                <li>Conservez vos backups dans un endroit sûr</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Restore modal */}
      <Modal open={showRestore} onClose={() => { setShowRestore(false); setRestorePw('') }} title="Restauration du backup">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <div style={{ background: 'var(--warning-muted)', borderLeft: '4px solid var(--warning)', borderRadius: 'var(--radius-md)', padding: 'var(--space-3)' }}>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--warning)', fontWeight: 600, margin: 0 }}>Cette action remplacera TOUTES vos données actuelles !</p>
          </div>
          <Input type="password" label="Mot de passe maître" value={restorePw} onChange={(e) => setRestorePw(e.target.value)} onKeyDown={(e: React.KeyboardEvent) => e.key === 'Enter' && confirmRestore()} placeholder="Mot de passe" autoFocus />
          <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
            <Button fullWidth variant="secondary" onClick={() => { setShowRestore(false); setRestorePw('') }}>Annuler</Button>
            <Button fullWidth variant="danger" onClick={confirmRestore} disabled={!restorePw}>Confirmer</Button>
          </div>
        </div>
      </Modal>
    </AppShell>
  )
}

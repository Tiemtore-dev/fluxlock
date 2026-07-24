import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { open, save } from '@tauri-apps/plugin-dialog'
import { readFile } from '@tauri-apps/plugin-fs'
import { listen } from '@tauri-apps/api/event'
import { invoke } from '@tauri-apps/api/core'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import {
  Upload, Download, Trash2, FileText, Image, Film, Music, Archive,
  File as FileIcon, AlertCircle, Share2, FolderLock, ShieldAlert,
} from 'lucide-react'
import { files as filesSvc, type SecureFile } from '../lib/vault-service'
import { useAuthStore } from '../stores/authStore'
import { AppShell } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { SearchBar, EmptyState, Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'

/** If a backend error indicates expired session, logout and redirect */
function useSessionGuard() {
  const clearAuth = useAuthStore((s) => s.clearAuth)
  const navigate = useNavigate()
  return (error: unknown) => {
    const msg = String(error)
    if (msg.includes('Non authentifié') || msg.includes('not authenticated')) {
      clearAuth()
      navigate('/login')
    }
  }
}

/* ───── helpers ───── */
const fmtSize = (b: number) => {
  if (b === 0) return '0 B'
  const k = 1024, s = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(b) / Math.log(k))
  return `${parseFloat((b / Math.pow(k, i)).toFixed(2))} ${s[i]}`
}

const fmtDate = (d: string) =>
  new Date(d).toLocaleDateString('fr-FR', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })

const mimeIcon = (mime?: string) => {
  const s: React.CSSProperties = { width: 28, height: 28 }
  if (!mime) return <FileIcon style={{ ...s, color: 'var(--text-disabled)' }} />
  if (mime.startsWith('image/')) return <Image style={{ ...s, color: 'var(--accent)' }} />
  if (mime.startsWith('video/')) return <Film style={{ ...s, color: '#a78bfa' }} />
  if (mime.startsWith('audio/')) return <Music style={{ ...s, color: '#34d399' }} />
  if (mime.includes('zip') || mime.includes('compressed')) return <Archive style={{ ...s, color: '#fbbf24' }} />
  if (mime.startsWith('text/') || mime.includes('pdf')) return <FileText style={{ ...s, color: '#f87171' }} />
  return <FileIcon style={{ ...s, color: 'var(--text-disabled)' }} />
}

/* ───── component ───── */
const FilesPage = () => {
  const qc = useQueryClient()
  const { toast } = useToast()
  const guardSession = useSessionGuard()
  const [search, setSearch] = useState('')
  const [showUpload, setShowUpload] = useState(false)
  const [showShare, setShowShare] = useState(false)
  const [shareTarget, setShareTarget] = useState<SecureFile | null>(null)
  const [shareEmail, setShareEmail] = useState('')
  const [shareExpiry, setShareExpiry] = useState('7')
  const [selectedName, setSelectedName] = useState<string | null>(null)
  const [selectedPath, setSelectedPath] = useState<string | null>(null)
  const [uploadErr, setUploadErr] = useState('')
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [progressMsg, setProgressMsg] = useState('')
  const [showProgress, setShowProgress] = useState(false)
  const [isReadonly, setIsReadonly] = useState(false)

  // Check readonly status
  useEffect(() => {
    invoke<{ is_readonly: boolean }>('get_security_status')
      .then((s) => setIsReadonly(s.is_readonly))
      .catch(() => {})
  }, [])

  /* encryption / decryption progress listeners */
  useEffect(() => {
    let offEnc: (() => void) | null = null
    let offDec: (() => void) | null = null
    const setup = async () => {
      const handler = (e: { payload: { progress: number; message: string } }) => {
        setProgress(e.payload.progress)
        setProgressMsg(e.payload.message)
        setShowProgress(true)
        if (e.payload.progress === 100) setTimeout(() => { setShowProgress(false); setProgress(0); setProgressMsg('') }, 1500)
      }
      offEnc = await listen<any>('file-encryption-progress', handler)
      offDec = await listen<any>('file-decryption-progress', handler)
    }
    setup()
    return () => { offEnc?.(); offDec?.() }
  }, [])

  const { data: list = [], isLoading, isError, error: queryError, refetch } = useQuery({
    queryKey: ['secureFiles'],
    queryFn: filesSvc.list,
    retry: 1,
  })

  // Surface query errors
  useEffect(() => {
    if (isError && queryError) {
      console.error('[FilesPage] list query error:', queryError)
      guardSession(queryError)
    }
  }, [isError, queryError])

  const handleMutError = (label: string) => (e: unknown) => {
    console.error(`[FilesPage] ${label} error:`, e)
    toast('Erreur : ' + String(e), 'error')
    guardSession(e)
  }

  const createMut = useMutation({
    mutationFn: (p: string) => filesSvc.createFromPath(p),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['secureFiles'] }); closeUpload(); toast('Fichier chiffré et ajouté', 'success') },
    onError: (e: Error) => { setUploadErr(String(e) || 'Erreur'); handleMutError('createFromPath')(e) },
  })
  const deleteMut = useMutation({
    mutationFn: (id: number) => filesSvc.delete(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['secureFiles'] }); toast('Fichier supprimé', 'success') },
    onError: handleMutError('delete'),
  })

  const filtered = list.filter((f) => f.filename.toLowerCase().includes(search.toLowerCase()))

  const closeUpload = () => { setShowUpload(false); setSelectedName(null); setSelectedPath(null); setUploadErr('') }

  const handleSelect = async () => {
    try {
      const sel = await open({ multiple: false })
      if (!sel || Array.isArray(sel)) return
      setSelectedPath(sel)
      setSelectedName(sel.split('/').pop() || sel.split('\\').pop() || 'fichier')
      setUploadErr('')
    } catch (e) {
      console.error('[FilesPage] file dialog error:', e)
      setUploadErr('Erreur ouverture du sélecteur de fichier : ' + String(e))
    }
  }

  const handleUpload = async () => {
    if (!selectedPath) return
    setUploading(true); setShowProgress(true); setProgress(0); setProgressMsg('Préparation…'); setUploadErr('')
    try {
      // On Android, file dialog returns content:// URIs that Rust can't open directly.
      // Read via Tauri's fs plugin (handles content:// URIs) and send base64 to backend.
      if (selectedPath.startsWith('content://') || selectedPath.startsWith('file://')) {
        const bytes = await readFile(selectedPath)
        const uint8 = new Uint8Array(bytes)
        // Chunked base64 encoding to avoid call stack overflow on large files
        let binary = ''
        const chunkSize = 8192
        for (let i = 0; i < uint8.length; i += chunkSize) {
          binary += String.fromCharCode(...uint8.subarray(i, Math.min(i + chunkSize, uint8.length)))
        }
        const base64 = btoa(binary)
        const filename = selectedName || 'fichier'
        await filesSvc.create(filename, base64)
        qc.invalidateQueries({ queryKey: ['secureFiles'] })
        closeUpload()
        toast('Fichier chiffré et ajouté', 'success')
      } else {
        await createMut.mutateAsync(selectedPath)
      }
    } catch (e) { console.error('[FilesPage] upload error:', e); setUploadErr(String(e)) }
    finally { setUploading(false) }
  }

  const handleDownload = async (f: SecureFile) => {
    setShowProgress(true); setProgress(0); setProgressMsg('Préparation…')
    const dest = await save({ defaultPath: f.filename })
    if (!dest) { setShowProgress(false); return }
    try {
      await filesSvc.decryptToPath(f.id, dest)
      toast(`"${f.filename}" téléchargé`, 'success')
    } catch (e) { toast('Erreur téléchargement : ' + e, 'error') }
    finally { setShowProgress(false) }
  }

  const handleShareSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!shareTarget || !shareEmail.trim()) return
    try {
      const res = await invoke<{ success: boolean; share_link: string; expires_at: string }>('share_file', {
        request: { file_id: shareTarget.id, recipient_email: shareEmail, expiration_days: parseInt(shareExpiry) }
      })
      if (res.success) { await writeText(res.share_link); toast('Lien copié dans le presse-papiers', 'success') }
      setShowShare(false); setShareTarget(null); setShareEmail(''); setShareExpiry('7')
    } catch (e) { toast('Erreur partage : ' + e, 'error') }
  }

  if (isLoading) return <AppShell><div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--space-16)' }}><Spinner size={32} /></div></AppShell>

  if (isError) return (
    <AppShell>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-4)', padding: 'var(--space-16)' }}>
        <AlertCircle size={40} style={{ color: 'var(--danger)' }} />
        <p style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-base)' }}>
          Erreur de chargement des fichiers
        </p>
        <p style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)', textAlign: 'center', maxWidth: 400 }}>
          {String(queryError)}
        </p>
        <Button onClick={() => refetch()}>Réessayer</Button>
      </div>
    </AppShell>
  )

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div className="page-header flex flex-col items-start sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <FolderLock size={28} style={{ color: 'var(--accent)' }} />
              Fichiers sécurisés
            </h1>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', marginTop: 'var(--space-1)' }}>
              {list.length} fichier{list.length !== 1 ? 's' : ''} chiffré{list.length !== 1 ? 's' : ''}
            </p>
          </div>
          <Button icon={Upload} onClick={() => setShowUpload(true)} disabled={isReadonly} className="w-full sm:w-auto">Ajouter</Button>
        </div>

        {/* Readonly banner */}
        {isReadonly && (
          <div className="flex items-center gap-2 rounded-lg px-4 py-3 text-sm" style={{ background: 'var(--danger-muted)', border: '1px solid var(--danger)', color: 'var(--danger)', fontFamily: 'var(--font-body)' }}>
            <ShieldAlert size={16} />
            Coffre-fort en lecture seule — modifications bloquées
          </div>
        )}

        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher un fichier…" />

        {/* Progress bar (visible during encrypt/decrypt) */}
        {showProgress && (
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 'var(--text-sm)', fontFamily: 'var(--font-body)' }}>
              <span style={{ color: 'var(--text-secondary)' }}>{progressMsg}</span>
              <span style={{ color: 'var(--accent)', fontWeight: 600 }}>{progress}%</span>
            </div>
            <div style={{ width: '100%', height: 6, background: 'var(--bg-input)', borderRadius: 'var(--radius-full)', overflow: 'hidden' }}>
              <div style={{ width: `${progress}%`, height: '100%', background: 'var(--accent)', borderRadius: 'var(--radius-full)', transition: 'width 0.3s ease' }} />
            </div>
          </div>
        )}

        {/* File grid */}
        {filtered.length === 0 ? (
          <EmptyState icon={FolderLock} title={search ? 'Aucun résultat' : 'Aucun fichier'} description={search ? undefined : 'Ajoutez votre premier fichier sécurisé'}
            action={!search ? <Button icon={Upload} onClick={() => setShowUpload(true)}>Ajouter</Button> : undefined} />
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(min(280px, 100%), 1fr))', gap: 'var(--space-4)' }}>
            {filtered.map((f) => (
              <div key={f.id} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 'var(--space-5)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', transition: 'border-color var(--transition-fast)' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)' }}>
                  {mimeIcon(f.mime_type)}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)', overflow: 'hidden', textOverflow: 'ellipsis' }} className="break-all" title={f.filename}>{f.filename}</p>
                    <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{fmtSize(f.file_size)}</p>
                  </div>
                </div>
                <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-disabled)', fontFamily: 'var(--font-body)' }}>{fmtDate(f.created_at)}</span>
                <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                  <Button size="sm" icon={Download} onClick={() => handleDownload(f)} style={{ flex: 1 }}>Télécharger</Button>
                  <Button size="sm" variant="ghost" icon={Trash2} onClick={() => { if (confirm(`Supprimer "${f.filename}" ?`)) deleteMut.mutate(f.id) }} disabled={isReadonly} style={{ color: 'var(--danger)' }} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Upload modal */}
      <Modal open={showUpload} onClose={closeUpload} title="Ajouter un fichier">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <button onClick={handleSelect} style={{
            width: '100%', padding: 'var(--space-6)', border: '2px dashed var(--border)', borderRadius: 'var(--radius-lg)',
            background: 'transparent', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)',
            cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-2)',
            transition: 'border-color var(--transition-fast)',
          }}>
            <Upload size={18} /> Cliquer pour choisir un fichier
          </button>

          {selectedName && (
            <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 'var(--space-3)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              <FileIcon size={18} style={{ color: 'var(--accent)' }} />
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selectedName}</span>
            </div>
          )}

          {uploadErr && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'var(--danger-muted)', borderRadius: 'var(--radius-md)' }}>
              <AlertCircle size={16} style={{ color: 'var(--danger)', flexShrink: 0 }} />
              <span style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)', fontFamily: 'var(--font-body)' }}>{uploadErr}</span>
            </div>
          )}

          <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-disabled)', fontFamily: 'var(--font-body)' }}>
            Les fichiers sont chiffrés sur disque — aucune limite de taille.
          </p>

          <div style={{ display: 'flex', gap: 'var(--space-3)', paddingTop: 'var(--space-2)' }}>
            <Button fullWidth onClick={handleUpload} loading={uploading} disabled={!selectedPath}>Chiffrer et ajouter</Button>
            <Button fullWidth variant="secondary" onClick={closeUpload}>Annuler</Button>
          </div>
        </div>
      </Modal>

      {/* Share modal */}
      <Modal open={showShare && !!shareTarget} onClose={() => { setShowShare(false); setShareTarget(null) }} title="Partager le fichier">
        {shareTarget && (
          <form onSubmit={handleShareSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 'var(--space-3)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
              {mimeIcon(shareTarget.mime_type)}
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{shareTarget.filename}</p>
                <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{fmtSize(shareTarget.file_size)}</p>
              </div>
            </div>
            <Input label="Email du destinataire" type="email" value={shareEmail} onChange={(e) => setShareEmail(e.target.value)} placeholder="user@example.com" required />
            <div>
              <label style={{ display: 'block', fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', letterSpacing: 'var(--tracking-wide)', textTransform: 'uppercase', marginBottom: 'var(--space-1)' }}>Expiration</label>
              <select value={shareExpiry} onChange={(e) => setShareExpiry(e.target.value)} style={{ width: '100%', padding: '10px 12px', background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)', outline: 'none' }}>
                <option value="1">1 jour</option><option value="3">3 jours</option><option value="7">7 jours</option><option value="14">14 jours</option><option value="30">30 jours</option>
              </select>
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'color-mix(in srgb, var(--accent) 8%, transparent)', borderRadius: 'var(--radius-md)' }}>
              <AlertCircle size={16} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 2 }} />
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)' }}>Lien sécurisé chiffré — authentification requise.</span>
            </div>
            <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
              <Button type="submit" fullWidth icon={Share2}>Partager</Button>
              <Button type="button" variant="secondary" fullWidth onClick={() => { setShowShare(false); setShareTarget(null) }}>Annuler</Button>
            </div>
          </form>
        )}
      </Modal>
    </AppShell>
  )
}

export default FilesPage

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useNavigate } from 'react-router-dom'
import { open, save } from '@tauri-apps/plugin-dialog'
import { readFile, stat } from '@tauri-apps/plugin-fs'
import { hasAndroidStorage, saveFileToPublic } from '../lib/public-storage'
import { listen } from '@tauri-apps/api/event'
import { invoke } from '@tauri-apps/api/core'
import {
  Upload, Download, Trash2, FileText, Image, Film, Music, Archive,
  File as FileIcon, AlertCircle,
} from 'lucide-react'
import { files as filesSvc, type SecureFile } from '../lib/vault-service'
import { useAuthStore } from '../stores/authStore'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Spinner } from '../design-system/atoms'
import { SearchBar, Modal } from '../design-system/molecules'
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
        const fileInfo = await stat(selectedPath)
        if (fileInfo.size > 32 * 1024 * 1024) {
          throw new Error('Sur Android, cet import accepte les fichiers de 32 Mio maximum.')
        }
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
    try {
      if (hasAndroidStorage()) {
        const stagedPath = await filesSvc.decryptToPath(f.id)
        const destination = saveFileToPublic(stagedPath, f.filename, f.mime_type || 'application/octet-stream')
        toast(`Fichier exporté dans ${destination}`, 'success')
      } else {
        const destination = await save({ defaultPath: f.filename })
        if (!destination) return
        await filesSvc.decryptToPath(f.id, destination)
        toast(`« ${f.filename} » exporté`, 'success')
      }
    } catch (error) {
      toast(`Export impossible. ${String(error)}`, 'error')
    } finally {
      setShowProgress(false)
    }

  }

  return (
    <WorkspacePage title="Fichiers chiffrés" description="Ajoutez des documents au coffre et exportez-les lorsque vous en avez besoin."
      actions={<>
        <Link to="/shares" className="workspace-link">Fichiers partagés</Link>
        <Button icon={Upload} onClick={() => setShowUpload(true)} disabled={isReadonly}>Ajouter un fichier</Button>
      </>}>
      {isReadonly && <p role="status" className="workspace-error">Le coffre est en lecture seule. Les modifications sont désactivées.</p>}
      {showProgress && <section className="workspace-panel workspace-stack" role="status">
        <div className="workspace-actions"><h2>{progressMsg}</h2><span className="workspace-label">{progress} %</span></div>
        <progress value={progress} max={100} aria-label={progressMsg || 'Opération sur un fichier'} />
      </section>}
      <section className="workspace-panel workspace-stack" aria-labelledby="file-list">
        <h2 id="file-list">Documents du coffre</h2>
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher un fichier…" />
        {isLoading ? <p role="status" className="workspace-label"><Spinner size={18} /> Chargement…</p> :
          isError ? <div className="workspace-stack">
            <p role="alert" className="workspace-error">Impossible de charger les fichiers. {String(queryError)}</p>
            <div><Button variant="secondary" onClick={() => void refetch()}>Réessayer</Button></div>
          </div> : filtered.length === 0 ? (
          <p className="workspace-empty">{search ? 'Aucun fichier ne correspond à votre recherche.' : 'Ajoutez votre premier document pour le chiffrer.'}</p>
        ) : (
          <ul className="workspace-list">
            {filtered.map((file) => (
              <li key={file.id} className="workspace-row">
                <span className="workspace-icon" aria-hidden="true">{mimeIcon(file.mime_type)}</span>
                <div className="workspace-row-copy">
                  <strong>{file.filename}</strong>
                  <span>{fmtSize(file.file_size)} · {fmtDate(file.created_at)}</span>
                </div>
                <div className="workspace-actions">
                  <Button variant="secondary" size="sm" icon={Download} onClick={() => void handleDownload(file)}
                    aria-label={`Exporter ${file.filename}`}>Exporter</Button>
                  <Button variant="ghost" size="sm" icon={Trash2} disabled={isReadonly}
                    aria-label={`Supprimer ${file.filename}`}
                    onClick={() => { if (confirm(`Supprimer « ${file.filename} » ?`)) deleteMut.mutate(file.id) }} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Upload modal */}
      <Modal open={showUpload} onClose={closeUpload} title="Ajouter un fichier">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <button onClick={handleSelect} style={{
            width: '100%', padding: 'var(--space-6)', border: '2px dashed var(--border)', borderRadius: 'var(--radius-lg)',
            background: 'transparent', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)',
            cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-2)',
            transition: 'border-color var(--transition-fast)',
          }}>
            <Upload size={18} /> Choisir un fichier
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
            Le document est chiffré dès son ajout au coffre.
          </p>

          <div style={{ display: 'flex', gap: 'var(--space-3)', paddingTop: 'var(--space-2)' }}>
            <Button fullWidth onClick={handleUpload} loading={uploading} disabled={!selectedPath}>Chiffrer et ajouter</Button>
            <Button fullWidth variant="secondary" onClick={closeUpload}>Annuler</Button>
          </div>
        </div>
      </Modal>

    </WorkspacePage>
  )
}

export default FilesPage

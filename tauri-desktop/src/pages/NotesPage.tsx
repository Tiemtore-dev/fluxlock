import { useEffect, useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { open, save } from '@tauri-apps/plugin-dialog'
import { readFile, stat } from '@tauri-apps/plugin-fs'
import { FileText, Plus, Paperclip, Trash2, Download, Pencil } from 'lucide-react'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner } from '../design-system/atoms'
import { Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { notes, files, type NoteDetail, type NoteSummary, type NotePayload } from '../lib/vault-service'
import { captureVaultContext, invoke } from '../lib/vault-context'
import { hasAndroidStorage, saveFileToPublic } from '../lib/public-storage'
import { useAuthStore } from '../stores/authStore'

const MAX_FILE_BYTES = 32 * 1024 * 1024
const errorText = (error: unknown) => error instanceof Error ? error.message : String(error)
const formatSize = (size: number) => `${(size / 1024).toLocaleString('fr-FR', { maximumFractionDigits: 1 })} Kio`

export default function NotesPage() {
  const vaultId = useAuthStore((s) => s.selectedVault?.id)
  const client = useQueryClient()
  const { toast } = useToast()
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const [editor, setEditor] = useState(false)
  const [editing, setEditing] = useState<NoteDetail | null>(null)
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [fileId, setFileId] = useState<number | undefined>()
  const [path, setPath] = useState<string | undefined>()
  const [filename, setFilename] = useState('')
  const [dirty, setDirty] = useState(false)
  const [discard, setDiscard] = useState(false)
  const [viewing, setViewing] = useState<NoteDetail | null>(null)
  const [deleting, setDeleting] = useState<NoteSummary | null>(null)
  const [error, setError] = useState('')
  const [opening, setOpening] = useState(false)
  const [picking, setPicking] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [readonly, setReadonly] = useState(false)
  const list = useQuery({ queryKey: ['notes', vaultId, search, offset], queryFn: () => notes.list(search, offset) })
  const availableFiles = useQuery({ queryKey: ['secureFiles'], queryFn: files.list, enabled: editor })

  useEffect(() => {
    invoke<{ is_readonly: boolean }>('get_security_status').then((s) => setReadonly(s.is_readonly)).catch(() => {})
  }, [])
  useEffect(() => {
    if (!dirty) return
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = '' }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [dirty])

  function closeEditor() {
    setEditor(false); setEditing(null); setTitle(''); setBody(''); setFileId(undefined)
    setPath(undefined); setFilename(''); setDirty(false); setDiscard(false); setError('')
    saveMutation.reset()
  }
  function startEditor(note: NoteDetail | null = null) {
    setViewing(null); setEditing(note); setTitle(note?.title || ''); setBody(note?.body || '')
    setFileId(note?.attachment?.id); setFilename(note?.attachment?.filename || ''); setPath(undefined)
    setDirty(false); setError(''); setEditor(true)
  }
  function refresh() {
    void client.invalidateQueries({ queryKey: ['notes'] })
    void client.invalidateQueries({ queryKey: ['secureFiles'] })
  }
  const saveMutation = useMutation({
    mutationFn: async () => {
      const ensureCurrent = captureVaultContext()
      const request: NotePayload = { id: editing?.id, revision: editing?.revision, title, body, attachment_file_id: fileId }
      if (new TextEncoder().encode(body).length > 1024 * 1024) throw new Error('La note dépasse 1 Mio de texte UTF-8.')
      if (path) {
        if (path.startsWith('content://') || path.startsWith('file://')) {
          const info = await stat(path); ensureCurrent()
          if (info.size > MAX_FILE_BYTES) throw new Error('La pièce jointe dépasse 32 Mio.')
          const bytes = await readFile(path); ensureCurrent()
          if (bytes.length > MAX_FILE_BYTES) throw new Error('La pièce jointe dépasse 32 Mio.')
          let binary = ''
          for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192))
          request.attachment_name = filename
          request.attachment_data = btoa(binary)
        } else request.attachment_path = path
      }
      ensureCurrent()
      try { return await notes.save(request) }
      finally { request.body = ''; request.attachment_data = undefined }
    },
    onSuccess: () => { closeEditor(); refresh(); toast('Note chiffrée et enregistrée', 'success') },
    onError: (reason) => setError(errorText(reason)),
  })
  const deleteMutation = useMutation({
    mutationFn: (note: NoteSummary) => notes.delete(note.id, note.revision),
    onSuccess: () => { setDeleting(null); setOffset(0); refresh(); toast('Note supprimée. Les fichiers sont conservés dans Fichiers.', 'success') },
  })

  async function readNote(note: NoteSummary, edit: boolean) {
    if (opening) return
    setOpening(true)
    try {
      const detail = await notes.get(note.id)
      if (edit) startEditor(detail)
      else setViewing(detail)
    } catch (reason) { toast(errorText(reason), 'error') }
    finally { setOpening(false) }
  }
  async function selectFile() {
    const ensureCurrent = captureVaultContext()
    setPicking(true); setError('')
    try {
      const selected = await open({ multiple: false }); ensureCurrent()
      if (!selected || Array.isArray(selected)) return
      const info = await stat(selected); ensureCurrent()
      if (info.size > MAX_FILE_BYTES) throw new Error('La pièce jointe dépasse 32 Mio.')
      setPath(selected); setFileId(undefined); setFilename(selected.split(/[/\\]/).pop() || 'piece-jointe'); setDirty(true)
    } catch (reason) { setError(errorText(reason)) }
    finally { setPicking(false) }
  }
  async function exportAttachment(note: NoteDetail) {
    if (!note.attachment) return
    const ensureCurrent = captureVaultContext()
    setExporting(true)
    try {
      if (hasAndroidStorage()) {
        const temporary = await notes.exportAttachment(note.id, note.revision); ensureCurrent()
        try {
          const destination = saveFileToPublic(temporary, note.attachment.filename, 'application/octet-stream')
          toast(`Copie en clair exportée dans ${destination}`, 'success')
        } finally { await invoke('cleanup_decrypted_files') }
      } else {
        const destination = await save({ defaultPath: note.attachment.filename }); ensureCurrent()
        if (!destination) return
        await notes.exportAttachment(note.id, note.revision, destination)
        toast('Copie en clair exportée', 'success')
      }
    } catch (reason) { toast(errorText(reason), 'error') }
    finally { setExporting(false) }
  }

  function submit(event: FormEvent) { event.preventDefault(); setError(''); saveMutation.mutate() }
  const busy = saveMutation.isPending || picking
  return <WorkspacePage title="Notes" description="Conservez vos textes et leurs pièces jointes dans votre coffre chiffré."
    actions={<Button icon={Plus} disabled={readonly} onClick={() => startEditor()}>Nouvelle note</Button>}>
    {readonly && <p role="status" className="workspace-error">Le coffre est en lecture seule.</p>}
    <Input type="search" label="Rechercher dans les titres" value={search} maxLength={256}
      onChange={(event) => { setSearch(event.target.value); setOffset(0) }} />
    {list.isPending ? <p role="status"><Spinner size={18} /> Chargement des notes…</p>
      : list.isError ? <div role="alert" className="workspace-stack"><p>{errorText(list.error)}</p><Button variant="secondary" onClick={() => void list.refetch()}>Réessayer</Button></div>
      : <>
        {list.data.items.length === 0 ? <p className="workspace-panel">{search ? 'Aucune note ne correspond à ce titre.' : 'Aucune note. Créez votre première note chiffrée.'}</p>
          : <ul className="workspace-list" aria-label="Notes enregistrées">{list.data.items.map((note) => <li key={note.id} className="notes-row">
            <button type="button" className="notes-open workspace-row-copy" aria-label={`Ouvrir ${note.title}`} onClick={() => void readNote(note, false)} disabled={opening}>
              <strong><FileText size={18} aria-hidden="true" /> {note.title}</strong>
              <span>{new Date(note.updated_at.replace(' ', 'T') + 'Z').toLocaleString('fr-FR')}{note.has_attachment ? ' · Pièce jointe' : ''}</span>
            </button>
            <div className="workspace-actions">
              <Button variant="secondary" size="sm" icon={Pencil} disabled={readonly || opening} onClick={() => void readNote(note, true)} aria-label={`Modifier ${note.title}`}>Modifier</Button>
              <Button variant="ghost" size="sm" icon={Trash2} disabled={readonly} onClick={() => { deleteMutation.reset(); setDeleting(note) }} aria-label={`Supprimer ${note.title}`}>Supprimer</Button>
            </div>
          </li>)}</ul>}
        <div className="workspace-actions" aria-label="Pagination des notes">
          <Button variant="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Précédent</Button>
          <span role="status">{list.data.total} note{list.data.total !== 1 ? 's' : ''}</span>
          <Button variant="secondary" disabled={offset + 50 >= list.data.total} onClick={() => setOffset(offset + 50)}>Suivant</Button>
        </div>
      </>}

    <Modal open={editor} title={editing ? 'Modifier la note' : 'Nouvelle note'} width={720}
      onClose={() => { if (!busy) { if (dirty) setDiscard(true); else closeEditor() } }}>
      <form onSubmit={submit} className="workspace-stack">
        <Input label="Titre" value={title} required maxLength={256} autoComplete="off" autoCorrect="off" spellCheck={false} disabled={busy}
          onChange={(event) => { setTitle(event.target.value); setDirty(true) }} />
        <div className="workspace-stack"><label htmlFor="note-body">Texte de la note</label>
          <textarea id="note-body" className="notes-textarea" rows={12} value={body} maxLength={1024 * 1024} disabled={busy}
            autoComplete="off" autoCorrect="off" spellCheck={false} onChange={(event) => { setBody(event.target.value); setDirty(true) }} />
        </div>
        <fieldset className="workspace-stack notes-attachment" disabled={busy}>
          <legend>Pièce jointe facultative · 32 Mio maximum</legend>
          {filename && <p><Paperclip size={16} aria-hidden="true" /> {filename}</p>}
          <div className="workspace-actions">
            <Button type="button" variant="secondary" icon={Paperclip} onClick={() => void selectFile()} loading={picking}>Choisir un fichier</Button>
            {filename && <Button type="button" variant="ghost" onClick={() => { setFileId(undefined); setPath(undefined); setFilename(''); setDirty(true) }}>Détacher</Button>}
          </div>
          <label htmlFor="note-existing-file">Ou rattacher un fichier du coffre</label>
          <select id="note-existing-file" className="notes-select" value={fileId ?? ''} onChange={(event) => {
            const id = event.target.value ? Number(event.target.value) : undefined
            setFileId(id); setPath(undefined); setFilename(availableFiles.data?.find((f) => f.id === id)?.filename || ''); setDirty(true)
          }}>
            <option value="">Aucun fichier existant</option>
            {availableFiles.data?.filter((f) => f.file_size <= MAX_FILE_BYTES).map((file) => <option key={file.id} value={file.id}>{file.filename} · {formatSize(file.file_size)}</option>)}
          </select>
          {availableFiles.isError && <p role="alert">Impossible de charger les fichiers existants.</p>}
          {path && <p className="workspace-label">Une copie chiffrée sera ajoutée au coffre. Le fichier original reste à son emplacement.</p>}
        </fieldset>
        {error && <p role="alert" className="workspace-error">{error}</p>}
        {discard && <div role="alert" className="workspace-stack"><p>Abandonner les modifications non enregistrées ?</p><div className="workspace-actions">
          <Button type="button" variant="secondary" onClick={() => setDiscard(false)}>Continuer la rédaction</Button>
          <Button type="button" variant="danger" onClick={closeEditor}>Abandonner</Button>
        </div></div>}
        <div className="workspace-actions">
          <Button type="submit" loading={saveMutation.isPending} disabled={busy || readonly || !title.trim()}>Enregistrer la note</Button>
          <Button type="button" variant="secondary" disabled={busy} onClick={() => dirty ? setDiscard(true) : closeEditor()}>Annuler</Button>
        </div>
      </form>
    </Modal>
    <Modal open={!!viewing} title={viewing?.title || 'Note'} width={720} onClose={() => { if (!exporting) setViewing(null) }}>
      {viewing && <div className="workspace-stack">
        <p className="notes-body">{viewing.body || 'Cette note ne contient pas de texte.'}</p>
        {viewing.attachment && <section className="workspace-stack notes-attachment" aria-label="Pièce jointe">
          <p><Paperclip size={16} aria-hidden="true" /> {viewing.attachment.filename} · {formatSize(viewing.attachment.file_size)}</p>
          <p className="workspace-label">L’export crée une copie en clair à la destination choisie.</p>
          <Button variant="secondary" icon={Download} loading={exporting} onClick={() => void exportAttachment(viewing)}>Exporter la pièce jointe</Button>
        </section>}
        <Button icon={Pencil} disabled={readonly || exporting} onClick={() => startEditor(viewing)}>Modifier la note</Button>
      </div>}
    </Modal>
    <Modal open={!!deleting} title="Supprimer la note" onClose={() => { if (!deleteMutation.isPending) setDeleting(null) }}>
      <div className="workspace-stack"><p>Supprimer « {deleting?.title} » ? Le fichier joint restera dans Fichiers.</p>
        {deleteMutation.isError && <p role="alert" className="workspace-error">{errorText(deleteMutation.error)}</p>}
        <div className="workspace-actions"><Button variant="danger" loading={deleteMutation.isPending} disabled={readonly} onClick={() => deleting && deleteMutation.mutate(deleting)}>Supprimer définitivement</Button>
          <Button variant="secondary" disabled={deleteMutation.isPending} onClick={() => setDeleting(null)}>Annuler</Button></div>
      </div>
    </Modal>
  </WorkspacePage>
}

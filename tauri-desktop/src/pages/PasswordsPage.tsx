import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Plus, Edit2, Trash2, RefreshCw, ShieldAlert, Download, Upload, Fingerprint, Eye, EyeOff, FileText, CheckCircle2, ArrowRightLeft } from 'lucide-react'
import { invoke, captureVaultContext } from '../lib/vault-context'
import { hasAndroidKeystore } from '../lib/android-biometric'
import { hasAndroidStorage, saveTextToPublic } from '../lib/public-storage'
import { passwords, csvIO, biometric, type Password, type EntryAction, type ImportCsvResponse } from '../lib/vault-service'
import { useAuthStore } from '../stores/authStore'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { SearchBar, PasswordField, PasswordStrength, Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { useClipboard } from '../hooks/useClipboard'

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

export default function PasswordsPage() {
  const queryClient = useQueryClient()
  const { toast } = useToast()
  const copy = useClipboard()
  const guardSession = useSessionGuard()
  const [search, setSearch] = useState('')
  const [filterCategory, setFilterCategory] = useState<string | null>(null)
  const [isReadonly, setIsReadonly] = useState(false)
  const [showModal, setShowModal] = useState(false)
  const [editing, setEditing] = useState<Password | null>(null)
  const [revealed, setRevealed] = useState<Set<number>>(new Set())
  const [copied, setCopied] = useState<number | null>(null)
  const [pwLength, setPwLength] = useState(20)
  const [pwUpper, setPwUpper] = useState(true)
  const [pwLower, setPwLower] = useState(true)
  const [pwDigits, setPwDigits] = useState(true)
  const [pwSymbols, setPwSymbols] = useState(true)

  const [title, setTitle] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [url, setUrl] = useState('')
  const [notes, setNotes] = useState('')
  const [category, setCategory] = useState('')

  // ── CSV Import/Export state ──
  const [showImportModal, setShowImportModal] = useState(false)
  const [showExportModal, setShowExportModal] = useState(false)
  const [csvAuthPw, setCsvAuthPw] = useState('')
  const [csvAuthVisible, setCsvAuthVisible] = useState(false)
  const [csvLoading, setCsvLoading] = useState(false)
  const [csvError, setCsvError] = useState('')
  // Import-specific
  const [csvFile, setCsvFile] = useState<File | null>(null)
  const [csvFormat, setCsvFormat] = useState('auto')
  const [csvPreview, setCsvPreview] = useState<ImportCsvResponse | null>(null)
  const [csvActions, setCsvActions] = useState<Record<number, 'import' | 'skip' | 'overwrite'>>({})
  const [csvImportResult, setCsvImportResult] = useState<ImportCsvResponse | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const reviewedCsv = useRef<{ content: string; biometric: boolean } | null>(null)
  const csvBiometrics = useQuery({
    queryKey: ['csv-biometric-status'],
    queryFn: biometric.checkStatus,
    enabled: (showImportModal || showExportModal) && !hasAndroidKeystore(),
    staleTime: 0,
  })
  const canUseCsvBiometrics = !hasAndroidKeystore() && !!csvBiometrics.data?.available &&
    csvBiometrics.data.enrolled && !csvBiometrics.data.requires_password
  // Export-specific
  const [exportDone, setExportDone] = useState(false)
  const [exportLocation, setExportLocation] = useState('')

  const { data: list = [], isLoading, isError, error: queryError, refetch } = useQuery({
    queryKey: ['passwords'],
    queryFn: passwords.list,
    retry: 1,
  })

  // Surface query errors
  useEffect(() => {
    if (isError && queryError) {
      console.error('[PasswordsPage] list query error:', queryError)
      guardSession(queryError)
    }
  }, [isError, queryError])

  // Check readonly status
  useEffect(() => {
    invoke<{ is_readonly: boolean }>('get_security_status')
      .then((s) => setIsReadonly(s.is_readonly))
      .catch(() => {})
  }, [])

  const handleMutError = (e: unknown) => {
    console.error('[PasswordsPage] mutation error:', e)
    toast('Erreur : ' + String(e), 'error')
    guardSession(e)
  }

  const createMut = useMutation({
    mutationFn: () => passwords.create({ title, username, password, url, notes, category }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['passwords'] }); close(); toast('Mot de passe créé', 'success') },
    onError: handleMutError,
  })

  const updateMut = useMutation({
    mutationFn: () => passwords.update({ id: editing!.id, title, username, password, url, notes, category }),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['passwords'] }); close(); toast('Mot de passe modifié', 'success') },
    onError: handleMutError,
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => passwords.delete(id),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['passwords'] }); toast('Supprimé', 'success') },
    onError: handleMutError,
  })

  // Listen for ⌘N shortcut
  useEffect(() => {
    const h = () => openCreate()
    window.addEventListener('fluxlock:new-entry', h)
    return () => window.removeEventListener('fluxlock:new-entry', h)
  }, [])

  const filtered = list.filter((p) => {
    const s = search.toLowerCase()
    const matchesSearch = p.title.toLowerCase().includes(s) || (p.username?.toLowerCase() || '').includes(s) || (p.url?.toLowerCase() || '').includes(s) || (p.category?.toLowerCase() || '').includes(s)
    const matchesCategory = !filterCategory || (p.category?.toLowerCase() === filterCategory.toLowerCase())
    return matchesSearch && matchesCategory
  })

  // Extract unique categories from the password list for filter chips
  const categories = Array.from(new Set(list.map((p) => p.category).filter(Boolean) as string[]))

  const resetForm = () => { setTitle(''); setUsername(''); setPassword(''); setUrl(''); setNotes(''); setCategory(''); setEditing(null) }
  const close = () => { setShowModal(false); resetForm() }
  const openCreate = () => { resetForm(); setShowModal(true) }
  const openEdit = (p: Password) => { setEditing(p); setTitle(p.title); setUsername(p.username || ''); setPassword(p.password); setUrl(p.url || ''); setNotes(p.notes || ''); setCategory(p.category || ''); setShowModal(true) }

  // ── CSV Import helpers ──
  const resetImportModal = () => {
    reviewedCsv.current = null
    setCsvFile(null); setCsvFormat('auto'); setCsvPreview(null); setCsvActions({})
    setCsvImportResult(null); setCsvAuthPw(''); setCsvAuthVisible(false); setCsvError('')
    setCsvLoading(false)
  }
  const openImport = () => { resetImportModal(); setShowImportModal(true) }
  const closeImport = () => { setShowImportModal(false); resetImportModal() }

  const handleCsvFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    setCsvError('')
    if (file && file.size > 10 * 1024 * 1024) {
      setCsvFile(null)
      e.target.value = ''
      setCsvError('Le fichier dépasse la limite de 10 Mio.')
      return
    }
    setCsvFile(file ?? null)
  }

  const handleCsvPreview = async (useBiometrics = false) => {
    if (!csvFile || csvLoading || (!useBiometrics && csvAuthPw === '')) return
    const ensureCurrent = captureVaultContext()
    setCsvLoading(true); setCsvError('')
    try {
      const content = new TextDecoder('utf-8', { fatal: true }).decode(await csvFile.arrayBuffer())
      ensureCurrent()
      const credential = useBiometrics ? null : csvAuthPw
      const result = await csvIO.preview(credential, content, csvFormat)
      reviewedCsv.current = { content, biometric: useBiometrics }
      setCsvPreview(result)
      // Default actions: 'import' for new, 'skip' for duplicates
      const defaults: Record<number, 'import' | 'skip' | 'overwrite'> = {}
      result.entries?.forEach((e) => {
        if (!e.parse_error) defaults[e.index] = e.is_duplicate ? 'skip' : 'import'
      })
      setCsvActions(defaults)
    } catch (err) {
      setCsvError(String(err))
    } finally {
      setCsvLoading(false)
    }
  }

  const handleCsvImport = async () => {
    if (!csvPreview || !reviewedCsv.current || csvLoading) return
    setCsvLoading(true); setCsvError('')
    try {
      const { content, biometric } = reviewedCsv.current
      const masterPw = biometric ? null : csvAuthPw
      const entryActions: EntryAction[] = Object.entries(csvActions).map(([idx, action]) => {
        const entry = csvPreview.entries?.find((e) => e.index === Number(idx))
        return {
          index: Number(idx),
          action,
          overwrite_id: action === 'overwrite' ? entry?.existing_match?.id : undefined,
        }
      })
      const result = await csvIO.import(masterPw, content, csvFormat, entryActions)
      reviewedCsv.current = null
      setCsvAuthPw('')
      setCsvAuthVisible(false)
      setCsvImportResult(result)
      queryClient.invalidateQueries({ queryKey: ['passwords'] })

    } catch (err) {
      setCsvError(String(err))
    } finally {
      setCsvLoading(false)
    }
  }

  // ── CSV Export helpers ──
  const openExport = () => { setCsvAuthPw(''); setCsvAuthVisible(false); setCsvError(''); setExportDone(false); setExportLocation(''); setCsvLoading(false); setShowExportModal(true) }
  const closeExport = () => { setShowExportModal(false); setCsvAuthPw(''); setCsvError('') }

  const handleCsvExport = async (useBiometrics = false) => {
    setCsvLoading(true); setCsvError('')
    try {
      const masterPw = useBiometrics ? null : csvAuthPw
      const result = await csvIO.export(masterPw)
      const fileName = `fluxlock-export-${new Date().toISOString().slice(0, 10)}.csv`
      const location = hasAndroidStorage()
        ? saveTextToPublic(result.csv_content, fileName, 'text/csv')
        : await invoke<string>('export_text_to_downloads', { filename: fileName, content: result.csv_content })
      setExportLocation(location)
      setExportDone(true)
      toast(`${result.count} mots de passe exportés`, 'success')
    } catch (err) {
      setCsvError(String(err))
    } finally {
      setCsvLoading(false)
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!title || !password) { toast('Titre et mot de passe requis', 'error'); return }
    editing ? updateMut.mutate() : createMut.mutate()
  }

  const handleCopy = (text: string, id: number) => {
    copy(text)
    setCopied(id)
    toast('Copié — effacé dans 30 s', 'success')
    setTimeout(() => setCopied(null), 2000)
  }

  const generatePassword = () => {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    const lower = 'abcdefghijklmnopqrstuvwxyz'
    const digits = '0123456789'
    const symbols = '!@#$%^&*()_+-='
    // Rejection sampling : élimine tout biais de modulo
    const rnd = (max: number) => {
      const limit = Math.floor(0x100000000 / max) * max
      let r: number
      do {
        const a = new Uint32Array(1)
        crypto.getRandomValues(a)
        r = a[0]
      } while (r >= limit)
      return r % max
    }
    // Construire le charset selon les toggles
    let charset = ''
    if (pwUpper) charset += upper
    if (pwLower) charset += lower
    if (pwDigits) charset += digits
    if (pwSymbols) charset += symbols
    if (charset.length === 0) charset = upper + lower + digits + symbols
    // Garantir au moins un caractère de chaque catégorie activée
    let pw = ''
    if (pwUpper) pw += upper[rnd(upper.length)]
    if (pwLower) pw += lower[rnd(lower.length)]
    if (pwDigits) pw += digits[rnd(digits.length)]
    if (pwSymbols) pw += symbols[rnd(symbols.length)]
    const len = Math.max(pwLength, pw.length)
    for (let i = pw.length; i < len; i++) pw += charset[rnd(charset.length)]
    // Fisher-Yates shuffle
    const chars = pw.split('')
    for (let i = chars.length - 1; i > 0; i--) { const j = rnd(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]] }
    setPassword(chars.join(''))
  }

  const renderForm = () => (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Input label="Titre" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ex: Gmail" required />
      <Input label="Nom d'utilisateur / Email" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="user@example.com" />
      <div>
        <div className="flex flex-col sm:flex-row gap-2 sm:items-end">
          <div className="flex-1">
            <Input label="Mot de passe" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Mot de passe" required />
          </div>
          <Button type="button" variant="secondary" icon={RefreshCw} onClick={generatePassword} style={{ marginBottom: 0 }} className="w-full sm:w-auto">
            Générer
          </Button>
        </div>
        <div className="mt-3 flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <label htmlFor="password-generator-length" className="text-xs text-tx-secondary font-body min-w-[70px]">Longueur : {pwLength}</label>
            <input id="password-generator-length" type="range" min={8} max={64} value={pwLength} onChange={(e) => setPwLength(Number(e.target.value))} className="flex-1 accent-accent" />
          </div>
          <div className="flex gap-4 flex-wrap">
            {([['A-Z', pwUpper, setPwUpper], ['a-z', pwLower, setPwLower], ['0-9', pwDigits, setPwDigits], ['!@#', pwSymbols, setPwSymbols]] as const).map(([label, val, set]) => (
              <label key={label} className="flex items-center gap-1.5 text-xs text-tx-secondary font-mono cursor-pointer">
                <input type="checkbox" checked={val as boolean} onChange={() => (set as React.Dispatch<React.SetStateAction<boolean>>)((v: boolean) => !v)} className="accent-accent" />
                {label}
              </label>
            ))}
          </div>
        </div>
        <div className="mt-3">
          <PasswordStrength password={password} />
        </div>
      </div>
      <Input label="URL" inputMode="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" />
      <Input label="Catégorie" value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Social, Email, Travail…" />
      <div>
        <label htmlFor="password-notes" className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Notes</label>
        <textarea
          id="password-notes"
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="Notes additionnelles…"
          rows={3}
          className="w-full bg-input border border-bd rounded-lg px-3 py-2.5 text-tx-primary font-body text-sm outline-none resize-y focus:border-accent transition-colors"
        />
      </div>
      <div className="flex gap-3 pt-2 mt-auto">
        <Button type="submit" fullWidth loading={createMut.isPending || updateMut.isPending}>
          {editing ? 'Modifier' : 'Créer'}
        </Button>
        <Button type="button" variant="secondary" fullWidth onClick={close}>Annuler</Button>
      </div>
    </form>
  )

  return (
    <WorkspacePage title="Mots de passe" description={`${list.length} identifiant${list.length === 1 ? '' : 's'} enregistré${list.length === 1 ? '' : 's'}`}
      actions={<>
        <Button variant="secondary" icon={Download} onClick={openImport} disabled={isReadonly}>Importer un CSV</Button>
        <Button variant="secondary" icon={Upload} onClick={openExport}>Exporter un CSV</Button>
        <Button icon={Plus} onClick={openCreate} disabled={isReadonly}>Nouvel identifiant</Button>
      </>}>
      {isReadonly && <p className="workspace-error" role="status">Le coffre est en lecture seule. Les modifications sont désactivées.</p>}
      <section className="workspace-panel workspace-stack" aria-labelledby="password-list">
        <h2 id="password-list">Identifiants du coffre</h2>
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher un identifiant…" />
        {categories.length > 0 && <div className="workspace-segments" role="group" aria-label="Filtrer par catégorie">
          <button type="button" aria-pressed={!filterCategory} onClick={() => setFilterCategory(null)}>Tous</button>
          {categories.map((name) => <button key={name} type="button" aria-pressed={filterCategory === name}
            onClick={() => setFilterCategory(filterCategory === name ? null : name)}>{name}</button>)}
        </div>}
        {isLoading ? <p role="status" className="workspace-label"><Spinner size={18} /> Chargement…</p> :
          isError ? <div className="workspace-stack">
            <p role="alert" className="workspace-error">Impossible de charger les identifiants. {String(queryError)}</p>
            <div><Button variant="secondary" onClick={() => void refetch()}>Réessayer</Button></div>
          </div> : filtered.length === 0 ? (
          <p className="workspace-empty">{search || filterCategory ? 'Aucun identifiant ne correspond à votre recherche.' : 'Ajoutez votre premier identifiant ou importez un CSV.'}</p>
        ) : (
          <ul className="workspace-list">
            {filtered.map((item) => (
              <li key={item.id} className="workspace-row">
                <div className="workspace-row-copy">
                  <strong>{item.title}</strong>
                  {item.username && <span>{item.username}</span>}
                  {item.url && <span>{item.url}</span>}
                  {item.category && <span>{item.category}</span>}
                </div>
                <div className="workspace-secret">
                  <PasswordField value={item.password} revealed={revealed.has(item.id)}
                    onToggleReveal={() => setRevealed((previous) => {
                      const next = new Set(previous)
                      if (next.has(item.id)) next.delete(item.id)
                      else next.add(item.id)
                      return next
                    })}
                    onCopy={() => handleCopy(item.password, item.id)} copied={copied === item.id} />
                </div>
                <div className="workspace-actions">
                  <Button variant="secondary" size="sm" icon={Edit2} onClick={() => openEdit(item)}
                    disabled={isReadonly} aria-label={`Modifier ${item.title}`}>Modifier</Button>
                  <Button variant="ghost" size="sm" icon={Trash2} disabled={isReadonly}
                    aria-label={`Supprimer ${item.title}`}
                    onClick={() => { if (confirm(`Supprimer « ${item.title} » ?`)) deleteMut.mutate(item.id) }} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <Modal open={showModal} onClose={close} title={editing ? 'Modifier le mot de passe' : 'Nouveau mot de passe'}>
        {renderForm()}
      </Modal>

      {/* ═══ Import CSV Modal ═══ */}
      <Modal open={showImportModal} onClose={() => { if (!csvLoading) closeImport() }} title="Importer des mots de passe" width={680}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {/* Step indicator */}
          <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-body)' }}>
            <span className={`px-2 py-0.5 rounded-full ${!csvPreview ? 'bg-accent/20 text-accent-text' : 'opacity-50'}`} style={{ background: !csvPreview ? 'var(--accent-muted)' : undefined }}>1. Fichier</span>
            <span>→</span>
            <span className={`px-2 py-0.5 rounded-full ${csvPreview && !csvImportResult ? 'bg-accent/20 text-accent-text' : 'opacity-50'}`} style={{ background: csvPreview && !csvImportResult ? 'var(--accent-muted)' : undefined }}>2. Vérification</span>
            <span>→</span>
            <span className={`px-2 py-0.5 rounded-full ${csvImportResult ? 'bg-accent/20 text-accent-text' : 'opacity-50'}`} style={{ background: csvImportResult ? 'var(--accent-muted)' : undefined }}>3. Résultat</span>
          </div>

          {/* ── Result screen ── */}
          {csvImportResult ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-4)', padding: 'var(--space-6)' }}>
              <CheckCircle2 size={48} style={{ color: 'var(--success)' }} />
              <p style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
                Import terminé
              </p>
              <div className="grid grid-cols-3 gap-4 text-center w-full" style={{ fontFamily: 'var(--font-body)' }}>
                <div className="p-3 rounded-lg" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                  <p style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--success)' }}>{csvImportResult.imported_count}</p>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Importés</p>
                </div>
                <div className="p-3 rounded-lg" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                  <p style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--warning)' }}>{csvImportResult.overwritten_count}</p>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Écrasés</p>
                </div>
                <div className="p-3 rounded-lg" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                  <p style={{ fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--text-muted)' }}>{csvImportResult.skipped_count}</p>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>Ignorés</p>
                </div>
              </div>
              {csvImportResult.errors.length > 0 && (
                <div className="w-full rounded-lg p-3 text-xs" style={{ background: 'var(--danger-muted)', border: '1px solid var(--danger)', color: 'var(--danger)', fontFamily: 'var(--font-body)' }}>
                  {csvImportResult.errors.map((e, i) => <p key={i}>{e}</p>)}
                </div>
              )}
              <Button onClick={closeImport} fullWidth>Fermer</Button>
            </div>
          ) : csvPreview ? (
            /* ── Preview / conflict resolution screen ── */
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              <div className="workspace-actions justify-between">
                <Badge>{csvPreview.detected_format}</Badge>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                  {csvPreview.new_count} à ajouter · {csvPreview.duplicate_count} doublon{csvPreview.duplicate_count > 1 ? 's' : ''} · {csvPreview.error_count} erreur{csvPreview.error_count > 1 ? 's' : ''}
                </span>
              </div>
              <div style={{ maxHeight: 340, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                {csvPreview.entries?.filter((e) => !e.parse_error).map((entry) => (
                  <div key={entry.index}
                    className="rounded-lg p-3 flex flex-col gap-1"
                    style={{
                      background: 'var(--bg-surface)',
                      border: `1px solid ${entry.is_duplicate ? 'var(--warning)' : 'var(--border)'}`,
                      fontFamily: 'var(--font-body)',
                    }}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <p style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }} className="truncate">{entry.title}</p>
                        {entry.username && <p className="text-sm break-words">{entry.username}</p>}
                        {entry.url && <p className="workspace-label break-all">{entry.url}</p>}
                        {entry.category && <p className="workspace-label break-words">{entry.category}</p>}
                        {entry.notes && <p className="workspace-label whitespace-pre-wrap break-words">{entry.notes}</p>}
                      </div>
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{entry.password_preview}</span>
                    </div>
                    {!entry.is_duplicate && (
                      <label className="workspace-choice text-sm">
                        <input type="checkbox" checked={csvActions[entry.index] === 'import'}
                          aria-label={`Inclure ${entry.title}`}
                          onChange={(event) => {
                            const action = event.target.checked ? 'import' : 'skip'
                            setCsvActions((previous) => ({ ...previous, [entry.index]: action }))
                          }} />
                        Inclure
                      </label>
                    )}
                    {entry.is_duplicate && entry.existing_match && (
                      <div className="mt-1 flex flex-col gap-1.5">
                        <div className="flex items-center gap-1.5" style={{ fontSize: 'var(--text-xs)', color: 'var(--warning)' }}>
                          <ArrowRightLeft size={12} />
                          <span>Doublon de : <strong>{entry.existing_match.title}</strong></span>
                        </div>
                        <div className="flex gap-2 flex-wrap">
                          {(['skip', 'overwrite', 'import'] as const).map((action) => (
                            <label key={action} className="flex items-center gap-1 cursor-pointer" style={{ fontSize: 'var(--text-xs)', color: csvActions[entry.index] === action ? 'var(--accent-text)' : 'var(--text-muted)' }}>
                              <input type="radio" name={`action-${entry.index}`} checked={csvActions[entry.index] === action}
                                onChange={() => setCsvActions((prev) => ({ ...prev, [entry.index]: action }))}
                                style={{ accentColor: 'var(--accent)' }} />
                              {action === 'skip' ? 'Ignorer' : action === 'overwrite' ? 'Écraser' : 'Ajouter'}
                            </label>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
              {csvPreview.error_count > 0 && <details className="workspace-details">
                <summary>Lignes ignorées ({csvPreview.error_count})</summary>
                <ul className="text-sm space-y-1">
                  {csvPreview.entries?.filter((entry) => entry.parse_error).map((entry) => (
                    <li key={entry.index}>Entrée {entry.index + 1} · {entry.parse_error}</li>
                  ))}
                </ul>
              </details>}
              {csvError && <p role="alert" className="workspace-error">{csvError}</p>}
              <div className="workspace-actions">
                <Button onClick={() => { reviewedCsv.current = null; setCsvPreview(null); setCsvError('') }}
                  variant="secondary" disabled={csvLoading}>Retour</Button>
                <Button onClick={handleCsvImport} loading={csvLoading}
                  disabled={!Object.values(csvActions).some((action) => action !== 'skip')}>
                  Importer la sélection
                </Button>
              </div>
            </div>
          ) : (
            <form className="workspace-stack" onSubmit={(event) => { event.preventDefault(); void handleCsvPreview() }}>
              <label className="workspace-field">
                Format source
                <select value={csvFormat} onChange={(event) => setCsvFormat(event.target.value)} disabled={csvLoading}>
                  <option value="auto">Détection automatique</option>
                  <option value="chromium">Brave / Chrome</option>
                  <option value="firefox">Firefox</option>
                  <option value="bitwarden">Bitwarden</option>
                  <option value="lastpass">LastPass</option>
                  <option value="1password">1Password</option>
                  <option value="fluxlock">FluXlock</option>
                </select>
              </label>

              <div className="workspace-stack">
                <div><Button type="button" variant="secondary" icon={FileText}
                  onClick={() => fileInputRef.current?.click()} disabled={csvLoading}>Choisir un fichier CSV</Button></div>
                <input ref={fileInputRef} aria-label="Fichier CSV" type="file" accept=".csv,text/csv" onChange={handleCsvFileSelect} hidden />
                {csvFile && <p className="break-all" role="status">{csvFile.name}</p>}
              </div>

              {csvFile && <>
                <Input label="Mot de passe maître" type={csvAuthVisible ? 'text' : 'password'}
                  value={csvAuthPw} onChange={(event) => setCsvAuthPw(event.target.value)} disabled={csvLoading}
                  autoComplete="current-password" iconRight={csvAuthVisible ? EyeOff : Eye}
                  onIconRightClick={() => setCsvAuthVisible(!csvAuthVisible)} />
                <div className="workspace-actions">
                  <Button type="submit" disabled={csvAuthPw === ''} loading={csvLoading}>Analyser le fichier</Button>
                  {canUseCsvBiometrics && <Button type="button" variant="secondary" icon={Fingerprint} disabled={csvLoading}
                    onClick={() => void handleCsvPreview(true)}>Utiliser la biométrie</Button>}
                </div>
              </>}

              {csvError && <p role="alert" className="workspace-error">{csvError}</p>}
            </form>
          )}
        </div>
      </Modal>

      {/* ═══ Export CSV Modal ═══ */}
      <Modal open={showExportModal} onClose={closeExport} title="Exporter les mots de passe">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {exportDone ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-4)', padding: 'var(--space-6)' }}>
              <CheckCircle2 size={48} style={{ color: 'var(--success)' }} />
              <p style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>Export réussi</p>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', textAlign: 'center' }}>
                Le fichier CSV a été enregistré ici :
              </p>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', textAlign: 'center', wordBreak: 'break-all', margin: 0 }}>
                {exportLocation}
              </p>
              <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', textAlign: 'center' }}>
                <strong>Supprimez-le</strong> dès que l'import est terminé.
              </p>
              <Button onClick={closeExport} fullWidth>Fermer</Button>
            </div>
          ) : (
            <>
              {/* Security warning */}
              <div className="flex items-start gap-3 rounded-lg px-4 py-3" style={{ background: 'var(--danger-muted)', border: '1px solid var(--danger)', fontFamily: 'var(--font-body)' }}>
                <ShieldAlert size={20} style={{ color: 'var(--danger)', flexShrink: 0, marginTop: 2 }} />
                <div>
                  <p style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--danger)' }}>Données en clair</p>
                  <p style={{ fontSize: 'var(--text-xs)', color: 'var(--danger)', opacity: 0.8, marginTop: 2 }}>
                    Le fichier CSV exporté contiendra vos {list.length} mots de passe <strong>non chiffrés</strong>. Supprimez-le immédiatement après usage.
                  </p>
                </div>
              </div>

              {/* Re-authentication */}
              <div className="rounded-lg p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                <p style={{ fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', letterSpacing: 'var(--tracking-wide)', textTransform: 'uppercase', marginBottom: 'var(--space-2)' }}>Authentification requise</p>
                <div className="flex flex-col gap-2">
                  <Input
                    type={csvAuthVisible ? 'text' : 'password'}
                    value={csvAuthPw}
                    onChange={(e) => setCsvAuthPw(e.target.value)}
                    placeholder="Mot de passe maître"
                    iconRight={csvAuthVisible ? EyeOff : Eye}
                    onIconRightClick={() => setCsvAuthVisible(!csvAuthVisible)}
                  />
                  <div className="flex gap-2">
                    <Button variant="danger" onClick={() => void handleCsvExport()} disabled={csvAuthPw === ''} loading={csvLoading} fullWidth icon={Upload}>
                      Exporter {list.length} mot{list.length !== 1 ? 's' : ''} de passe
                    </Button>
                    {canUseCsvBiometrics && <Button variant="secondary" icon={Fingerprint} disabled={csvLoading}
                      onClick={() => void handleCsvExport(true)}>Utiliser la biométrie</Button>}
                  </div>
                </div>
              </div>

              {csvError && <p style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)', fontFamily: 'var(--font-body)' }}>{csvError}</p>}
            </>
          )}
        </div>
      </Modal>
    </WorkspacePage>
  )
}

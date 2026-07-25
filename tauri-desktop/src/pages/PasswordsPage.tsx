import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Plus, Edit2, Trash2, KeyRound, RefreshCw, AlertCircle, ShieldAlert, Download, Upload, Fingerprint, Eye, EyeOff, FileText, CheckCircle2, XCircle, ArrowRightLeft, X } from 'lucide-react'
import { invoke } from '@tauri-apps/api/core'
import { passwords, csvIO, type Password, type ParsedCsvEntry, type EntryAction, type ImportCsvResponse } from '../lib/vault-service'
import { useAuthStore } from '../stores/authStore'
import { AppShell } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { SearchBar, PasswordField, PasswordStrength, EmptyState, Modal } from '../design-system/molecules'
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
  // Export-specific
  const [exportDone, setExportDone] = useState(false)

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
    setCsvFile(null); setCsvFormat('auto'); setCsvPreview(null); setCsvActions({})
    setCsvImportResult(null); setCsvAuthPw(''); setCsvAuthVisible(false); setCsvError('')
    setCsvLoading(false)
  }
  const openImport = () => { resetImportModal(); setShowImportModal(true) }
  const closeImport = () => { setShowImportModal(false); resetImportModal() }

  const handleCsvFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) setCsvFile(file)
  }

  const handleCsvPreview = async () => {
    if (!csvFile) return
    setCsvLoading(true); setCsvError('')
    try {
      const content = await csvFile.text()
      const masterPw = csvAuthPw.trim() || null
      const result = await csvIO.preview(masterPw, content, csvFormat)
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
    if (!csvFile || !csvPreview) return
    setCsvLoading(true); setCsvError('')
    try {
      const content = await csvFile.text()
      const masterPw = csvAuthPw.trim() || null
      const entryActions: EntryAction[] = Object.entries(csvActions).map(([idx, action]) => {
        const entry = csvPreview.entries?.find((e) => e.index === Number(idx))
        return {
          index: Number(idx),
          action,
          overwrite_id: action === 'overwrite' ? entry?.existing_match?.id : undefined,
        }
      })
      const result = await csvIO.import(masterPw, content, csvPreview.detected_format, entryActions)
      setCsvImportResult(result)
      queryClient.invalidateQueries({ queryKey: ['passwords'] })
      toast(`Import terminé: ${result.imported_count} importés, ${result.overwritten_count} écrasés`, 'success')
    } catch (err) {
      setCsvError(String(err))
    } finally {
      setCsvLoading(false)
    }
  }

  const handleBiometricAuth = async (mode: 'import' | 'export') => {
    setCsvAuthPw('')  // null password = biometric path
    if (mode === 'import') await handleCsvPreview()
    else await handleCsvExport()
  }

  // ── CSV Export helpers ──
  const openExport = () => { setCsvAuthPw(''); setCsvAuthVisible(false); setCsvError(''); setExportDone(false); setCsvLoading(false); setShowExportModal(true) }
  const closeExport = () => { setShowExportModal(false); setCsvAuthPw(''); setCsvError('') }

  const handleCsvExport = async () => {
    setCsvLoading(true); setCsvError('')
    try {
      const masterPw = csvAuthPw.trim() || null
      const result = await csvIO.export(masterPw)
      // Trigger browser download via Blob
      const blob = new Blob([result.csv_content], { type: 'text/csv;charset=utf-8;' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `fluxlock-export-${new Date().toISOString().slice(0, 10)}.csv`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
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

  if (isLoading) return <AppShell><div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--space-16)' }}><Spinner size={32} /></div></AppShell>

  if (isError) return (
    <AppShell>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-4)', padding: 'var(--space-16)' }}>
        <AlertCircle size={40} style={{ color: 'var(--danger)' }} />
        <p style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-base)' }}>
          Erreur de chargement des mots de passe
        </p>
        <p style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)', textAlign: 'center', maxWidth: 400 }}>
          {String(queryError)}
        </p>
        <Button onClick={() => refetch()}>Réessayer</Button>
      </div>
    </AppShell>
  )

  const renderForm = () => (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Input label="Titre" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ex: Gmail" required />
      <Input label="Nom d'utilisateur / Email" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="user@example.com" />
      <div>
        <div className="flex flex-col sm:flex-row gap-2 sm:items-end">
          <div className="flex-1">
            <Input label="Mot de passe" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Mot de passe" required />
          </div>
          <Button type="button" variant="secondary" icon={RefreshCw} onClick={generatePassword} style={{ marginBottom: 0 }} className="w-full sm:w-auto">
            Générer
          </Button>
        </div>
        <div className="mt-3 flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <label className="text-xs text-tx-secondary font-body min-w-[70px]">Longueur : {pwLength}</label>
            <input type="range" min={8} max={64} value={pwLength} onChange={(e) => setPwLength(Number(e.target.value))} className="flex-1 accent-accent" />
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
      <Input label="URL" type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" />
      <Input label="Catégorie" value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Social, Email, Travail…" />
      <div>
        <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Notes</label>
        <textarea
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
    <AppShell>
      <div className="flex h-full w-full">
        {/* MASTER PANE */}
        <div className={`flex-1 flex-col gap-6 min-w-0 overflow-y-auto page-content ${showModal ? 'hidden md:flex' : 'flex'} pr-0 md:pr-6 pb-20 md:pb-0`}>
          {/* Header */}
          <div className="page-header flex-col items-start sm:flex-row sm:items-center gap-4">
            <div>
              <h1 className="font-display text-3xl text-tx-primary flex items-center gap-3">
                <KeyRound size={28} className="text-accent" />
                Mots de passe
              </h1>
              <p className="text-sm text-tx-muted font-body mt-1">
                {list.length} entrée{list.length !== 1 ? 's' : ''} enregistrée{list.length !== 1 ? 's' : ''}
              </p>
            </div>
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Button variant="secondary" size="sm" icon={Download} onClick={openImport} disabled={isReadonly} title="Importer" style={{ padding: '8px' }} />
              <Button variant="secondary" size="sm" icon={Upload} onClick={openExport} title="Exporter" style={{ padding: '8px' }} />
              <Button icon={Plus} onClick={openCreate} disabled={isReadonly} className="w-full sm:w-auto ml-1">Nouveau</Button>
            </div>
          </div>

          {/* Readonly banner */}
          {isReadonly && (
            <div className="flex items-center gap-2 rounded-lg px-4 py-3 text-sm bg-danger-muted border border-danger text-danger font-body shrink-0">
              <ShieldAlert size={16} />
              Coffre-fort en lecture seule — modifications bloquées
            </div>
          )}

          {/* Search */}
          <div className="shrink-0">
            <SearchBar value={search} onChange={setSearch} placeholder="Rechercher un mot de passe…" />
          </div>

          {/* Category filter chips */}
          {categories.length > 0 && (
            <div className="flex gap-2 overflow-x-auto pb-2 -mx-4 px-4 sm:mx-0 sm:px-0 [&::-webkit-scrollbar]:hidden shrink-0">
              <button
                onClick={() => setFilterCategory(null)}
                className={`shrink-0 px-3 py-1 rounded-full text-xs font-medium cursor-pointer transition-all duration-150 font-body border ${!filterCategory ? 'border-accent bg-accent-muted text-accent-text' : 'border-bd bg-transparent text-tx-muted'}`}
              >
                Tous
              </button>
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setFilterCategory(filterCategory === cat ? null : cat)}
                  className={`shrink-0 px-3 py-1 rounded-full text-xs font-medium cursor-pointer transition-all duration-150 font-body border ${filterCategory === cat ? 'border-accent bg-accent-muted text-accent-text' : 'border-bd bg-transparent text-tx-muted'}`}
                >
                  {cat}
                </button>
              ))}
            </div>
          )}

          {/* List */}
          {filtered.length === 0 ? (
            <EmptyState
              icon={KeyRound}
              title={search ? 'Aucun résultat' : 'Aucun mot de passe'}
              description={search ? undefined : 'Commencez par ajouter votre premier mot de passe'}
              action={!search ? <Button icon={Plus} onClick={openCreate}>Créer</Button> : undefined}
            />
          ) : (
            <div className="flex flex-col gap-3">
              {filtered.map((p) => (
                <div key={p.id} onClick={() => openEdit(p)} className={`bg-surface sm:border rounded-2xl p-4 sm:p-5 flex flex-col gap-3 transition-all duration-200 cursor-pointer ${editing?.id === p.id ? 'sm:border-accent ring-1 ring-accent/20' : 'sm:border-bd hover:border-accent/50'}`}>
                  <div className="flex justify-between items-start gap-4">
                    <div className="flex items-start gap-3 min-w-0 flex-1">
                      <div className="w-10 h-10 rounded-full bg-accent-muted text-accent-text flex items-center justify-center text-lg font-display shrink-0 mt-0.5">
                        {p.title.charAt(0).toUpperCase()}
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="text-base font-semibold text-tx-primary font-body break-words">
                          {p.title}
                        </p>
                        {p.username && <p className="text-sm text-tx-secondary font-body mt-0.5 truncate">{p.username}</p>}
                        {p.url && <p className="text-xs text-tx-muted font-mono mt-0.5 truncate">{p.url}</p>}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0">
                      {p.category && <Badge size="sm" className="hidden sm:inline-flex">{p.category}</Badge>}
                    </div>
                  </div>

                  <div className="pl-0 sm:pl-[52px]" onClick={e => e.stopPropagation()}>
                    <PasswordField
                      value={p.password}
                      revealed={revealed.has(p.id)}
                      onToggleReveal={() => setRevealed((prev) => { const s = new Set(prev); s.has(p.id) ? s.delete(p.id) : s.add(p.id); return s })}
                      onCopy={() => handleCopy(p.password, p.id)}
                      copied={copied === p.id}
                    />
                  </div>

                  <div className="flex items-center justify-between pt-2 mt-1 border-t border-bd/50 pl-0 sm:pl-[52px]">
                    <span className="text-xs text-tx-disabled font-body">
                      {new Date(p.created_at).toLocaleDateString('fr-FR')}
                    </span>
                    <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                      <Button variant="ghost" size="sm" onClick={() => { if (confirm(`Supprimer "${p.title}" ?`)) deleteMut.mutate(p.id) }} disabled={isReadonly} className="w-8 h-8 p-0 flex items-center justify-center text-danger hover:bg-danger-muted" title="Supprimer">
                        <Trash2 size={16} />
                      </Button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        
        {/* DETAIL PANE (Desktop) */}
        <div className="hidden md:flex flex-col w-[350px] lg:w-[450px] shrink-0 border-l border-bd bg-surface/50 h-[calc(100vh-2rem)] rounded-r-xl overflow-hidden -mt-4 -mr-4 ml-2">
          {showModal ? (
            <div className="flex flex-col h-full bg-surface shadow-[-4px_0_15px_rgba(0,0,0,0.03)]">
              <div className="flex items-center justify-between p-6 border-b border-bd/50 shrink-0 bg-surface z-10 sticky top-0">
                <h2 className="text-xl font-display font-semibold text-tx-primary">
                  {editing ? 'Modifier' : 'Nouveau'}
                </h2>
                <button onClick={close} className="p-2 -mr-2 rounded-full hover:bg-elevated text-tx-secondary transition-colors" aria-label="Fermer">
                  <X size={20} />
                </button>
              </div>
              <div className="p-6 overflow-y-auto">
                {renderForm()}
              </div>
            </div>
          ) : (
            <div className="flex flex-col h-full items-center justify-center p-8 text-center opacity-60">
              <KeyRound size={48} className="text-tx-disabled mb-4" />
              <h3 className="text-lg font-medium text-tx-secondary font-display">Aucun élément sélectionné</h3>
              <p className="text-sm text-tx-muted mt-2 font-body">Sélectionnez un mot de passe dans la liste ou créez-en un nouveau pour afficher les détails.</p>
            </div>
          )}
        </div>
      </div>

      {/* MOBILE DETAIL PANE (Modal) */}
      <div className="md:hidden">
        <Modal open={showModal} onClose={close} title={editing ? 'Modifier le mot de passe' : 'Nouveau mot de passe'}>
          {renderForm()}
        </Modal>
      </div>

      {/* ═══ Import CSV Modal ═══ */}
      <Modal open={showImportModal} onClose={closeImport} title="Importer des mots de passe" width={680}>
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
              <div className="flex items-center justify-between" style={{ fontFamily: 'var(--font-body)' }}>
                <Badge>{csvPreview.detected_format}</Badge>
                <span style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)' }}>
                  {csvPreview.new_count} nouvelles · {csvPreview.duplicate_count} doublons · {csvPreview.error_count} erreurs
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
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <p style={{ fontSize: 'var(--text-sm)', fontWeight: 600, color: 'var(--text-primary)' }} className="truncate">{entry.title}</p>
                        {entry.username && <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)' }} className="truncate">{entry.username}</p>}
                      </div>
                      <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{entry.password_preview}</span>
                    </div>
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
              {csvError && <p style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)', fontFamily: 'var(--font-body)' }}>{csvError}</p>}
              <div className="flex gap-3 pt-2">
                <Button onClick={() => setCsvPreview(null)} variant="secondary" fullWidth>← Retour</Button>
                <Button onClick={handleCsvImport} loading={csvLoading} fullWidth>
                  Importer {Object.values(csvActions).filter((a) => a !== 'skip').length} entrées
                </Button>
              </div>
            </div>
          ) : (
            /* ── File selection + auth screen ── */
            <>
              {/* Format selector */}
              <div>
                <label style={{ display: 'block', fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', letterSpacing: 'var(--tracking-wide)', textTransform: 'uppercase', marginBottom: 'var(--space-1)' }}>Format source</label>
                <select value={csvFormat} onChange={(e) => setCsvFormat(e.target.value)}
                  style={{ width: '100%', background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '10px 12px', color: 'var(--text-primary)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)' }}>
                  <option value="auto">Auto-détection</option>
                  <option value="chrome">Google Chrome</option>
                  <option value="bitwarden">Bitwarden</option>
                  <option value="lastpass">LastPass</option>
                  <option value="1password">1Password</option>
                  <option value="fluxlock">FluXlock</option>
                </select>
              </div>

              {/* File picker */}
              <div
                className="flex flex-col items-center justify-center gap-2 rounded-lg p-6 cursor-pointer transition-colors"
                style={{ border: '2px dashed var(--border)', background: csvFile ? 'var(--accent-muted)' : 'transparent' }}
                onClick={() => fileInputRef.current?.click()}
              >
                <FileText size={28} style={{ color: csvFile ? 'var(--accent-text)' : 'var(--text-muted)' }} />
                {csvFile ? (
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--accent-text)', fontFamily: 'var(--font-body)', fontWeight: 500 }}>{csvFile.name} ({(csvFile.size / 1024).toFixed(1)} Ko)</p>
                ) : (
                  <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)' }}>Cliquez pour sélectionner un fichier CSV</p>
                )}
                <input ref={fileInputRef} type="file" accept=".csv,text/csv" onChange={handleCsvFileSelect} style={{ display: 'none' }} />
              </div>

              {/* Re-authentication */}
              {csvFile && (
                <div className="rounded-lg p-4" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                  <p style={{ fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', letterSpacing: 'var(--tracking-wide)', textTransform: 'uppercase', marginBottom: 'var(--space-2)' }}>Authentification requise</p>
                  <div className="flex flex-col gap-2">
                    <div className="relative">
                      <Input
                        type={csvAuthVisible ? 'text' : 'password'}
                        value={csvAuthPw}
                        onChange={(e) => setCsvAuthPw(e.target.value)}
                        placeholder="Mot de passe maître"
                        iconRight={csvAuthVisible ? EyeOff : Eye}
                        onIconRightClick={() => setCsvAuthVisible(!csvAuthVisible)}
                      />
                    </div>
                    <div className="flex gap-2">
                      <Button onClick={handleCsvPreview} disabled={!csvAuthPw.trim()} loading={csvLoading} fullWidth>Analyser le fichier</Button>
                      <Button variant="secondary" onClick={() => handleBiometricAuth('import')} loading={csvLoading} title="Authentification biométrique">
                        <Fingerprint size={18} />
                      </Button>
                    </div>
                  </div>
                </div>
              )}

              {csvError && <p style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)', fontFamily: 'var(--font-body)' }}>{csvError}</p>}
            </>
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
                Le fichier CSV a été téléchargé. <strong>Supprimez-le</strong> dès que l'import est terminé.
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
                    <Button variant="danger" onClick={handleCsvExport} disabled={!csvAuthPw.trim()} loading={csvLoading} fullWidth icon={Upload}>
                      Exporter {list.length} mot{list.length !== 1 ? 's' : ''} de passe
                    </Button>
                    <Button variant="secondary" onClick={() => handleBiometricAuth('export')} loading={csvLoading} title="Authentification biométrique">
                      <Fingerprint size={18} />
                    </Button>
                  </div>
                </div>
              </div>

              {csvError && <p style={{ fontSize: 'var(--text-sm)', color: 'var(--danger)', fontFamily: 'var(--font-body)' }}>{csvError}</p>}
            </>
          )}
        </div>
      </Modal>
    </AppShell>
  )
}

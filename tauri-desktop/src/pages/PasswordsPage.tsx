import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Plus, Edit2, Trash2, KeyRound, RefreshCw, AlertCircle } from 'lucide-react'
import { passwords, type Password } from '../lib/vault-service'
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
    return p.title.toLowerCase().includes(s) || (p.username?.toLowerCase() || '').includes(s) || (p.url?.toLowerCase() || '').includes(s) || (p.category?.toLowerCase() || '').includes(s)
  })

  const resetForm = () => { setTitle(''); setUsername(''); setPassword(''); setUrl(''); setNotes(''); setCategory(''); setEditing(null) }
  const close = () => { setShowModal(false); resetForm() }
  const openCreate = () => { resetForm(); setShowModal(true) }
  const openEdit = (p: Password) => { setEditing(p); setTitle(p.title); setUsername(p.username || ''); setPassword(p.password); setUrl(p.url || ''); setNotes(p.notes || ''); setCategory(p.category || ''); setShowModal(true) }

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

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }} className="page-header">
          <div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <KeyRound size={28} style={{ color: 'var(--accent)' }} />
              Mots de passe
            </h1>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', marginTop: 'var(--space-1)' }}>
              {list.length} entrée{list.length !== 1 ? 's' : ''} enregistrée{list.length !== 1 ? 's' : ''}
            </p>
          </div>
          <Button icon={Plus} onClick={openCreate}>Nouveau</Button>
        </div>

        {/* Search */}
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher un mot de passe…" />

        {/* List */}
        {filtered.length === 0 ? (
          <EmptyState
            icon={KeyRound}
            title={search ? 'Aucun résultat' : 'Aucun mot de passe'}
            description={search ? undefined : 'Commencez par ajouter votre premier mot de passe'}
            action={!search ? <Button icon={Plus} onClick={openCreate}>Créer</Button> : undefined}
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {filtered.map((p) => (
              <div key={p.id} style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-lg)',
                padding: 'var(--space-5)',
                display: 'flex',
                flexDirection: 'column',
                gap: 'var(--space-3)',
                transition: `border-color var(--transition-fast)`,
              }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                  <div>
                    <p style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
                      {p.title}
                    </p>
                    {p.username && <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', marginTop: 2 }}>{p.username}</p>}
                    {p.url && <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{p.url}</p>}
                  </div>
                  <div style={{ display: 'flex', gap: 'var(--space-1)' }}>
                    {p.category && <Badge size="sm">{p.category}</Badge>}
                  </div>
                </div>

                <PasswordField
                  value={p.password}
                  revealed={revealed.has(p.id)}
                  onToggleReveal={() => setRevealed((prev) => { const s = new Set(prev); s.has(p.id) ? s.delete(p.id) : s.add(p.id); return s })}
                  onCopy={() => handleCopy(p.password, p.id)}
                  copied={copied === p.id}
                />

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-disabled)', fontFamily: 'var(--font-body)' }}>
                    {new Date(p.created_at).toLocaleDateString('fr-FR')}
                  </span>
                  <div style={{ display: 'flex', gap: 'var(--space-1)' }}>
                    <Button variant="ghost" size="sm" icon={Edit2} onClick={() => openEdit(p)}>Modifier</Button>
                    <Button variant="ghost" size="sm" icon={Trash2} onClick={() => { if (confirm(`Supprimer "${p.title}" ?`)) deleteMut.mutate(p.id) }} style={{ color: 'var(--danger)' }}>Supprimer</Button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Modal */}
      <Modal open={showModal} onClose={close} title={editing ? 'Modifier le mot de passe' : 'Nouveau mot de passe'}>
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <Input label="Titre" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Ex: Gmail" required />
          <Input label="Nom d'utilisateur / Email" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="user@example.com" />
          <div>
            <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'flex-end' }}>
              <div style={{ flex: 1 }}>
                <Input label="Mot de passe" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Mot de passe" required />
              </div>
              <Button type="button" variant="secondary" icon={RefreshCw} onClick={generatePassword} style={{ marginBottom: 0 }}>
                Générer
              </Button>
            </div>
            {/* Password generation options */}
            <div style={{ marginTop: 'var(--space-2)', display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                <label style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', minWidth: 70 }}>
                  Longueur : {pwLength}
                </label>
                <input type="range" min={8} max={64} value={pwLength} onChange={(e) => setPwLength(Number(e.target.value))}
                  style={{ flex: 1, accentColor: 'var(--accent)' }} />
              </div>
              <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap' }}>
                {([['A-Z', pwUpper, setPwUpper], ['a-z', pwLower, setPwLower], ['0-9', pwDigits, setPwDigits], ['!@#', pwSymbols, setPwSymbols]] as const).map(([label, val, set]) => (
                  <label key={label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', cursor: 'pointer' }}>
                    <input type="checkbox" checked={val as boolean} onChange={() => (set as React.Dispatch<React.SetStateAction<boolean>>)((v: boolean) => !v)} style={{ accentColor: 'var(--accent)' }} />
                    {label}
                  </label>
                ))}
              </div>
            </div>
            <div style={{ marginTop: 'var(--space-2)' }}>
              <PasswordStrength password={password} />
            </div>
          </div>
          <Input label="URL" type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" />
          <Input label="Catégorie" value={category} onChange={(e) => setCategory(e.target.value)} placeholder="Social, Email, Travail…" />
          <div>
            <label style={{ display: 'block', fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', letterSpacing: 'var(--tracking-wide)', textTransform: 'uppercase', marginBottom: 'var(--space-1)' }}>
              Notes
            </label>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Notes additionnelles…"
              rows={3}
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)',
                padding: '10px 12px',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-body)',
                fontSize: 'var(--text-sm)',
                resize: 'vertical',
                outline: 'none',
              }}
            />
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-3)', paddingTop: 'var(--space-2)' }}>
            <Button type="submit" fullWidth loading={createMut.isPending || updateMut.isPending}>
              {editing ? 'Modifier' : 'Créer'}
            </Button>
            <Button type="button" variant="secondary" fullWidth onClick={close}>Annuler</Button>
          </div>
        </form>
      </Modal>
    </AppShell>
  )
}

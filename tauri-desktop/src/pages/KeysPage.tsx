import { useState, useEffect, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Key, Plus, Eye, EyeOff, Copy, Trash2, Shield, Terminal,
  Lock, Fingerprint, Upload, X, ShieldAlert,
} from 'lucide-react'
import { keys as keysSvc, type SecureKey } from '../lib/vault-service'
import { AppShell } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { SearchBar, EmptyState, Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import { useClipboard } from '../hooks/useClipboard'

/* ───── helpers ───── */
const keyIcon = (t: string, size = 18) => {
  const s: React.CSSProperties = { width: size, height: size }
  switch (t.toLowerCase()) {
    case 'ssh': return <Terminal style={s} />
    case 'api': return <Key style={s} />
    case 'gpg': return <Fingerprint style={s} />
    case 'encryption': return <Lock style={s} />
    default: return <Shield style={s} />
  }
}
const keyColor = (t: string) => {
  switch (t.toLowerCase()) {
    case 'ssh': return 'var(--accent)'
    case 'api': return '#a78bfa'
    case 'gpg': return '#34d399'
    case 'encryption': return '#fbbf24'
    default: return 'var(--text-muted)'
  }
}
const fmtDate = (d: string) => new Date(d).toLocaleDateString('fr-FR', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })

/* ───── KeyDataViewer (reusable for SSH split keys) ───── */
function KeyDataViewer({ data, name, onCopy }: { data: string; name: string; onCopy: (text: string, label: string) => void }) {
  if (data.includes('|||')) {
    const [priv, pub] = data.split('|||')
    return (
      <div className="flex flex-col gap-4">
        <div>
          <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Clé privée</label>
          <div className="relative">
            <textarea readOnly rows={6} value={priv} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-mono text-sm resize-y outline-none focus:border-accent" />
            <Button size="sm" className="absolute top-2 right-2" icon={Copy} onClick={() => onCopy(priv, name + ' (Private)')}>Copier</Button>
          </div>
        </div>
        <div>
          <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Clé publique</label>
          <div className="relative">
            <textarea readOnly rows={3} value={pub} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-mono text-sm resize-y outline-none focus:border-accent" />
            <Button size="sm" className="absolute top-2 right-2" icon={Copy} onClick={() => onCopy(pub, name + ' (Public)')}>Copier</Button>
          </div>
        </div>
      </div>
    )
  }
  return (
    <div>
      <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Données de la clé</label>
      <div className="relative">
        <textarea readOnly rows={8} value={data} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-mono text-sm resize-y outline-none focus:border-accent" />
        <Button size="sm" className="absolute top-2 right-2" icon={Copy} onClick={() => onCopy(data, name)}>Copier</Button>
      </div>
    </div>
  )
}

/* ───── component ───── */
type RightPanelState = 
  | null 
  | { type: 'create' } 
  | { type: 'import' } 
  | { type: 'view', key: SecureKey, data: string }
  | { type: 'generated', name: string, data: string }

export default function KeysPage() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const copy = useClipboard()
  const [search, setSearch] = useState('')
  
  const [rightPanel, setRightPanel] = useState<RightPanelState>(null)
  const [revealedKeys, setRevealedKeys] = useState<Set<number>>(new Set())
  const [decryptedCache, setDecryptedCache] = useState<Map<number, string>>(new Map())
  const cacheTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // EXP-008: Auto-clear du cache de clés déchiffrées après 60 secondes
  useEffect(() => {
    if (decryptedCache.size === 0) return
    if (cacheTimerRef.current) clearTimeout(cacheTimerRef.current)
    cacheTimerRef.current = setTimeout(() => {
      setDecryptedCache(new Map())
      setRevealedKeys(new Set())
      if (rightPanel?.type === 'view') setRightPanel(null)
    }, 60_000)
    return () => { if (cacheTimerRef.current) clearTimeout(cacheTimerRef.current) }
  }, [decryptedCache.size, rightPanel])

  const [keyName, setKeyName] = useState('')
  const [keyType, setKeyType] = useState('api')
  const [algorithm, setAlgorithm] = useState('AES-256-GCM')
  const [impName, setImpName] = useState('')
  const [impType, setImpType] = useState('api')
  const [impAlgo, setImpAlgo] = useState('AES-256-GCM')
  const [impData, setImpData] = useState('')

  const { data: list = [], isLoading } = useQuery({ queryKey: ['secureKeys'], queryFn: keysSvc.list })

  const createMut = useMutation({
    mutationFn: async () => {
      const id = await keysSvc.create({ key_name: keyName, key_type: keyType, algorithm })
      const dec = await keysSvc.decrypt(id)
      return { id, dec, name: keyName }
    },
    onSuccess: async (d) => {
      await qc.invalidateQueries({ queryKey: ['secureKeys'] })
      setRightPanel({ type: 'generated', name: d.name, data: d.dec })
      setKeyName(''); setKeyType('api'); setAlgorithm('AES-256-GCM')
      toast('Clé générée', 'success')
    },
    onError: (e) => toast('Erreur : ' + e, 'error'),
  })

  const importMut = useMutation({
    mutationFn: () => keysSvc.import({ key_name: impName, key_type: impType, key_data: impData, algorithm: impAlgo }),
    onSuccess: () => { 
      qc.invalidateQueries({ queryKey: ['secureKeys'] })
      setRightPanel(null)
      setImpName(''); setImpType('api'); setImpData(''); setImpAlgo('AES-256-GCM')
      toast('Clé importée', 'success') 
    },
    onError: (e) => toast('Erreur : ' + e, 'error'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => keysSvc.delete(id),
    onSuccess: () => { 
      qc.invalidateQueries({ queryKey: ['secureKeys'] })
      toast('Clé supprimée', 'success') 
    },
    onError: (e) => toast('Erreur : ' + e, 'error'),
  })

  const decryptMut = useMutation({ mutationFn: (id: number) => keysSvc.decrypt(id) })

  const filtered = list.filter(k => k.key_name.toLowerCase().includes(search.toLowerCase()) || k.key_type.toLowerCase().includes(search.toLowerCase()))

  const handleCopy = (text: string, label: string) => { copy(text); toast(`"${label}" copié — effacé dans 30 s`, 'success') }

  const handleReveal = async (k: SecureKey) => {
    let d = decryptedCache.get(k.id)
    if (!d) { 
      d = await decryptMut.mutateAsync(k.id)
      setDecryptedCache(p => new Map(p).set(k.id, d!)) 
    }
    setRevealedKeys(p => new Set(p).add(k.id))
    setRightPanel({ type: 'view', key: k, data: d })
  }

  const handleDelete = (k: SecureKey) => {
    if (confirm(`Supprimer "${k.key_name}" ?`)) { 
      deleteMut.mutate(k.id)
      setRevealedKeys(p => { const s = new Set(p); s.delete(k.id); return s })
      setDecryptedCache(p => { const m = new Map(p); m.delete(k.id); return m })
      if (rightPanel?.type === 'view' && rightPanel.key.id === k.id) {
        setRightPanel(null)
      }
    }
  }

  const showModal = rightPanel !== null

  if (isLoading) return <AppShell><div className="flex justify-center p-16"><Spinner size={32} /></div></AppShell>

  // Rendering form content based on rightPanel state
  const renderRightPanelContent = () => {
    if (!rightPanel) {
      return (
        <div className="flex flex-col items-center justify-center h-full text-center px-4 animate-fade-in opacity-60">
          <Shield size={64} className="text-bd mb-4" />
          <h2 className="text-xl font-display text-tx-secondary mb-2">Aucune clé sélectionnée</h2>
          <p className="text-sm text-tx-muted font-body">
            Sélectionnez une clé pour voir ses détails, ou générez/importez une nouvelle clé.
          </p>
        </div>
      )
    }

    if (rightPanel.type === 'create') {
      return (
        <form onSubmit={(e) => { e.preventDefault(); if (!keyName.trim()) { toast('Nom requis', 'error'); return }; createMut.mutate() }} className="flex flex-col gap-5 h-full animate-fade-in">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-2xl text-tx-primary flex items-center gap-2 m-0">
              <Plus size={24} className="text-accent" /> Générer une clé
            </h2>
            <Button variant="ghost" size="sm" icon={X} onClick={() => setRightPanel(null)} className="md:hidden" />
          </div>
          <Input label="Nom de la clé" value={keyName} onChange={e => setKeyName(e.target.value)} placeholder="Ex: GitHub SSH" required />
          <div>
            <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Type</label>
            <select value={keyType} onChange={e => setKeyType(e.target.value)} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-body text-sm outline-none focus:border-accent">
              <option value="api">API</option><option value="ssh">SSH</option><option value="gpg">GPG</option><option value="encryption">Chiffrement</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Algorithme</label>
            <select value={algorithm} onChange={e => setAlgorithm(e.target.value)} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-body text-sm outline-none focus:border-accent">
              <option value="AES-256-GCM">AES-256-GCM</option><option value="AES-256-CBC">AES-256-CBC</option><option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
            </select>
            <p className="mt-1 text-xs text-tx-disabled font-body">Toutes les clés sont chiffrées en AES-256-GCM dans le coffre.</p>
          </div>
          <div className="flex gap-3 pt-2 mt-auto">
            <Button type="submit" fullWidth loading={createMut.isPending}>Générer</Button>
            <Button type="button" variant="secondary" fullWidth onClick={() => setRightPanel(null)}>Annuler</Button>
          </div>
        </form>
      )
    }

    if (rightPanel.type === 'import') {
      return (
        <form onSubmit={(e) => { e.preventDefault(); if (!impName.trim() || !impData.trim()) { toast('Nom et données requis', 'error'); return }; importMut.mutate() }} className="flex flex-col gap-5 h-full animate-fade-in">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-2xl text-tx-primary flex items-center gap-2 m-0">
              <Upload size={24} className="text-accent" /> Importer une clé
            </h2>
            <Button variant="ghost" size="sm" icon={X} onClick={() => setRightPanel(null)} className="md:hidden" />
          </div>
          <Input label="Nom" value={impName} onChange={e => setImpName(e.target.value)} placeholder="Ex: Ma clé SSH" required />
          <div>
            <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Type</label>
            <select value={impType} onChange={e => setImpType(e.target.value)} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-body text-sm outline-none focus:border-accent">
              <option value="api">API</option><option value="ssh">SSH</option><option value="gpg">GPG</option><option value="encryption">Chiffrement</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Algorithme d'origine</label>
            <select value={impAlgo} onChange={e => setImpAlgo(e.target.value)} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-body text-sm outline-none focus:border-accent">
              <optgroup label="Symétrique"><option value="AES-256-GCM">AES-256-GCM</option><option value="AES-256-CBC">AES-256-CBC</option><option value="AES-192-GCM">AES-192-GCM</option><option value="AES-128-GCM">AES-128-GCM</option><option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option></optgroup>
              <optgroup label="Asymétrique"><option value="RSA-4096">RSA-4096</option><option value="RSA-2048">RSA-2048</option><option value="Ed25519">Ed25519</option><option value="ECDSA-P256">ECDSA-P256</option><option value="ECDSA-P384">ECDSA-P384</option></optgroup>
              <optgroup label="SSH"><option value="ssh-rsa">ssh-rsa</option><option value="ssh-ed25519">ssh-ed25519</option><option value="ecdsa-sha2-nistp256">ecdsa-sha2-nistp256</option><option value="ecdsa-sha2-nistp384">ecdsa-sha2-nistp384</option></optgroup>
              <optgroup label="Autre"><option value="Custom">Autre</option></optgroup>
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Données de la clé</label>
            <textarea value={impData} onChange={e => setImpData(e.target.value)} placeholder="Collez votre clé ici…" className="w-full h-[150px] px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-mono text-sm resize-y outline-none focus:border-accent" required />
          </div>
          <div className="flex gap-3 pt-2 mt-auto">
            <Button type="submit" fullWidth loading={importMut.isPending}>Importer</Button>
            <Button type="button" variant="secondary" fullWidth onClick={() => setRightPanel(null)}>Annuler</Button>
          </div>
        </form>
      )
    }

    if (rightPanel.type === 'generated') {
      return (
        <div className="flex flex-col gap-5 h-full animate-fade-in">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-2xl text-tx-primary flex items-center gap-2 m-0">
              <Shield size={24} className="text-success" /> Clé générée
            </h2>
          </div>
          <div>
            <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Nom</label>
            <div className="px-3 py-2.5 bg-elevated rounded-lg text-tx-primary font-body font-semibold">{rightPanel.name}</div>
          </div>
          <KeyDataViewer data={rightPanel.data} name={rightPanel.name} onCopy={handleCopy} />
          <div className="flex items-start gap-2 p-3 bg-warning-muted border border-warning rounded-lg mt-2">
            <ShieldAlert size={16} className="text-warning shrink-0 mt-0.5" />
            <span className="text-xs text-tx-primary font-body">Sauvegardez cette clé maintenant. C'est la seule fois qu'elle sera affichée en clair.</span>
          </div>
          <div className="pt-2 mt-auto">
            <Button fullWidth onClick={() => setRightPanel(null)}>J'ai sauvegardé ma clé</Button>
          </div>
        </div>
      )
    }

    if (rightPanel.type === 'view') {
      const k = rightPanel.key
      return (
        <div className="flex flex-col gap-5 h-full animate-fade-in">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-2xl text-tx-primary flex items-center gap-2 m-0">
              <Eye size={24} className="text-accent" /> Détails
            </h2>
            <Button variant="ghost" size="sm" icon={X} onClick={() => setRightPanel(null)} className="md:hidden" />
          </div>
          <div>
            <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Nom</label>
            <div className="px-3 py-2.5 bg-elevated border border-bd rounded-lg text-tx-primary font-body font-semibold">{k.key_name}</div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Type</label>
              <div className="px-3 py-2.5 bg-elevated border border-bd rounded-lg text-tx-primary font-body flex items-center gap-2">
                <span style={{ color: keyColor(k.key_type) }}>{keyIcon(k.key_type)}</span>
                {k.key_type.toUpperCase()}
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Algorithme</label>
              <div className="px-3 py-2.5 bg-elevated border border-bd rounded-lg text-tx-primary font-body">{k.algorithm}</div>
            </div>
          </div>
          <KeyDataViewer data={rightPanel.data} name={k.key_name} onCopy={handleCopy} />
          
          <div className="flex gap-3 pt-2 mt-auto">
            <Button variant="danger" icon={Trash2} fullWidth onClick={() => handleDelete(k)}>Supprimer</Button>
            <Button variant="secondary" fullWidth onClick={() => setRightPanel(null)}>Fermer</Button>
          </div>
        </div>
      )
    }
  }

  return (
    <AppShell>
      <div className="flex h-full w-full">
        {/* MASTER PANE */}
        <div className={`flex-1 flex-col gap-6 min-w-0 overflow-y-auto page-content ${showModal ? 'hidden md:flex' : 'flex'} pr-0 md:pr-6 pb-20 md:pb-0`}>
          {/* Header */}
          <div className="page-header flex-col items-start sm:flex-row sm:items-center gap-4">
            <div>
              <h1 className="font-display text-3xl text-tx-primary flex items-center gap-3 m-0">
                <Shield size={28} className="text-accent" /> Clés cryptographiques
              </h1>
              <p className="text-sm text-tx-muted font-body mt-1 m-0">
                {list.length} clé{list.length !== 1 ? 's' : ''} stockée{list.length !== 1 ? 's' : ''}
              </p>
            </div>
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <Button variant="secondary" size="sm" icon={Upload} onClick={() => setRightPanel({ type: 'import' })} title="Importer" style={{ padding: '8px' }} />
              <Button icon={Plus} onClick={() => setRightPanel({ type: 'create' })} className="w-full sm:w-auto ml-1">Générer</Button>
            </div>
          </div>

          <div className="shrink-0">
            <SearchBar value={search} onChange={setSearch} placeholder="Rechercher une clé…" />
          </div>

          {/* List */}
          {filtered.length === 0 ? (
            <EmptyState icon={Shield} title={search ? 'Aucun résultat' : 'Aucune clé'}
              description={search ? undefined : 'Générez ou importez votre première clé'}
              action={!search ? <Button icon={Plus} onClick={() => setRightPanel({ type: 'create' })}>Générer</Button> : undefined} />
          ) : (
            <div className="flex flex-col gap-3">
              {filtered.map(k => {
                const isActive = rightPanel?.type === 'view' && rightPanel.key.id === k.id
                return (
                  <div 
                    key={k.id} 
                    onClick={() => handleReveal(k)}
                    className={`flex flex-col sm:flex-row sm:items-center gap-4 p-4 rounded-xl border transition-all duration-200 cursor-pointer ${
                      isActive ? 'bg-accent-muted border-accent shadow-sm' : 'bg-surface border-bd hover:border-bd-hover hover:bg-bg-hover'
                    }`}
                  >
                    <div className="flex items-center gap-4 flex-1 min-w-0">
                      <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0" style={{ background: `color-mix(in srgb, ${keyColor(k.key_type)} 15%, transparent)`, color: keyColor(k.key_type) }}>
                        {keyIcon(k.key_type, 20)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-base font-semibold text-tx-primary font-body truncate m-0">{k.key_name}</p>
                        <div className="flex flex-wrap items-center gap-2 mt-1">
                          <Badge size="sm">{k.key_type.toUpperCase()}</Badge>
                          <Badge size="sm" variant="info">{k.algorithm}</Badge>
                        </div>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* DETAIL PANE (Desktop) */}
        <div className="hidden md:block w-[400px] lg:w-[450px] shrink-0 border-l border-bd pl-6 overflow-y-auto">
          {renderRightPanelContent()}
        </div>
      </div>

      {/* MODAL (Mobile) */}
      {showModal && (
        <div className="md:hidden fixed inset-0 z-50 bg-bg-base/95 backdrop-blur-sm animate-fade-in flex flex-col">
          <div className="flex-1 overflow-y-auto p-4 pb-24">
            <div className="bg-surface rounded-2xl border border-bd p-5 shadow-xl min-h-full">
              {renderRightPanelContent()}
            </div>
          </div>
        </div>
      )}
    </AppShell>
  )
}

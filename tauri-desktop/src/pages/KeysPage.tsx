import { useState, useEffect, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Key, Plus, Eye, EyeOff, Copy, Trash2, Shield, Terminal,
  Lock, Fingerprint, Upload,
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

const selectStyle: React.CSSProperties = { width: '100%', padding: '10px 12px', background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-sm)', outline: 'none' }
const labelStyle: React.CSSProperties = { display: 'block', fontSize: 'var(--text-xs)', fontWeight: 500, color: 'var(--text-secondary)', fontFamily: 'var(--font-body)', letterSpacing: 'var(--tracking-wide)', textTransform: 'uppercase' as const, marginBottom: 'var(--space-1)' }
const taStyle: React.CSSProperties = { width: '100%', padding: '10px 12px', background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 'var(--text-sm)', resize: 'vertical' as const, outline: 'none' }

/* ───── KeyDataViewer (reusable for SSH split keys) ───── */
function KeyDataViewer({ data, name, onCopy }: { data: string; name: string; onCopy: (text: string, label: string) => void }) {
  if (data.includes('|||')) {
    const [priv, pub] = data.split('|||')
    return (
      <>
        <div>
          <label style={labelStyle}>Clé privée</label>
          <div style={{ position: 'relative' }}>
            <textarea readOnly rows={6} value={priv} style={taStyle} />
            <Button size="sm" style={{ position: 'absolute', top: 8, right: 8 }} icon={Copy} onClick={() => onCopy(priv, name + ' (Private)')}>Copier</Button>
          </div>
        </div>
        <div>
          <label style={labelStyle}>Clé publique</label>
          <div style={{ position: 'relative' }}>
            <textarea readOnly rows={3} value={pub} style={taStyle} />
            <Button size="sm" style={{ position: 'absolute', top: 8, right: 8 }} icon={Copy} onClick={() => onCopy(pub, name + ' (Public)')}>Copier</Button>
          </div>
        </div>
      </>
    )
  }
  return (
    <div>
      <label style={labelStyle}>Données de la clé</label>
      <div style={{ position: 'relative' }}>
        <textarea readOnly rows={8} value={data} style={taStyle} />
        <Button size="sm" style={{ position: 'absolute', top: 8, right: 8 }} icon={Copy} onClick={() => onCopy(data, name)}>Copier</Button>
      </div>
    </div>
  )
}

/* ───── component ───── */
export default function KeysPage() {
  const qc = useQueryClient()
  const { toast } = useToast()
  const copy = useClipboard()
  const [search, setSearch] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [showGenerated, setShowGenerated] = useState(false)
  const [showDetail, setShowDetail] = useState(false)
  const [generatedData, setGeneratedData] = useState<{ name: string; data: string } | null>(null)
  const [viewDetail, setViewDetail] = useState<{ key: SecureKey; data: string } | null>(null)
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
    }, 60_000)
    return () => { if (cacheTimerRef.current) clearTimeout(cacheTimerRef.current) }
  }, [decryptedCache.size])

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
      setShowCreate(false)
      setGeneratedData({ name: d.name, data: d.dec }); setShowGenerated(true)
      setKeyName(''); setKeyType('api'); setAlgorithm('AES-256-GCM')
      toast('Clé générée', 'success')
    },
    onError: (e) => toast('Erreur : ' + e, 'error'),
  })

  const importMut = useMutation({
    mutationFn: () => keysSvc.import({ key_name: impName, key_type: impType, key_data: impData, algorithm: impAlgo }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['secureKeys'] }); setShowImport(false); setImpName(''); setImpType('api'); setImpData(''); setImpAlgo('AES-256-GCM'); toast('Clé importée', 'success') },
    onError: (e) => toast('Erreur : ' + e, 'error'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: number) => keysSvc.delete(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['secureKeys'] }); toast('Clé supprimée', 'success') },
    onError: (e) => toast('Erreur : ' + e, 'error'),
  })

  const decryptMut = useMutation({ mutationFn: (id: number) => keysSvc.decrypt(id) })

  const filtered = list.filter(k => k.key_name.toLowerCase().includes(search.toLowerCase()) || k.key_type.toLowerCase().includes(search.toLowerCase()))

  const handleCopy = (text: string, label: string) => { copy(text); toast(`"${label}" copié — effacé dans 30 s`, 'success') }

  const handleReveal = async (k: SecureKey) => {
    if (revealedKeys.has(k.id)) { setRevealedKeys(p => { const s = new Set(p); s.delete(k.id); return s }); return }
    let d = decryptedCache.get(k.id)
    if (!d) { d = await decryptMut.mutateAsync(k.id); setDecryptedCache(p => new Map(p).set(k.id, d!)) }
    setRevealedKeys(p => new Set(p).add(k.id))
    setViewDetail({ key: k, data: d }); setShowDetail(true)
  }

  const handleCopyKey = async (k: SecureKey) => {
    let d = decryptedCache.get(k.id)
    if (!d) { d = await decryptMut.mutateAsync(k.id); setDecryptedCache(p => new Map(p).set(k.id, d!)) }
    if (d) handleCopy(d, k.key_name)
  }

  if (isLoading) return <AppShell><div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--space-16)' }}><Spinner size={32} /></div></AppShell>

  return (
    <AppShell>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
              <Shield size={28} style={{ color: 'var(--accent)' }} /> Clés cryptographiques
            </h1>
            <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', marginTop: 'var(--space-1)' }}>
              {list.length} clé{list.length !== 1 ? 's' : ''} stockée{list.length !== 1 ? 's' : ''}
            </p>
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            <Button icon={Plus} onClick={() => setShowCreate(true)}>Générer</Button>
            <Button variant="secondary" icon={Upload} onClick={() => setShowImport(true)}>Importer</Button>
          </div>
        </div>

        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher une clé…" />

        {/* List */}
        {filtered.length === 0 ? (
          <EmptyState icon={Shield} title={search ? 'Aucun résultat' : 'Aucune clé'}
            description={search ? undefined : 'Générez ou importez votre première clé'}
            action={!search ? <Button icon={Plus} onClick={() => setShowCreate(true)}>Générer</Button> : undefined} />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
            {filtered.map(k => (
              <div key={k.id} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 'var(--space-5)', display: 'flex', alignItems: 'center', gap: 'var(--space-4)', transition: 'border-color var(--transition-fast)' }}>
                <div style={{ width: 40, height: 40, borderRadius: 'var(--radius-md)', background: `color-mix(in srgb, ${keyColor(k.key_type)} 12%, transparent)`, display: 'flex', alignItems: 'center', justifyContent: 'center', color: keyColor(k.key_type), flexShrink: 0 }}>
                  {keyIcon(k.key_type)}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontSize: 'var(--text-base)', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>{k.key_name}</p>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginTop: 2 }}>
                    <Badge size="sm">{k.key_type.toUpperCase()}</Badge>
                    <Badge size="sm" variant="info">{k.algorithm}</Badge>
                    <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-disabled)', fontFamily: 'var(--font-body)' }}>{fmtDate(k.created_at)}</span>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 'var(--space-1)', flexShrink: 0 }}>
                  <Button variant="ghost" size="sm" icon={revealedKeys.has(k.id) ? EyeOff : Eye} onClick={() => handleReveal(k)} disabled={decryptMut.isPending} />
                  <Button variant="ghost" size="sm" icon={Copy} onClick={() => handleCopyKey(k)} disabled={decryptMut.isPending} />
                  <Button variant="ghost" size="sm" icon={Trash2} onClick={() => { if (confirm(`Supprimer "${k.key_name}" ?`)) { deleteMut.mutate(k.id); setRevealedKeys(p => { const s = new Set(p); s.delete(k.id); return s }); setDecryptedCache(p => { const m = new Map(p); m.delete(k.id); return m }) } }} style={{ color: 'var(--danger)' }} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Create Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Générer une clé">
        <form onSubmit={(e) => { e.preventDefault(); if (!keyName.trim()) { toast('Nom requis', 'error'); return }; createMut.mutate() }} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <Input label="Nom de la clé" value={keyName} onChange={e => setKeyName(e.target.value)} placeholder="Ex: GitHub SSH" required />
          <div><label style={labelStyle}>Type</label>
            <select value={keyType} onChange={e => setKeyType(e.target.value)} style={selectStyle}>
              <option value="api">API</option><option value="ssh">SSH</option><option value="gpg">GPG</option><option value="encryption">Chiffrement</option>
            </select>
          </div>
          <div><label style={labelStyle}>Algorithme</label>
            <select value={algorithm} onChange={e => setAlgorithm(e.target.value)} style={selectStyle}>
              <option value="AES-256-GCM">AES-256-GCM</option><option value="AES-256-CBC">AES-256-CBC</option><option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
            </select>
            <p style={{ marginTop: 4, fontSize: 'var(--text-xs)', color: 'var(--text-disabled)', fontFamily: 'var(--font-body)' }}>Toutes les clés sont chiffrées en AES-256-GCM.</p>
          </div>
          <div style={{ display: 'flex', gap: 'var(--space-3)', paddingTop: 'var(--space-2)' }}>
            <Button type="submit" fullWidth loading={createMut.isPending}>Générer</Button>
            <Button type="button" variant="secondary" fullWidth onClick={() => setShowCreate(false)}>Annuler</Button>
          </div>
        </form>
      </Modal>

      {/* Import Modal */}
      <Modal open={showImport} onClose={() => setShowImport(false)} title="Importer une clé">
        <form onSubmit={(e) => { e.preventDefault(); if (!impName.trim() || !impData.trim()) { toast('Nom et données requis', 'error'); return }; importMut.mutate() }} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          <Input label="Nom" value={impName} onChange={e => setImpName(e.target.value)} placeholder="Ex: Ma clé SSH" required />
          <div><label style={labelStyle}>Type</label>
            <select value={impType} onChange={e => setImpType(e.target.value)} style={selectStyle}>
              <option value="api">API</option><option value="ssh">SSH</option><option value="gpg">GPG</option><option value="encryption">Chiffrement</option>
            </select>
          </div>
          <div><label style={labelStyle}>Algorithme</label>
            <select value={impAlgo} onChange={e => setImpAlgo(e.target.value)} style={selectStyle}>
              <optgroup label="Symétrique"><option value="AES-256-GCM">AES-256-GCM</option><option value="AES-256-CBC">AES-256-CBC</option><option value="AES-192-GCM">AES-192-GCM</option><option value="AES-128-GCM">AES-128-GCM</option><option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option></optgroup>
              <optgroup label="Asymétrique"><option value="RSA-4096">RSA-4096</option><option value="RSA-2048">RSA-2048</option><option value="Ed25519">Ed25519</option><option value="ECDSA-P256">ECDSA-P256</option><option value="ECDSA-P384">ECDSA-P384</option></optgroup>
              <optgroup label="SSH"><option value="ssh-rsa">ssh-rsa</option><option value="ssh-ed25519">ssh-ed25519</option><option value="ecdsa-sha2-nistp256">ecdsa-sha2-nistp256</option><option value="ecdsa-sha2-nistp384">ecdsa-sha2-nistp384</option></optgroup>
              <optgroup label="Autre"><option value="Custom">Autre</option></optgroup>
            </select>
          </div>
          <div><label style={labelStyle}>Données de la clé</label><textarea value={impData} onChange={e => setImpData(e.target.value)} placeholder="Collez votre clé ici…" rows={6} style={taStyle} required /></div>
          <div style={{ display: 'flex', gap: 'var(--space-3)', paddingTop: 'var(--space-2)' }}>
            <Button type="submit" fullWidth loading={importMut.isPending}>Importer</Button>
            <Button type="button" variant="secondary" fullWidth onClick={() => setShowImport(false)}>Annuler</Button>
          </div>
        </form>
      </Modal>

      {/* Generated key modal */}
      <Modal open={showGenerated && !!generatedData} onClose={() => { setShowGenerated(false); setGeneratedData(null) }} title="Clé générée">
        {generatedData && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div><label style={labelStyle}>Nom</label><div style={{ padding: '10px 12px', background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)', fontWeight: 600 }}>{generatedData.name}</div></div>
            <KeyDataViewer data={generatedData.data} name={generatedData.name} onCopy={handleCopy} />
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-2)', padding: 'var(--space-3)', background: 'color-mix(in srgb, var(--warning) 10%, transparent)', borderRadius: 'var(--radius-md)' }}>
              <Shield size={16} style={{ color: 'var(--warning)', flexShrink: 0, marginTop: 2 }} />
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-secondary)', fontFamily: 'var(--font-body)' }}>Sauvegardez cette clé maintenant. C'est la seule fois qu'elle sera affichée en clair.</span>
            </div>
            <Button fullWidth onClick={() => { setShowGenerated(false); setGeneratedData(null) }}>J'ai sauvegardé ma clé</Button>
          </div>
        )}
      </Modal>

      {/* Detail modal */}
      <Modal open={showDetail && !!viewDetail} onClose={() => { setShowDetail(false); setViewDetail(null) }} title={viewDetail?.key.key_type === 'ssh' ? 'Détails clé SSH' : 'Détails de la clé'}>
        {viewDetail && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
            <div><label style={labelStyle}>Nom</label><div style={{ padding: '10px 12px', background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)', fontWeight: 600 }}>{viewDetail.key.key_name}</div></div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 'var(--space-3)' }}>
              <div><label style={labelStyle}>Type</label><div style={{ padding: '10px 12px', background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>{viewDetail.key.key_type.toUpperCase()}</div></div>
              <div><label style={labelStyle}>Algorithme</label><div style={{ padding: '10px 12px', background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>{viewDetail.key.algorithm}</div></div>
            </div>
            <KeyDataViewer data={viewDetail.data} name={viewDetail.key.key_name} onCopy={handleCopy} />
            <Button variant="secondary" fullWidth onClick={() => { setShowDetail(false); setViewDetail(null) }}>Fermer</Button>
          </div>
        )}
      </Modal>
    </AppShell>
  )
}

import { useState, useEffect, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Key, Plus, Eye, EyeOff, Copy, Trash2, Shield, Terminal,
  Lock, Fingerprint, Upload, ShieldAlert,
} from 'lucide-react'
import { keys as keysSvc, type SecureKey } from '../lib/vault-service'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner } from '../design-system/atoms'
import { SearchBar, Modal } from '../design-system/molecules'
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
const DEFAULT_ALGO_BY_TYPE: Record<string, string> = {
  api: 'ChaCha20-Poly1305',
  ssh: 'ssh-ed25519',
  gpg: 'ML-DSA-65',
  encryption: 'ChaCha20-Poly1305',
}

const ALGO_OPTIONS_BY_TYPE: Record<string, { value: string; label: string }[]> = {
  api: [
    { value: 'ChaCha20-Poly1305', label: 'ChaCha20-Poly1305 (256 bits)' },
    { value: 'AES-256-GCM', label: 'AES-256-GCM (256 bits)' },
  ],
  ssh: [
    { value: 'ssh-ed25519', label: 'ssh-ed25519 (OpenSSH RFC 8709)' },
    { value: 'Ed25519', label: 'Ed25519 (RFC 8032)' },
  ],
  gpg: [
    { value: 'ML-DSA-65', label: 'ML-DSA-65 (Post-Quantique FIPS 204)' },
    { value: 'Ed25519', label: 'Ed25519 (Signature RFC 8032)' },
  ],
  encryption: [
    { value: 'ChaCha20-Poly1305', label: 'ChaCha20-Poly1305 (Symétrique 256b)' },
    { value: 'AES-256-GCM', label: 'AES-256-GCM (Symétrique 256b)' },
    { value: 'ML-KEM-768', label: 'ML-KEM-768 (Post-Quantique FIPS 203)' },
    { value: 'X25519', label: 'X25519 (Diffie-Hellman RFC 7748)' },
  ],
}

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
  const [decryptedCache, setDecryptedCache] = useState<Map<number, string>>(new Map())
  const cacheTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // EXP-008: Auto-clear du cache de clés déchiffrées après 60 secondes
  useEffect(() => {
    if (decryptedCache.size === 0) return
    if (cacheTimerRef.current) clearTimeout(cacheTimerRef.current)
    cacheTimerRef.current = setTimeout(() => {
      setDecryptedCache(new Map())
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

  const { data: list = [], isLoading, isError, refetch } = useQuery({ queryKey: ['secureKeys'], queryFn: keysSvc.list })

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
      try {
        d = await decryptMut.mutateAsync(k.id)
        setDecryptedCache(p => new Map(p).set(k.id, d!))
      } catch {
        return
      }
    }
    setRightPanel({ type: 'view', key: k, data: d })
  }

  const handleDelete = (k: SecureKey) => {
    if (confirm(`Supprimer "${k.key_name}" ?`)) { 
      deleteMut.mutate(k.id)
      setDecryptedCache(p => { const m = new Map(p); m.delete(k.id); return m })
      if (rightPanel?.type === 'view' && rightPanel.key.id === k.id) {
        setRightPanel(null)
      }
    }
  }


  const renderForm = () => {
    if (!rightPanel) return null

    if (rightPanel.type === 'create') {
      const algoOptions = ALGO_OPTIONS_BY_TYPE[keyType] ?? ALGO_OPTIONS_BY_TYPE.api
      return (
        <form onSubmit={(e) => { e.preventDefault(); if (!keyName.trim()) { toast('Nom requis', 'error'); return }; createMut.mutate() }} className="flex flex-col gap-5 h-full animate-fade-in">
          <Input label="Nom de la clé" value={keyName} onChange={e => setKeyName(e.target.value)} placeholder="Ex: GitHub SSH" required />
          <div>
            <label htmlFor="generate-key-type" className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Type</label>
            <select id="generate-key-type" value={keyType} onChange={e => {
              const nextType = e.target.value
              setKeyType(nextType)
              setAlgorithm(DEFAULT_ALGO_BY_TYPE[nextType] ?? 'ChaCha20-Poly1305')
            }} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-body text-sm outline-none focus:border-accent">
              <option value="api">API</option><option value="ssh">SSH</option><option value="gpg">Signature / GPG</option><option value="encryption">Chiffrement / KEM</option>
            </select>
          </div>
          <div>
            <label htmlFor="generate-key-algorithm" className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Algorithme</label>
            <select id="generate-key-algorithm" value={algorithm} onChange={e => setAlgorithm(e.target.value)} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-body text-sm outline-none focus:border-accent">
              {algoOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
            <p className="mt-1 text-xs text-tx-disabled font-body">Toutes les clés sont chiffrées en ChaCha20-Poly1305 (AEAD + AAD) dans le coffre.</p>
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
          <Input label="Nom" value={impName} onChange={e => setImpName(e.target.value)} placeholder="Ex: Ma clé SSH" required />
          <div>
            <label htmlFor="import-key-type" className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Type</label>
            <select id="import-key-type" value={impType} onChange={e => setImpType(e.target.value)} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-body text-sm outline-none focus:border-accent">
              <option value="api">API</option><option value="ssh">SSH</option><option value="gpg">GPG</option><option value="encryption">Chiffrement</option>
            </select>
          </div>
          <div>
            <label htmlFor="import-key-algorithm" className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Algorithme d'origine</label>
            <select id="import-key-algorithm" value={impAlgo} onChange={e => setImpAlgo(e.target.value)} className="w-full px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-body text-sm outline-none focus:border-accent">
              <optgroup label="Post-Quantique (NIST)"><option value="ML-DSA-65">ML-DSA-65 (FIPS 204)</option><option value="ML-KEM-768">ML-KEM-768 (FIPS 203)</option></optgroup>
              <optgroup label="Symétrique"><option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option><option value="AES-256-GCM">AES-256-GCM</option><option value="AES-256-CBC">AES-256-CBC</option><option value="AES-192-GCM">AES-192-GCM</option><option value="AES-128-GCM">AES-128-GCM</option></optgroup>
              <optgroup label="Asymétrique"><option value="Ed25519">Ed25519</option><option value="X25519">X25519</option><option value="RSA-4096">RSA-4096</option><option value="RSA-2048">RSA-2048</option><option value="ECDSA-P256">ECDSA-P256</option><option value="ECDSA-P384">ECDSA-P384</option></optgroup>
              <optgroup label="SSH"><option value="ssh-rsa">ssh-rsa</option><option value="ssh-ed25519">ssh-ed25519</option><option value="ecdsa-sha2-nistp256">ecdsa-sha2-nistp256</option><option value="ecdsa-sha2-nistp384">ecdsa-sha2-nistp384</option></optgroup>
              <optgroup label="Autre"><option value="Custom">Autre</option></optgroup>
            </select>
          </div>
          <div className="flex-1">
            <label htmlFor="import-key-data" className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Données de la clé</label>
            <textarea id="import-key-data" value={impData} onChange={e => setImpData(e.target.value)} placeholder="Collez votre clé ici…" className="w-full h-[150px] px-3 py-2.5 bg-input border border-bd rounded-lg text-tx-primary font-mono text-sm resize-y outline-none focus:border-accent" required />
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
          <div>
            <label className="block text-xs font-medium text-tx-secondary font-body tracking-wide uppercase mb-1">Nom</label>
            <div className="px-3 py-2.5 bg-elevated rounded-lg text-tx-primary font-body font-semibold">{rightPanel.name}</div>
          </div>
          <KeyDataViewer data={rightPanel.data} name={rightPanel.name} onCopy={handleCopy} />
          <div className="flex items-start gap-2 p-3 bg-warning-muted border border-warning rounded-lg mt-2">
            <ShieldAlert size={16} className="text-warning shrink-0 mt-0.5" />
            <span className="text-xs text-tx-primary font-body">Conservez une copie sécurisée si cette clé doit être utilisée hors du coffre.</span>
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

  const dialogTitle = rightPanel?.type === 'create' ? 'Générer une clé'
    : rightPanel?.type === 'import' ? 'Importer une clé'
    : rightPanel?.type === 'generated' ? 'Clé générée' : 'Détails de la clé'
  const close = () => {
    if (!createMut.isPending && !importMut.isPending) setRightPanel(null)
  }

  return (
    <WorkspacePage title="Clés cryptographiques" description="Générez, importez et consultez les clés enregistrées dans le coffre."
      actions={<>
        <Button variant="secondary" icon={Upload} onClick={() => setRightPanel({ type: 'import' })}>Importer une clé</Button>
        <Button icon={Plus} onClick={() => setRightPanel({ type: 'create' })}>Générer une clé</Button>
      </>}>
      <section className="workspace-panel workspace-stack" aria-labelledby="key-list">
        <h2 id="key-list">Clés enregistrées</h2>
        <SearchBar value={search} onChange={setSearch} placeholder="Rechercher une clé…" />
        {decryptMut.isError && <p role="alert" className="workspace-error">Impossible d’ouvrir la clé. {String(decryptMut.error)}</p>}
        {isLoading ? <p role="status" className="workspace-label"><Spinner size={18} /> Chargement…</p> :
          isError ? <div className="workspace-stack">
            <p role="alert" className="workspace-error">Impossible de charger les clés.</p>
            <div><Button variant="secondary" onClick={() => void refetch()}>Réessayer</Button></div>
          </div> : filtered.length === 0 ? (
          <p className="workspace-empty">{search ? 'Aucune clé ne correspond à votre recherche.' : 'Générez ou importez votre première clé.'}</p>
        ) : (
          <ul className="workspace-list">
            {filtered.map((key) => (
              <li key={key.id} className="workspace-row">
                <span className="workspace-icon" style={{ color: keyColor(key.key_type) }} aria-hidden="true">{keyIcon(key.key_type)}</span>
                <div className="workspace-row-copy">
                  <strong>{key.key_name}</strong>
                  <span>{key.key_type.toUpperCase()} · {key.algorithm}</span>
                </div>
                <Button variant="secondary" icon={Eye} size="sm" onClick={() => void handleReveal(key)}
                  disabled={decryptMut.isPending} aria-label={`Consulter ${key.key_name}`}>Consulter</Button>
              </li>
            ))}
          </ul>
        )}
      </section>
      <Modal open={rightPanel !== null} onClose={close} title={dialogTitle}>
        {renderForm()}
        {(createMut.isError || importMut.isError) &&
          <p role="alert" className="workspace-error">{String(createMut.error || importMut.error)}</p>}
      </Modal>
    </WorkspacePage>
  )
}

import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowLeftRight, Send, Download, Wifi, WifiOff,
  Shield, ShieldCheck, ShieldAlert, Copy, Check,
  Loader2, X, RefreshCw, Users, Fingerprint, Trash2,
  KeyRound, Files, Lock, Radio, Globe,
} from 'lucide-react'
import { AppShell } from '../design-system/layouts'
import { Button, Badge, Spinner } from '../design-system/atoms'
import { EmptyState } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'
import {
  transfer,
  passwords as passwordsService,
  files as filesService,
  keys as keysService,
  type TransferOffer,
  type TransferConnection,
  type DiscoveredPeer,
  type TrustedPeer,
  type Password,
  type SecureFile,
  type SecureKey,
} from '../lib/vault-service'

type Tab = 'send' | 'receive' | 'peers'

/* ─── Styles ─── */
const card: React.CSSProperties = {
  background: 'var(--bg-surface)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-lg)',
  padding: 'var(--space-6)',
}
const label: React.CSSProperties = {
  fontSize: 'var(--text-sm)',
  color: 'var(--text-secondary)',
  marginBottom: 'var(--space-2)',
  display: 'block',
}
const codeBox: React.CSSProperties = {
  background: 'var(--bg-input)',
  border: '1px solid var(--border)',
  borderRadius: 'var(--radius-md)',
  padding: 'var(--space-4)',
  fontFamily: 'var(--font-mono)',
  fontSize: 'var(--text-lg)',
  textAlign: 'center' as const,
  letterSpacing: '0.15em',
  color: 'var(--accent-text)',
  userSelect: 'all' as const,
}
const safetyBox: React.CSSProperties = {
  background: 'var(--warning-muted)',
  border: '1px solid var(--warning)',
  borderRadius: 'var(--radius-lg)',
  padding: 'var(--space-5)',
  textAlign: 'center' as const,
}

/* ─── SafetyIdenticon — visual hash of the safety number ─── */
/* Grille 3×3 avec 24 couleurs → 24^9 ≈ 2.6 milliards de combinaisons uniques.
   L'ORDRE compte : même couleurs + positions différentes = identicon différent.
   Utilise deux fonctions de hash (FNV-1a + DJB2) pour distribuer l'entropie
   sur les 9 cellules de la grille. */
function SafetyIdenticon({ value }: { value: string }) {
  // FNV-1a hash — complementary to DJB2 for better entropy spread
  const fnv1a = (s: string): number => {
    let h = 0x811c9dc5
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i)
      h = Math.imul(h, 0x01000193)
    }
    return h >>> 0
  }
  // DJB2 hash
  const djb2 = (s: string): number => {
    let h = 5381
    for (let i = 0; i < s.length; i++) {
      h = ((h << 5) + h + s.charCodeAt(i)) | 0
    }
    return Math.abs(h)
  }

  // 24 couleurs hautement distinctes, optimisées pour un fond sombre
  const palette = [
    '#EF4444', '#F97316', '#F59E0B', '#EAB308',  // rouges → jaunes
    '#84CC16', '#22C55E', '#10B981', '#14B8A6',  // verts
    '#06B6D4', '#22D3EE', '#0EA5E9', '#3B82F6',  // cyans → bleus
    '#6366F1', '#8B5CF6', '#A855F7', '#D946EF',  // indigos → violets
    '#EC4899', '#F43F5E', '#FB7185', '#FBBF24',  // roses + doré
    '#2DD4BF', '#34D399', '#A78BFA', '#C084FC',  // teals + lavandes
  ]

  const h1 = fnv1a(value)
  const h2 = djb2(value)

  // 9 cellules : 5 du premier hash, 4 du second (5 bits par cellule)
  const colors = [
    palette[h1 % 24],
    palette[(h1 >> 5) % 24],
    palette[(h1 >> 10) % 24],
    palette[(h1 >> 15) % 24],
    palette[(h1 >> 20) % 24],
    palette[h2 % 24],
    palette[(h2 >> 5) % 24],
    palette[(h2 >> 10) % 24],
    palette[(h2 >> 15) % 24],
  ]

  return (
    <div className="inline-grid grid-cols-3 gap-0.5 w-11 h-11 rounded-md overflow-hidden" title="Identicon de vérification — les couleurs ET leur position doivent correspondre">
      {colors.map((c, i) => (
        <div key={i} className="rounded-sm" style={{
          background: c,
          boxShadow: `inset 0 0 0 0.5px rgba(255,255,255,0.1), 0 0 4px ${c}55`,
        }} />
      ))}
    </div>
  )
}

/* ─── SonarScanner — animated sonar effect for scanning ─── */
function SonarScanner() {
  return (
    <div className="relative w-12 h-12 flex items-center justify-center">
      <div className="absolute inset-0 rounded-full border-2 opacity-30 animate-[sonarPulse_2s_ease-out_infinite]" style={{ borderColor: 'var(--accent)' }} />
      <div className="absolute inset-1 rounded-full border-2 opacity-50 animate-[sonarPulse_2s_ease-out_0.4s_infinite]" style={{ borderColor: 'var(--accent)' }} />
      <div className="w-3 h-3 rounded-full" style={{ background: 'var(--accent)', boxShadow: 'var(--shadow-glow)' }} />
      <style>{`
        @keyframes sonarPulse {
          0% { transform: scale(0.8); opacity: 0.6; }
          100% { transform: scale(2); opacity: 0; }
        }
      `}</style>
    </div>
  )
}

/* ─── WormholeSend ─── */
function WormholeSend({ onItemsSelected }: { onItemsSelected: (type: string, ids: number[]) => void }) {
  const [selectedType, setSelectedType] = useState<string>('passwords')
  const [selectedIds, setSelectedIds] = useState<number[]>([])

  // Chargement des items sélectionnables
  const { data: passwords = [] } = useQuery({ queryKey: ['passwords'], queryFn: passwordsService.list })
  const { data: secureFiles = [] } = useQuery({ queryKey: ['secureFiles'], queryFn: filesService.list })
  const { data: secureKeys = [] } = useQuery({ queryKey: ['secureKeys'], queryFn: keysService.list })

  const items = selectedType === 'passwords' ? passwords
    : selectedType === 'files' ? secureFiles
    : secureKeys

  const toggleItem = (id: number) => {
    setSelectedIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
      {/* Type selector */}
      <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
        {[
          { key: 'passwords', label: 'Mots de passe', icon: KeyRound },
          { key: 'files', label: 'Fichiers', icon: Files },
          { key: 'keys', label: 'Clés', icon: Lock },
        ].map(t => (
          <Button
            key={t.key}
            variant={selectedType === t.key ? 'primary' : 'secondary'}
            size="sm"
            icon={t.icon}
            onClick={() => { setSelectedType(t.key); setSelectedIds([]) }}
          >
            {t.label}
          </Button>
        ))}
      </div>

      {/* Item list */}
      <div style={{ ...card, maxHeight: 300, overflowY: 'auto' }}>
        {items.length === 0 ? (
          <p style={{ color: 'var(--text-muted)', textAlign: 'center', margin: 0 }}>Aucun élément disponible</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
            {items.map((item: any) => {
              const id = item.id as number
              const name = item.title || item.filename || item.key_name || '—'
              const selected = selectedIds.includes(id)
              return (
                <div
                  key={id}
                  onClick={() => toggleItem(id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
                    padding: '8px 12px', borderRadius: 'var(--radius-md)',
                    cursor: 'pointer',
                    background: selected ? 'var(--accent-muted)' : 'transparent',
                    border: `1px solid ${selected ? 'var(--accent)' : 'transparent'}`,
                    transition: 'all 0.15s',
                  }}
                >
                  <div style={{
                    width: 18, height: 18, borderRadius: 4,
                    border: `2px solid ${selected ? 'var(--accent)' : 'var(--text-muted)'}`,
                    background: selected ? 'var(--accent)' : 'transparent',
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                  }}>
                    {selected && <Check size={12} style={{ color: 'var(--text-inverse)' }} />}
                  </div>
                  <span style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)' }}>{name}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <Button
        icon={Users}
        onClick={() => onItemsSelected(selectedType, selectedIds)}
        disabled={selectedIds.length === 0}
      >
        Choisir un destinataire {selectedIds.length > 0 ? `(${selectedIds.length})` : ''}
      </Button>
    </div>
  )
}

/* ─── WormholeReceive ─── */
function WormholeReceive() {
  const { toast } = useToast()
  const qc = useQueryClient()
  const [code, setCode] = useState('')
  const [connection, setConnection] = useState<TransferConnection | null>(null)
  const [receiveStatus, setReceiveStatus] = useState<'idle' | 'connecting' | 'confirming' | 'transferring' | 'completed' | 'failed'>('idle')
  const pollRef = useRef<number | null>(null)

  // Poll transfer status after confirmation
  useEffect(() => {
    if (!connection || receiveStatus !== 'transferring') return
    pollRef.current = window.setInterval(async () => {
      try {
        const status = await transfer.getStatus(connection.transfer_id)
        if (!status) return
        if (status.state === 'Completed') {
          setReceiveStatus('completed')
          qc.invalidateQueries({ queryKey: ['passwords'] })
          qc.invalidateQueries({ queryKey: ['secureFiles'] })
          qc.invalidateQueries({ queryKey: ['secureKeys'] })
          toast('Données reçues avec succès !', 'success')
          if (pollRef.current) window.clearInterval(pollRef.current)
        }
        if (typeof status.state === 'object' && 'Failed' in status.state) {
          setReceiveStatus('failed')
          toast(status.state.Failed.reason || 'Réception échouée', 'error')
          if (pollRef.current) window.clearInterval(pollRef.current)
        }
      } catch { /* ignore */ }
    }, 2000)
    return () => { if (pollRef.current) window.clearInterval(pollRef.current) }
  }, [connection, receiveStatus, toast])

  const connectMut = useMutation({
    mutationFn: () => transfer.connect(code.trim()),
    onSuccess: (data) => { setConnection(data); setReceiveStatus('confirming'); toast('Connexion établie', 'success') },
    onError: (e: any) => { setReceiveStatus('idle'); toast(e?.toString() || 'Erreur connexion — vérifiez que l\'autre appareil a créé une offre', 'error') },
  })

  const confirmMut = useMutation({
    mutationFn: (confirmed: boolean) =>
      transfer.confirmAndExecute(connection!.transfer_id, confirmed),
    onSuccess: (ok) => {
      if (ok) { setReceiveStatus('transferring'); toast('Réception en cours…', 'success') }
      else { setConnection(null); setReceiveStatus('idle'); toast('Transfert annulé', 'info') }
    },
    onError: (e: any) => toast(e?.toString() || 'Erreur', 'error'),
  })

  const resetState = () => {
    setConnection(null)
    setCode('')
    setReceiveStatus('idle')
  }

  // Completed
  if (receiveStatus === 'completed') {
    return (
      <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)', textAlign: 'center' as const }}>
        <ShieldCheck size={40} style={{ color: 'var(--success)', margin: '0 auto' }} />
        <p style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: 'var(--text-lg)' }}>Données reçues !</p>
        <Button variant="secondary" onClick={resetState}>
          Recevoir un autre transfert
        </Button>
      </div>
    )
  }

  // Failed
  if (receiveStatus === 'failed') {
    return (
      <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)', textAlign: 'center' as const }}>
        <ShieldAlert size={40} style={{ color: 'var(--danger, #ef4444)', margin: '0 auto' }} />
        <p style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Réception échouée</p>
        <Button variant="secondary" onClick={resetState}>
          Réessayer
        </Button>
      </div>
    )
  }

  // Transferring
  if (receiveStatus === 'transferring') {
    return (
      <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)', alignItems: 'center' }}>
        <Loader2 size={32} style={{ color: 'var(--accent)' }} className="animate-spin" />
        <p style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Réception en cours…</p>
        {connection && <SecurityBadge method={connection.connection_method} />}
      </div>
    )
  }

  if (connection && receiveStatus === 'confirming') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
        <SecurityBadge method={connection.connection_method} />

        {/* Safety number */}
        <div style={safetyBox}>
          <ShieldAlert size={24} style={{ color: 'var(--warning)', margin: '0 auto var(--space-2)' }} />
          <p style={{ color: 'var(--text-primary)', fontWeight: 600, margin: 0 }}>
            Vérifiez le Safety Number
          </p>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-3)', margin: 'var(--space-3) 0' }}>
            <SafetyIdenticon value={connection.safety_number || ''} />
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xl)', color: 'var(--text-primary)', letterSpacing: '0.2em', margin: 0 }}>
              {connection.safety_number}
            </p>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', margin: 0 }}>
            Comparez le code <strong>et</strong> le motif coloré : chaque couleur doit être à la <strong>même position</strong> sur les deux appareils
          </p>
        </div>

        {/* Peer info */}
        <div style={card}>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', margin: 0 }}>
            Pair : <strong style={{ color: 'var(--text-primary)' }}>{connection.peer_name}</strong>
          </p>
          {connection.items.length > 0 && (
            <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', margin: 'var(--space-2) 0 0' }}>
              {connection.items.length} élément(s) — {formatSize(connection.total_size)}
            </p>
          )}
        </div>

        <div className="flex flex-col sm:flex-row gap-3 w-full">
          <Button
            icon={ShieldCheck}
            onClick={() => confirmMut.mutate(true)}
            loading={confirmMut.isPending}
            className="flex-1 w-full"
          >
            Confirmer et recevoir
          </Button>
          <Button
            variant="danger"
            icon={X}
            onClick={() => confirmMut.mutate(false)}
            className="flex-1 w-full"
          >
            Refuser
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
      <div>
        <span style={label}>Code Wormhole reçu du sender</span>
        <input
          type="text"
          value={code}
          onChange={e => setCode(e.target.value)}
          placeholder="ex: 42-alpha-beacon-drift"
          style={{
            width: '100%',
            padding: 'var(--space-3) var(--space-4)',
            background: 'var(--bg-input)',
            border: '1px solid var(--border)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--text-primary)',
            fontFamily: 'var(--font-mono)',
            fontSize: 'var(--text-base)',
            outline: 'none',
          }}
          onFocus={e => (e.target.style.borderColor = 'var(--border-focus)')}
          onBlur={e => (e.target.style.borderColor = 'var(--border)')}
          onKeyDown={e => { if (e.key === 'Enter' && code.trim()) connectMut.mutate() }}
        />
      </div>
      <Button
        icon={Download}
        onClick={() => { setReceiveStatus('connecting'); connectMut.mutate() }}
        disabled={!code.trim()}
        loading={connectMut.isPending}
      >
        {connectMut.isPending ? 'Connexion en cours…' : 'Se connecter'}
      </Button>
    </div>
  )
}

/* ─── SecurityBadge ─── */
function SecurityBadge({ method }: { method: string }) {
  const isSecure = method.includes('IPv6') || method.includes('mDNS') || method.includes('Local') || method.includes('TLS') || method.includes('PQC')
  const color = isSecure ? 'var(--success)' : 'var(--warning)'
  const bg = isSecure ? 'var(--success-muted)' : 'var(--warning-muted)'
  const Icon = isSecure ? ShieldCheck : WifiOff

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 'var(--space-2)',
      padding: '6px 12px', borderRadius: 'var(--radius-full)',
      background: bg, width: 'fit-content',
    }}>
      <Icon size={14} style={{ color }} />
      <span style={{ color, fontSize: 'var(--text-xs)', fontWeight: 500 }}>{method}</span>
      <Shield size={12} style={{ color }} />
      <span style={{ color, fontSize: 'var(--text-xs)' }}>E2E PQC</span>
    </div>
  )
}

/* ─── TrustedPeers ─── */
function TrustedPeers({ pendingItems, onClearPending }: { pendingItems: { type: string; ids: number[] } | null; onClearPending: () => void }) {
  const { toast } = useToast()
  const qc = useQueryClient()
  const [syncEnabled, setSyncEnabled] = useState<Record<string, boolean>>({})
  const autoSyncingRef = useRef<Set<string>>(new Set())
  const lastAutoSyncRef = useRef<Record<string, number>>({})
  // Sender flow state: offer created after clicking a discovered peer
  const [offer, setOffer] = useState<TransferOffer | null>(null)
  const [copied, setCopied] = useState(false)
  const [transferStatus, setTransferStatus] = useState<string>('idle')
  const [safetyNumber, setSafetyNumber] = useState<string | null>(null)
  const [peerName, setPeerName] = useState<string | null>(null)
  const pollRef = useRef<number | null>(null)

  const { data: peers = [], isLoading } = useQuery({
    queryKey: ['trustedPeers'],
    queryFn: transfer.getTrustedPeers,
  })

  const { data: discovered = [], refetch: rescan, isFetching: isScanning } = useQuery({
    queryKey: ['discoveredPeers'],
    queryFn: transfer.scanLocalNetwork,
    refetchInterval: 10000,
  })

  // Visibility state
  const { data: isVisible = false } = useQuery({
    queryKey: ['transferVisibility'],
    queryFn: transfer.getVisibility,
  })

  const visibilityMut = useMutation({
    mutationFn: (visible: boolean) => transfer.setVisibility(visible),
    onSuccess: (visible) => {
      qc.invalidateQueries({ queryKey: ['transferVisibility'] })
      toast(visible ? 'Visible sur le réseau' : 'Masqué du réseau', visible ? 'success' : 'info')
    },
    onError: () => toast('Erreur changement visibilité', 'error'),
  })

  const revokeMut = useMutation({
    mutationFn: (fp: string) => transfer.revokeTrust(fp),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['trustedPeers'] }); toast('Confiance révoquée', 'success') },
    onError: () => toast('Erreur', 'error'),
  })

  // ── Sender flow: create offer when clicking a discovered peer ──
  const createOfferMut = useMutation({
    mutationFn: (crossNetwork: boolean = false) => {
      if (!pendingItems) throw new Error('Aucun élément sélectionné')
      return transfer.createOffer(pendingItems.type, pendingItems.ids, crossNetwork)
    },
    onSuccess: (data) => {
      setOffer(data)
      setTransferStatus('waiting')
      setSafetyNumber(null)
      toast('Offre créée — partagez le code avec le destinataire', 'success')
    },
    onError: (e: any) => toast(e?.toString() || 'Erreur création offre', 'error'),
  })

  const cancelMut = useMutation({
    mutationFn: (id: string) => transfer.cancel(id),
    onSuccess: () => {
      setOffer(null)
      setTransferStatus('idle')
      setSafetyNumber(null)
      setPeerName(null)
    },
  })

  const confirmMut = useMutation({
    mutationFn: (confirmed: boolean) =>
      transfer.confirmAndExecute(offer!.transfer_id, confirmed),
    onSuccess: (ok) => {
      if (ok) { setTransferStatus('transferring'); toast('Transfert en cours…', 'success') }
      else { setOffer(null); setSafetyNumber(null); setTransferStatus('idle'); toast('Transfert annulé', 'info') }
    },
    onError: (e: any) => toast(e?.toString() || 'Erreur', 'error'),
  })

  // Poll transfer status after creating offer
  useEffect(() => {
    if (!offer) return
    pollRef.current = window.setInterval(async () => {
      try {
        const status = await transfer.getStatus(offer.transfer_id)
        if (!status) return
        if (status.safety_number && !safetyNumber) {
          setSafetyNumber(status.safety_number)
          setPeerName(status.peer_name || null)
          setTransferStatus('confirming')
        }
        if (status.state === 'Completed') {
          setTransferStatus('completed')
          qc.invalidateQueries({ queryKey: ['passwords'] })
          qc.invalidateQueries({ queryKey: ['secureFiles'] })
          qc.invalidateQueries({ queryKey: ['secureKeys'] })
          toast('Transfert terminé avec succès !', 'success')
          if (pollRef.current) window.clearInterval(pollRef.current)
        }
        if (typeof status.state === 'object' && 'Failed' in status.state) {
          setTransferStatus('failed')
          toast((status.state as any).Failed.reason || 'Transfert échoué', 'error')
          if (pollRef.current) window.clearInterval(pollRef.current)
        }
        if (typeof status.state === 'object' && 'Transferring' in status.state) {
          setTransferStatus('transferring')
        }
      } catch { /* ignore */ }
    }, 2000)
    return () => { if (pollRef.current) window.clearInterval(pollRef.current) }
  }, [offer, safetyNumber, toast])

  const handleCopy = async () => {
    if (!offer) return
    try {
      await navigator.clipboard.writeText(offer.wormhole_code)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch { toast('Erreur copie', 'error') }
  }

  const resetSenderFlow = () => {
    setOffer(null)
    setTransferStatus('idle')
    setSafetyNumber(null)
    setPeerName(null)
    onClearPending()
  }

  // Fetch sync settings from backend to initialize toggle state
  const { data: syncSettings } = useQuery({
    queryKey: ['syncSettings'],
    queryFn: transfer.getSyncSettings,
  })

  // Initialize syncEnabled from backend settings
  useEffect(() => {
    if (syncSettings?.enabled) {
      const enabledMap: Record<string, boolean> = {}
      for (const device of syncSettings.devices) {
        enabledMap[device.verifying_key] = true
      }
      setSyncEnabled(prev => ({ ...prev, ...enabledMap }))
    }
  }, [syncSettings])

  const toggleSync = async (fingerprint: string) => {
    const newValue = !syncEnabled[fingerprint]
    setSyncEnabled(prev => ({ ...prev, [fingerprint]: newValue }))
    try {
      await transfer.setSyncEnabled(newValue)
      toast(
        newValue
          ? 'Synchronisation activée — les transferts seront signés avec ML-DSA-65'
          : 'Synchronisation désactivée',
        newValue ? 'success' : 'info',
      )
      qc.invalidateQueries({ queryKey: ['syncSettings'] })
    } catch {
      // Revert on error
      setSyncEnabled(prev => ({ ...prev, [fingerprint]: !newValue }))
      toast('Erreur changement synchronisation', 'error')
    }
  }

  // Auto-sync: when a verified (paired) peer is discovered on the network, sync automatically
  useEffect(() => {
    if (!syncSettings?.enabled || discovered.length === 0) return

    const verifiedPeers = discovered.filter(p => p.verified)
    if (verifiedPeers.length === 0) return

    const AUTO_SYNC_COOLDOWN_MS = 60_000 // 1 minute minimum between auto-syncs per peer

    for (const peer of verifiedPeers) {
      const peerKey = `${peer.addr}:${peer.port}`
      const lastSync = lastAutoSyncRef.current[peerKey] || 0
      const now = Date.now()

      if (now - lastSync < AUTO_SYNC_COOLDOWN_MS) continue
      if (autoSyncingRef.current.has(peerKey)) continue

      autoSyncingRef.current.add(peerKey)
      lastAutoSyncRef.current[peerKey] = now

      transfer.autoSyncWithPeer(peer.addr, peer.port)
        .then(result => {
          if (result.success && result.merged_count > 0) {
            toast(`Sync auto avec ${result.peer_name}: ${result.merged_count} entrée(s) fusionnée(s)`, 'success')
            qc.invalidateQueries({ queryKey: ['trustedPeers'] })
          }
        })
        .catch(() => { /* auto-sync silently fails — will retry next scan cycle */ })
        .finally(() => {
          autoSyncingRef.current.delete(peerKey)
        })
    }
  }, [discovered, syncSettings])

  // ── Sender flow overlays (offer created, waiting, confirming, transferring, done) ──
  if (offer && transferStatus === 'completed') {
    return (
      <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)', textAlign: 'center' as const }}>
        <ShieldCheck size={40} style={{ color: 'var(--success)', margin: '0 auto' }} />
        <p style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: 'var(--text-lg)' }}>Transfert terminé !</p>
        <Button variant="secondary" onClick={resetSenderFlow}>Nouveau transfert</Button>
      </div>
    )
  }

  if (offer && transferStatus === 'failed') {
    return (
      <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)', textAlign: 'center' as const }}>
        <ShieldAlert size={40} style={{ color: 'var(--danger, #ef4444)', margin: '0 auto' }} />
        <p style={{ color: 'var(--text-primary)', fontWeight: 600 }}>Transfert échoué</p>
        <Button variant="secondary" onClick={resetSenderFlow}>Réessayer</Button>
      </div>
    )
  }

  if (offer && transferStatus === 'transferring') {
    return (
      <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)', alignItems: 'center' }}>
        <Loader2 size={32} style={{ color: 'var(--accent)' }} className="animate-spin" />
        <p style={{ color: 'var(--text-primary)', fontWeight: 500 }}>Transfert en cours…</p>
        <SecurityBadge method={offer.connection_method} />
      </div>
    )
  }

  // Safety number confirmation (sender side)
  if (offer && safetyNumber && transferStatus === 'confirming') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
        <SecurityBadge method={offer.connection_method} />
        <div style={safetyBox}>
          <ShieldAlert size={24} style={{ color: 'var(--warning)', margin: '0 auto var(--space-2)' }} />
          <p style={{ color: 'var(--text-primary)', fontWeight: 600, margin: 0 }}>Vérifiez le Safety Number</p>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-3)', margin: 'var(--space-3) 0' }}>
            <SafetyIdenticon value={safetyNumber} />
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: 'var(--text-xl)', color: 'var(--text-primary)', letterSpacing: '0.2em', margin: 0 }}>
              {safetyNumber}
            </p>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', margin: 0 }}>
            Comparez le code <strong>et</strong> le motif coloré : chaque couleur doit être à la <strong>même position</strong> sur les deux appareils
          </p>
          {peerName && (
            <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', marginTop: 'var(--space-2)' }}>
              Pair : <strong>{peerName}</strong>
            </p>
          )}
        </div>
        <div className="flex flex-col sm:flex-row gap-3 w-full">
          <Button icon={ShieldCheck} onClick={() => confirmMut.mutate(true)} loading={confirmMut.isPending} className="flex-1 w-full">
            Confirmer et envoyer
          </Button>
          <Button variant="danger" icon={X} onClick={() => confirmMut.mutate(false)} className="flex-1 w-full">Refuser</Button>
        </div>
      </div>
    )
  }

  // Offer created — waiting for receiver to enter the code
  if (offer && transferStatus === 'waiting') {
    return (
      <div style={{ ...card, display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <Radio size={20} style={{ color: 'var(--accent)' }} className="animate-pulse" />
          <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>En attente du destinataire…</span>
        </div>
        <div>
          <span style={label}>Code Wormhole — partagez-le avec le destinataire</span>
          <div style={codeBox}>{offer.wormhole_code}</div>
          <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', marginTop: 'var(--space-2)', textAlign: 'center' }}>
            Le destinataire doit saisir ce code dans l'onglet « Recevoir »
          </p>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
          <Button variant="secondary" icon={copied ? Check : Copy} onClick={handleCopy}>
            {copied ? 'Copié !' : 'Copier le code'}
          </Button>
          <Button variant="danger" icon={X} onClick={() => { cancelMut.mutate(offer.transfer_id); resetSenderFlow() }}>
            Annuler
          </Button>
        </div>
        <SecurityBadge method={offer.connection_method} />
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-5)' }}>
      {/* Visibility toggle */}
      <div style={{
        ...card,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: 'var(--space-4) var(--space-6)',
        background: isVisible ? 'var(--success-muted)' : 'var(--bg-surface)',
        border: `1px solid ${isVisible ? 'var(--success)' : 'var(--border)'}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          {isVisible
            ? <Wifi size={20} style={{ color: 'var(--success)' }} />
            : <WifiOff size={20} style={{ color: 'var(--text-muted)' }} />
          }
          <div>
            <div style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)', fontWeight: 600 }}>
              {isVisible ? 'Visible sur le réseau' : 'Masqué du réseau'}
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>
              {isVisible
                ? 'Les autres appareils peuvent vous découvrir'
                : 'Activez pour être détectable par les autres appareils'
              }
            </div>
          </div>
        </div>
        <button
          onClick={() => visibilityMut.mutate(!isVisible)}
          disabled={visibilityMut.isPending}
          style={{
            width: 44, height: 24, borderRadius: 12, border: 'none', cursor: 'pointer',
            background: isVisible ? 'var(--success)' : 'var(--bg-input)',
            position: 'relative', transition: 'background 0.2s',
            opacity: visibilityMut.isPending ? 0.6 : 1,
          }}
        >
          <div style={{
            width: 20, height: 20, borderRadius: '50%', background: 'white',
            position: 'absolute', top: 2,
            left: isVisible ? 22 : 2,
            transition: 'left 0.2s',
          }} />
        </button>
      </div>

      {/* Pending items banner */}
      {pendingItems && !offer && (
        <div style={{
          ...card,
          background: 'var(--accent-muted)',
          border: '1px solid var(--accent)',
          display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
          padding: 'var(--space-4)',
        }}>
          <Send size={18} style={{ color: 'var(--accent)', flexShrink: 0 }} />
          <div style={{ flex: 1 }}>
            <p style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)', fontWeight: 600, margin: 0 }}>
              {pendingItems.ids.length} élément(s) sélectionné(s)
            </p>
            <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)', margin: 'var(--space-1) 0 0' }}>
              Choisissez un destinataire ci-dessous pour lancer le transfert
            </p>
          </div>
          <Button variant="ghost" size="sm" icon={X} onClick={resetSenderFlow}>Annuler</Button>
        </div>
      )}

      {/* Discovered on network */}
      <div style={card}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-4)' }}>
          <h3 style={{ color: 'var(--text-primary)', fontSize: 'var(--text-base)', margin: 0, display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <Wifi size={16} style={{ color: 'var(--accent)' }} /> Réseau local
          </h3>
          <Button variant="ghost" size="sm" icon={RefreshCw} onClick={() => rescan()} loading={isScanning}>
            Scanner
          </Button>
        </div>
        {discovered.length === 0 ? (
          <div style={{ textAlign: 'center' as const, padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-3)' }}>
            {isScanning && <SonarScanner />}
            <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-sm)', margin: 0 }}>
              {isScanning ? 'Recherche de pairs sur le réseau…' : 'Aucun pair détecté sur le réseau'}
            </p>
            <p style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', marginTop: 'var(--space-2)' }}>
              Assurez-vous que l'autre appareil est sur le même réseau Wi-Fi
            </p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {discovered.map((p, i) => (
              
              
                <div key={i} style={{
                  padding: '10px 12px', borderRadius: 'var(--radius-md)',
                  background: 'var(--bg-elevated)',
                  border: '1px solid transparent',
                  transition: 'all 0.15s',
                }} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-2 flex-1 min-w-0 w-full">
                    <Radio size={14} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                    <div className="min-w-0 flex-1">
                      <span style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)', fontWeight: 500 }} className="break-all">{p.name}</span>
                      <div className="flex flex-wrap gap-2 items-center mt-1">
                        <Badge variant="info">{p.method}</Badge>
                        <span style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)' }} className="break-all">{p.addr}</span>
                      </div>
                    </div>
                  </div>
                  {pendingItems && !offer && (
                    <Button
                      variant="primary"
                      size="sm"
                      icon={Send}
                      onClick={() => {
                        setPeerName(p.name)
                        createOfferMut.mutate(false)
                      }}
                      loading={createOfferMut.isPending}
                      className="w-full sm:w-auto flex-shrink-0"
                    >
                      Envoyer à
                    </Button>
                  )}
                </div>
            ))}
          </div>
        )}
      </div>

      {/* Cross-network / manual send option */}
      {pendingItems && !offer && (
        <div style={{
          ...card,
          background: 'var(--bg-surface)',
          border: '1px dashed var(--border)',
          display: 'flex', flexDirection: 'column', gap: 'var(--space-3)',
          padding: 'var(--space-4)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <Globe size={18} style={{ color: 'var(--text-secondary)', flexShrink: 0 }} />
            <div style={{ flex: 1 }}>
              <p style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)', fontWeight: 600, margin: 0 }}>
                Envoyer à distance
              </p>
              <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)', margin: 'var(--space-1) 0 0' }}>
                Destinataire sur un autre réseau ? Générez un code à partager
              </p>
            </div>
            <Button
              variant="secondary"
              size="sm"
              icon={Send}
              onClick={() => createOfferMut.mutate(true)}
              loading={createOfferMut.isPending}
            >
              Générer un code
            </Button>
          </div>
        </div>
      )}

      {/* ML-DSA-65 Security info */}
      <div style={{
        ...card,
        background: 'var(--accent-muted)',
        border: '1px solid var(--accent)',
        display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
        padding: 'var(--space-4)',
      }}>
        <Shield size={20} style={{ color: 'var(--accent)', flexShrink: 0 }} />
        <div>
          <p style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)', fontWeight: 600, margin: 0 }}>
            Sécurité Post-Quantique ML-DSA-65
          </p>
          <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)', margin: 'var(--space-1) 0 0' }}>
            Tous les transferts et synchronisations sont signés avec ML-DSA-65 (Dilithium) pour garantir l'intégrité et l'authenticité des données.
          </p>
        </div>
      </div>

      {/* Trusted peers with sync controls */}
      <div style={card}>
        <h3 style={{ color: 'var(--text-primary)', fontSize: 'var(--text-base)', margin: '0 0 var(--space-4)', display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
          <Fingerprint size={16} style={{ color: 'var(--accent)' }} /> Pairs de confiance
        </h3>
        {isLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 'var(--space-6)' }}><Spinner size={24} /></div>
        ) : peers.length === 0 ? (
          <EmptyState icon={Users} title="Aucun pair de confiance" description="Scannez le réseau et ajoutez des pairs, ou effectuez un transfert réussi" />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
            {peers.map(p => (
              <div key={p.fingerprint} style={{
                padding: '12px 14px', borderRadius: 'var(--radius-md)', background: 'var(--bg-elevated)',
              }}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="min-w-0 flex-1 w-full">
                    <div style={{ color: 'var(--text-primary)', fontSize: 'var(--text-sm)', fontWeight: 500 }} className="break-all">{p.name}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', fontFamily: 'var(--font-mono)', marginTop: 2 }} className="break-all">{p.fingerprint}</div>
                    <div style={{ color: 'var(--text-muted)', fontSize: 'var(--text-xs)', marginTop: 2 }}>
                      {p.transfer_count} transfert(s) · Vu {new Date(p.last_seen).toLocaleDateString('fr-FR')}
                    </div>
                  </div>
                  <div className="flex gap-2 items-center justify-end sm:justify-start w-full sm:w-auto">
                    <Button variant="ghost" size="sm" icon={Trash2} onClick={() => {
                      if (confirm(`Révoquer la confiance de ${p.name} ?`)) revokeMut.mutate(p.fingerprint)
                    }} />
                  </div>
                </div>
                {/* Sync toggle */}
                <div style={{
                  marginTop: 'var(--space-3)', paddingTop: 'var(--space-3)',
                  borderTop: '1px solid var(--border)',
                }} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <RefreshCw size={14} style={{ color: syncEnabled[p.fingerprint] ? 'var(--accent)' : 'var(--text-muted)' }} />
                    <span style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-xs)' }}>
                      Synchronisation automatique
                    </span>
                  </div>
                  <button
                    onClick={() => toggleSync(p.fingerprint)}
                    style={{
                      width: 36, height: 20, borderRadius: 10, border: 'none', cursor: 'pointer',
                      background: syncEnabled[p.fingerprint] ? 'var(--accent)' : 'var(--bg-input)',
                      position: 'relative', transition: 'background 0.2s',
                    }}
                    className="self-end sm:self-auto"
                  >
                    <div style={{
                      width: 16, height: 16, borderRadius: '50%', background: 'white',
                      position: 'absolute', top: 2,
                      left: syncEnabled[p.fingerprint] ? 18 : 2,
                      transition: 'left 0.2s',
                    }} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

/* ─── Helpers ─── */
function formatSize(bytes: number): string {
  if (bytes === 0) return '0 o'
  const units = ['o', 'Ko', 'Mo', 'Go']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`
}

/* ─── TransferPage ─── */
export default function TransferPage() {
  const [tab, setTab] = useState<Tab>('send')
  // Shared sender state: items selected in Send tab, used in Peers tab
  const [pendingItems, setPendingItems] = useState<{ type: string; ids: number[] } | null>(null)

  const tabs: { key: Tab; label: string; icon: typeof Send }[] = [
    { key: 'send', label: 'Envoyer', icon: Send },
    { key: 'receive', label: 'Recevoir', icon: Download },
    { key: 'peers', label: 'Pairs', icon: Users },
  ]

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-3)' }} className="page-header">
          <div>
            <h1 style={{
              fontFamily: 'var(--font-display)',
              fontSize: 'var(--text-3xl)',
              color: 'var(--text-primary)',
              display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
              margin: 0,
            }}>
              <ArrowLeftRight size={28} style={{ color: 'var(--accent)' }} />
              Vault Secure Transfer
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginTop: 'var(--space-1)' }}>
              Transfert P2P chiffré end-to-end · Post-Quantum
            </p>
          </div>
          <SecurityBadge method="PQC ML-KEM-768 + SPAKE2" />
        </div>

        {/* Tabs */}
        <div style={{ background: 'var(--bg-surface)', padding: 4, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }} className="flex gap-1 w-full">
          {tabs.map(t => {
            const active = tab === t.key
            const Icon = t.icon
            return (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                style={{
                  border: 'none',
                  borderRadius: 'var(--radius-sm)',
                  background: active ? 'var(--bg-elevated)' : 'transparent',
                  color: active ? 'var(--text-primary)' : 'var(--text-muted)',
                  fontFamily: 'var(--font-body)',
                  fontWeight: active ? 500 : 400,
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                }}
                className="flex-1 flex items-center justify-center gap-2 py-2.5 px-3 text-xs sm:text-sm"
              >
                <Icon size={16} />
                <span className="hidden min-[380px]:inline">{t.label}</span>
              </button>
            )
          })}
        </div>

        {/* Tab content */}
        <div className="animate-fade-in">
          {tab === 'send' && <WormholeSend onItemsSelected={(type, ids) => { setPendingItems({ type, ids }); setTab('peers') }} />}
          {tab === 'receive' && <WormholeReceive />}
          {tab === 'peers' && <TrustedPeers pendingItems={pendingItems} onClearPending={() => setPendingItems(null)} />}
        </div>
      </div>
    </AppShell>
  )
}

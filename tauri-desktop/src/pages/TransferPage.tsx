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

/* ─── Shared Helpers ─── */

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
    <div className="flex flex-col gap-5">
      {/* Type selector (Segmented Control) */}
      <div className="flex p-1 bg-input rounded-xl border border-bd">
        {[
          { key: 'passwords', label: 'Mots de passe', icon: KeyRound },
          { key: 'files', label: 'Fichiers', icon: Files },
          { key: 'keys', label: 'Clés', icon: Lock },
        ].map(t => {
          const Icon = t.icon
          const isSelected = selectedType === t.key
          return (
            <button
              key={t.key}
              onClick={() => { setSelectedType(t.key); setSelectedIds([]) }}
              className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-sm font-medium transition-all duration-200 ${
                isSelected ? 'bg-surface shadow-sm text-tx-primary' : 'text-tx-secondary hover:text-tx-primary'
              }`}
            >
              <Icon size={16} className={isSelected ? 'text-accent' : 'text-tx-muted'} />
              <span className="hidden sm:inline">{t.label}</span>
            </button>
          )
        })}
      </div>

      {/* Item list */}
      <div className="bg-surface border border-bd rounded-xl p-2 max-h-[300px] overflow-y-auto">
        {items.length === 0 ? (
          <p className="text-tx-muted text-center py-6 text-sm font-body">Aucun élément disponible</p>
        ) : (
          <div className="flex flex-col gap-1">
            {items.map((item: any) => {
              const id = item.id as number
              const name = item.title || item.filename || item.key_name || '—'
              const selected = selectedIds.includes(id)
              return (
                <div
                  key={id}
                  onClick={() => toggleItem(id)}
                  className={`flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-all duration-150 border ${
                    selected ? 'bg-accent-muted border-accent text-accent-text' : 'border-transparent hover:bg-elevated'
                  }`}
                >
                  <div className={`w-5 h-5 rounded flex items-center justify-center border-2 transition-colors ${
                    selected ? 'bg-accent border-accent text-white' : 'border-tx-muted'
                  }`}>
                    {selected && <Check size={14} />}
                  </div>
                  <span className={`text-sm font-medium font-body truncate ${selected ? 'text-tx-primary' : 'text-tx-secondary'}`}>{name}</span>
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
      <div className="bg-surface border border-bd rounded-xl p-6 flex flex-col gap-5 text-center">
        <ShieldCheck size={48} className="text-success mx-auto" />
        <p className="text-tx-primary font-semibold text-lg">Données reçues !</p>
        <Button variant="secondary" onClick={resetState}>Recevoir un autre transfert</Button>
      </div>
    )
  }

  // Failed
  if (receiveStatus === 'failed') {
    return (
      <div className="bg-surface border border-bd rounded-xl p-6 flex flex-col gap-5 text-center">
        <ShieldAlert size={48} className="text-danger mx-auto" />
        <p className="text-tx-primary font-semibold">Réception échouée</p>
        <Button variant="secondary" onClick={resetState}>Réessayer</Button>
      </div>
    )
  }

  // Transferring
  if (receiveStatus === 'transferring') {
    return (
      <div className="bg-surface border border-bd rounded-xl p-6 flex flex-col gap-5 items-center">
        <Loader2 size={36} className="text-accent animate-spin" />
        <p className="text-tx-primary font-medium">Réception en cours…</p>
        {connection && <SecurityBadge method={connection.connection_method} />}
      </div>
    )
  }

  // Confirming
  if (connection && receiveStatus === 'confirming') {
    return (
      <div className="flex flex-col gap-5">
        <SecurityBadge method={connection.connection_method} />

        {/* Safety number */}
        <div className="bg-warning-muted border border-warning rounded-xl p-6 text-center shadow-[inset_0_0_20px_rgba(245,158,11,0.05)]">
          <ShieldAlert size={28} className="text-warning mx-auto mb-3" />
          <p className="text-tx-primary font-semibold">Vérifiez le Safety Number</p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-5 my-5 bg-surface/50 p-4 rounded-xl border border-warning/20">
            <SafetyIdenticon value={connection.safety_number || ''} />
            <p className="font-mono text-2xl text-tx-primary tracking-[0.2em] font-medium">
              {connection.safety_number}
            </p>
          </div>
          <p className="text-tx-secondary text-sm">
            Comparez le code <strong>et</strong> le motif coloré : chaque couleur doit être à la <strong>même position</strong> sur les deux appareils
          </p>
        </div>

        {/* Peer info */}
        <div className="bg-surface border border-bd rounded-xl p-5">
          <p className="text-tx-secondary text-sm">
            Pair : <strong className="text-tx-primary">{connection.peer_name}</strong>
          </p>
          {connection.items.length > 0 && (
            <p className="text-tx-secondary text-sm mt-2">
              {connection.items.length} élément(s) — {formatSize(connection.total_size)}
            </p>
          )}
        </div>

        <div className="flex flex-col sm:flex-row gap-3 w-full">
          <Button icon={ShieldCheck} onClick={() => confirmMut.mutate(true)} loading={confirmMut.isPending} className="flex-1 w-full">
            Confirmer et recevoir
          </Button>
          <Button variant="danger" icon={X} onClick={() => confirmMut.mutate(false)} className="flex-1 w-full">
            Refuser
          </Button>
        </div>
      </div>
    )
  }

  // Idle
  return (
    <div className="flex flex-col gap-4">
      <div>
        <span className="text-sm text-tx-secondary mb-2 block font-medium">Code Wormhole reçu du sender</span>
        <input
          type="text"
          value={code}
          onChange={e => setCode(e.target.value)}
          placeholder="ex: 42-alpha-beacon-drift"
          className="w-full px-4 py-3 bg-input border border-bd rounded-lg text-tx-primary font-mono text-base outline-none focus:border-accent transition-colors tracking-wide"
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
  
  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full w-fit border ${isSecure ? 'bg-success-muted border-success/30 text-success' : 'bg-warning-muted border-warning/30 text-warning'}`}>
      {isSecure ? <ShieldCheck size={16} /> : <WifiOff size={16} />}
      <span className="text-xs font-medium">{method}</span>
      <Shield size={14} className="ml-1 opacity-70" />
      <span className="text-xs opacity-90">E2E PQC</span>
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
      <div className="bg-surface border border-bd rounded-xl p-6 flex flex-col gap-5 text-center">
        <ShieldCheck size={48} className="text-success mx-auto" />
        <p className="text-tx-primary font-semibold text-lg">Transfert terminé !</p>
        <Button variant="secondary" onClick={resetSenderFlow}>Nouveau transfert</Button>
      </div>
    )
  }

  if (offer && transferStatus === 'failed') {
    return (
      <div className="bg-surface border border-bd rounded-xl p-6 flex flex-col gap-5 text-center">
        <ShieldAlert size={48} className="text-danger mx-auto" />
        <p className="text-tx-primary font-semibold">Transfert échoué</p>
        <Button variant="secondary" onClick={resetSenderFlow}>Réessayer</Button>
      </div>
    )
  }

  if (offer && transferStatus === 'transferring') {
    return (
      <div className="bg-surface border border-bd rounded-xl p-6 flex flex-col gap-5 items-center">
        <Loader2 size={36} className="text-accent animate-spin" />
        <p className="text-tx-primary font-medium">Transfert en cours…</p>
        <SecurityBadge method={offer.connection_method} />
      </div>
    )
  }

  // Safety number confirmation (sender side)
  if (offer && safetyNumber && transferStatus === 'confirming') {
    return (
      <div className="flex flex-col gap-5">
        <SecurityBadge method={offer.connection_method} />
        <div className="bg-warning-muted border border-warning rounded-xl p-6 text-center shadow-[inset_0_0_20px_rgba(245,158,11,0.05)]">
          <ShieldAlert size={28} className="text-warning mx-auto mb-3" />
          <p className="text-tx-primary font-semibold">Vérifiez le Safety Number</p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-5 my-5 bg-surface/50 p-4 rounded-xl border border-warning/20">
            <SafetyIdenticon value={safetyNumber} />
            <p className="font-mono text-2xl text-tx-primary tracking-[0.2em] font-medium">
              {safetyNumber}
            </p>
          </div>
          <p className="text-tx-secondary text-sm">
            Comparez le code <strong>et</strong> le motif coloré : chaque couleur doit être à la <strong>même position</strong> sur les deux appareils
          </p>
          {peerName && (
            <p className="text-tx-muted text-xs mt-3 bg-surface/50 p-2 rounded-lg inline-block">
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
      <div className="bg-surface border border-bd rounded-xl p-6 flex flex-col gap-5">
        <div className="flex items-center gap-3">
          <Radio size={20} className="text-accent animate-pulse" />
          <span className="text-tx-primary font-medium">En attente du destinataire…</span>
        </div>
        <div>
          <span className="text-sm text-tx-secondary mb-2 block font-medium">Code Wormhole — partagez-le avec le destinataire</span>
          <div className="bg-input border border-bd rounded-lg p-4 font-mono text-xl text-center tracking-[0.15em] text-accent-text select-all shadow-inner">
            {offer.wormhole_code}
          </div>
          <p className="text-tx-muted text-xs mt-3 text-center">
            Le destinataire doit saisir ce code dans l'onglet « Recevoir »
          </p>
        </div>
        <div className="flex flex-col sm:flex-row gap-3">
          <Button variant="secondary" icon={copied ? Check : Copy} onClick={handleCopy} className="flex-1">
            {copied ? 'Copié !' : 'Copier le code'}
          </Button>
          <Button variant="danger" icon={X} onClick={() => { cancelMut.mutate(offer.transfer_id); resetSenderFlow() }} className="flex-1">
            Annuler
          </Button>
        </div>
        <SecurityBadge method={offer.connection_method} />
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Visibility toggle */}
      <div className={`flex items-center justify-between p-4 sm:p-5 rounded-xl border transition-colors ${isVisible ? 'bg-success-muted border-success/30' : 'bg-surface border-bd'}`}>
        <div className="flex items-center gap-3">
          {isVisible
            ? <Wifi size={20} className="text-success shrink-0" />
            : <WifiOff size={20} className="text-tx-muted shrink-0" />
          }
          <div>
            <div className={`text-sm font-semibold ${isVisible ? 'text-success' : 'text-tx-primary'}`}>
              {isVisible ? 'Visible sur le réseau' : 'Masqué du réseau'}
            </div>
            <div className={`text-xs mt-0.5 ${isVisible ? 'text-success/80' : 'text-tx-secondary'}`}>
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
          className={`relative w-11 h-6 rounded-full transition-colors focus:outline-none ${visibilityMut.isPending ? 'opacity-60' : ''} ${isVisible ? 'bg-success' : 'bg-input border border-bd'}`}
        >
          <div className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform shadow-sm ${isVisible ? 'translate-x-5' : 'translate-x-0'}`} />
        </button>
      </div>

      {/* Pending items banner */}
      {pendingItems && !offer && (
        <div className="bg-accent-muted border border-accent rounded-xl p-4 flex items-center gap-3">
          <Send size={18} className="text-accent shrink-0" />
          <div className="flex-1">
            <p className="text-tx-primary text-sm font-semibold m-0">
              {pendingItems.ids.length} élément(s) sélectionné(s)
            </p>
            <p className="text-tx-secondary text-xs mt-1 mb-0">
              Choisissez un destinataire ci-dessous pour lancer le transfert
            </p>
          </div>
          <Button variant="ghost" size="sm" icon={X} onClick={resetSenderFlow}>Annuler</Button>
        </div>
      )}

      {/* Discovered on network */}
      <div className="bg-surface border border-bd rounded-xl p-5 sm:p-6">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-tx-primary text-base font-semibold m-0 flex items-center gap-2">
            <Wifi size={16} className="text-accent" /> Réseau local
          </h3>
          <Button variant="ghost" size="sm" icon={RefreshCw} onClick={() => rescan()} loading={isScanning}>
            Scanner
          </Button>
        </div>
        {discovered.length === 0 ? (
          <div className="text-center p-4 flex flex-col items-center gap-3">
            {isScanning && <SonarScanner />}
            <p className="text-tx-muted text-sm m-0">
              {isScanning ? 'Recherche de pairs sur le réseau…' : 'Aucun pair détecté sur le réseau'}
            </p>
            <p className="text-tx-muted text-xs mt-2 mb-0">
              Assurez-vous que l'autre appareil est sur le même réseau Wi-Fi
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {discovered.map((p, i) => (
              
              
                <div key={i} className="px-3 py-2.5 rounded-lg bg-elevated border border-transparent transition-all duration-150 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:border-bd/50">
                  <div className="flex items-center gap-2 flex-1 min-w-0 w-full">
                    <Radio size={14} className="text-accent shrink-0" />
                    <div className="min-w-0 flex-1">
                      <span className="text-tx-primary text-sm font-medium break-all">{p.name}</span>
                      <div className="flex flex-wrap gap-2 items-center mt-1">
                        <Badge variant="info" size="sm">{p.method}</Badge>
                        <span className="text-tx-muted text-xs font-mono break-all">{p.addr}</span>
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
        <div className="bg-surface border border-dashed border-bd rounded-xl p-4 flex flex-col gap-3">
          <div className="flex items-center gap-3 flex-wrap">
            <Globe size={18} className="text-tx-secondary shrink-0 hidden sm:block" />
            <div className="flex-1 min-w-[200px]">
              <p className="text-tx-primary text-sm font-semibold m-0">
                Envoyer à distance
              </p>
              <p className="text-tx-secondary text-xs mt-1 mb-0">
                Destinataire sur un autre réseau ? Générez un code à partager
              </p>
            </div>
            <Button
              variant="secondary"
              size="sm"
              icon={Send}
              onClick={() => createOfferMut.mutate(true)}
              loading={createOfferMut.isPending}
              className="w-full sm:w-auto"
            >
              Générer un code
            </Button>
          </div>
        </div>
      )}

      {/* ML-DSA-65 Security info */}
      <div className="bg-accent-muted border border-accent rounded-xl p-4 flex items-start sm:items-center gap-3">
        <Shield size={20} className="text-accent shrink-0 mt-0.5 sm:mt-0" />
        <div>
          <p className="text-tx-primary text-sm font-semibold m-0">
            Sécurité Post-Quantique ML-DSA-65
          </p>
          <p className="text-tx-secondary text-xs mt-1 mb-0">
            Tous les transferts et synchronisations sont signés avec ML-DSA-65 (Dilithium) pour garantir l'intégrité et l'authenticité des données.
          </p>
        </div>
      </div>

      {/* Trusted peers with sync controls */}
      <div className="bg-surface border border-bd rounded-xl p-5 sm:p-6">
        <h3 className="text-tx-primary text-base font-semibold m-0 mb-4 flex items-center gap-2">
          <Fingerprint size={16} className="text-accent" /> Pairs de confiance
        </h3>
        {isLoading ? (
          <div className="flex justify-center p-6"><Spinner size={24} /></div>
        ) : peers.length === 0 ? (
          <EmptyState icon={Users} title="Aucun pair de confiance" description="Scannez le réseau et ajoutez des pairs, ou effectuez un transfert réussi" />
        ) : (
          <div className="flex flex-col gap-3">
            {peers.map(p => (
              <div key={p.fingerprint} className="p-3.5 rounded-xl bg-elevated border border-bd/50">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="min-w-0 flex-1 w-full">
                    <div className="text-tx-primary text-sm font-semibold break-all">{p.name}</div>
                    <div className="text-tx-muted text-xs font-mono mt-1 break-all">{p.fingerprint}</div>
                    <div className="text-tx-muted text-xs mt-1">
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
                <div className="mt-3 pt-3 border-t border-bd/50 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <RefreshCw size={14} className={syncEnabled[p.fingerprint] ? 'text-accent' : 'text-tx-muted'} />
                    <span className="text-tx-secondary text-xs font-medium">
                      Synchronisation automatique
                    </span>
                  </div>
                  <button
                    onClick={() => toggleSync(p.fingerprint)}
                    className={`relative w-9 h-5 rounded-full transition-colors focus:outline-none self-end sm:self-auto ${syncEnabled[p.fingerprint] ? 'bg-accent' : 'bg-input border border-bd'}`}
                  >
                    <div className={`absolute top-[2px] left-[2px] w-4 h-4 bg-white rounded-full transition-transform shadow-sm ${syncEnabled[p.fingerprint] ? 'translate-x-[16px]' : 'translate-x-0'}`} />
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
      <div className="page-content flex flex-col gap-6 w-full max-w-4xl mx-auto pb-24 md:pb-6">
        {/* Header */}
        <div className="page-header flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h1 className="font-display text-2xl sm:text-3xl text-tx-primary flex items-center gap-3 m-0">
              <ArrowLeftRight size={28} className="text-accent" />
              Vault Secure Transfer
            </h1>
            <p className="text-tx-secondary text-sm mt-1">
              Transfert P2P chiffré end-to-end · Post-Quantum
            </p>
          </div>
          <SecurityBadge method="PQC ML-KEM-768 + SPAKE2" />
        </div>

        {/* Tabs */}
        <div className="bg-surface p-1 rounded-xl border border-bd flex gap-1 w-full">
          {tabs.map(t => {
            const active = tab === t.key
            const Icon = t.icon
            return (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`flex-1 flex items-center justify-center gap-2 py-2.5 px-3 text-xs sm:text-sm rounded-lg font-body transition-all duration-200 ${
                  active ? 'bg-elevated text-tx-primary font-medium shadow-sm' : 'bg-transparent text-tx-muted hover:text-tx-secondary'
                }`}
              >
                <Icon size={16} />
                <span className="hidden min-[380px]:inline">{t.label}</span>
              </button>
            )
          })}
        </div>

        {/* Tab content */}
        <div className="animate-fade-in w-full">
          {tab === 'send' && <WormholeSend onItemsSelected={(type, ids) => { setPendingItems({ type, ids }); setTab('peers') }} />}
          {tab === 'receive' && <WormholeReceive />}
          {tab === 'peers' && <TrustedPeers pendingItems={pendingItems} onClearPending={() => setPendingItems(null)} />}
        </div>
      </div>
    </AppShell>
  )
}

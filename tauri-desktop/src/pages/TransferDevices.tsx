import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Eye, EyeOff, RefreshCw, Smartphone, Trash2 } from 'lucide-react'
import { Button, Input } from '../design-system/atoms'
import { transfer, type SyncPairingOffer } from '../lib/vault-service'
import { TemporaryCode } from './TemporaryCode'

export function TransferDevices({ active, disabled }: { active: boolean; disabled: boolean }) {
  const client = useQueryClient()
  const [mode, setMode] = useState<'generate' | 'join'>()
  const [crossNetwork, setCrossNetwork] = useState(false)
  const [joinCode, setJoinCode] = useState('')
  const [offer, setOffer] = useState<SyncPairingOffer>()
  const [joinedName, setJoinedName] = useState('')
  const sync = useQuery({
    queryKey: ['sync-settings'],
    queryFn: transfer.getSyncSettings,
    enabled: active,
    refetchInterval: (query) => query.state.data?.enabled ? 15000 : false,
  })
  const canPair = !disabled && sync.isSuccess

  function refreshLists() {
    void client.invalidateQueries({ queryKey: ['sync-settings'] })
    void client.invalidateQueries({ queryKey: ['trustedPeers'] })
  }

  const pairing = useQuery({
    queryKey: ['pairing-status', offer?.pairing_id],
    queryFn: async () => {
      const status = await transfer.getStatus(offer!.pairing_id)
      if (status?.state === 'Completed') refreshLists()
      return status
    },
    enabled: !!offer,
    retry: 1,
    refetchInterval: (query) => {
      const state = query.state.data?.state
      return state === 'Completed' || (typeof state === 'object' && 'Failed' in state) ? false : 1200
    },
  })
  const start = useMutation({
    mutationFn: () => transfer.startSyncPairing(crossNetwork),
    onSuccess: setOffer,
  })
  const join = useMutation({
    mutationFn: () => transfer.joinSyncPairing(joinCode.trim()),
    onSuccess: (result) => {
      if (result.success) {
        setJoinedName(result.device_name || 'Nouvel appareil')
        setJoinCode('')
        refreshLists()
      }
    },
  })
  const cancel = useMutation({
    mutationFn: () => transfer.cancel(offer!.pairing_id),
    onSuccess: reset,
  })
  const remove = useMutation({
    mutationFn: transfer.removeSyncDevice,
    onSuccess: refreshLists,
  })

  function reset() {
    setMode(undefined)
    setJoinedName('')
    setOffer(undefined)
    setJoinCode('')
    start.reset()
    join.reset()
    cancel.reset()
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!canPair) return
    if (mode === 'generate' && !start.isPending) start.mutate()
    if (mode === 'join' && joinCode.trim() && !join.isPending) join.mutate()
  }

  const paired = joinedName || (pairing.data?.state === 'Completed' ? pairing.data.peer_name || 'Nouvel appareil' : '')
  const status = pairing.data?.state
  const pairingFailed = typeof status === 'object' && 'Failed' in status ? status.Failed.reason : ''
  const error = pairingFailed || (join.data?.success === false ? 'Appairage refusé.' : '')
    || (start.error || join.error || cancel.error || pairing.error ? String(start.error || join.error || cancel.error || pairing.error) : '')

  return (
    <div className="workspace-stack">
      <section className="workspace-panel workspace-stack" aria-labelledby="pair-devices">
        <div>
          <h2 id="pair-devices">Appairer deux appareils</h2>
          <p>Ce jumelage échange les listes signées de pairs de confiance. Les deux appareils doivent utiliser une version compatible de FluXlock.</p>
        </div>
        {paired ? (
          <div className="workspace-stack" role="status">
            <p><strong>{paired}</strong> est appairé. Les listes de confiance ont été échangées.</p>
            <div><Button variant="secondary" onClick={reset}>Terminer</Button></div>
          </div>
        ) : offer ? (
          <div className="workspace-stack">
            {pairingFailed ? <div><Button variant="secondary" onClick={reset}>Recommencer</Button></div> : <>
              <p>Sur l’autre appareil, choisissez <strong>Saisir un code d’appairage</strong>.</p>
              <TemporaryCode code={offer.wormhole_code} />
              <div className="workspace-actions">
                <p className="workspace-label" role="status">En attente de l’autre appareil</p>
                <Button variant="secondary" loading={cancel.isPending} onClick={() => cancel.mutate()}>Annuler l’appairage</Button>
              </div>
            </>}
          </div>
        ) : mode ? (
          <form onSubmit={submit} className="workspace-stack">
            {mode === 'generate' ? (
              <label className="workspace-choice"><input type="checkbox" checked={crossNetwork}
                onChange={(event) => setCrossNetwork(event.target.checked)} />
                L’autre appareil se trouve sur un réseau différent
              </label>
            ) : (
              <Input label="Code d’appairage" value={joinCode} required autoComplete="off" autoCapitalize="none" spellCheck={false}
                onChange={(event) => setJoinCode(event.target.value)} disabled={join.isPending} />
            )}
            <div className="workspace-actions">
              <Button type="submit" loading={start.isPending || join.isPending}
                disabled={!canPair || (mode === 'join' && !joinCode.trim())}>
                {mode === 'generate' ? 'Créer le code d’appairage' : 'Rejoindre l’appairage'}
              </Button>
              <Button variant="secondary" onClick={reset} disabled={start.isPending || join.isPending}>Retour</Button>
            </div>
          </form>
        ) : (
          <div className="workspace-actions">
            <Button onClick={() => setMode('generate')} disabled={!canPair}>Créer un code d’appairage</Button>
            <Button variant="secondary" onClick={() => setMode('join')} disabled={!canPair}>Saisir un code d’appairage</Button>
          </div>
        )}
        {error && !paired && <p role="alert" className="workspace-error">{error}</p>}
      </section>

      <section className="workspace-panel workspace-stack" aria-labelledby="paired-list">
        <h2 id="paired-list">Appareils appairés</h2>
        {sync.isPending ? <p role="status">Chargement des appareils…</p> : sync.isError ? (
          <div className="workspace-actions"><p role="alert">Impossible de lire le registre.</p>
            <Button variant="secondary" onClick={() => void sync.refetch()}>Réessayer</Button></div>
        ) : !sync.data?.devices.length ? <p className="workspace-empty">Aucun appareil appairé sur ce coffre.</p> : (
          <ul className="workspace-list">
            {sync.data.devices.map((device) => (
              <li key={device.verifying_key} className="workspace-row">
                <Smartphone size={19} aria-hidden="true" />
                <div className="workspace-row-copy"><strong>{device.name}</strong>
                  <span>{device.last_sync ? `Dernier échange le ${new Date(device.last_sync).toLocaleDateString('fr-FR')}` : 'Appareil appairé'}</span>
                </div>
                <Button variant="secondary" icon={Trash2} disabled={remove.isPending}
                  onClick={() => {
                    if (confirm(`Retirer « ${device.name} » des appareils appairés ?`)) remove.mutate(device.verifying_key)
                  }}>Retirer</Button>
              </li>
            ))}
          </ul>
        )}
        {remove.isError && <p className="workspace-error" role="alert">{String(remove.error)}</p>}
      </section>

      <LocalDiscovery disabled={disabled} />
    </div>
  )
}

function LocalDiscovery({ disabled }: { disabled: boolean }) {
  const client = useQueryClient()
  const [opened, setOpened] = useState(false)
  const visibility = useQuery({ queryKey: ['transferVisibility'], queryFn: transfer.getVisibility, enabled: opened })
  const scan = useQuery({ queryKey: ['discoveredPeers'], queryFn: transfer.scanLocalNetwork, enabled: false })
  const trusted = useQuery({ queryKey: ['trustedPeers'], queryFn: transfer.getTrustedPeers, enabled: opened })
  const action = useMutation({
    mutationFn: (visible: boolean) => transfer.setVisibility(visible),
    onSuccess: (visible) => client.setQueryData(['transferVisibility'], visible),
  })
  const revoke = useMutation({
    mutationFn: transfer.revokeTrust,
    onSuccess: () => client.invalidateQueries({ queryKey: ['trustedPeers'] }),
  })

  return (
    <details className="workspace-panel workspace-details" onToggle={(event) => setOpened(event.currentTarget.open)}>
      <summary>Découverte et pairs de confiance</summary>
      <div className="workspace-stack">
        <div className="workspace-actions">
          <Button variant="secondary" icon={visibility.data ? EyeOff : Eye} disabled={disabled || !visibility.isSuccess}
            loading={action.isPending} onClick={() => action.mutate(!visibility.data)}>
            {visibility.data ? 'Masquer cet appareil' : 'Rendre cet appareil visible'}
          </Button>
          <Button variant="secondary" icon={RefreshCw} disabled={disabled}
            loading={scan.isFetching} onClick={() => void scan.refetch()}>Rechercher sur le réseau local</Button>
        </div>
        {(scan.isError || action.isError) && <p className="workspace-error" role="alert">{String(scan.error || action.error)}</p>}
        {scan.data && (scan.data.length ? (
          <ul className="workspace-list">{scan.data.map((peer) => <li className="workspace-row" key={`${peer.addr}:${peer.port}`}>
            <span className="workspace-row-copy"><strong>{peer.name}</strong><span>{peer.addr}</span></span>
          </li>)}</ul>
        ) : <p className="workspace-label" role="status">Aucun appareil détecté.</p>)}
        <h3>Pairs enregistrés</h3>
        {trusted.isError ? <p role="alert">Impossible de charger les pairs.</p> : trusted.data?.length ? (
          <ul className="workspace-list">{trusted.data.map((peer) => <li key={peer.fingerprint} className="workspace-row">
            <span className="workspace-row-copy"><strong>{peer.name}</strong><span>{peer.fingerprint}</span></span>
            <Button variant="secondary" disabled={revoke.isPending} onClick={() => {
              if (confirm(`Révoquer la confiance accordée à « ${peer.name} » ?`)) revoke.mutate(peer.fingerprint)
            }}>Révoquer</Button>
          </li>)}</ul>
        ) : trusted.isSuccess && <p className="workspace-label">Aucun pair de confiance enregistré.</p>}
        {revoke.isError && <p className="workspace-error" role="alert">{String(revoke.error)}</p>}
      </div>
    </details>
  )
}

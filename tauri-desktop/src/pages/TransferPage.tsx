import { useId, useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Check, Download, Files, KeyRound, Send, Smartphone } from 'lucide-react'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner } from '../design-system/atoms'
import {
  transfer, passwords, files, isolationMode, type TransferOffer, type TransferConnection,
} from '../lib/vault-service'
import { TransferDevices } from './TransferDevices'
import { TemporaryCode } from './TemporaryCode'

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error)
}

function sizeLabel(size: number) {
  return size >= 1024 * 1024 ? `${(size / (1024 * 1024)).toLocaleString('fr-FR', { maximumFractionDigits: 1 })} Mio`
    : size >= 1024 ? `${Math.round(size / 1024)} Kio` : `${size} octets`
}

function invalidateVault(client: ReturnType<typeof useQueryClient>) {
  void client.invalidateQueries({ queryKey: ['passwords'] })
  void client.invalidateQueries({ queryKey: ['secureFiles'] })
}

function Confirmation({
  number, peer, direction, pending, onConfirm, onReject, children,
}: {
  number: string
  peer?: string
  direction: 'envoyer' | 'recevoir'
  pending: boolean
  onConfirm: () => void
  onReject: () => void
  children?: React.ReactNode
}) {
  const headingId = useId()
  return (
    <section className="workspace-panel workspace-stack" aria-labelledby={headingId}>
      <h2 id={headingId}>Comparer le code de vérification</h2>
      {peer && <p className="workspace-label">Appareil distant · {peer}</p>}
      <p>Comparez la valeur affichée avec celle de l’autre appareil. Si les valeurs diffèrent, refusez le transfert.</p>
      <output className="verification-code">{number}</output>
      {children}
      <div className="workspace-actions">
        <Button icon={Check} loading={pending} disabled={!number} onClick={onConfirm}>
          Confirmer et {direction}
        </Button>
        <Button variant="secondary" disabled={pending} onClick={onReject}>Refuser</Button>
      </div>
    </section>
  )
}

function TransferOutcome({ success, onReset, receive, error }: {
  success: boolean
  onReset: () => void
  receive?: boolean
  error?: string
}) {
  return (
    <section className="workspace-panel workspace-stack" role={success ? 'status' : 'alert'}>
      <h2>{success ? (receive ? 'Données reçues' : 'Données envoyées') : 'Transfert interrompu'}</h2>
      {error && <p>{error}</p>}
      <div><Button variant="secondary" onClick={onReset}>{success ? 'Nouveau transfert' : 'Recommencer'}</Button></div>
    </section>
  )
}

type Kind = 'passwords' | 'files'
const MAX_FILE_BYTES = 32 * 1024 * 1024

function SendTransfer({ disabled }: { disabled: boolean }) {
  const client = useQueryClient()
  const [kind, setKind] = useState<Kind>('passwords')
  const [selected, setSelected] = useState<number[]>([])
  const [offer, setOffer] = useState<TransferOffer>()
  const [complete, setComplete] = useState(false)
  const [error, setError] = useState('')
  const [crossNetwork, setCrossNetwork] = useState(false)
  const passwordItems = useQuery({ queryKey: ['passwords'], queryFn: passwords.list, enabled: kind === 'passwords' })
  const fileItems = useQuery({ queryKey: ['secureFiles'], queryFn: files.list, enabled: kind === 'files' })
  const query = kind === 'passwords' ? passwordItems : fileItems
  const items = kind === 'passwords'
    ? (passwordItems.data ?? []).map((item) => ({ id: item.id, name: item.title, detail: item.username, allowed: true }))
    : (fileItems.data ?? []).map((item) => ({
      id: item.id, name: item.filename, detail: sizeLabel(item.file_size), allowed: item.file_size <= MAX_FILE_BYTES,
    }))
  const availableSelection = selected.filter((id) => items.some((item) => item.id === id && item.allowed))

  const status = useQuery({
    queryKey: ['transfer-status', offer?.transfer_id],
    queryFn: () => transfer.getStatus(offer!.transfer_id),
    enabled: !!offer && !complete && !error,
    refetchInterval: (query) => {
      const state = query.state.data?.state
      return state === 'Completed' || (typeof state === 'object' && 'Failed' in state) ? false : 1200
    },
    staleTime: 0,
    retry: 1,
  })

  function reset() {
    setOffer(undefined)
    setComplete(false)
    setSelected([])
    setError('')
    createOffer.reset()
    finish.reset()
  }

  const createOffer = useMutation({
    mutationFn: () => transfer.createOffer(kind, availableSelection, crossNetwork),
    onSuccess: setOffer,
  })
  const finish = useMutation({
    mutationFn: (accept: boolean) => accept
      ? transfer.confirmAndExecute(offer!.transfer_id, true)
      : transfer.cancel(offer!.transfer_id),
    onSuccess: (ok, accept) => {
      if (!accept) {
        reset()
      } else if (ok) {
        setComplete(true)
        invalidateVault(client)
      } else {
        setError('L’autre appareil a refusé le transfert.')
      }
    },
    onError: (reason, accept) => {
      if (accept) setError(errorMessage(reason))
    },
  })

  if (complete) return <TransferOutcome success onReset={reset} />
  const transferState = status.data?.state
  const remoteError = typeof transferState === 'object' && 'Failed' in transferState ? transferState.Failed.reason : ''
  if (remoteError || error) return <TransferOutcome success={false} error={remoteError || error} onReset={reset} />
  if (offer) {
    if (finish.isPending && finish.variables === true) {
      return <section className="workspace-panel workspace-stack" role="status">
        <h2>Envoi en cours</h2><p>Laissez les deux appareils connectés jusqu’à la confirmation.</p>
        <progress aria-label="Envoi en cours" />
      </section>
    }
    if (status.data?.safety_number) {
      return <Confirmation number={status.data.safety_number} peer={status.data.peer_name} direction="envoyer"
        pending={finish.isPending} onConfirm={() => finish.mutate(true)} onReject={() => finish.mutate(false)}>
        {finish.isError && <p role="alert" className="workspace-error">{errorMessage(finish.error)}</p>}
      </Confirmation>
    }
    return (
      <section className="workspace-panel workspace-stack">
        <h2>Transmettre le code temporaire</h2>
        <p>Sur l’autre appareil, ouvrez <strong>Transferts → Recevoir</strong> et saisissez ce code.</p>
        <TemporaryCode code={offer.wormhole_code} />
        <div className="workspace-actions">
          <p role="status" className="workspace-label"><Spinner size={15} /> En attente du destinataire</p>
          <Button variant="secondary" disabled={finish.isPending} onClick={() => finish.mutate(false)}>Annuler l’envoi</Button>
        </div>
        {(status.isError || finish.isError) && <p role="alert" className="workspace-error">
          {errorMessage(status.error || finish.error)}
        </p>}
      </section>
    )
  }

  return (
    <section className="workspace-panel workspace-stack" aria-labelledby="select-transfer-items">
      <h2 id="select-transfer-items">Éléments à envoyer</h2>
      <div className="workspace-segments transfer-types" role="group" aria-label="Type d’élément">
        <button type="button" aria-pressed={kind === 'passwords'} onClick={() => { setKind('passwords'); setSelected([]) }}>
          <KeyRound size={17} aria-hidden="true" /> Mots de passe
        </button>
        <button type="button" aria-pressed={kind === 'files'} onClick={() => { setKind('files'); setSelected([]) }}>
          <Files size={17} aria-hidden="true" /> Fichiers
        </button>
      </div>
      {query.isPending ? <p role="status">Chargement du coffre…</p> : query.isError ? (
        <div className="workspace-actions"><p role="alert">Impossible de charger les éléments.</p><Button variant="secondary" onClick={() => void query.refetch()}>Réessayer</Button></div>
      ) : items.length === 0 ? <p className="workspace-empty">Aucun élément de ce type dans votre coffre.</p> : (
        <ul className="workspace-list transfer-items">
          {items.map((item) => <li key={item.id}>
            <label className="workspace-row transfer-select">
              <input type="checkbox" checked={selected.includes(item.id)} disabled={!item.allowed || createOffer.isPending || disabled}
                onChange={(event) => setSelected(event.target.checked ? [...selected, item.id] : selected.filter((id) => id !== item.id))} />
              <span className="workspace-row-copy">
                <strong>{item.name}</strong>
                {item.detail && <span>{item.detail}{!item.allowed && ' · Limite de 32 Mio'}</span>}
              </span>
            </label>
          </li>)}
        </ul>
      )}
      <label className="workspace-choice">
        <input type="checkbox" checked={crossNetwork} onChange={(event) => setCrossNetwork(event.target.checked)} />
        L’autre appareil se trouve sur un réseau différent
      </label>
      {crossNetwork && <p className="workspace-label">La connexion directe nécessite une adresse IPv6 publique accessible depuis l’autre appareil.</p>}
      {createOffer.isError && <p className="workspace-error" role="alert">{errorMessage(createOffer.error)}</p>}
      <div className="workspace-actions">
        <Button iconRight={ArrowRight} onClick={() => createOffer.mutate()} loading={createOffer.isPending}
          disabled={!availableSelection.length || disabled}>Générer le code</Button>
        <span className="workspace-label">{availableSelection.length} sélectionné{availableSelection.length > 1 ? 's' : ''}</span>
      </div>
    </section>
  )
}

function ReceiveTransfer({ disabled }: { disabled: boolean }) {
  const client = useQueryClient()
  const [code, setCode] = useState('')
  const [connection, setConnection] = useState<TransferConnection>()
  const [complete, setComplete] = useState(false)
  const [failure, setFailure] = useState('')

  function reset() {
    setCode('')
    setConnection(undefined)
    setComplete(false)
    setFailure('')
    connect.reset()
    finish.reset()
  }

  const connect = useMutation({
    mutationFn: () => transfer.connect(code.trim()),
    onSuccess: (response) => { setCode(''); setConnection(response) },
  })
  const finish = useMutation({
    mutationFn: (accept: boolean) => transfer.confirmAndExecute(connection!.transfer_id, accept),
    onSuccess: (ok, accept) => {
      if (!accept) return reset()
      if (ok) {
        invalidateVault(client)
        setComplete(true)
      } else {
        setFailure('L’autre appareil a refusé le transfert.')
      }
    },
    onError: (reason, accept) => { if (accept) setFailure(errorMessage(reason)) },
  })

  if (complete || failure) return <TransferOutcome receive success={complete} error={failure} onReset={reset} />
  if (finish.isPending && finish.variables === true) {
    return <section className="workspace-panel workspace-stack" role="status">
      <h2>Réception en cours</h2><progress aria-label="Réception en cours" />
    </section>
  }
  if (connection) {
    return <Confirmation number={connection.safety_number} peer={connection.peer_name} direction="recevoir"
      pending={finish.isPending} onConfirm={() => finish.mutate(true)} onReject={() => finish.mutate(false)}>
      <p>{connection.items.length} élément{connection.items.length === 1 ? '' : 's'} à recevoir.</p>
      {finish.isError && <p role="alert" className="workspace-error">{errorMessage(finish.error)}</p>}
    </Confirmation>
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (code.trim() && !disabled && !connect.isPending) connect.mutate()
  }

  return (
    <form onSubmit={submit} className="workspace-panel workspace-stack">
      <h2>Ouvrir un transfert</h2>
      <p>Demandez à l’expéditeur le code temporaire généré sur son appareil.</p>
      <Input label="Code de transfert" value={code} onChange={(event) => setCode(event.target.value)}
        autoComplete="off" autoCapitalize="none" spellCheck={false} required disabled={connect.isPending || disabled} />
      {connect.isError && <p role="alert" className="workspace-error">{errorMessage(connect.error)}</p>}
      <div><Button icon={Download} type="submit" loading={connect.isPending} disabled={disabled || !code.trim()}>Rejoindre le transfert</Button></div>
    </form>
  )
}

const views = [
  { id: 'send', name: 'Envoyer', icon: Send },
  { id: 'receive', name: 'Recevoir', icon: Download },
  { id: 'devices', name: 'Appareils', icon: Smartphone },
] as const
type View = typeof views[number]['id']

export default function TransferPage() {
  const [params, setParams] = useSearchParams()
  const view = views.find(({ id }) => id === params.get('vue'))?.id ?? 'send'
  const [visited, setVisited] = useState<View[]>([view])
  const isolation = useQuery({ queryKey: ['isolation-mode'], queryFn: isolationMode.get, staleTime: 0 })
  const disabled = isolation.data === true

  return (
    <WorkspacePage title="Transférer des données" description="Échangez des fichiers et des identifiants entre vos appareils.">
      {disabled && <p className="workspace-error" role="status">Le mode isolation bloque les transferts et l’appairage.</p>}
      <nav aria-label="Parcours de transfert" className="workspace-segments transfer-modes">
        {views.map(({ id, name, icon: Icon }) => (
          <button key={id} type="button" aria-current={view === id ? 'page' : undefined} onClick={() => {
            setVisited((previous) => previous.includes(id) ? previous : [...previous, id])
            setParams(id === 'send' ? {} : { vue: id }, { replace: true })
          }}><Icon size={18} aria-hidden="true" />{name}</button>
        ))}
      </nav>
      {(visited.includes('send') || view === 'send') && <div hidden={view !== 'send'}><SendTransfer disabled={disabled} /></div>}
      {(visited.includes('receive') || view === 'receive') && <div hidden={view !== 'receive'}><ReceiveTransfer disabled={disabled} /></div>}
      {(visited.includes('devices') || view === 'devices') && <div hidden={view !== 'devices'}><TransferDevices active={view === 'devices'} disabled={disabled} /></div>}
    </WorkspacePage>
  )
}

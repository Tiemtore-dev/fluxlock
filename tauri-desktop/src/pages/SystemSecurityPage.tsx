import { useState, type FormEvent } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { invoke } from '@tauri-apps/api/core'
import { Unlock, RefreshCw } from 'lucide-react'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Input, Spinner, Badge } from '../design-system/atoms'
import { Modal } from '../design-system/molecules'
import { useToast } from '../design-system/organisms'

interface SecurityState {
  is_locked: boolean
  is_readonly: boolean
  threat_level: 'none' | 'low' | 'medium' | 'high' | 'critical'
  active_threats: string[]
}

interface FilesystemStats {
  total_events: number
  modifications: number
  creations: number
  deletions: number
  renames: number
  suspicious_extensions: number
  rapid_changes: number
  monitored_paths: string[]
  active_threats: string[]
  threat_level: string
  monitoring_enabled: boolean
}

const threatLabels: Record<string, string> = {
  none: 'Aucune menace signalée', low: 'Faible', medium: 'Modérée', high: 'Élevée', critical: 'Critique',
}

function ThreatBadge({ level }: { level: string }) {
  const name = level.toLowerCase()
  const variant = name === 'critical' || name === 'high' ? 'danger'
    : name === 'medium' || name === 'low' ? 'warning' : name === 'none' ? 'success' : 'info'
  return <Badge variant={variant}>{threatLabels[name] ?? level}</Badge>
}

export default function SystemSecurityPage() {
  const { toast } = useToast()
  const [showPwDialog, setShowPwDialog] = useState(false)
  const [password, setPassword] = useState('')
  const status = useQuery({ queryKey: ['vault-protection'], queryFn: () => invoke<SecurityState>('get_security_status'), refetchInterval: 5000 })
  const filesystem = useQuery({ queryKey: ['filesystem-protection'], queryFn: () => invoke<FilesystemStats>('get_filesystem_stats'), refetchInterval: 5000 })
  const sec = status.data
  const fs = filesystem.data

  const unlock = useMutation({
    mutationFn: () => invoke<string>('disable_readonly_mode', { password }),
    onSuccess: (message) => {
      setShowPwDialog(false)
      setPassword('')
      void status.refetch()
      toast(message, 'success')
    },
    onError: () => setPassword(''),
  })
  const monitor = useMutation({
    mutationFn: (enable: boolean) => invoke<string>(enable ? 'enable_filesystem_monitoring' : 'disable_filesystem_monitoring'),
    onSuccess: (message) => {
      void filesystem.refetch()
      toast(message, 'success')
    },
  })
  const counters = fs ? [
    { label: 'Événements', value: fs.total_events },
    { label: 'Modifications', value: fs.modifications },
    { label: 'Créations', value: fs.creations },
    { label: 'Suppressions', value: fs.deletions },
    { label: 'Renommages', value: fs.renames },
    { label: 'Extensions suspectes', value: fs.suspicious_extensions },
    { label: 'Modifications rapides', value: fs.rapid_changes },
  ] : []

  function closeDialog() {
    if (unlock.isPending) return
    setShowPwDialog(false)
    setPassword('')
    unlock.reset()
  }

  function confirmUnlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (password && !unlock.isPending) unlock.mutate()
  }

  return (
    <WorkspacePage title="Protection du coffre" description="Vérifiez le verrouillage, les menaces signalées et la surveillance locale des fichiers."
      actions={<>
        <Link className="workspace-link" to="/security">Journal de sécurité</Link>
        <Button variant="secondary" icon={RefreshCw} onClick={() => { void status.refetch(); void filesystem.refetch() }}>Actualiser</Button>
      </>}>
      <div className="workspace-columns">
        <section className="workspace-panel workspace-stack" aria-labelledby="vault-protection">
          <h2 id="vault-protection">État du coffre</h2>
          {status.isError && <p role="alert" className="workspace-error">Impossible de lire l’état du coffre.</p>}
          {status.isPending && <p role="status" className="workspace-label"><Spinner size={18} /> Chargement…</p>}
          {sec && <>
            <dl className="workspace-list">
              <div className="workspace-row"><dt className="workspace-row-copy">Niveau de menace</dt><dd><ThreatBadge level={sec.threat_level} /></dd></div>
              <div className="workspace-row"><dt className="workspace-row-copy">Verrouillage</dt><dd>{sec.is_locked ? 'Verrouillé' : 'Déverrouillé'}</dd></div>
              <div className="workspace-row"><dt className="workspace-row-copy">Lecture seule</dt><dd>{sec.is_readonly ? 'Activée' : 'Désactivée'}</dd></div>
            </dl>
            {sec.is_readonly && <div className="workspace-stack">
              <p role="status" className="workspace-danger">Les modifications sont bloquées sur ce coffre.</p>
              <div><Button variant="danger" icon={Unlock} onClick={() => setShowPwDialog(true)}>Désactiver la lecture seule</Button></div>
            </div>}
            {!!sec.active_threats.length && <div>
              <h3>Menaces actives</h3>
              <ul className="list-disc pl-5">{sec.active_threats.map((threat, index) => <li key={index}>{threat}</li>)}</ul>
            </div>}
          </>}
        </section>

        <section className="workspace-panel workspace-stack" aria-labelledby="file-monitoring">
          <h2 id="file-monitoring">Surveillance des fichiers</h2>
          {filesystem.isError && <p role="alert" className="workspace-error">Impossible de lire la surveillance.</p>}
          {filesystem.isPending && <p role="status" className="workspace-label"><Spinner size={18} /> Chargement…</p>}
          {fs && <>
            <div className="workspace-actions">
              <Badge variant={fs.monitoring_enabled ? 'success' : 'default'}>{fs.monitoring_enabled ? 'Active' : 'Désactivée'}</Badge>
              <Button variant="secondary" loading={monitor.isPending} onClick={() => {
                const enable = !fs.monitoring_enabled
                if (confirm(`${enable ? 'Activer' : 'Désactiver'} la surveillance ?`)) monitor.mutate(enable)
              }}>{fs.monitoring_enabled ? 'Désactiver la surveillance' : 'Activer la surveillance'}</Button>
            </div>
            {monitor.isError && <p className="workspace-error" role="alert">{String(monitor.error)}</p>}
            <div className="workspace-actions"><span>Niveau de menace</span><ThreatBadge level={fs.threat_level} /></div>
            <dl className="workspace-list">{counters.map(({ label, value }) => (
              <div className="workspace-row" key={label}><dt className="workspace-row-copy">{label}</dt><dd>{value.toLocaleString('fr-FR')}</dd></div>
            ))}</dl>
            {!!fs.active_threats.length && <ul className="list-disc pl-5">{fs.active_threats.map((threat, index) => <li key={index}>{threat}</li>)}</ul>}
            <details className="workspace-details">
              <summary>Dossiers surveillés ({fs.monitored_paths.length})</summary>
              {fs.monitored_paths.length ? <ul className="workspace-list">{fs.monitored_paths.map((path) => (
                <li className="workspace-row" key={path}><code className="workspace-row-copy">{path}</code></li>
              ))}</ul> : <p className="workspace-label">Aucun dossier surveillé.</p>}
            </details>
          </>}
        </section>
      </div>
      <Modal open={showPwDialog} onClose={closeDialog} title="Désactiver la lecture seule">
        <form className="workspace-stack" onSubmit={confirmUnlock}>
          <Input label="Mot de passe maître" type="password" autoComplete="current-password"
            value={password} required disabled={unlock.isPending} onChange={(event) => setPassword(event.target.value)} />
          {unlock.isError && <p className="workspace-error" role="alert">{String(unlock.error)}</p>}
          <div className="workspace-actions">
            <Button variant="secondary" onClick={closeDialog} disabled={unlock.isPending}>Annuler</Button>
            <Button type="submit" loading={unlock.isPending} disabled={!password}>Confirmer</Button>
          </div>
        </form>
      </Modal>
    </WorkspacePage>
  )
}

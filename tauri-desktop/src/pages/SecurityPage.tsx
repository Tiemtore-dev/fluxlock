import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { AlertTriangle, Activity, RefreshCw } from 'lucide-react'
import { WorkspacePage } from '../design-system/layouts'
import { Button, Badge, Spinner } from '../design-system/atoms'
import { security } from '../lib/vault-service'

const eventLabels: Record<string, string> = {
  anomaly: 'Anomalie détectée',
  login: 'Connexion',
  file_access: 'Accès à un fichier',
}

const severityLabels: Record<string, string> = {
  critical: 'Critique',
  warning: 'Avertissement',
  info: 'Information',
}

export default function SecurityPage() {
  const [showAlerts, setShowAlerts] = useState(false)
  const query = useQuery({ queryKey: ['securityEvents'], queryFn: security.getEvents, refetchInterval: 30_000 })
  const events = query.data ?? []
  const anomalies = events.filter((event) => event.event_type === 'anomaly' || event.severity === 'critical' || event.severity === 'warning')
  const visibleEvents = showAlerts ? anomalies : events

  return (
    <WorkspacePage title="Journal de sécurité" description="Consultez les événements et les alertes enregistrés sur cet appareil."
      actions={<>
        <Link className="workspace-link" to="/system-security">Protection du coffre</Link>
        <Button variant="secondary" icon={RefreshCw} loading={query.isRefetching} onClick={() => void query.refetch()}>Actualiser</Button>
      </>}>
      <section className="workspace-panel workspace-stack" aria-labelledby="security-events">
        <h2 id="security-events">Événements récents</h2>
        <div className="workspace-segments" role="group" aria-label="Type d’événement">
          <button type="button" aria-pressed={!showAlerts} onClick={() => setShowAlerts(false)}>Tous les événements</button>
          <button type="button" aria-pressed={showAlerts} onClick={() => setShowAlerts(true)}>Alertes ({anomalies.length})</button>
        </div>
        {query.isPending ? <p className="workspace-label" role="status"><Spinner size={18} /> Chargement…</p> : query.isError ? (
          <p className="workspace-error" role="alert">Impossible de lire le journal.</p>
        ) : !visibleEvents.length ? (
          <p className="workspace-empty">{showAlerts ? 'Aucune alerte enregistrée.' : 'Aucun événement enregistré.'}</p>
        ) : (
          <ol className="workspace-list">{visibleEvents.slice(0, 20).map((event) => (
            <li key={event.id} className="workspace-row">
              <span className="workspace-icon" aria-hidden="true">{event.event_type === 'anomaly' ? <AlertTriangle size={18} /> : <Activity size={18} />}</span>
              <div className="workspace-row-copy">
                <strong>{eventLabels[event.event_type] ?? event.event_type}</strong>
                <span>{event.description}</span>
                <span><time dateTime={event.timestamp}>{new Date(event.timestamp).toLocaleString('fr-FR')}</time>{event.ip_address && ` · ${event.ip_address}`}</span>
              </div>
              {event.severity && <Badge variant={event.severity === 'critical' ? 'danger' : event.severity === 'warning' ? 'warning' : 'info'}>
                {severityLabels[event.severity] ?? event.severity}
              </Badge>}
            </li>
          ))}</ol>
        )}
        {visibleEvents.length > 20 && <p className="workspace-label">Les 20 derniers événements de cette vue sont affichés.</p>}
      </section>
    </WorkspacePage>
  )
}

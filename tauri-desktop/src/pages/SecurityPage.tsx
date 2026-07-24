import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Shield, AlertTriangle, Activity, Clock, MapPin, Monitor,
  CheckCircle, RefreshCw,
} from 'lucide-react'
import { AppShell } from '../design-system'
import { Button, Badge, Spinner } from '../design-system'
import { EmptyState } from '../design-system'
import { useToast } from '../design-system'
import { security as secService, SecurityEvent } from '../lib/vault-service'

/* severity → design-system badge variant */
const sevBadge = (s?: string): 'danger' | 'warning' | 'info' => {
  if (s === 'critical') return 'danger'
  if (s === 'warning') return 'warning'
  return 'info'
}

const eventLabel = (t: string) =>
  t === 'anomaly' ? 'Anomalie détectée'
    : t === 'login' ? 'Connexion'
    : t === 'file_access' ? 'Accès fichier'
    : t

export default function SecurityPage() {
  const { toast } = useToast()
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const { data: events = [], isLoading, refetch } = useQuery({
    queryKey: ['securityEvents'],
    queryFn: secService.getEvents,
    refetchInterval: 30_000,
  })

  const anomalies = events.filter(e => e.event_type === 'anomaly')

  const handleAnalyze = async () => {
    setIsAnalyzing(true)
    try {
      await refetch()
      toast('Analyse de sécurité actualisée', 'success')
    } catch (error: any) {
      toast('Erreur lors de l\'analyse : ' + error?.toString(), 'error')
    } finally { setIsAnalyzing(false) }
  }

  /* ─── styles ─── */
  const card: React.CSSProperties = {
    background: 'var(--bg-elevated)', borderRadius: 'var(--radius-lg)',
    border: '1px solid var(--border)', padding: 'var(--space-6)',
  }
  const statNum: React.CSSProperties = {
    fontFamily: 'var(--font-body)', fontSize: 'var(--text-2xl)', fontWeight: 700, color: 'var(--text-primary)',
  }
  const statLabel: React.CSSProperties = {
    fontSize: 'var(--text-sm)', color: 'var(--text-muted)',
  }
  const rowStyle = (isAnomaly: boolean): React.CSSProperties => ({
    background: isAnomaly ? 'var(--danger-muted)' : 'var(--bg-surface)',
    borderRadius: 'var(--radius-md)', padding: 'var(--space-4)',
    borderLeft: `3px solid ${isAnomaly ? 'var(--danger)' : 'var(--border)'}`,
  })

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }} className="page-header">
          <div>
            <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)', margin: 0 }}>
              Sécurité
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: 'var(--text-sm)', marginTop: 'var(--space-1)' }}>
              Analyse comportementale et détection de menaces
            </p>
          </div>
          <Button onClick={handleAnalyze} disabled={isAnalyzing} icon={RefreshCw}>
            {isAnalyzing ? 'Analyse…' : 'Analyser'}
          </Button>
        </div>

        {/* Stats row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 'var(--space-4)' }}>
          {[
            { label: 'Événements normaux', value: events.length - anomalies.length, Icon: CheckCircle, color: 'var(--success)' },
            { label: 'Anomalies détectées', value: anomalies.length, Icon: AlertTriangle, color: 'var(--danger)' },
            { label: 'Total événements', value: events.length, Icon: Activity, color: 'var(--info)' },
            { label: 'Surveillance', value: 'Active', Icon: Shield, color: 'var(--accent)' },
          ].map(({ label, value, Icon, color }) => (
            <div key={label} style={card}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                <div style={{ padding: 'var(--space-3)', borderRadius: 'var(--radius-md)', background: `color-mix(in srgb, ${color} 15%, transparent)` }}>
                  <Icon size={20} style={{ color }} />
                </div>
                <div>
                  <p style={statLabel}>{label}</p>
                  <p style={statNum}>{value}</p>
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Events list */}
        <div style={card}>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', color: 'var(--text-primary)', fontWeight: 600, fontSize: 'var(--text-xl)', marginBottom: 'var(--space-4)' }}>
            <Shield size={20} /> Événements de sécurité récents
          </h2>

          {isLoading ? (
            <div style={{ textAlign: 'center', padding: 'var(--space-12)' }}><Spinner /></div>
          ) : events.length === 0 ? (
            <EmptyState icon={Shield} title="Aucun événement" description="Aucun événement de sécurité enregistré." />
          ) : (
            <div style={{ maxHeight: 400, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>
              {events.slice(0, 20).map(ev => (
                <div key={ev.id} style={rowStyle(ev.event_type === 'anomaly')}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
                        {ev.event_type === 'anomaly'
                          ? <AlertTriangle size={16} style={{ color: 'var(--danger)' }} />
                          : ev.event_type === 'login'
                          ? <Monitor size={16} style={{ color: 'var(--info)' }} />
                          : <Activity size={16} style={{ color: 'var(--success)' }} />}
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: 'var(--text-sm)' }}>
                          {eventLabel(ev.event_type)}
                        </span>
                      </div>
                      <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-secondary)', margin: '0 0 var(--space-2)' }}>{ev.description}</p>
                      <div style={{ display: 'flex', gap: 'var(--space-4)', fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
                        <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><Clock size={12} /> {new Date(ev.timestamp).toLocaleString('fr-FR')}</span>
                        {ev.ip_address && <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><MapPin size={12} /> {ev.ip_address}</span>}
                      </div>
                    </div>
                    {ev.severity && <Badge variant={sevBadge(ev.severity)}>{ev.severity.toUpperCase()}</Badge>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </AppShell>
  )
}

import { useQuery } from '@tanstack/react-query'
import { KeyRound, Files, Shield, AlertTriangle } from 'lucide-react'
import { passwords, files, security } from '../lib/vault-service'
import { AppShell } from '../design-system/layouts'
import { StatCard, EmptyState } from '../design-system/molecules'
import { Badge } from '../design-system/atoms'

export default function DashboardPage() {
  const { data: pwList = [] } = useQuery({ queryKey: ['passwords'], queryFn: passwords.list })
  const { data: fileList = [] } = useQuery({ queryKey: ['secureFiles'], queryFn: files.list })
  const { data: events = [] } = useQuery({ queryKey: ['security-events'], queryFn: security.getEvents })

  const highAlerts = events.filter((e) => e.severity === 'high').length

  return (
    <AppShell>
      <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-8)' }}>
        {/* Header */}
        <div className="page-header">
          <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'var(--text-3xl)', color: 'var(--text-primary)' }}>
            Tableau de bord
          </h1>
          <p style={{ fontSize: 'var(--text-sm)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', marginTop: 'var(--space-1)' }}>
            Vue d'ensemble de votre coffre-fort sécurisé
          </p>
        </div>

        {/* Stats */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 'var(--space-4)' }}>
          <StatCard icon={KeyRound} label="Mots de passe" value={pwList.length} />
          <StatCard icon={Files} label="Fichiers chiffrés" value={fileList.length} accentColor="var(--info)" />
          <StatCard icon={Shield} label="Sécurité" value="Élevé" accentColor="var(--success)" />
          <StatCard icon={AlertTriangle} label="Alertes" value={highAlerts} accentColor="var(--warning)" />
        </div>

        {/* Recent Activity */}
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: 'var(--space-6)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-5)' }}>
            <h2 style={{ fontSize: 'var(--text-lg)', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
              Activités récentes
            </h2>
            {events.length > 0 && (
              <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)' }}>
                {events.length} événement{events.length > 1 ? 's' : ''}
              </span>
            )}
          </div>

          {events.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)', maxHeight: 380, overflowY: 'auto' }}>
              {events.slice(0, 10).map((ev, i) => (
                <div key={i} style={{
                  padding: 'var(--space-3) var(--space-4)',
                  borderRadius: 'var(--radius-md)', background: 'var(--bg-elevated)',
                }} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 'var(--space-3)', flex: 1 }}>
                    <div style={{
                      width: 6, height: 6, borderRadius: 'var(--radius-full)', marginTop: 7, flexShrink: 0,
                      background: ev.severity === 'high' ? 'var(--danger)' : ev.severity === 'medium' ? 'var(--warning)' : 'var(--success)',
                    }} />
                    <div>
                      <p style={{ fontSize: 'var(--text-sm)', fontWeight: 500, color: 'var(--text-primary)', fontFamily: 'var(--font-body)' }}>
                        {ev.event_type || 'Événement'}
                      </p>
                      {ev.description && (
                        <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)', fontFamily: 'var(--font-body)', marginTop: 2 }}>
                          {ev.description}
                        </p>
                      )}
                      <p style={{ fontSize: 'var(--text-xs)', color: 'var(--text-disabled)', fontFamily: 'var(--font-body)', marginTop: 2 }}>
                        {new Date(ev.timestamp).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </p>
                    </div>
                  </div>
                  <div className="self-start sm:self-auto">
                    <Badge variant={ev.severity === 'high' ? 'danger' : ev.severity === 'medium' ? 'warning' : 'success'} size="sm">
                      {ev.severity === 'high' ? 'Élevé' : ev.severity === 'medium' ? 'Moyen' : 'Faible'}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState icon={Shield} title="Aucune activité récente" description="Les événements de sécurité apparaîtront ici" />
          )}
        </div>
      </div>
    </AppShell>
  )
}

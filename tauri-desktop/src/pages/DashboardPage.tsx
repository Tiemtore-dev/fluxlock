import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { KeyRound, Files, Shield, AlertTriangle } from 'lucide-react'
import { getVersion } from '@tauri-apps/api/app'
import { passwords, files, security } from '../lib/vault-service'
import { AppShell } from '../design-system/layouts'
import { StatCard, EmptyState } from '../design-system/molecules'
import { Badge } from '../design-system/atoms'

export default function DashboardPage() {
  const [appVersion, setAppVersion] = useState<string>('2.2.16')

  useEffect(() => {
    getVersion()
      .then((ver) => setAppVersion(ver))
      .catch(() => {
        // En mode navigateur ou si l'API n'est pas disponible, on garde la valeur par défaut
      })
  }, [])

  const { data: pwList = [] } = useQuery({ queryKey: ['passwords'], queryFn: passwords.list })
  const { data: fileList = [] } = useQuery({ queryKey: ['secureFiles'], queryFn: files.list })
  const { data: events = [] } = useQuery({ queryKey: ['security-events'], queryFn: security.getEvents })

  const highAlerts = events.filter((e) => e.severity === 'high').length

  return (
    <AppShell>
      <div className="page-content flex flex-col gap-8">
        {/* Header */}
        <div className="page-header flex-col items-start gap-1">
          <h1 className="font-display text-2xl sm:text-3xl text-tx-primary m-0">
            Tableau de bord
          </h1>
          <Badge variant="success">application version {appVersion}</Badge>
          <p className="text-xs sm:text-sm text-tx-muted font-body mt-1 m-0">
            Vue d'ensemble de votre coffre-fort sécurisé
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
          <StatCard icon={KeyRound} label="Mots de passe" value={pwList.length} />
          <StatCard icon={Files} label="Fichiers chiffrés" value={fileList.length} accentColor="var(--info)" />
          <StatCard icon={Shield} label="Sécurité" value={highAlerts > 0 ? "Alerte" : "Élevé"} accentColor={highAlerts > 0 ? "var(--warning)" : "var(--success)"} />
          <StatCard icon={AlertTriangle} label="Alertes" value={highAlerts} accentColor="var(--warning)" />
        </div>

        {/* Recent Activity */}
        <div className="bg-surface border border-bd rounded-2xl p-4 sm:p-6 shadow-sm">
          <div className="flex items-center justify-between mb-4 sm:mb-5">
            <h2 className="text-base sm:text-lg font-semibold text-tx-primary font-body m-0">
              Activités récentes
            </h2>
            {events.length > 0 && (
              <span className="text-[10px] sm:text-xs text-tx-muted font-body bg-bg-hover px-2 py-1 rounded-md">
                {events.length} événement{events.length > 1 ? 's' : ''}
              </span>
            )}
          </div>

          {events.length > 0 ? (
            <div className="flex flex-col gap-2.5 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
              {events.slice(0, 10).map((ev, i) => (
                <div key={i} className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3.5 sm:px-5 rounded-xl bg-elevated border border-transparent hover:border-bd transition-colors">
                  <div className="flex items-start gap-3.5 flex-1 min-w-0">
                    <div 
                      className="w-2.5 h-2.5 rounded-full mt-1.5 shrink-0 shadow-sm"
                      style={{ background: ev.severity === 'high' ? 'var(--danger)' : ev.severity === 'medium' ? 'var(--warning)' : 'var(--success)' }}
                    />
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-tx-primary font-body m-0 truncate">
                        {ev.event_type || 'Événement'}
                      </p>
                      {ev.description && (
                        <p className="text-xs text-tx-secondary font-body mt-1 m-0 line-clamp-2 leading-relaxed">
                          {ev.description}
                        </p>
                      )}
                      <p className="text-[10px] text-tx-disabled font-body mt-1.5 m-0 font-medium">
                        {new Date(ev.timestamp).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })}
                      </p>
                    </div>
                  </div>
                  <div className="self-end sm:self-auto shrink-0">
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


import { useQuery } from '@tanstack/react-query'
import DashboardLayout from '../components/DashboardLayout'
import { Shield, Key, Files, AlertTriangle } from 'lucide-react'
import { tauriAPI } from '../lib/tauri-api'

export default function DashboardPage() {
  const { data: passwords = [] } = useQuery({
    queryKey: ['passwords'],
    queryFn: tauriAPI.getPasswords
  })

  const { data: files = [] } = useQuery({
    queryKey: ['secureFiles'],
    queryFn: tauriAPI.getSecureFiles
  })

  const { data: securityEvents = [] } = useQuery({
    queryKey: ['security-events'],
    queryFn: tauriAPI.getSecurityEvents
  })

  const stats = [
    {
      name: 'Mots de passe',
      value: passwords?.length || 0,
      icon: Key,
      color: 'bg-blue-500',
    },
    {
      name: 'Fichiers chiffrés',
      value: files?.length || 0,
      icon: Files,
      color: 'bg-green-500',
    },
    {
      name: 'Niveau de sécurité',
      value: 'Élevé',
      icon: Shield,
      color: 'bg-purple-500',
    },
    {
      name: 'Alertes',
      value: securityEvents?.filter((e: any) => e.severity === 'high').length || 0,
      icon: AlertTriangle,
      color: 'bg-orange-500',
    },
  ]

  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Tableau de bord
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Vue d'ensemble de votre coffre-fort sécurisé
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {stats.map((stat) => {
            const Icon = stat.icon
            return (
              <div key={stat.name} className="card">
                <div className="flex items-center">
                  <div className={`${stat.color} p-3 rounded-lg`}>
                    <Icon className="w-6 h-6 text-white" />
                  </div>
                  <div className="ml-4">
                    <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                      {stat.name}
                    </p>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {stat.value}
                    </p>
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Recent Activity */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white">
              Activités récentes
            </h2>
            {securityEvents && securityEvents.length > 0 && (
              <span className="text-sm text-gray-500 dark:text-gray-400">
                {securityEvents.length} événement{securityEvents.length > 1 ? 's' : ''}
              </span>
            )}
          </div>
          
          {/* Conteneur scrollable avec hauteur maximale */}
          <div className="max-h-96 overflow-y-auto space-y-4 pr-2">
            {securityEvents && securityEvents.length > 0 ? (
              securityEvents.slice(0, 10).map((event: any, index: number) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 transition-colors"
                >
                  <div className="flex items-center flex-1">
                    <div className={`w-2 h-2 rounded-full mr-3 ${
                      event.severity === 'high' ? 'bg-red-500' :
                      event.severity === 'medium' ? 'bg-orange-500' :
                      'bg-green-500'
                    }`}></div>
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-900 dark:text-white">
                        {event.event_type || 'Événement'}
                      </p>
                      {event.description && (
                        <p className="text-xs text-gray-600 dark:text-gray-400 mt-0.5">
                          {event.description}
                        </p>
                      )}
                      <div className="flex items-center gap-3 mt-1">
                        <p className="text-xs text-gray-500 dark:text-gray-400">
                          {new Date(event.timestamp || event.created_at).toLocaleString('fr-FR', {
                            day: '2-digit',
                            month: '2-digit',
                            year: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit'
                          })}
                        </p>
                        {event.ip_address && (
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            IP: {event.ip_address}
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                  <span className={`
                    text-xs font-medium px-2.5 py-1 rounded-full whitespace-nowrap ml-3
                    ${event.severity === 'high' ? 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300' : 
                      event.severity === 'medium' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300' :
                      'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'}
                  `}>
                    {event.severity === 'high' ? 'Élevé' :
                     event.severity === 'medium' ? 'Moyen' : 
                     'Faible'}
                  </span>
                </div>
              ))
            ) : (
              <div className="text-center py-12">
                <Shield className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-3" />
                <p className="text-gray-500 dark:text-gray-400 text-sm">
                  Aucune activité récente
                </p>
                <p className="text-gray-400 dark:text-gray-500 text-xs mt-1">
                  Les événements de sécurité apparaîtront ici
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Security Tips */}
        <div className="card bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800">
          <div className="flex items-start">
            <Shield className="w-6 h-6 text-primary-600 mr-3 flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-lg font-semibold text-primary-900 dark:text-primary-300 mb-2">
                Conseils de sécurité
              </h3>
              <ul className="space-y-2 text-sm text-primary-800 dark:text-primary-400">
                <li>• Utilisez des mots de passe uniques pour chaque compte</li>
                <li>• Activez l'authentification à deux facteurs (2FA)</li>
                <li>• Ne partagez jamais votre mot de passe maître</li>
                <li>• Mettez régulièrement à jour vos mots de passe</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  )
}

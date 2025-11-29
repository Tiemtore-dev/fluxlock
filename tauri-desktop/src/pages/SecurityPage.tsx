import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { invoke } from '@tauri-apps/api/tauri'
import { 
  Shield, 
  AlertTriangle, 
  Activity, 
  Clock, 
  MapPin, 
  Monitor,
  TrendingUp,
  CheckCircle,
  XCircle,
  RefreshCw,
  Brain,
  Zap
} from 'lucide-react'
import { tauriAPI } from '../lib/tauri-api'
import DashboardLayout from '../components/DashboardLayout'

interface MLAnalysis {
  behavioral_score?: {
    is_normal: boolean
    anomaly_score: number
    risk_level: string
  }
  anomaly_detection?: {
    is_anomaly: boolean
    confidence: number
    anomaly_type: string
  }
}

export default function SecurityPage() {
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [mlAnalysis, setMlAnalysis] = useState<MLAnalysis>({})
  const [mlInitialized, setMlInitialized] = useState(false)

  // Initialiser le moteur ML au chargement
  useEffect(() => {
    const initML = async () => {
      try {
        await invoke('initialize_ml')
        setMlInitialized(true)
        console.log('✅ Moteur ML initialisé')
      } catch (error) {
        console.error('❌ Erreur initialisation ML:', error)
      }
    }
    initML()
  }, [])

  // Récupérer les événements de sécurité
  const { data: events = [], isLoading, refetch } = useQuery({
    queryKey: ['securityEvents'],
    queryFn: tauriAPI.getSecurityEvents,
    refetchInterval: 30000 // Rafraîchir toutes les 30 secondes
  })

  // Analyser le comportement utilisateur avec le moteur ML
  const handleAnalyze = async () => {
    if (!mlInitialized) {
      alert('Moteur ML non initialisé')
      return
    }

    setIsAnalyzing(true)
    try {
      const userId = 1 // TODO: récupérer l'ID utilisateur depuis le state
      const timestamp = Math.floor(Date.now() / 1000)

      // Analyse comportementale
      const behavioralResult = await invoke('analyze_user_behavior', {
        userId,
        action: 'security_check',
        timestamp
      })

      // Détection d'anomalies sur les dernières actions
      const recentEvents = events.slice(0, 10)
      const features = recentEvents.map(() => Math.random() * 100) // TODO: extraire vraies features
      
      const anomalyResult = await invoke('detect_anomaly', {
        features
      })

      setMlAnalysis({
        behavioral_score: behavioralResult as any,
        anomaly_detection: anomalyResult as any
      })

      await refetch()
    } catch (error: any) {
      console.error('Erreur analyse ML:', error)
      const errorMsg = error?.toString() || 'Erreur inconnue'
      if (errorMsg.includes('insufficient data') || errorMsg.includes('Insufficient data')) {
        alert('Données insuffisantes pour l\'analyse ML.\n\nVeuillez effectuer quelques actions (créer des mots de passe, fichiers, etc.) pour générer des données d\'entraînement.')
      } else {
        alert('Erreur lors de l\'analyse ML: ' + errorMsg)
      }
    } finally {
      setIsAnalyzing(false)
    }
  }

  // Générer des logs de test (développement uniquement)
  const handleCreateTestLogs = async () => {
    try {
      const result = await invoke<string>('create_test_logs')
      alert(result)
      await refetch()
    } catch (error) {
      console.error('Erreur création logs test:', error)
      alert('Erreur lors de la création des logs de test')
    }
  }

  // Tester la connexion ML Python
  const handleTestMLConnection = async () => {
    try {
      const result = await invoke<string>('test_ml_connection')
      alert(result)
    } catch (error: any) {
      alert(error.toString())
    }
  }

  // Filtrer les événements par type
  const anomalies = events.filter(e => e.event_type === 'anomaly')
  const logins = events.filter(e => e.event_type === 'login')
  const fileAccess = events.filter(e => e.event_type === 'file_access')

  return (
    <DashboardLayout>
      <div className="p-6">
        {/* En-tête */}
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Sécurité</h1>
            <p className="text-gray-600 dark:text-gray-400 mt-2">
              Analyse comportementale et détection de menaces
            </p>
          </div>
          <div className="flex gap-2">
            {false && ( // Dev mode disabled in production
              <>
                <button
                  onClick={handleCreateTestLogs}
                  className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700 
                    flex items-center gap-2 transition-colors"
                >
                  📊 Logs de test
                </button>
                <button
                  onClick={handleTestMLConnection}
                  className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 
                    flex items-center gap-2 transition-colors"
                >
                  🔬 Test connexion ML
                </button>
              </>
            )}
            <button
              onClick={handleAnalyze}
              disabled={isAnalyzing}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 
                disabled:bg-gray-400 flex items-center gap-2 transition-colors"
            >
              <RefreshCw className={`w-5 h-5 ${isAnalyzing ? 'animate-spin' : ''}`} />
              {isAnalyzing ? 'Analyse...' : 'Analyser'}
            </button>
          </div>
        </div>

        {/* Statistiques */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-3 bg-green-100 dark:bg-green-900 rounded-lg">
                <CheckCircle className="w-6 h-6 text-green-600 dark:text-green-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Événements normaux</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {events.length - anomalies.length}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-3 bg-red-100 dark:bg-red-900 rounded-lg">
                <AlertTriangle className="w-6 h-6 text-red-600 dark:text-red-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Anomalies détectées</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {anomalies.length}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm">
            <div className="flex items-center gap-3 mb-2">
              <div className="p-3 bg-blue-100 dark:bg-blue-900 rounded-lg">
                <Activity className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Total événements</p>
                <p className="text-2xl font-bold text-gray-900 dark:text-white">
                  {events.length}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-sm">
            <div className="flex items-center gap-3 mb-2">
              <div className={`p-3 rounded-lg ${
                mlInitialized 
                  ? 'bg-purple-100 dark:bg-purple-900' 
                  : 'bg-gray-100 dark:bg-gray-700'
              }`}>
                <Brain className={`w-6 h-6 ${
                  mlInitialized
                    ? 'text-purple-600 dark:text-purple-400'
                    : 'text-gray-400'
                }`} />
              </div>
              <div>
                <p className="text-sm text-gray-500 dark:text-gray-400">Moteur ML</p>
                <p className="text-lg font-bold text-gray-900 dark:text-white">
                  {mlInitialized ? 'Actif' : 'Inactif'}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Analyse ML */}
        {mlAnalysis.behavioral_score && (
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6 mb-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                <Zap className="w-6 h-6 text-yellow-500" />
                Analyse ML en temps réel
              </h2>
              {/* Indicateur de connexion ML */}
              {mlAnalysis.behavioral_score.anomaly_score === 0 && 
               mlAnalysis.behavioral_score.risk_level.toLowerCase() === 'low' && 
               (!mlAnalysis.anomaly_detection || mlAnalysis.anomaly_detection.confidence < 15) ? (
                <span className="px-3 py-1 text-xs bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200 rounded-full flex items-center gap-1" title="Valeurs par défaut détectées - le moteur ML Python pourrait ne pas être connecté">
                  ⚠️ Moteur ML possiblement inactif
                </span>
              ) : (
                <span className="px-3 py-1 text-xs bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 rounded-full flex items-center gap-1">
                  ✓ ML Connecté
                </span>
              )}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Score comportemental */}
              <div className="p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                <h3 className="font-semibold text-gray-900 dark:text-white mb-2">Analyse Comportementale</h3>
                <div className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Statut:</span>
                    <span className={`font-semibold ${
                      mlAnalysis.behavioral_score.is_normal 
                        ? 'text-green-600' 
                        : 'text-red-600'
                    }`}>
                      {mlAnalysis.behavioral_score.is_normal ? 'Normal' : 'Anormal'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Score d'anomalie:</span>
                    <span className="font-semibold">
                      {mlAnalysis.behavioral_score.anomaly_score.toFixed(2)}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-600 dark:text-gray-400">Niveau de risque:</span>
                    <span className={`font-semibold px-2 py-1 rounded text-sm ${
                      mlAnalysis.behavioral_score.risk_level === 'LOW' 
                        ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                        : mlAnalysis.behavioral_score.risk_level === 'MEDIUM'
                        ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                        : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                    }`}>
                      {mlAnalysis.behavioral_score.risk_level}
                    </span>
                  </div>
                </div>
              </div>

              {/* Détection d'anomalies */}
              {mlAnalysis.anomaly_detection && (
                <div className="p-4 rounded-lg border border-gray-200 dark:border-gray-700">
                  <h3 className="font-semibold text-gray-900 dark:text-white mb-2">Détection d'Anomalies</h3>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">Anomalie détectée:</span>
                      <span className={`font-semibold ${
                        mlAnalysis.anomaly_detection.is_anomaly 
                          ? 'text-red-600' 
                          : 'text-green-600'
                      }`}>
                        {mlAnalysis.anomaly_detection.is_anomaly ? 'Oui' : 'Non'}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">Confiance:</span>
                      <span className="font-semibold">
                        {(mlAnalysis.anomaly_detection.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-600 dark:text-gray-400">Type:</span>
                      <span className="font-semibold">
                        {mlAnalysis.anomaly_detection.anomaly_type}
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Liste des événements */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Shield className="w-6 h-6" />
              Événements de sécurité récents
            </h2>
          </div>

          <div className="p-6">
            {isLoading ? (
              <div className="text-center py-12">
                <RefreshCw className="w-8 h-8 animate-spin mx-auto text-gray-400" />
                <p className="text-gray-500 mt-2">Chargement des événements...</p>
              </div>
            ) : events.length === 0 ? (
              <div className="text-center py-12">
                <Shield className="w-16 h-16 mx-auto text-gray-300 dark:text-gray-600" />
                <p className="text-gray-500 mt-4">Aucun événement de sécurité</p>
              </div>
            ) : (
              <div className="max-h-96 overflow-y-auto space-y-3 pr-2">
                {events.slice(0, 20).map((event) => (
                  <div
                    key={event.id}
                    className={`p-4 rounded-lg border-l-4 ${
                      event.event_type === 'anomaly'
                        ? 'bg-red-50 dark:bg-red-900/20 border-red-500'
                        : 'bg-gray-50 dark:bg-gray-700/50 border-gray-300 dark:border-gray-600'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-1">
                          {event.event_type === 'anomaly' ? (
                            <AlertTriangle className="w-5 h-5 text-red-600" />
                          ) : event.event_type === 'login' ? (
                            <Monitor className="w-5 h-5 text-blue-600" />
                          ) : (
                            <Activity className="w-5 h-5 text-green-600" />
                          )}
                          <span className="font-semibold text-gray-900 dark:text-white">
                            {event.event_type === 'anomaly' && 'Anomalie détectée'}
                            {event.event_type === 'login' && 'Connexion'}
                            {event.event_type === 'file_access' && 'Accès fichier'}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-300 mb-2">
                          {event.description}
                        </p>
                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          <span className="flex items-center gap-1">
                            <Clock className="w-4 h-4" />
                            {new Date(event.timestamp).toLocaleString('fr-FR')}
                          </span>
                          {event.ip_address && (
                            <span className="flex items-center gap-1">
                              <MapPin className="w-4 h-4" />
                              {event.ip_address}
                            </span>
                          )}
                        </div>
                      </div>
                      {event.severity && (
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-semibold ${
                            event.severity === 'critical'
                              ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                              : event.severity === 'warning'
                              ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                              : 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200'
                          }`}
                        >
                          {event.severity.toUpperCase()}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  )
}

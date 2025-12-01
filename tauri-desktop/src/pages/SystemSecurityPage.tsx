import { useEffect, useState } from 'react'
import { invoke } from '@tauri-apps/api/tauri'
import { Shield, AlertTriangle, Lock, Unlock, RefreshCw, Mail, HardDrive, Activity } from 'lucide-react'
import DashboardLayout from '../components/DashboardLayout'

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

export default function SystemSecurityPage() {
  const [securityState, setSecurityState] = useState<SecurityState | null>(null)
  const [filesystemStats, setFilesystemStats] = useState<FilesystemStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [otpCode, setOtpCode] = useState('')
  const [showOtpDialog, setShowOtpDialog] = useState(false)
  const [showPasswordDialog, setShowPasswordDialog] = useState(false)
  const [passwordInput, setPasswordInput] = useState('')

  const loadSecurityState = async () => {
    try {
      const state = await invoke<SecurityState>('get_security_status')
      console.log('🔍 DEBUG: État sécurité chargé:', state)
      console.log('🔍 DEBUG: is_readonly =', state.is_readonly)
      console.log('🔍 DEBUG: threat_level =', state.threat_level)
      setSecurityState(state)
      
      const fsStats = await invoke<FilesystemStats>('get_filesystem_stats')
      setFilesystemStats(fsStats)
    } catch (err) {
      console.error('Erreur chargement état sécurité:', err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadSecurityState()
    const interval = setInterval(loadSecurityState, 5000) // Refresh toutes les 5s
    return () => clearInterval(interval)
  }, [])

  const handleRequestOtp = async () => {
    const userEmail = localStorage.getItem('userEmail')
    if (!userEmail) {
      alert('Email utilisateur introuvable')
      return
    }

    try {
      const result = await invoke<string>('request_otp_code', { userEmail })
      alert(result)
      setShowOtpDialog(true)
    } catch (err: any) {
      alert('Erreur: ' + err.toString())
    }
  }

  const handleVerifyOtp = async () => {
    const userEmail = localStorage.getItem('userEmail')
    if (!userEmail) {
      alert('Email utilisateur introuvable')
      return
    }

    try {
      const valid = await invoke<boolean>('verify_otp_code', { 
        userEmail, 
        code: otpCode 
      })
      
      if (valid) {
        alert('✅ Code OTP vérifié avec succès!')
        setShowOtpDialog(false)
        setOtpCode('')
      } else {
        alert('❌ Code OTP invalide ou expiré')
      }
    } catch (err: any) {
      alert('Erreur: ' + err.toString())
    }
  }

  const handleDisableReadonly = async () => {
    console.log('🔐 DEBUG: handleDisableReadonly appelé')
    
    // Ouvrir le dialogue custom au lieu de prompt()
    setShowPasswordDialog(true)
  }

  const confirmDisableReadonly = async () => {
    console.log('🔐 DEBUG: confirmDisableReadonly appelé avec password:', passwordInput ? 'oui' : 'non')
    
    if (!passwordInput) {
      alert('⚠️ Veuillez entrer un mot de passe')
      return
    }

    try {
      console.log('📡 DEBUG: Appel disable_readonly_mode...')
      const result = await invoke<string>('disable_readonly_mode', { 
        password: passwordInput 
      })
      console.log('✅ DEBUG: Résultat:', result)
      
      // Fermer le dialogue et réinitialiser
      setShowPasswordDialog(false)
      setPasswordInput('')
      
      // Recharger l'état pour mettre à jour l'indicateur
      console.log('🔄 DEBUG: Rechargement état sécurité...')
      await loadSecurityState()
      console.log('✅ DEBUG: État rechargé')
      
      alert('✅ ' + result)
    } catch (err: any) {
      console.error('❌ DEBUG: Erreur disable_readonly_mode:', err)
      alert('❌ Erreur: ' + err.toString())
    }
  }

  const handleResetCounters = async () => {
    if (!confirm('Réinitialiser tous les compteurs de sécurité ?')) return

    try {
      const result = await invoke<string>('reset_security_counters')
      alert(result)
      await loadSecurityState()
    } catch (err: any) {
      alert('Erreur: ' + err.toString())
    }
  }
  
  const handleDisableFilesystemReadonly = async () => {
    if (!confirm('Désactiver le mode lecture seule du système ?')) return

    try {
      const result = await invoke<string>('disable_filesystem_readonly')
      alert(result)
      await loadSecurityState()
    } catch (err: any) {
      alert('Erreur: ' + err.toString())
    }
  }

  const handleToggleMonitoring = async (enable: boolean) => {
    const action = enable ? 'activer' : 'désactiver'
    if (!confirm(`Voulez-vous vraiment ${action} la surveillance des fichiers ?`)) return

    try {
      const command = enable ? 'enable_filesystem_monitoring' : 'disable_filesystem_monitoring'
      const result = await invoke<string>(command)
      alert(`✅ ${result}`)
      await loadSecurityState()
    } catch (err: any) {
      alert('❌ Erreur: ' + err.toString())
    }
  }

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'none': return 'text-green-600 bg-green-100 dark:bg-green-900/30 dark:text-green-200'
      case 'low': return 'text-blue-600 bg-blue-100 dark:bg-blue-900/30 dark:text-blue-200'
      case 'medium': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/30 dark:text-yellow-200'
      case 'high': return 'text-orange-600 bg-orange-100 dark:bg-orange-900/30 dark:text-orange-200'
      case 'critical': return 'text-red-600 bg-red-100 dark:bg-red-900/30 dark:text-red-200'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  if (loading) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="w-8 h-8 animate-spin text-gray-400" />
        </div>
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* En-tête */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
              <Shield className="w-8 h-8 text-blue-600" />
              Sécurité Système
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-2">
              Protection anti-brute force et détection ransomware
            </p>
          </div>
          <button
            onClick={loadSecurityState}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
          >
            <RefreshCw className="w-5 h-5" />
            Actualiser
          </button>
        </div>

        {/* État global */}
        {securityState && (
          <>
            {/* Cartes de statut */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {/* Niveau de menace */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
                <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                  Niveau de Menace
                </h3>
                <div className="flex items-center gap-3">
                  <AlertTriangle className={`w-8 h-8 ${
                    securityState.threat_level === 'critical' ? 'text-red-600' :
                    securityState.threat_level === 'high' ? 'text-orange-600' :
                    securityState.threat_level === 'medium' ? 'text-yellow-600' :
                    'text-green-600'
                  }`} />
                  <div>
                    <span className={`px-3 py-1 rounded-full text-sm font-semibold ${getThreatLevelColor(securityState.threat_level)}`}>
                      {securityState.threat_level.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Mode lecture seule */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
                <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                  Mode Lecture Seule
                </h3>
                <div className="flex items-center gap-3">
                  {securityState.is_readonly ? (
                    <>
                      <Lock className="w-8 h-8 text-red-600" />
                      <div>
                        <span className="text-red-600 font-semibold">ACTIVÉ</span>
                        <p className="text-xs text-gray-500">Protection active</p>
                      </div>
                    </>
                  ) : (
                    <>
                      <Unlock className="w-8 h-8 text-green-600" />
                      <div>
                        <span className="text-green-600 font-semibold">DÉSACTIVÉ</span>
                        <p className="text-xs text-gray-500">Accès normal</p>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* Verrouillage système */}
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
                <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 mb-2">
                  Verrouillage
                </h3>
                <div className="flex items-center gap-3">
                  <Shield className={`w-8 h-8 ${securityState.is_locked ? 'text-red-600' : 'text-green-600'}`} />
                  <div>
                    <span className={`font-semibold ${securityState.is_locked ? 'text-red-600' : 'text-green-600'}`}>
                      {securityState.is_locked ? 'VERROUILLÉ' : 'DÉVERROUILLÉ'}
                    </span>
                    <p className="text-xs text-gray-500">État du système</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Alertes actives */}
            {securityState.active_threats.length > 0 && (
              <div className="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-6 rounded-lg">
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-6 h-6 text-red-600 flex-shrink-0 mt-1" />
                  <div className="flex-1">
                    <h3 className="text-lg font-bold text-red-800 dark:text-red-200 mb-3">
                      🚨 Menaces Actives Détectées
                    </h3>
                    <ul className="space-y-2">
                      {securityState.active_threats.map((threat, idx) => (
                        <li key={idx} className="text-red-700 dark:text-red-300">
                          • {threat}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* Actions */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
              <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                Actions de Sécurité
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Toggle surveillance fichiers */}
                <div className="border-2 border-blue-200 dark:border-blue-700 rounded-lg p-4 bg-blue-50 dark:bg-blue-900/20">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Activity className="w-5 h-5 text-blue-600" />
                      <h3 className="font-semibold text-gray-900 dark:text-white">
                        Surveillance Fichiers
                      </h3>
                    </div>
                    <button
                      onClick={() => handleToggleMonitoring(!filesystemStats?.monitoring_enabled)}
                      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                        filesystemStats?.monitoring_enabled
                          ? 'bg-green-600'
                          : 'bg-gray-300 dark:bg-gray-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                          filesystemStats?.monitoring_enabled ? 'translate-x-6' : 'translate-x-1'
                        }`}
                      />
                    </button>
                  </div>
                  <p className="text-xs text-gray-600 dark:text-gray-400">
                    {filesystemStats?.monitoring_enabled
                      ? '🟢 Surveillance active - Détection ransomware en temps réel'
                      : '🔴 Surveillance désactivée - Aucune protection active'}
                  </p>
                </div>

                {/* Désactiver mode lecture seule */}
                <button
                  onClick={(e) => {
                    console.log('🖱️ CLICK DÉTECTÉ sur le bouton readonly');
                    console.log('🔍 securityState?.is_readonly =', securityState?.is_readonly);
                    console.log('🔍 bouton disabled =', !securityState?.is_readonly);
                    e.preventDefault();
                    handleDisableReadonly();
                  }}
                  disabled={!securityState?.is_readonly}
                  className="px-4 py-3 bg-orange-600 text-white rounded-lg hover:bg-orange-700 flex items-center gap-2 justify-center transition-all transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
                  title={securityState?.is_readonly ? 'Cliquez pour désactiver le mode lecture seule' : 'Mode lecture seule inactif'}
                >
                  <Unlock className="w-5 h-5" />
                  🔓 Désactiver Mode Lecture Seule
                  {securityState?.is_readonly && <span className="text-xs font-bold">(✅ ACTIF)</span>}
                  {!securityState?.is_readonly && <span className="text-xs opacity-70">(Inactif)</span>}
                </button>
              </div>
            </div>

            {/* Informations */}
            <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-6">
              <h3 className="font-bold text-blue-900 dark:text-blue-100 mb-3">
                ℹ️ Fonctionnalités de Protection
              </h3>
              <ul className="space-y-2 text-blue-800 dark:text-blue-200 text-sm">
                <li>• <strong>Anti-Brute Force:</strong> Verrouillage progressif après tentatives échouées (30s, 5min, 30min)</li>
                <li>• <strong>OTP Email:</strong> Code de vérification envoyé après 5 tentatives (expire en 30s)</li>
                <li>• <strong>Détection Ransomware:</strong> Surveillance continue du système de fichiers (Documents, Bureau, etc.)</li>
                <li>• <strong>Protection Temps Réel:</strong> Détection extensions suspectes (.encrypted, .locked, .wannacry, etc.)</li>
                <li>• <strong>Analyse Comportementale:</strong> Détection chiffrement massif (&gt;30 fichiers en 30s)</li>
                <li>• <strong>Mode Lecture Seule:</strong> Blocage automatique de toutes modifications si menace détectée</li>
                <li>• <strong>Alertes Temps Réel:</strong> Notification immédiate des menaces système</li>
              </ul>
            </div>
            
            {/* Statistiques système en temps réel */}
            {filesystemStats && (
              <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm p-6">
                <div className="flex items-center gap-3 mb-4">
                  <Activity className="w-6 h-6 text-purple-600" />
                  <h2 className="text-xl font-bold text-gray-900 dark:text-white">
                    Surveillance Système Temps Réel
                  </h2>
                </div>
                
                {/* Niveau de menace système */}
                <div className="mb-4 p-4 rounded-lg bg-gray-50 dark:bg-gray-700">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-gray-700 dark:text-gray-300">
                      Niveau de Menace Système:
                    </span>
                    <span className={`px-3 py-1 rounded-full font-bold ${getThreatLevelColor(filesystemStats.threat_level.toLowerCase())}`}>
                      {filesystemStats.threat_level}
                    </span>
                  </div>
                </div>
                
                {/* Statistiques d'activité */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-blue-600">{filesystemStats.total_events.toLocaleString()}</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400">Événements Total</div>
                  </div>
                  <div className="bg-green-50 dark:bg-green-900/20 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">{filesystemStats.modifications.toLocaleString()}</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400">Modifications</div>
                  </div>
                  <div className="bg-purple-50 dark:bg-purple-900/20 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-purple-600">{filesystemStats.creations.toLocaleString()}</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400">Créations</div>
                  </div>
                  <div className="bg-red-50 dark:bg-red-900/20 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-red-600">{filesystemStats.deletions.toLocaleString()}</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400">Suppressions</div>
                  </div>
                </div>
                
                {/* Menaces détectées */}
                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div className="bg-orange-50 dark:bg-orange-900/20 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-orange-600">{filesystemStats.suspicious_extensions}</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400">Extensions Suspectes</div>
                  </div>
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 p-3 rounded-lg">
                    <div className="text-2xl font-bold text-yellow-600">{filesystemStats.rapid_changes}</div>
                    <div className="text-xs text-gray-600 dark:text-gray-400">Modifications Rapides</div>
                  </div>
                </div>
                
                {/* Répertoires surveillés */}
                <div className="mb-4">
                  <h3 className="font-semibold text-gray-700 dark:text-gray-300 mb-2">
                    📁 Répertoires Surveillés ({filesystemStats.monitored_paths.length})
                  </h3>
                  <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded max-h-40 overflow-y-auto">
                    <ul className="text-xs text-gray-600 dark:text-gray-400 space-y-1">
                      {filesystemStats.monitored_paths.map((path, idx) => (
                        <li key={idx} className="font-mono">• {path}</li>
                      ))}
                    </ul>
                  </div>
                </div>
                
                {/* Menaces actives système */}
                {filesystemStats.active_threats.length > 0 && (
                  <div className="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 rounded">
                    <h3 className="font-bold text-red-800 dark:text-red-200 mb-2">
                      ⚠️ Menaces Système Actives
                    </h3>
                    <ul className="space-y-1">
                      {filesystemStats.active_threats.map((threat, idx) => (
                        <li key={idx} className="text-sm text-red-700 dark:text-red-300">• {threat}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* Dialog OTP */}
        {showOtpDialog && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                Vérification OTP
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Un code de 6 chiffres a été envoyé à votre adresse email. 
                Saisissez-le dans les 30 secondes.
              </p>
              <input
                type="text"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value)}
                placeholder="000000"
                maxLength={6}
                className="w-full px-4 py-3 text-center text-2xl font-mono tracking-widest border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white mb-4"
              />
              <div className="flex gap-2">
                <button
                  onClick={handleVerifyOtp}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Vérifier
                </button>
                <button
                  onClick={() => {
                    setShowOtpDialog(false)
                    setOtpCode('')
                  }}
                  className="px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-white rounded-lg hover:bg-gray-400 dark:hover:bg-gray-500"
                >
                  Annuler
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Dialog Password pour désactiver readonly */}
        {showPasswordDialog && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
              <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                🔐 Désactivation Mode Lecture Seule
              </h3>
              <p className="text-gray-600 dark:text-gray-400 mb-4">
                Entrez votre mot de passe pour désactiver le mode lecture seule.
              </p>
              <input
                type="password"
                value={passwordInput}
                onChange={(e) => setPasswordInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && confirmDisableReadonly()}
                placeholder="Mot de passe"
                autoFocus
                className="w-full px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white mb-4"
              />
              <div className="flex gap-2">
                <button
                  onClick={confirmDisableReadonly}
                  className="flex-1 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700"
                >
                  Confirmer
                </button>
                <button
                  onClick={() => {
                    setShowPasswordDialog(false)
                    setPasswordInput('')
                  }}
                  className="px-4 py-2 bg-gray-300 dark:bg-gray-600 text-gray-700 dark:text-white rounded-lg hover:bg-gray-400 dark:hover:bg-gray-500"
                >
                  Annuler
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  )
}

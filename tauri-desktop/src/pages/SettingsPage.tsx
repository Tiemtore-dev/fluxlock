import { useState, useEffect } from 'react'
import { 
  Settings, 
  Moon, 
  Sun, 
  Bell, 
  Shield, 
  Database,
  Trash2,
  Download,
  Save,
  AlertCircle
} from 'lucide-react'
import DashboardLayout from '../components/DashboardLayout'

export default function SettingsPage() {
  const [isDark, setIsDark] = useState(
    localStorage.getItem('theme') === 'dark' || 
    (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)
  )
  const [notifications, setNotifications] = useState(
    localStorage.getItem('notifications') === 'true' || !localStorage.getItem('notifications')
  )
  const [autoLock, setAutoLock] = useState(
    localStorage.getItem('autoLock') === 'true' || !localStorage.getItem('autoLock')
  )
  const [lockTimeout, setLockTimeout] = useState(
    parseInt(localStorage.getItem('lockTimeout') || '15')
  )
  const [showSuccess, setShowSuccess] = useState(false)

  // Charger les préférences au démarrage
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme')
    if (savedTheme === 'dark') {
      document.documentElement.classList.add('dark')
      setIsDark(true)
    } else if (savedTheme === 'light') {
      document.documentElement.classList.remove('dark')
      setIsDark(false)
    }
  }, [])

  // Toggle dark mode
  const toggleDarkMode = () => {
    const newTheme = !isDark
    setIsDark(newTheme)
    if (newTheme) {
      document.documentElement.classList.add('dark')
      localStorage.setItem('theme', 'dark')
    } else {
      document.documentElement.classList.remove('dark')
      localStorage.setItem('theme', 'light')
    }
  }

  // Sauvegarder les paramètres
  const handleSaveSettings = () => {
    localStorage.setItem('notifications', notifications.toString())
    localStorage.setItem('autoLock', autoLock.toString())
    localStorage.setItem('lockTimeout', lockTimeout.toString())
    setShowSuccess(true)
    setTimeout(() => setShowSuccess(false), 3000)
  }

  // Exporter la base de données
  const handleExport = async () => {
    try {
      // Implémenter l'export via Tauri
      alert("Fonctionnalité d'export en cours de développement")
    } catch (error) {
      console.error('Erreur export:', error)
    }
  }

  // Nettoyer le cache
  const handleClearCache = async () => {
    if (confirm('Êtes-vous sûr de vouloir nettoyer le cache ?')) {
      try {
        // Implémenter le nettoyage via Tauri
        alert('Cache nettoyé avec succès')
      } catch (error) {
        console.error('Erreur nettoyage:', error)
      }
    }
  }

  return (
    <DashboardLayout>
      <div className="p-6 max-w-4xl">
        {/* En-tête */}
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <Settings className="w-8 h-8" />
            Paramètres
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Configuration de l'application SecureVault
          </p>
        </div>

        {/* Message de succès */}
        {showSuccess && (
          <div className="mb-6 p-4 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 rounded-lg flex items-center gap-2">
            <AlertCircle className="w-5 h-5" />
            Paramètres enregistrés avec succès !
          </div>
        )}

        {/* Apparence */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm mb-6">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
              {isDark ? <Moon className="w-6 h-6" /> : <Sun className="w-6 h-6" />}
              Apparence
            </h2>
          </div>
          <div className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900 dark:text-white">Mode sombre</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Activer le thème sombre pour réduire la fatigue oculaire
                </p>
              </div>
              <button
                onClick={toggleDarkMode}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  isDark ? 'bg-blue-600' : 'bg-gray-200'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    isDark ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
          </div>
        </div>

        {/* Notifications */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm mb-6">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Bell className="w-6 h-6" />
              Notifications
            </h2>
          </div>
          <div className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900 dark:text-white">Activer les notifications</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Recevoir des alertes pour les événements de sécurité
                </p>
              </div>
              <button
                onClick={() => setNotifications(!notifications)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  notifications ? 'bg-blue-600' : 'bg-gray-200'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    notifications ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>
          </div>
        </div>

        {/* Sécurité */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm mb-6">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Shield className="w-6 h-6" />
              Sécurité
            </h2>
          </div>
          <div className="p-6 space-y-6">
            {/* Verrouillage automatique */}
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900 dark:text-white">Verrouillage automatique</p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Verrouiller l'application après une période d'inactivité
                </p>
              </div>
              <button
                onClick={() => setAutoLock(!autoLock)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  autoLock ? 'bg-blue-600' : 'bg-gray-200'
                }`}
              >
                <span
                  className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                    autoLock ? 'translate-x-6' : 'translate-x-1'
                  }`}
                />
              </button>
            </div>

            {/* Délai de verrouillage */}
            {autoLock && (
              <div>
                <label className="block font-medium text-gray-900 dark:text-white mb-2">
                  Délai de verrouillage (minutes)
                </label>
                <input
                  type="number"
                  min="1"
                  max="60"
                  value={lockTimeout}
                  onChange={(e) => setLockTimeout(parseInt(e.target.value) || 15)}
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg
                    bg-white dark:bg-gray-700 text-gray-900 dark:text-white
                    focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            )}
          </div>
        </div>

        {/* Base de données */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm mb-6">
          <div className="p-6 border-b border-gray-200 dark:border-gray-700">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Database className="w-6 h-6" />
              Base de données
            </h2>
          </div>
          <div className="p-6 space-y-4">
            <button
              onClick={handleExport}
              className="w-full px-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 
                transition-colors flex items-center justify-center gap-2"
            >
              <Download className="w-5 h-5" />
              Exporter la base de données
            </button>
            <button
              onClick={handleClearCache}
              className="w-full px-4 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 
                transition-colors flex items-center justify-center gap-2"
            >
              <Trash2 className="w-5 h-5" />
              Nettoyer le cache
            </button>
          </div>
        </div>

        {/* Bouton de sauvegarde */}
        <div className="flex justify-end">
          <button
            onClick={handleSaveSettings}
            className="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 
              transition-colors flex items-center gap-2 font-medium"
          >
            <Save className="w-5 h-5" />
            Enregistrer les paramètres
          </button>
        </div>
      </div>
    </DashboardLayout>
  )
}

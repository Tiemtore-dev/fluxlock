import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Lock, Mail, User, AlertTriangle } from 'lucide-react'
import { tauriAPI } from '../lib/tauri-api'
import { useAuthStore } from '../stores/authStore'

export default function RegisterPage() {
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)
  
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
  })
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [hasUser, setHasUser] = useState(false)
  const [checkingUser, setCheckingUser] = useState(true)

  // Vérifier s'il y a déjà un utilisateur au chargement
  useEffect(() => {
    const checkExistingUser = async () => {
      try {
        const exists = await tauriAPI.hasExistingUser()
        setHasUser(exists)
      } catch (err) {
        console.error('Erreur vérification utilisateur:', err)
      } finally {
        setCheckingUser(false)
      }
    }

    checkExistingUser()
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    // Validation
    if (formData.password !== formData.confirmPassword) {
      setError('Les mots de passe ne correspondent pas')
      return
    }

    if (formData.password.length < 12) {
      setError('Le mot de passe doit contenir au moins 12 caractères')
      return
    }

    setIsLoading(true)
    try {
      const response = await tauriAPI.register(
        formData.username,
        formData.email,
        formData.password
      )

      if (response.success && response.token) {
        // Créer un objet utilisateur pour le store
        const user = {
          id: response.user_id?.toString() || '1',
          username: formData.username,
          email: formData.email
        }
        
        setAuth(user, response.token, response.token)
        navigate('/')
      } else {
        setError(response.message || 'Erreur lors de l\'inscription')
      }
    } catch (err: any) {
      setError(err.message || 'Erreur lors de l\'inscription')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-500 to-primary-700 p-4">
      <div className="card max-w-md w-full">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary-100 rounded-full mb-4">
            <Lock className="w-8 h-8 text-primary-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">SecureVault</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">Créer un nouveau compte</p>
        </div>

        {checkingUser ? (
          <div className="text-center py-8">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600"></div>
            <p className="text-gray-600 dark:text-gray-400 mt-4">Vérification...</p>
          </div>
        ) : hasUser ? (
          <div>
            <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg p-6 mb-6">
              <div className="flex items-start">
                <AlertTriangle className="w-6 h-6 text-orange-600 dark:text-orange-400 mr-3 flex-shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-lg font-semibold text-orange-900 dark:text-orange-300 mb-2">
                    Appareil déjà enregistré
                  </h3>
                  <p className="text-sm text-orange-800 dark:text-orange-400 mb-4">
                    Cet appareil possède déjà un compte utilisateur. Pour des raisons de sécurité, 
                    chaque appareil ne peut avoir qu'un seul utilisateur.
                  </p>
                  <p className="text-sm text-orange-800 dark:text-orange-400">
                    Si vous avez oublié vos identifiants ou si vous souhaitez créer un nouveau compte, 
                    vous devez d'abord réinitialiser l'application.
                  </p>
                </div>
              </div>
            </div>
            <div className="text-center">
              <Link 
                to="/login" 
                className="inline-flex items-center justify-center w-full px-6 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium"
              >
                Retour à la connexion
              </Link>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Nom d'utilisateur
            </label>
            <div className="relative">
              <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                className="input pl-10"
                placeholder="johndoe"
                required
                autoFocus
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Email
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="email"
                value={formData.email}
                onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                className="input pl-10"
                placeholder="john@example.com"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Mot de passe
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                className="input pl-10"
                placeholder="••••••••••••"
                required
                minLength={12}
              />
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Minimum 12 caractères
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Confirmer le mot de passe
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="password"
                value={formData.confirmPassword}
                onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                className="input pl-10"
                placeholder="••••••••••••"
                required
              />
            </div>
          </div>

          {error && (
            <div className="bg-danger-50 border border-danger-200 text-danger-700 px-4 py-3 rounded-lg">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={isLoading}
            className="btn btn-primary w-full"
          >
            {isLoading ? 'Inscription...' : 'S\'inscrire'}
          </button>
        </form>
        )}

        {!checkingUser && !hasUser && (
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Vous avez déjà un compte ?{' '}
              <Link to="/login" className="text-primary-600 hover:text-primary-700 font-medium">
                Se connecter
              </Link>
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Lock, User, Sparkles, Shield, AlertTriangle, LogIn } from 'lucide-react'
import { tauriAPI } from '../lib/tauri-api'
import { useAuthStore } from '../stores/authStore'
import { invoke } from '@tauri-apps/api/tauri'

export default function LoginPage() {
  const navigate = useNavigate()
  const setAuth = useAuthStore((state) => state.setAuth)
  
  const [formData, setFormData] = useState({
    username: '',
    password: '',
  })
  const [loginDelay, setLoginDelay] = useState(0)
  const [remainingTime, setRemainingTime] = useState(0)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)

  // Formater le temps en minutes:secondes
  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60)
    const secs = seconds % 60
    return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`
  }

  // Compte à rebours pour le délai de connexion
  useEffect(() => {
    if (remainingTime > 0) {
      const timer = setInterval(() => {
        setRemainingTime(prev => {
          if (prev <= 1) {
            setLoginDelay(0)
            setError('')
            return 0
          }
          return prev - 1
        })
      }, 1000)
      
      return () => clearInterval(timer)
    }
  }, [remainingTime])

  // Compte à rebours pour le délai de connexion
  useEffect(() => {
    if (remainingTime > 0) {
      const timer = setInterval(() => {
        setRemainingTime(prev => {
          if (prev <= 1) {
            setLoginDelay(0)
            setError('')
            return 0
          }
          return prev - 1
        })
      }, 1000)
      
      return () => clearInterval(timer)
    }
  }, [remainingTime])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      // Tentative de connexion directe - le backend testera le mot de passe
      const response = await tauriAPI.login(formData.username, formData.password)
      
      if (response.success && response.token) {
        // Connexion réussie
        if (response.email) {
          localStorage.setItem('userEmail', response.email)
        }
        
        const user = {
          id: response.user_id?.toString() || '1',
          username: formData.username,
          email: response.email || formData.username + '@local.app'
        }
        
        setAuth(user, response.token, response.token)
        navigate('/')
      } else {
        // Échec de connexion - vérifier le délai d'attente
        const delay = await invoke<number>('check_login_delay', { 
          username: formData.username 
        })
        
        if (delay > 0) {
          setLoginDelay(delay)
          setRemainingTime(delay)
          setError(`⏱️ ${response.message || 'Identifiants incorrects'}. Temps d'attente: ${formatTime(delay)}`)
        } else {
          setError(response.message || 'Identifiants incorrects')
        }
      }
    } catch (err: any) {
      setError(err.message || 'Erreur de connexion')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div 
      className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden"
      style={{ background: 'linear-gradient(135deg, #0a0e1a 0%, #121826 50%, #0f1420 100%)' }}
    >
      {/* Animated background effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full filter blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full filter blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
      </div>

      <div className="relative z-10 max-w-md w-full">
        {/* Header avec effet de glow */}
        <div className="text-center mb-8 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl mb-6 relative"
               style={{
                 background: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)',
                 boxShadow: '0 8px 32px rgba(59, 130, 246, 0.4), 0 0 60px rgba(59, 130, 246, 0.2)'
               }}>
            <Shield className="w-10 h-10 text-white" style={{ filter: 'drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3))' }} />
            <div className="absolute inset-0 rounded-2xl animate-pulse"
                 style={{ boxShadow: '0 0 40px rgba(59, 130, 246, 0.6)' }}></div>
          </div>
          
          <h1 className="text-4xl font-bold mb-3"
              style={{
                background: 'linear-gradient(135deg, #3b82f6 0%, #60a5fa 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                textShadow: '0 0 30px rgba(59, 130, 246, 0.3)'
              }}>
            SecureVault
          </h1>
          <p className="text-gray-400 flex items-center justify-center gap-2">
            <Sparkles className="w-4 h-4" />
            Connexion sécurisée à votre coffre-fort
          </p>
        </div>

        {/* Card avec glassmorphism */}
        <div 
          className="p-8 rounded-2xl backdrop-blur-xl animate-fadeIn"
          style={{
            background: 'rgba(26, 34, 52, 0.8)',
            border: '1px solid rgba(148, 163, 184, 0.1)',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3), 0 0 60px rgba(59, 130, 246, 0.05)'
          }}
        >
          <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username */}
            <div>
              <label className="block text-sm font-semibold mb-2" style={{ color: '#e2e8f0' }}>
                Nom d'utilisateur
              </label>
              <div className="relative group">
                <User className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-colors"
                      style={{ color: '#64748b' }} />
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  className="w-full pl-12 pr-4 py-3.5 rounded-xl transition-all duration-300 focus:outline-none font-medium"
                  style={{
                    background: '#121826',
                    border: '1px solid rgba(148, 163, 184, 0.1)',
                    color: '#e2e8f0'
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = '#3b82f6'
                    e.target.style.boxShadow = '0 0 0 3px rgba(59, 130, 246, 0.1), 0 0 20px rgba(59, 130, 246, 0.1)'
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(148, 163, 184, 0.1)'
                    e.target.style.boxShadow = 'none'
                  }}
                  placeholder="Entrez votre nom d'utilisateur"
                  required
                  autoFocus
                  disabled={remainingTime > 0}
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm font-semibold mb-2" style={{ color: '#e2e8f0' }}>
                Mot de passe
              </label>
              <div className="relative group">
                <Lock className="absolute left-4 top-1/2 transform -translate-y-1/2 w-5 h-5 transition-colors"
                      style={{ color: '#64748b' }} />
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  className="w-full pl-12 pr-4 py-3.5 rounded-xl transition-all duration-300 focus:outline-none font-medium"
                  style={{
                    background: '#121826',
                    border: '1px solid rgba(148, 163, 184, 0.1)',
                    color: '#e2e8f0'
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = '#3b82f6'
                    e.target.style.boxShadow = '0 0 0 3px rgba(59, 130, 246, 0.1), 0 0 20px rgba(59, 130, 246, 0.1)'
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(148, 163, 184, 0.1)'
                    e.target.style.boxShadow = 'none'
                  }}
                  placeholder="••••••••••••"
                  required
                  disabled={remainingTime > 0}
                />
              </div>
            </div>

            {/* Délai d'attente après trop de tentatives */}
            {loginDelay > 0 && remainingTime > 0 && (
              <div className="animate-fadeIn bg-orange-50 dark:bg-orange-900/20 p-6 rounded-xl border-2 border-orange-500 text-center">
                <div className="text-6xl mb-4">⏱️</div>
                <p className="text-xl font-bold mb-2" style={{ color: '#fb923c' }}>
                  Trop de tentatives échouées
                </p>
                <div className="text-5xl font-mono font-bold my-4" style={{ color: '#f97316' }}>
                  {formatTime(remainingTime)}
                </div>
                <p className="text-sm text-gray-400">
                  Veuillez patienter avant de réessayer
                </p>
                <div className="mt-4 w-full bg-gray-700 rounded-full h-2 overflow-hidden">
                  <div 
                    className="bg-orange-500 h-full transition-all duration-1000 ease-linear"
                    style={{ width: `${(remainingTime / loginDelay) * 100}%` }}
                  ></div>
                </div>
              </div>
            )}

            {/* Error message */}
            {error && (
              <div className="p-3 rounded-lg flex items-center gap-2 text-sm"
                   style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.2)', color: '#fca5a5' }}>
                <AlertTriangle className="w-4 h-4" />
                {error}
              </div>
            )}

            {/* Submit button */}
            <button
              type="submit"
              disabled={isLoading || (loginDelay > 0 && remainingTime > 0)}
              className="w-full py-3.5 px-6 rounded-xl font-bold transition-all duration-300 flex items-center justify-center gap-2 text-base"
              style={{
                background: (isLoading || (loginDelay > 0 && remainingTime > 0)) ? '#475569' : 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)',
                color: '#ffffff',
                boxShadow: (isLoading || (loginDelay > 0 && remainingTime > 0)) ? 'none' : '0 4px 16px rgba(59, 130, 246, 0.3)',
                opacity: (loginDelay > 0 && remainingTime > 0) ? 0.5 : 1,
                cursor: (loginDelay > 0 && remainingTime > 0) ? 'not-allowed' : 'pointer'
              }}
              onMouseOver={(e) => !(isLoading || (loginDelay > 0 && remainingTime > 0)) && (e.currentTarget.style.transform = 'translateY(-2px)')}
              onMouseOut={(e) => !(isLoading || (loginDelay > 0 && remainingTime > 0)) && (e.currentTarget.style.transform = 'translateY(0)')}
            >
              {isLoading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  Connexion...
                </>
              ) : (
                <>
                  Se connecter
                  <LogIn className="w-5 h-5" />
                </>
              )}
            </button>
          </form>

          {/* Forgot password link */}
          <div className="mt-4 text-center">
            <Link 
              to="/reset-vault" 
              className="text-sm font-medium transition-colors inline-flex items-center gap-1"
              style={{ color: '#ef4444' }}
              onMouseEnter={(e) => e.currentTarget.style.color = '#dc2626'}
              onMouseLeave={(e) => e.currentTarget.style.color = '#ef4444'}
            >
              <AlertTriangle className="w-4 h-4" />
              Mot de passe oublié ? Réinitialiser le coffre-fort
            </Link>
          </div>

          {/* Sign up link */}
          <div className="mt-4 text-center">
            <p className="text-sm" style={{ color: '#94a3b8' }}>
              Pas encore de compte ?{' '}
              <Link 
                to="/register" 
                className="font-semibold transition-colors"
                style={{ color: '#3b82f6' }}
                onMouseEnter={(e) => e.currentTarget.style.color = '#60a5fa'}
                onMouseLeave={(e) => e.currentTarget.style.color = '#3b82f6'}
              >
                Créer un compte
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

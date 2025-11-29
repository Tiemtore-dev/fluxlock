import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { AlertTriangle, Shield, ArrowLeft, Trash2 } from 'lucide-react'
import { invoke } from '@tauri-apps/api/tauri'

export default function ResetVaultPage() {
  const navigate = useNavigate()
  const [step, setStep] = useState<'warning' | 'confirmation'>('warning')
  const [confirmText, setConfirmText] = useState('')
  const [isResetting, setIsResetting] = useState(false)
  const [error, setError] = useState('')

  const handleReset = async () => {
    if (confirmText !== 'SUPPRIMER TOUT') {
      setError('Veuillez saisir exactement "SUPPRIMER TOUT" pour confirmer')
      return
    }

    setIsResetting(true)
    setError('')

    try {
      await invoke('reset_vault_completely')
      
      // Effacer les données locales
      localStorage.clear()
      sessionStorage.clear()
      
      // Message de succès et redirection
      alert('✅ Coffre-fort complètement réinitialisé. Toutes les données ont été supprimées.')
      navigate('/register')
    } catch (err: any) {
      setError('Erreur: ' + err.toString())
    } finally {
      setIsResetting(false)
    }
  }

  return (
    <div 
      className="min-h-screen flex items-center justify-center p-4 relative overflow-hidden"
      style={{ background: 'linear-gradient(135deg, #1a0a0a 0%, #3a1010 50%, #1f0505 100%)' }}
    >
      {/* Animated background effects */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-red-500/10 rounded-full filter blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-orange-500/10 rounded-full filter blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
      </div>

      <div className="relative z-10 max-w-2xl w-full">
        {/* Header */}
        <div className="text-center mb-8 animate-fadeIn">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl mb-6 relative"
               style={{
                 background: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)',
                 boxShadow: '0 8px 32px rgba(220, 38, 38, 0.4), 0 0 60px rgba(220, 38, 38, 0.2)'
               }}>
            <AlertTriangle className="w-10 h-10 text-white" style={{ filter: 'drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3))' }} />
            <div className="absolute inset-0 rounded-2xl animate-pulse"
                 style={{ boxShadow: '0 0 40px rgba(220, 38, 38, 0.6)' }}></div>
          </div>
          
          <h1 className="text-4xl font-bold mb-3"
              style={{
                background: 'linear-gradient(135deg, #dc2626 0%, #f87171 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                textShadow: '0 0 30px rgba(220, 38, 38, 0.3)'
              }}>
            Réinitialisation du Coffre-Fort
          </h1>
          <p className="text-gray-400 flex items-center justify-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            Action irréversible - Toutes les données seront supprimées
          </p>
        </div>

        {/* Card */}
        <div 
          className="p-8 rounded-2xl backdrop-blur-xl animate-fadeIn"
          style={{
            background: 'rgba(26, 10, 10, 0.8)',
            border: '1px solid rgba(220, 38, 38, 0.2)',
            boxShadow: '0 8px 32px rgba(0, 0, 0, 0.3), 0 0 60px rgba(220, 38, 38, 0.05)'
          }}
        >
          {step === 'warning' && (
            <div className="space-y-6">
              {/* Warning Section */}
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-6">
                <div className="flex items-start gap-4">
                  <AlertTriangle className="w-8 h-8 text-red-500 flex-shrink-0 mt-1" />
                  <div>
                    <h2 className="text-xl font-bold text-red-400 mb-3">
                      ⚠️ ATTENTION - ACTION DANGEREUSE
                    </h2>
                    <p className="text-red-300 mb-4">
                      Cette action supprimera <strong>définitivement et irréversiblement</strong> :
                    </p>
                    <ul className="space-y-2 text-red-200">
                      <li className="flex items-center gap-2">
                        <Trash2 className="w-4 h-4" />
                        <span>Tous vos mots de passe enregistrés</span>
                      </li>
                      <li className="flex items-center gap-2">
                        <Trash2 className="w-4 h-4" />
                        <span>Tous vos fichiers chiffrés</span>
                      </li>
                      <li className="flex items-center gap-2">
                        <Trash2 className="w-4 h-4" />
                        <span>Toutes vos clés cryptographiques</span>
                      </li>
                      <li className="flex items-center gap-2">
                        <Trash2 className="w-4 h-4" />
                        <span>Votre compte utilisateur et paramètres</span>
                      </li>
                      <li className="flex items-center gap-2">
                        <Trash2 className="w-4 h-4" />
                        <span>L'historique des événements de sécurité</span>
                      </li>
                      <li className="flex items-center gap-2">
                        <Trash2 className="w-4 h-4" />
                        <span>La base de données complète du coffre-fort</span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* Info Section */}
              <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4">
                <p className="text-orange-300 text-sm">
                  <strong>💡 Cas d'utilisation :</strong> Utilisez cette fonction uniquement si :
                </p>
                <ul className="mt-2 space-y-1 text-orange-200 text-sm">
                  <li>• Vous avez oublié votre mot de passe maître</li>
                  <li>• Vous souhaitez repartir de zéro avec un nouveau coffre</li>
                  <li>• Vous vendez/donnez votre ordinateur et voulez effacer toute trace</li>
                </ul>
              </div>

              {/* Buttons */}
              <div className="flex gap-4">
                <Link
                  to="/login"
                  className="flex-1 py-3 px-4 rounded-lg font-semibold transition-all flex items-center justify-center gap-2"
                  style={{
                    background: 'rgba(100, 100, 100, 0.3)',
                    border: '1px solid rgba(148, 163, 184, 0.2)',
                    color: '#94a3b8'
                  }}
                >
                  <ArrowLeft className="w-4 h-4" />
                  Retour à la connexion
                </Link>
                
                <button
                  onClick={() => setStep('confirmation')}
                  className="flex-1 py-3 px-4 rounded-lg font-semibold transition-all hover:scale-105 flex items-center justify-center gap-2"
                  style={{
                    background: 'linear-gradient(135deg, #dc2626 0%, #991b1b 100%)',
                    color: 'white',
                    boxShadow: '0 4px 20px rgba(220, 38, 38, 0.4)'
                  }}
                >
                  <AlertTriangle className="w-4 h-4" />
                  Je comprends, continuer
                </button>
              </div>
            </div>
          )}

          {step === 'confirmation' && (
            <div className="space-y-6">
              {/* Confirmation Section */}
              <div>
                <h2 className="text-2xl font-bold text-white mb-4">
                  Confirmation finale
                </h2>
                <p className="text-gray-300 mb-6">
                  Pour confirmer la suppression définitive de toutes vos données, 
                  veuillez saisir exactement le texte suivant :
                </p>
                
                <div className="bg-gray-900/50 border border-gray-700 rounded-lg p-4 mb-4">
                  <p className="text-center text-xl font-bold text-red-400 font-mono">
                    SUPPRIMER TOUT
                  </p>
                </div>

                <input
                  type="text"
                  value={confirmText}
                  onChange={(e) => {
                    setConfirmText(e.target.value)
                    setError('')
                  }}
                  placeholder="Saisissez ici..."
                  className="w-full px-4 py-3 rounded-lg text-center font-mono text-lg"
                  style={{
                    background: 'rgba(0, 0, 0, 0.3)',
                    border: '1px solid rgba(220, 38, 38, 0.3)',
                    color: 'white'
                  }}
                  autoFocus
                />
              </div>

              {error && (
                <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-3">
                  <p className="text-red-300 text-sm text-center">{error}</p>
                </div>
              )}

              {/* Buttons */}
              <div className="flex gap-4">
                <button
                  onClick={() => {
                    setStep('warning')
                    setConfirmText('')
                    setError('')
                  }}
                  className="flex-1 py-3 px-4 rounded-lg font-semibold transition-all"
                  style={{
                    background: 'rgba(100, 100, 100, 0.3)',
                    border: '1px solid rgba(148, 163, 184, 0.2)',
                    color: '#94a3b8'
                  }}
                  disabled={isResetting}
                >
                  Retour
                </button>
                
                <button
                  onClick={handleReset}
                  disabled={isResetting || confirmText !== 'SUPPRIMER TOUT'}
                  className="flex-1 py-3 px-4 rounded-lg font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  style={{
                    background: 'linear-gradient(135deg, #dc2626 0%, #7f1d1d 100%)',
                    border: '1px solid rgba(220, 38, 38, 0.3)',
                    color: 'white',
                    boxShadow: confirmText === 'SUPPRIMER TOUT' ? '0 4px 16px rgba(220, 38, 38, 0.4)' : 'none'
                  }}
                >
                  {isResetting ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                      Suppression en cours...
                    </>
                  ) : (
                    <>
                      <Trash2 className="w-4 h-4" />
                      Supprimer définitivement
                    </>
                  )}
                </button>
              </div>

              <p className="text-xs text-center text-gray-500">
                Cette action ne peut pas être annulée. Toutes vos données seront perdues à jamais.
              </p>
            </div>
          )}
        </div>

        {/* Back link */}
        {step === 'warning' && (
          <div className="mt-6 text-center">
            <Link 
              to="/login" 
              className="text-sm text-gray-400 hover:text-gray-300 transition-colors inline-flex items-center gap-2"
            >
              <Shield className="w-4 h-4" />
              J'ai retrouvé mon mot de passe, retour à la connexion
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}

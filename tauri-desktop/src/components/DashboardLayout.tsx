import { ReactNode } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { 
  LayoutDashboard, 
  Key, 
  Files, 
  Shield, 
  Settings, 
  LogOut,
  Sparkles,
  ShieldCheck
} from 'lucide-react'
import { useAuthStore } from '../stores/authStore'
import { useAutoLock } from '../hooks/useAutoLock'

interface LayoutProps {
  children: ReactNode
}

export default function DashboardLayout({ children }: LayoutProps) {
  const location = useLocation()
  const { user, clearAuth } = useAuthStore()
  
  // Activer le verrouillage automatique
  useAutoLock()

  const navigation = [
    { name: 'Tableau de bord', href: '/', icon: LayoutDashboard },
    { name: 'Mots de passe', href: '/passwords', icon: Key },
    { name: 'Fichiers', href: '/files', icon: Files },
    { name: 'Clés cryptographiques', href: '/keys', icon: Key },
    { name: 'Sécurité', href: '/system-security', icon: ShieldCheck },
    { name: 'Paramètres', href: '/settings', icon: Settings },
  ]

  const handleLogout = () => {
    clearAuth()
  }

  return (
    <div className="min-h-screen" style={{ background: 'linear-gradient(135deg, #0a0e1a 0%, #121826 50%, #0f1420 100%)' }}>
      {/* Sidebar */}
      <div 
        className="fixed inset-y-0 left-0 w-72 border-r animate-slideIn"
        style={{ 
          background: 'linear-gradient(180deg, #121826 0%, #0f1420 100%)',
          borderColor: 'rgba(148, 163, 184, 0.1)',
          boxShadow: '4px 0 24px rgba(0, 0, 0, 0.3)'
        }}
      >
        <div className="flex flex-col h-full">
          {/* Header avec effet lumineux */}
          <div className="relative flex items-center justify-center h-20 px-6 border-b"
               style={{ borderColor: 'rgba(148, 163, 184, 0.1)' }}>
            <div className="absolute inset-0 bg-gradient-to-r from-blue-500/5 to-purple-500/5"></div>
            <Sparkles className="w-8 h-8 text-blue-400 mr-3 relative z-10" style={{ filter: 'drop-shadow(0 0 8px rgba(59, 130, 246, 0.5))' }} />
            <h1 className="text-2xl font-bold relative z-10" style={{
              background: 'linear-gradient(135deg, #3b82f6 0%, #60a5fa 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}>
              SecureVault
            </h1>
          </div>

          {/* Navigation */}
          <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
            {navigation.map((item) => {
              const Icon = item.icon
              const isActive = location.pathname === item.href
              
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`
                    group flex items-center px-4 py-3.5 rounded-xl transition-all duration-300 relative overflow-hidden
                    ${isActive 
                      ? 'text-white' 
                      : 'text-gray-400 hover:text-white'
                    }
                  `}
                  style={isActive ? {
                    background: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)',
                    boxShadow: '0 4px 16px rgba(59, 130, 246, 0.3), 0 0 20px rgba(59, 130, 246, 0.1)'
                  } : {}}
                >
                  {/* Background hover effect */}
                  {!isActive && (
                    <div className="absolute inset-0 bg-white/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300 rounded-xl"></div>
                  )}
                  
                  <Icon className={`w-5 h-5 mr-3 relative z-10 transition-transform duration-300 ${isActive ? 'scale-110' : 'group-hover:scale-110'}`} 
                        style={isActive ? { filter: 'drop-shadow(0 0 4px rgba(255, 255, 255, 0.5))' } : {}} />
                  <span className="font-semibold relative z-10">{item.name}</span>
                  
                  {/* Active indicator */}
                  {isActive && (
                    <div className="absolute right-4 w-1.5 h-1.5 bg-white rounded-full"
                         style={{ boxShadow: '0 0 8px rgba(255, 255, 255, 0.8)' }}></div>
                  )}
                </Link>
              )
            })}
          </nav>

          {/* User section avec design amélioré */}
          <div className="border-t p-6"
               style={{ 
                 borderColor: 'rgba(148, 163, 184, 0.1)',
                 background: 'linear-gradient(180deg, transparent 0%, rgba(59, 130, 246, 0.03) 100%)'
               }}>
            <div className="flex items-center mb-4 p-3 rounded-xl transition-all duration-300 hover:bg-white/5">
              <div className="w-12 h-12 rounded-full flex items-center justify-center mr-3 relative"
                   style={{
                     background: 'linear-gradient(135deg, #3b82f6 0%, #2563eb 100%)',
                     boxShadow: '0 4px 12px rgba(59, 130, 246, 0.3)'
                   }}>
                <span className="text-white font-bold text-lg"
                      style={{ textShadow: '0 2px 4px rgba(0, 0, 0, 0.3)' }}>
                  {user?.username.charAt(0).toUpperCase()}
                </span>
                <div className="absolute inset-0 rounded-full animate-pulse"
                     style={{ boxShadow: '0 0 20px rgba(59, 130, 246, 0.4)' }}></div>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-semibold truncate" style={{ color: '#e2e8f0' }}>
                  {user?.username}
                </p>
                <p className="text-xs truncate" style={{ color: '#64748b' }}>
                  En ligne
                </p>
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center justify-center w-full px-4 py-3 text-sm font-semibold rounded-xl transition-all duration-300 group"
              style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.2)',
                color: '#f87171'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)'
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(239, 68, 68, 0.2)'
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = 'rgba(239, 68, 68, 0.1)'
                e.currentTarget.style.boxShadow = 'none'
              }}
            >
              <LogOut className="w-4 h-4 mr-2 group-hover:scale-110 transition-transform" />
              Déconnexion
            </button>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="pl-72">
        <main className="p-8 min-h-screen">
          <div className="animate-fadeIn">
            {children}
          </div>
        </main>
      </div>
    </div>
  )
}


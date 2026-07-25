import React, { useState, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Plus, X, KeyRound, FolderLock, ArrowLeftRight } from 'lucide-react'
import { Sidebar } from '../organisms/Sidebar'
import { useAutoLock } from '../../hooks/useAutoLock'

interface AppShellProps {
  children: React.ReactNode
}

export function AppShell({ children }: AppShellProps) {
  useAutoLock()
  const navigate = useNavigate()
  const location = useLocation()
  const [fabOpen, setFabOpen] = useState(false)
  const [isMobile, setIsMobile] = useState(false)

  // Hide FAB on auth pages
  const isAuthPage = ['/login', '/register', '/reset-vault'].includes(location.pathname)

  useEffect(() => {
    const mq = window.matchMedia('(max-width: 768px)')
    setIsMobile(mq.matches)
    const handler = (e: MediaQueryListEvent) => setIsMobile(e.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  const fabActions = [
    { icon: KeyRound, label: 'Mot de passe', color: 'var(--accent)', path: '/passwords', event: 'fluxlock:new-entry' },
    { icon: FolderLock, label: 'Fichier', color: '#a78bfa', path: '/files' },
    { icon: ArrowLeftRight, label: 'Transfert', color: '#22d3ee', path: '/transfer' },
  ]

  const handleFabAction = (action: typeof fabActions[0]) => {
    setFabOpen(false)
    if (location.pathname !== action.path) {
      navigate(action.path)
    }
    if (action.event) {
      // Dispatch after a small delay to let navigation settle
      setTimeout(() => window.dispatchEvent(new CustomEvent(action.event!)), 150)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-void)',
    }}>
      <Sidebar />
      <main className="app-main">
        <div className="app-main-inner animate-fade-in">
          {children}
        </div>
      </main>

      {/* Mobile FAB */}
      {isMobile && !isAuthPage && (
        <>
          {/* Overlay backdrop */}
          <div
            onClick={() => setFabOpen(false)}
            className={`fixed inset-0 bg-black/60 z-[998] transition-opacity duration-300 ${fabOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none'}`}
          />

          {/* Bottom Sheet */}
          <div
            className={`fixed inset-x-0 bottom-0 z-[999] bg-surface border-t border-bd rounded-t-[32px] p-6 pb-8 transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)] ${fabOpen ? 'translate-y-0' : 'translate-y-full'}`}
            style={{ paddingBottom: 'calc(env(safe-area-inset-bottom) + 32px)' }}
          >
            <div className="w-12 h-1.5 bg-bd rounded-full mx-auto mb-6" />
            
            <div className="flex items-center justify-between mb-8">
              <h3 className="text-xl font-semibold text-tx-primary font-display">Ajouter</h3>
              <button onClick={() => setFabOpen(false)} className="p-2 rounded-full bg-elevated text-tx-secondary">
                <X size={20} />
              </button>
            </div>

            <div className="grid grid-cols-3 gap-4">
              {fabActions.map((action) => {
                const Icon = action.icon
                return (
                  <div
                    key={action.label}
                    onClick={() => handleFabAction(action)}
                    className="flex flex-col items-center gap-3 cursor-pointer group"
                  >
                    <div className="w-16 h-16 rounded-2xl flex items-center justify-center transition-transform active:scale-95 border border-bd/50" style={{
                      background: `color-mix(in srgb, ${action.color} 15%, var(--bg-surface))`,
                    }}>
                      <Icon size={28} style={{ color: action.color }} />
                    </div>
                    <span className="text-xs font-medium text-tx-secondary font-body text-center leading-tight">
                      {action.label}
                    </span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Main FAB button */}
          <button
            onClick={() => setFabOpen(true)}
            aria-label="Actions rapides"
            className={`fixed right-5 z-[997] w-14 h-14 rounded-full border-none text-white flex items-center justify-center cursor-pointer transition-all duration-300 ${fabOpen ? 'scale-0 opacity-0' : 'scale-100 opacity-100'}`}
            style={{
              bottom: `calc(var(--mobile-bottom-nav-height) + 20px)`,
              background: 'var(--accent)',
              boxShadow: 'var(--shadow-glow)',
            }}
          >
            <Plus size={24} />
          </button>
        </>
      )}
    </div>
  )
}

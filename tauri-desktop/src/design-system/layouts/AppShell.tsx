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
          {fabOpen && (
            <div
              onClick={() => setFabOpen(false)}
              className="fixed inset-0 bg-black/50 z-[998] animate-fadeIn"
            />
          )}

          {/* Action items */}
          {fabOpen && fabActions.map((action, i) => {
            const Icon = action.icon
            const offset = (i + 1) * 64
            return (
              <div
                key={action.label}
                onClick={() => handleFabAction(action)}
                className="fixed right-5 z-[999] flex items-center gap-3 cursor-pointer"
                style={{
                  bottom: `calc(var(--mobile-bottom-nav-height) + 20px + ${offset}px)`,
                  animation: `slideUp 200ms cubic-bezier(0.34, 1.56, 0.64, 1) ${i * 50}ms both`,
                }}
              >
                <span className="px-2.5 py-1 rounded-lg text-xs font-medium whitespace-nowrap shadow-md" style={{
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-body)',
                }}>
                  {action.label}
                </span>
                <div className="w-11 h-11 rounded-full flex items-center justify-center" style={{
                  background: action.color,
                  boxShadow: `0 4px 14px ${action.color}44`,
                }}>
                  <Icon size={20} className="text-white" />
                </div>
              </div>
            )
          })}

          {/* Main FAB button */}
          <button
            onClick={() => setFabOpen((v) => !v)}
            aria-label={fabOpen ? 'Fermer le menu' : 'Actions rapides'}
            className="fixed right-5 z-[999] w-14 h-14 rounded-full border-none text-white flex items-center justify-center cursor-pointer transition-all duration-300"
            style={{
              bottom: `calc(var(--mobile-bottom-nav-height) + 20px)`,
              background: fabOpen ? 'var(--danger)' : 'var(--accent)',
              boxShadow: fabOpen
                ? '0 4px 16px rgba(239, 68, 68, 0.4)'
                : 'var(--shadow-glow)',
              transform: fabOpen ? 'rotate(45deg)' : 'rotate(0deg)',
            }}
          >
            {fabOpen ? <X size={24} /> : <Plus size={24} />}
          </button>
        </>
      )}
    </div>
  )
}

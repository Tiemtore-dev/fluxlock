import React from 'react'
import { Sidebar } from '../organisms/Sidebar'
import { useAutoLock } from '../../hooks/useAutoLock'

interface AppShellProps {
  children: React.ReactNode
}

export function AppShell({ children }: AppShellProps) {
  useAutoLock()

  return (
    <div style={{
      minHeight: '100vh',
      background: 'var(--bg-void)',
    }}>
      <Sidebar />
      <main className="app-main" style={{
        marginLeft: 'var(--sidebar-width)',
        minHeight: '100vh',
        padding: 'var(--space-8)',
      }}>
        <div className="animate-fade-in" style={{ maxWidth: 1100 }}>
          {children}
        </div>
      </main>
    </div>
  )
}

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
      <main className="app-main">
        <div className="app-main-inner animate-fade-in">
          {children}
        </div>
      </main>
    </div>
  )
}

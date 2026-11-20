import type { ReactNode } from 'react'
import { Sidebar } from '../organisms/Sidebar'
import { useAutoLock } from '../../hooks/useAutoLock'

export function AppShell({ children }: { children: ReactNode }) {
  useAutoLock()

  return (
    <div className="vault-shell">
      <a className="skip-link" href="#vault-main">Aller au contenu</a>
      <Sidebar />
      <main id="vault-main" className="app-main" tabIndex={-1}>
        <div className="app-main-inner">{children}</div>
      </main>
    </div>
  )
}

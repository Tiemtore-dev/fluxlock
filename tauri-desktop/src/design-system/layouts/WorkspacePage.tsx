import type { ReactNode } from 'react'
import { AppShell } from './AppShell'

type WorkspacePageProps = {
  title: string
  description?: string
  actions?: ReactNode
  children: ReactNode
}

export function WorkspacePage({ title, description, actions, children }: WorkspacePageProps) {
  return (
    <AppShell>
      <div className="workspace">
        <header className="workspace-header">
          <div>
            <h1>{title}</h1>
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="workspace-actions">{actions}</div>}
        </header>
        {children}
      </div>
    </AppShell>
  )
}

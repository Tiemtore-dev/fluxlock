import React from 'react'
import type { LucideIcon } from 'lucide-react'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description?: string
  action?: React.ReactNode
}

export function EmptyState({ icon: Icon, title, description, action }: EmptyStateProps) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 'var(--space-16) var(--space-8)',
      gap: 'var(--space-4)',
    }}>
      <div style={{
        width: 56,
        height: 56,
        borderRadius: 'var(--radius-xl)',
        background: 'var(--bg-elevated)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}>
        <Icon size={24} style={{ color: 'var(--text-muted)' }} />
      </div>
      <div style={{ textAlign: 'center' }}>
        <p style={{
          fontSize: 'var(--text-base)',
          fontWeight: 500,
          color: 'var(--text-secondary)',
          fontFamily: 'var(--font-body)',
        }}>
          {title}
        </p>
        {description && (
          <p style={{
            fontSize: 'var(--text-sm)',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-body)',
            marginTop: 'var(--space-1)',
          }}>
            {description}
          </p>
        )}
      </div>
      {action}
    </div>
  )
}

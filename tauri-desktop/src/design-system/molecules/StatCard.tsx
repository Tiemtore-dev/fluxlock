import React from 'react'
import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  icon: LucideIcon
  label: string
  value: string | number
  accentColor?: string
}

export function StatCard({ icon: Icon, label, value, accentColor = 'var(--accent)' }: StatCardProps) {
  return (
    <div style={{
      background: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-lg)',
      padding: 'var(--space-5)',
      display: 'flex',
      alignItems: 'center',
      gap: 'var(--space-4)',
      transition: `border-color var(--transition-fast)`,
    }}>
      <div style={{
        width: 40,
        height: 40,
        borderRadius: 'var(--radius-md)',
        background: `color-mix(in srgb, ${accentColor} 15%, transparent)`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexShrink: 0,
      }}>
        <Icon size={20} style={{ color: accentColor }} />
      </div>
      <div>
        <p style={{
          fontSize: 'var(--text-xs)',
          color: 'var(--text-muted)',
          fontFamily: 'var(--font-body)',
          letterSpacing: 'var(--tracking-wide)',
          textTransform: 'uppercase',
        }}>
          {label}
        </p>
        <p style={{
          fontSize: 'var(--text-2xl)',
          fontWeight: 600,
          color: 'var(--text-primary)',
          fontFamily: 'var(--font-body)',
          lineHeight: 'var(--leading-tight)',
        }}>
          {value}
        </p>
      </div>
    </div>
  )
}

import React from 'react'

type BadgeVariant = 'default' | 'success' | 'warning' | 'danger' | 'info' | 'accent'

interface BadgeProps {
  children: React.ReactNode
  variant?: BadgeVariant
  dot?: boolean
  size?: 'sm' | 'md'
  className?: string
}

const variantColors: Record<BadgeVariant, { bg: string; text: string; dot?: string }> = {
  default:  { bg: 'var(--bg-elevated)', text: 'var(--text-secondary)' },
  success:  { bg: 'var(--success-muted)', text: 'var(--success)', dot: 'var(--success)' },
  warning:  { bg: 'var(--warning-muted)', text: 'var(--warning)', dot: 'var(--warning)' },
  danger:   { bg: 'var(--danger-muted)',  text: 'var(--danger)',  dot: 'var(--danger)' },
  info:     { bg: 'var(--info-muted)',    text: 'var(--info)',    dot: 'var(--info)' },
  accent:   { bg: 'var(--accent-muted)',  text: 'var(--accent)',  dot: 'var(--accent)' },
}

export function Badge({ children, variant = 'default', dot = false, size = 'sm', className = '' }: BadgeProps) {
  const colors = variantColors[variant]
  const isSmall = size === 'sm'

  return (
    <span className={className} style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      padding: isSmall ? '2px 8px' : '4px 10px',
      borderRadius: 'var(--radius-full)',
      background: colors.bg,
      color: colors.text,
      fontSize: isSmall ? 'var(--text-xs)' : 'var(--text-sm)',
      fontWeight: 500,
      fontFamily: 'var(--font-body)',
      whiteSpace: 'nowrap',
      letterSpacing: 'var(--tracking-wide)',
    }}>
      {dot && (
        <span style={{
          width: 6, height: 6,
          borderRadius: '50%',
          background: colors.dot || colors.text,
          flexShrink: 0,
        }} />
      )}
      {children}
    </span>
  )
}

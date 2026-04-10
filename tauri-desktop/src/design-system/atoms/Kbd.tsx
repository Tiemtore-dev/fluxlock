import React from 'react'

interface KbdProps {
  children: React.ReactNode
}

export function Kbd({ children }: KbdProps) {
  return (
    <kbd style={{
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      minWidth: '22px',
      height: '22px',
      padding: '0 6px',
      borderRadius: 'var(--radius-sm)',
      background: 'var(--bg-elevated)',
      border: '1px solid var(--border-hover)',
      color: 'var(--text-muted)',
      fontSize: '11px',
      fontFamily: 'var(--font-mono)',
      fontWeight: 500,
      lineHeight: 1,
      boxShadow: 'var(--shadow-sm)',
    }}>
      {children}
    </kbd>
  )
}

import React from 'react'
import { Eye, EyeOff, Copy, Check } from 'lucide-react'

interface PasswordFieldProps {
  value: string
  revealed: boolean
  onToggleReveal: () => void
  onCopy: () => void
  copied?: boolean
}

export function PasswordField({ value, revealed, onToggleReveal, onCopy, copied }: PasswordFieldProps) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 'var(--space-2)',
      background: 'var(--bg-input)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-md)',
      padding: '8px 12px',
    }}>
      <span style={{
        flex: 1,
        fontFamily: 'var(--font-mono)',
        fontSize: 'var(--text-sm)',
        color: 'var(--text-primary)',
        letterSpacing: revealed ? '0.05em' : '0.2em',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        userSelect: revealed ? 'text' : 'none',
      }}>
        {revealed ? value : '••••••••••••'}
      </span>
      <button
        type="button"
        onClick={onToggleReveal}
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: 'var(--text-muted)',
          display: 'flex',
          padding: '4px',
          borderRadius: 'var(--radius-sm)',
          transition: `color var(--transition-fast)`,
        }}
        title={revealed ? 'Masquer' : 'Révéler'}
      >
        {revealed ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
      <button
        type="button"
        onClick={onCopy}
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: copied ? 'var(--success)' : 'var(--text-muted)',
          display: 'flex',
          padding: '4px',
          borderRadius: 'var(--radius-sm)',
          transition: `color var(--transition-fast)`,
        }}
        title="Copier"
      >
        {copied ? <Check size={16} /> : <Copy size={16} />}
      </button>
    </div>
  )
}

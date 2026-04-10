import React from 'react'
import { Search, X } from 'lucide-react'

interface SearchBarProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
}

export function SearchBar({ value, onChange, placeholder = 'Rechercher…' }: SearchBarProps) {
  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: 'var(--space-2)',
      background: 'var(--bg-input)',
      border: '1px solid var(--border)',
      borderRadius: 'var(--radius-md)',
      padding: '8px 12px',
      transition: `border-color var(--transition-fast)`,
    }}>
      <Search size={16} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        style={{
          flex: 1,
          background: 'transparent',
          border: 'none',
          outline: 'none',
          color: 'var(--text-primary)',
          fontFamily: 'var(--font-body)',
          fontSize: 'var(--text-sm)',
        }}
      />
      {value && (
        <button
          type="button"
          onClick={() => onChange('')}
          style={{
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            color: 'var(--text-muted)',
            display: 'flex',
            padding: '2px',
          }}
        >
          <X size={14} />
        </button>
      )}
    </div>
  )
}

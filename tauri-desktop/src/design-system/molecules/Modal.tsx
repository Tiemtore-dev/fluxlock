import React from 'react'
import { X } from 'lucide-react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  children: React.ReactNode
  width?: number
}

export function Modal({ open, onClose, title, children, width = 520 }: ModalProps) {
  if (!open) return null

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 'var(--z-modal)' as any,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 'var(--space-4)',
        overflow: 'auto',
      }}
    >
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="animate-fade-in"
        style={{
          position: 'fixed',
          inset: 0,
          background: 'var(--bg-overlay)',
          backdropFilter: 'blur(4px)',
        }}
      />

      {/* Panel */}
      <div
        className="animate-scale-in"
        style={{
          position: 'relative',
          background: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius-xl)',
          boxShadow: 'var(--shadow-lg)',
          width: '100%',
          maxWidth: width,
          maxHeight: 'calc(100vh - 40px)',
          margin: 'auto',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: 'var(--space-5) var(--space-6)',
          borderBottom: '1px solid var(--border)',
        }}>
          <h2 style={{
            fontSize: 'var(--text-lg)',
            fontWeight: 600,
            color: 'var(--text-primary)',
            fontFamily: 'var(--font-body)',
          }}>
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
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
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{
          padding: 'var(--space-6)',
          overflowY: 'auto',
          flex: 1,
        }}>
          {children}
        </div>
      </div>
    </div>
  )
}

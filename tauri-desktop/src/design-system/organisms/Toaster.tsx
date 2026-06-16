import React, { createContext, useCallback, useContext, useState } from 'react'
import { CheckCircle, AlertTriangle, Info, XCircle, X } from 'lucide-react'

type ToastVariant = 'success' | 'error' | 'warning' | 'info'

interface Toast {
  id: number
  message: string
  variant: ToastVariant
}

interface ToastContextType {
  toast: (message: string, variant?: ToastVariant) => void
}

const ToastContext = createContext<ToastContextType>({ toast: () => {} })

export function useToast() {
  return useContext(ToastContext)
}

let nextId = 0

const icons: Record<ToastVariant, React.ElementType> = {
  success: CheckCircle,
  error: XCircle,
  warning: AlertTriangle,
  info: Info,
}

const colors: Record<ToastVariant, { bg: string; border: string; icon: string }> = {
  success: { bg: 'var(--success-muted)', border: 'var(--success)', icon: 'var(--success)' },
  error: { bg: 'var(--danger-muted)', border: 'var(--danger)', icon: 'var(--danger)' },
  warning: { bg: 'var(--warning-muted)', border: 'var(--warning)', icon: 'var(--warning)' },
  info: { bg: 'var(--info-muted)', border: 'var(--info)', icon: 'var(--info)' },
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback((message: string, variant: ToastVariant = 'info') => {
    const id = nextId++
    setToasts((prev) => [...prev, { id, message, variant }])
    const duration = variant === 'error' ? 6000 : 3500
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, duration)
  }, [])

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}

      {/* Toast container */}
      <div className="toast-container">
        {toasts.map((t) => {
          const Icon = icons[t.variant]
          const color = colors[t.variant]
          return (
            <div
              key={t.id}
              className="toast-item animate-slide-up"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 'var(--space-3)',
                padding: 'var(--space-3) var(--space-4)',
                background: 'var(--bg-elevated)',
                border: `1px solid ${color.border}`,
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-lg)',
                minWidth: 280,
                maxWidth: 420,
                pointerEvents: 'auto',
              }}
            >
              <Icon size={18} style={{ color: color.icon, flexShrink: 0 }} />
              <span style={{
                flex: 1,
                fontSize: 'var(--text-sm)',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-body)',
              }}>
                {t.message}
              </span>
              <button
                type="button"
                onClick={() => dismiss(t.id)}
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
            </div>
          )
        })}
      </div>
    </ToastContext.Provider>
  )
}

import React from 'react'
import type { LucideIcon } from 'lucide-react'

interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  label?: string
  error?: string
  hint?: string
  icon?: LucideIcon
  iconRight?: LucideIcon
  onIconRightClick?: () => void
  iconRightLabel?: string
  size?: 'sm' | 'md' | 'lg'
  fullWidth?: boolean
}

const sizeMap = {
  sm: { padding: '6px 10px', fontSize: 'var(--text-xs)', iconSize: 14 },
  md: { padding: '10px 12px', fontSize: 'var(--text-sm)', iconSize: 16 },
  lg: { padding: '12px 16px', fontSize: 'var(--text-base)', iconSize: 18 },
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, hint, icon: Icon, iconRight: IconRight, onIconRightClick, iconRightLabel = "Afficher ou masquer le mot de passe", size = 'md', fullWidth = true, style, id, ...props }, ref) => {
    const [focused, setFocused] = React.useState(false)
    const generatedId = React.useId()
    const inputId = id || generatedId
    const { padding, fontSize, iconSize } = sizeMap[size]

    const wrapperStyle: React.CSSProperties = {
      display: 'flex',
      flexDirection: 'column',
      gap: 'var(--space-1)',
      width: fullWidth ? '100%' : undefined,
    }

    const containerStyle: React.CSSProperties = {
      display: 'flex',
      alignItems: 'center',
      gap: 'var(--space-2)',
      background: 'var(--bg-input)',
      border: `1px solid ${error ? 'var(--border-error)' : focused ? 'var(--border-focus)' : 'var(--control-border)'}`,
      borderRadius: 'var(--radius-md)',
      padding,
      transition: `all var(--transition-fast)`,
      boxShadow: focused ? '0 0 0 3px var(--accent-muted)' : 'none',
    }

    const inputStyle: React.CSSProperties = {
      flex: 1,
      background: 'transparent',
      border: 'none',
      outline: 'none',
      color: 'var(--text-primary)',
      fontFamily: 'var(--font-body)',
      fontSize,
      lineHeight: 'var(--leading-normal)',
      width: '100%',
      ...style,
    }

    return (
      <div style={wrapperStyle}>
        {label && (
          <label
            htmlFor={inputId}
            style={{
              fontSize: 'var(--text-xs)',
              fontWeight: 500,
              color: 'var(--text-secondary)',
              fontFamily: 'var(--font-body)',
              letterSpacing: 'var(--tracking-normal)',
            }}
          >
            {label}
          </label>
        )}
        <div style={containerStyle}>
          {Icon && <Icon size={iconSize} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />}
          <input
            ref={ref}
            id={inputId}
            aria-invalid={error ? true : undefined}
            aria-describedby={error || hint ? `${inputId}-hint` : undefined}
            onFocus={(e) => { setFocused(true); props.onFocus?.(e) }}
            onBlur={(e) => { setFocused(false); props.onBlur?.(e) }}
            style={inputStyle}
            {...props}
          />
          {IconRight && onIconRightClick && (
            <button
              type="button"
              onClick={onIconRightClick}
              aria-label={iconRightLabel}
              disabled={props.disabled}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--text-muted)',
                display: 'flex',
                padding: 4,
                flexShrink: 0,
              }}
            >
              <IconRight size={iconSize} />
            </button>
          )}
        </div>
        {(error || hint) && (
          <span id={`${inputId}-hint`} style={{
            fontSize: 'var(--text-xs)',
            color: error ? 'var(--danger)' : 'var(--text-muted)',
            fontFamily: 'var(--font-body)',
          }}>
            {error || hint}
          </span>
        )}
      </div>
    )
  }
)

Input.displayName = 'Input'

import React from 'react'
import type { LucideIcon } from 'lucide-react'

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
type ButtonSize = 'sm' | 'md' | 'lg'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  icon?: LucideIcon
  iconRight?: LucideIcon
  loading?: boolean
  fullWidth?: boolean
}

const variantStyles: Record<ButtonVariant, string> = {
  primary: `
    background: var(--accent);
    color: var(--text-inverse);
  `,
  secondary: `
    background: var(--bg-elevated);
    color: var(--text-primary);
    border: 1px solid var(--border);
  `,
  ghost: `
    background: transparent;
    color: var(--text-secondary);
  `,
  danger: `
    background: var(--danger);
    color: var(--text-primary);
  `,
}

const variantHoverStyles: Record<ButtonVariant, string> = {
  primary: `background: var(--accent-hover);`,
  secondary: `background: var(--bg-hover); border-color: var(--border-hover);`,
  ghost: `background: var(--bg-hover); color: var(--text-primary);`,
  danger: `background: var(--danger-hover);`,
}

const sizeStyles: Record<ButtonSize, React.CSSProperties> = {
  sm: { padding: '6px 12px', fontSize: 'var(--text-xs)', gap: '6px', borderRadius: 'var(--radius-sm)' },
  md: { padding: '8px 16px', fontSize: 'var(--text-sm)', gap: '8px', borderRadius: 'var(--radius-md)' },
  lg: { padding: '12px 24px', fontSize: 'var(--text-base)', gap: '10px', borderRadius: 'var(--radius-md)' },
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', icon: Icon, iconRight: IconRight, loading, fullWidth, children, disabled, style, onMouseEnter, onMouseLeave, ...props }, ref) => {
    const [hovered, setHovered] = React.useState(false)

    const baseStyle: React.CSSProperties = {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'var(--font-body)',
      fontWeight: 500,
      letterSpacing: 'var(--tracking-wide)',
      border: 'none',
      cursor: disabled || loading ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.5 : 1,
      transition: `all var(--transition-fast)`,
      whiteSpace: 'nowrap',
      userSelect: 'none',
      width: fullWidth ? '100%' : undefined,
      ...sizeStyles[size],
      ...style,
    }

    // Parse CSS text into style overrides
    const cssText = hovered && !disabled ? variantHoverStyles[variant] : variantStyles[variant]
    const parsedStyle = cssText.split(';').reduce((acc, rule) => {
      const [prop, val] = rule.split(':').map(s => s.trim())
      if (prop && val) {
        const camelProp = prop.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
        acc[camelProp] = val
      }
      return acc
    }, {} as Record<string, string>)

    const iconSize = size === 'sm' ? 14 : size === 'md' ? 16 : 18

    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        style={{ ...baseStyle, ...parsedStyle }}
        onMouseEnter={(e) => { setHovered(true); onMouseEnter?.(e) }}
        onMouseLeave={(e) => { setHovered(false); onMouseLeave?.(e) }}
        {...props}
      >
        {loading ? (
          <span style={{ width: iconSize, height: iconSize, border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 1s linear infinite' }} />
        ) : Icon ? (
          <Icon size={iconSize} />
        ) : null}
        {children}
        {IconRight && !loading && <IconRight size={iconSize} />}
      </button>
    )
  }
)

Button.displayName = 'Button'

/* ─── Icon-only Button ─── */

interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  icon: LucideIcon
  size?: ButtonSize
  variant?: ButtonVariant
  label: string  // Accessibility
}

export const IconButton = React.forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ icon: Icon, size = 'md', variant = 'ghost', label, disabled, style, ...props }, ref) => {
    const [hovered, setHovered] = React.useState(false)

    const dimension = size === 'sm' ? 28 : size === 'md' ? 36 : 44
    const iconSize = size === 'sm' ? 14 : size === 'md' ? 16 : 20

    const cssText = hovered && !disabled ? variantHoverStyles[variant] : variantStyles[variant]
    const parsedStyle = cssText.split(';').reduce((acc, rule) => {
      const [prop, val] = rule.split(':').map(s => s.trim())
      if (prop && val) {
        const camelProp = prop.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
        acc[camelProp] = val
      }
      return acc
    }, {} as Record<string, string>)

    return (
      <button
        ref={ref}
        aria-label={label}
        disabled={disabled}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          width: dimension,
          height: dimension,
          borderRadius: 'var(--radius-md)',
          border: 'none',
          cursor: disabled ? 'not-allowed' : 'pointer',
          opacity: disabled ? 0.5 : 1,
          transition: `all var(--transition-fast)`,
          ...parsedStyle,
          ...style,
        }}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
        {...props}
      >
        <Icon size={iconSize} />
      </button>
    )
  }
)

IconButton.displayName = 'IconButton'

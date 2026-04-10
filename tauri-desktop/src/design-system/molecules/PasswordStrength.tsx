import React from 'react'

interface PasswordStrengthProps {
  password: string
}

function calcStrength(pw: string): { score: number; label: string; color: string } {
  let score = 0
  if (pw.length >= 8) score++
  if (pw.length >= 12) score++
  if (pw.length >= 16) score++
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++
  if (/\d/.test(pw)) score++
  if (/[^a-zA-Z0-9]/.test(pw)) score++

  if (score <= 2) return { score, label: 'Faible', color: 'var(--danger)' }
  if (score <= 4) return { score, label: 'Moyen', color: 'var(--warning)' }
  return { score, label: 'Fort', color: 'var(--success)' }
}

export function PasswordStrength({ password }: PasswordStrengthProps) {
  if (!password) return null
  const { score, label, color } = calcStrength(password)
  const pct = Math.min((score / 6) * 100, 100)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
      <div style={{
        height: 3,
        borderRadius: 'var(--radius-full)',
        background: 'var(--bg-hover)',
        overflow: 'hidden',
      }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          borderRadius: 'var(--radius-full)',
          background: color,
          transition: `width var(--transition-normal)`,
        }} />
      </div>
      <span style={{
        fontSize: 'var(--text-xs)',
        color,
        fontFamily: 'var(--font-body)',
      }}>
        {label}
      </span>
    </div>
  )
}

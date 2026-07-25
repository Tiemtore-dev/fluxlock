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
    <div className="bg-surface border border-bd rounded-xl p-3.5 sm:p-5 flex flex-col sm:flex-row items-start sm:items-center gap-3 sm:gap-4 hover:border-bd-hover hover:shadow-sm transition-all duration-200">
      <div 
        className="w-10 h-10 sm:w-12 sm:h-12 rounded-xl flex items-center justify-center shrink-0"
        style={{ background: `color-mix(in srgb, ${accentColor} 15%, transparent)` }}
      >
        <Icon size={22} className="sm:w-6 sm:h-6" style={{ color: accentColor }} />
      </div>
      <div className="flex flex-col gap-0.5">
        <p className="text-[10px] sm:text-xs text-tx-muted font-body tracking-wider uppercase font-medium line-clamp-1">
          {label}
        </p>
        <p className="text-xl sm:text-2xl font-bold text-tx-primary font-display leading-none">
          {value}
        </p>
      </div>
    </div>
  )
}

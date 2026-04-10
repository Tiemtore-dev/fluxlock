import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'

/**
 * Global keyboard shortcuts:
 * - ⌘K / Ctrl+K — focus search (emits custom event)
 * - ⌘L / Ctrl+L — lock vault (logout)
 * - ⌘N / Ctrl+N — new entry (emits custom event)
 */
export function useKeyboardShortcuts() {
  const navigate = useNavigate()
  const clearAuth = useAuthStore((s) => s.clearAuth)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  useEffect(() => {
    if (!isAuthenticated) return

    const handler = (e: KeyboardEvent) => {
      const mod = e.metaKey || e.ctrlKey
      if (!mod) return

      switch (e.key.toLowerCase()) {
        case 'k':
          e.preventDefault()
          window.dispatchEvent(new CustomEvent('fluxlock:focus-search'))
          break
        case 'l':
          e.preventDefault()
          clearAuth()
          navigate('/login')
          break
        case 'n':
          e.preventDefault()
          window.dispatchEvent(new CustomEvent('fluxlock:new-entry'))
          break
      }
    }

    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [isAuthenticated, clearAuth, navigate])
}

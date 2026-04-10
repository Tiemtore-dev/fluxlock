import { useCallback, useRef } from 'react'

/**
 * Clipboard hook with auto-clear after 30 seconds.
 * Returns a `copy` function that writes text to clipboard
 * and schedules automatic clearance.
 */
export function useClipboard(clearDelay = 30_000) {
  const timerRef = useRef<number | null>(null)

  const copy = useCallback(async (text: string) => {
    await navigator.clipboard.writeText(text)

    // Clear previous timer
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
    }

    // Auto-clear clipboard after delay
    timerRef.current = window.setTimeout(async () => {
      try {
        await navigator.clipboard.writeText('')
      } catch {
        // Clipboard API may be blocked if window lost focus
      }
      timerRef.current = null
    }, clearDelay)
  }, [clearDelay])

  return copy
}

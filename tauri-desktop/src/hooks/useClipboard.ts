import { useCallback } from 'react'
import { copyVaultText } from '../lib/vault-clipboard'

/** Clipboard contents expire after 30 seconds and when the vault is locked. */
export function useClipboard(clearDelay = 30_000) {
  return useCallback((text: string) => copyVaultText(text, clearDelay), [clearDelay])
}

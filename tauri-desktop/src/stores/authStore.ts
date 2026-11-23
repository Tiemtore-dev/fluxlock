import { clearVaultClipboard } from '../lib/vault-clipboard'
import { create } from 'zustand'
import { auth, type VaultDescriptor, type VaultOverview } from '../lib/vault-service'
import { setVaultContext, setVaultToken } from '../lib/vault-context'

interface User { id: string; username: string; email: string }
interface AuthState {
  user: User | null
  isAuthenticated: boolean
  locking: boolean
  lockError: string | null
  dbReady: boolean
  startupError: string | null
  setStartupError: (error: string) => void
  vaults: VaultDescriptor[]
  selectedVault: VaultDescriptor | null
  setAuth: (user: User, token: string) => void
  clearAuth: () => Promise<void>
  acceptNativeLock: () => void
  setDbReady: (ready: boolean) => void
  setOverview: (overview: VaultOverview) => void
  setSelectedVault: (vault: VaultDescriptor) => void
}

sessionStorage.removeItem('auth-storage')
localStorage.removeItem('userEmail')
let lockRequest: Promise<void> | undefined

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null, isAuthenticated: false, locking: false, lockError: null, dbReady: false,
  vaults: [], selectedVault: null, startupError: null,
  setStartupError: (startupError) => set({ startupError, dbReady: false }),
  setAuth: (user, token) => {
    if (!get().selectedVault) throw new Error('Aucun coffre sélectionné')
    setVaultToken(token)
    set({ user, isAuthenticated: true, lockError: null })
  },
  clearAuth: () => {
    if (lockRequest) return lockRequest
    // Start IPC with the old context, then immediately unmount all secret views.
    const request = auth.logout()
    void clearVaultClipboard()
    set({ user: null, isAuthenticated: false, locking: true, lockError: null })
    lockRequest = request.then(() => {
      setVaultToken(null)
      set({ locking: false })
    }).catch((error) => {
      set({ lockError: String(error) })
      throw error
    }).finally(() => { lockRequest = undefined })
    return lockRequest
  },
  acceptNativeLock: () => {
    void clearVaultClipboard()
    setVaultToken(null)
    set({ user: null, isAuthenticated: false, locking: false, lockError: null })
  },
  setDbReady: (dbReady) => set({ dbReady }),
  setOverview: (overview) => {
    const selectedVault = overview.vaults.find((v) => v.id === overview.selected_vault_id) || null
    setVaultContext(selectedVault)
    set({ vaults: overview.vaults, selectedVault })
  },
  setSelectedVault: (vault) => {
    setVaultContext(vault)
    set((state) => ({ selectedVault: vault, vaults: [
      ...state.vaults.filter((entry) => entry.id !== vault.id), vault,
    ] }))
  },
}))

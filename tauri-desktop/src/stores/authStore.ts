import { create } from 'zustand'
import { auth } from '../lib/vault-service'

interface User {
  id: string
  username: string
  email: string
}

interface AuthState {
  user: User | null
  isAuthenticated: boolean
  locking: boolean
  dbReady: boolean
  setAuth: (user: User) => void
  clearAuth: () => Promise<void>
  setDbReady: (ready: boolean) => void
}

sessionStorage.removeItem('auth-storage')
localStorage.removeItem('userEmail')

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isAuthenticated: false,
  locking: false,
  dbReady: false,
  setAuth: (user) => set({ user, isAuthenticated: true }),
  clearAuth: async () => {
    if (get().locking) return
    set({ user: null, isAuthenticated: false, locking: true })
    try {
      await auth.logout()
    } finally {
      set({ locking: false })
    }
  },
  setDbReady: (dbReady) => set({ dbReady }),
}))

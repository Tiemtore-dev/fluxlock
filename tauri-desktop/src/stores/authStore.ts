import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { tauriAPI } from '../lib/tauri-api'

interface User {
  id: string
  username: string
  email: string
}

interface AuthState {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
  dbReady: boolean
  
  setAuth: (user: User, accessToken: string, refreshToken: string) => void
  clearAuth: () => void
  updateAccessToken: (accessToken: string) => void
  setDbReady: (ready: boolean) => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,
      dbReady: false,

      setAuth: (user, accessToken, refreshToken) =>
        set({
          user,
          accessToken,
          refreshToken,
          isAuthenticated: true,
        }),

      clearAuth: () => {
        // Appeler le logout backend
        tauriAPI.logout().catch(console.error)
        
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
        })
      },

      updateAccessToken: (accessToken) =>
        set({ accessToken }),

      setDbReady: (ready) =>
        set({ dbReady: ready }),
    }),
    {
      name: 'auth-storage',
      // CFG-014: Utiliser sessionStorage au lieu de localStorage
      // Les tokens ne survivent pas à la fermeture du navigateur/app
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({
        refreshToken: state.refreshToken,
        user: state.user,
      }) as unknown as AuthState,
    }
  )
)

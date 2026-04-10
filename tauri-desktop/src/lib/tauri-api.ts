import { invoke } from '@tauri-apps/api/core'

// Minimal legacy API — only methods still referenced by authStore.ts and useAutoLock.ts.
// All other operations have moved to vault-service.ts.
export const tauriAPI = {
  async logout() {
    try {
      await invoke('local_logout')
    } catch (error) {
      console.error('Erreur logout:', error)
    }
  },

  async notifyActivity() {
    await invoke('notify_activity')
  },

  async setAutoLockTimeout(minutes: number) {
    await invoke('set_auto_lock_timeout', { minutes })
  },

  async checkAutoLock(): Promise<{ locked: boolean; reason?: string; remaining_seconds?: number; elapsed_minutes?: number }> {
    return await invoke('check_auto_lock')
  }
}

import { useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'
import { tauriAPI } from '../lib/tauri-api'

/**
 * Hook d'auto-verrouillage après inactivité.
 * 
 * Double protection :
 * 1. Frontend : timer JS qui détecte l'inactivité utilisateur
 * 2. Backend  : check_auto_lock vérifie côté Rust (filet de sécurité si le timer JS est tué)
 * 
 * Le backend supprime la clé de chiffrement du Keychain OS et invalide la session.
 */
export function useAutoLock() {
  const navigate = useNavigate()
  const clearAuth = useAuthStore((state) => state.clearAuth)
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)
  const timeoutRef = useRef<number | null>(null)
  const checkIntervalRef = useRef<number | null>(null)
  const pendingLockRef = useRef(false)

  const lockApp = useCallback(() => {
    clearAuth()
    navigate('/login')
  }, [clearAuth, navigate])

  // Notifier le backend de l'activité utilisateur
  const notifyBackendActivity = useCallback(() => {
    tauriAPI.notifyActivity().catch(() => {
      // Silencieux — le backend n'est peut-être pas prêt
    })
  }, [])

  useEffect(() => {
    if (!isAuthenticated) return

    // VULN-019: Lire les paramètres depuis sessionStorage au lieu de localStorage
    // localStorage persiste après fermeture et est manipulable; sessionStorage est éphémère
    const autoLock = sessionStorage.getItem('autoLock') === 'true' || !sessionStorage.getItem('autoLock')
    if (!autoLock) return

    // Récupérer le délai en minutes (défaut: 15 minutes, max 60)
    const rawTimeout = parseInt(sessionStorage.getItem('lockTimeout') || '15')
    const lockTimeout = Math.min(Math.max(rawTimeout, 1), 60) // VULN-019: clamp 1-60 min
    const timeoutMs = lockTimeout * 60 * 1000

    // Synchroniser le timeout avec le backend
    tauriAPI.setAutoLockTimeout(lockTimeout).catch(console.error)

    // Fonction pour réinitialiser le timer d'inactivité
    const resetTimer = () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current)
      }

      // Notifier le backend de l'activité
      notifyBackendActivity()

      // Timer frontend (protection primaire) — reporte si app en arrière-plan
      timeoutRef.current = window.setTimeout(() => {
        if (document.visibilityState === 'visible') {
          lockApp()
        } else {
          pendingLockRef.current = true
        }
      }, timeoutMs)
    }

    // Vérification périodique côté backend (filet de sécurité, toutes les 30s)
    // Ne verrouille l'UI que si l'app est visible — sinon on reporte le lock
    // jusqu'à ce que l'utilisateur revienne (évite le prompt biométrique en arrière-plan)
    checkIntervalRef.current = window.setInterval(async () => {
      try {
        const result = await tauriAPI.checkAutoLock()
        if (result && result.locked) {
          console.log('🔒 Auto-lock backend déclenché:', result.reason)
          if (document.visibilityState === 'visible') {
            lockApp()
          } else {
            // Marquer comme "pending lock" — sera appliqué au retour au premier plan
            pendingLockRef.current = true
          }
        }
      } catch {
        // Silencieux
      }
    }, 30_000)

    // Événements d'interaction utilisateur
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click']
    events.forEach((event) => {
      document.addEventListener(event, resetTimer)
    })

    // Quand l'app redevient visible, appliquer le lock en attente
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && pendingLockRef.current) {
        pendingLockRef.current = false
        lockApp()
      }
    }
    document.addEventListener('visibilitychange', handleVisibilityChange)

    // Démarrer le timer initial
    resetTimer()

    // Nettoyage
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current)
      }
      if (checkIntervalRef.current !== null) {
        window.clearInterval(checkIntervalRef.current)
      }
      events.forEach((event) => {
        document.removeEventListener(event, resetTimer)
      })
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [isAuthenticated, clearAuth, navigate, lockApp, notifyBackendActivity])
}

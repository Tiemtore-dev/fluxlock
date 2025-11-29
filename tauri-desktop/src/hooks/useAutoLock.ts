import { useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'

export function useAutoLock() {
  const navigate = useNavigate()
  const clearAuth = useAuthStore((state) => state.clearAuth)
  const timeoutRef = useRef<number | null>(null)

  useEffect(() => {
    // Vérifier si le verrouillage automatique est activé
    const autoLock = localStorage.getItem('autoLock') === 'true' || !localStorage.getItem('autoLock')
    if (!autoLock) return

    // Récupérer le délai en millisecondes (minutes * 60 * 1000)
    const lockTimeout = parseInt(localStorage.getItem('lockTimeout') || '15')
    const timeoutMs = lockTimeout * 60 * 1000

    // Fonction pour réinitialiser le timer
    const resetTimer = () => {
      // Effacer le timer existant
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current)
      }

      // Créer un nouveau timer
      timeoutRef.current = window.setTimeout(() => {
        // Verrouiller l'application (déconnexion)
        clearAuth()
        navigate('/login')
      }, timeoutMs)
    }

    // Événements à surveiller pour réinitialiser le timer
    const events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart', 'click']

    // Ajouter les écouteurs d'événements
    events.forEach((event) => {
      document.addEventListener(event, resetTimer)
    })

    // Démarrer le timer initial
    resetTimer()

    // Nettoyage lors du démontage
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current)
      }
      events.forEach((event) => {
        document.removeEventListener(event, resetTimer)
      })
    }
  }, [clearAuth, navigate])
}

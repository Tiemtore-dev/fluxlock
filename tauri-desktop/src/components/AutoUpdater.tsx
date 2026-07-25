import { useEffect } from 'react'
import { check } from '@tauri-apps/plugin-updater'
import { useToast } from '../design-system/organisms'

export function AutoUpdater() {
  const { toast } = useToast()

  useEffect(() => {
    let mounted = true

    const checkForUpdates = async () => {
      try {
        // Le plugin updater est uniquement disponible sur Desktop
        // S'il n'est pas supporté (ex: navigateur), ça va throw, on catch silencieusement
        const update = await check()
        
        if (update && update.available && mounted) {
          toast(`Téléchargement de la mise à jour ${update.version}...`, 'info')
          
          let downloaded = 0
          let contentLength: number | undefined = 0
          
          // Téléchargement et installation en arrière-plan
          await update.downloadAndInstall((event) => {
            switch (event.event) {
              case 'Started':
                contentLength = event.data.contentLength
                console.log(`[Updater] Started downloading ${contentLength} bytes`)
                break
              case 'Progress':
                downloaded += event.data.chunkLength
                console.log(`[Updater] Downloaded ${downloaded} from ${contentLength}`)
                break
              case 'Finished':
                console.log('[Updater] Download finished')
                break
            }
          })

          if (mounted) {
            toast('Mise à jour installée avec succès. Veuillez redémarrer l\'application pour l\'appliquer.', 'success')
          }
        }
      } catch (error) {
        console.error('[Updater] Erreur lors de la vérification des mises à jour:', error)
      }
    }

    // Vérifier les mises à jour au démarrage, avec un léger délai pour ne pas ralentir l'ouverture de l'app
    const timer = setTimeout(() => {
      checkForUpdates()
    }, 5000)

    return () => {
      mounted = false
      clearTimeout(timer)
    }
  }, [toast])

  // Ce composant ne rend rien visuellement
  return null
}

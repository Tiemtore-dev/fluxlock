/**
 * Android public storage bridge — calls PublicStorage.kt (window.AndroidStorage).
 *
 * Files are saved to Documents/FluXlock/ so they survive an uninstall of the app.
 * Outside Android (or if the interface is missing), `hasAndroidStorage()` is false.
 */

declare global {
  interface Window {
    AndroidStorage?: {
      saveText(content: string, fileName: string, mimeType: string): string
      saveFile(sourcePath: string, fileName: string, mimeType: string): string
    }
  }
}

export function hasAndroidStorage(): boolean {
  return typeof window.AndroidStorage?.saveText === 'function'
}

function parse(result: string): string {
  if (result.startsWith('ok:')) return result.slice(3)
  if (result === 'needs_permission') {
    throw new Error('Autorisez l\'accès au stockage puis recommencez.')
  }
  throw new Error(result.replace(/^error:/, '') || 'Enregistrement impossible')
}

/** Saves text to Documents/FluXlock/ and returns the human-readable location. */
export function saveTextToPublic(content: string, fileName: string, mimeType: string): string {
  if (!window.AndroidStorage) throw new Error('Stockage Android indisponible')
  return parse(window.AndroidStorage.saveText(content, fileName, mimeType))
}

/** Copies a private file to Documents/FluXlock/ and returns the human-readable location. */
export function saveFileToPublic(sourcePath: string, fileName: string, mimeType: string): string {
  if (!window.AndroidStorage) throw new Error('Stockage Android indisponible')
  return parse(window.AndroidStorage.saveFile(sourcePath, fileName, mimeType))
}

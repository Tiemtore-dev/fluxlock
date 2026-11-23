import { currentVault, captureVaultContext } from './vault-context'
import { biometric } from './vault-service'
import { androidKeystoreDelete, androidKeystoreStore, hasAndroidKeystore } from './android-biometric'

export function biometricAccount(username: string) {
  const vault = currentVault()
  if (!vault) throw new Error('Aucun coffre sélectionné')
  return vault.id === 'legacy' ? `user_bio_${username.toLowerCase()}` : `vault_bio_${vault.id}`
}

export async function enrollBiometrics(password: string, username: string, compatibility?: boolean) {
  const ensureCurrent = captureVaultContext()
  const response = await biometric.enable(password, compatibility)
  if (!hasAndroidKeystore()) return

  const account = biometricAccount(username)
  try {
    const { key_b64 } = JSON.parse(response)
    if (typeof key_b64 !== 'string' || !key_b64) throw new Error('La clé biométrique est indisponible.')
    await androidKeystoreStore(account, key_b64)
    ensureCurrent()
  } catch (error) {
    androidKeystoreDelete(account)
    try { ensureCurrent(); await biometric.disable() } catch { /* Originating session has ended. */ }
    throw error
  }
}


/** Rust removes the enrollment file; Android's hardware alias belongs to the JS bridge. */
export function removeAndroidBiometricEnrollment(username?: string) {
  if (username && hasAndroidKeystore()) androidKeystoreDelete(biometricAccount(username))
}

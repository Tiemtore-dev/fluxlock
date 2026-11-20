import { biometric } from './vault-service'
import { androidKeystoreDelete, androidKeystoreStore, hasAndroidKeystore } from './android-biometric'

export function biometricAccount(username: string) {
  return `user_bio_${username.toLowerCase()}`
}

export async function enrollBiometrics(password: string, username: string, compatibility?: boolean) {
  const response = await biometric.enable(password, compatibility)
  if (!hasAndroidKeystore()) return

  const account = biometricAccount(username)
  try {
    const { key_b64 } = JSON.parse(response)
    if (typeof key_b64 !== 'string' || !key_b64) throw new Error('La clé biométrique est indisponible.')
    await androidKeystoreStore(account, key_b64)
  } catch (error) {
    androidKeystoreDelete(account)
    await biometric.disable().catch(() => {})
    throw error
  }
}

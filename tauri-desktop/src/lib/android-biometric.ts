/**
 * Android biometric bridge — calls BiometricPrompt via the native JS interface
 * registered by BiometricBridge.kt.
 *
 * On non-Android platforms (or when the interface is absent), every call
 * falls through to the Rust backend's existing biometric flow.
 *
 * Key storage uses Android Keystore (TEE/StrongBox) with CryptoObject-based
 * biometric authentication — the AES-256-GCM key never leaves the secure hardware.
 */

declare global {
  interface Window {
    AndroidBiometric?: {
      isAvailable(): boolean
      getBiometricType(): string
      authenticate(reason: string, callbackId: string): void
      // Hardware-backed key storage (Android Keystore + BiometricPrompt CryptoObject)
      storeKey(account: string, plainB64: string, callbackId: string): void
      retrieveKey(account: string, callbackId: string): void
      deleteKey(account: string): boolean
    }
    __biometricResolve?: (id: string, success: boolean, error: string) => void
    __keystoreResolve?: (id: string, success: boolean, error: string, data: string) => void
  }
}

/** True when running inside the Android WebView with the native bridge. */
export function hasAndroidBiometric(): boolean {
  return typeof window.AndroidBiometric?.isAvailable === 'function'
}

export function androidBiometricAvailable(): boolean {
  try {
    return window.AndroidBiometric?.isAvailable() ?? false
  } catch {
    return false
  }
}

export function androidBiometricType(): string {
  try {
    return window.AndroidBiometric?.getBiometricType() ?? 'none'
  } catch {
    return 'none'
  }
}

let callbackCounter = 0
const pendingCallbacks = new Map<string, { resolve: (v: boolean) => void; reject: (e: Error) => void }>()

// Global callback invoked from Kotlin via evaluateJavascript
window.__biometricResolve = (id: string, success: boolean, error: string) => {
  const cb = pendingCallbacks.get(id)
  if (!cb) return
  pendingCallbacks.delete(id)
  if (success) {
    cb.resolve(true)
  } else {
    cb.reject(new Error(error || 'Authentification biométrique annulée'))
  }
}

/** Show Android BiometricPrompt. Resolves true on success, rejects on failure/cancel. */
export function androidAuthenticate(reason: string): Promise<boolean> {
  return new Promise((resolve, reject) => {
    if (!window.AndroidBiometric) {
      reject(new Error('Android biometric bridge unavailable'))
      return
    }
    const id = `bio_${++callbackCounter}_${Date.now()}`
    pendingCallbacks.set(id, { resolve, reject })
    try {
      window.AndroidBiometric.authenticate(reason, id)
    } catch (e) {
      pendingCallbacks.delete(id)
      reject(e)
    }
    // Auto-cleanup after 60s (timeout safety net)
    setTimeout(() => {
      if (pendingCallbacks.has(id)) {
        pendingCallbacks.delete(id)
        reject(new Error('Biometric timeout'))
      }
    }, 60_000)
  })
}

// ═══════════════════════════════════════════════════════════════
// Hardware-backed key storage (Android Keystore TEE/StrongBox)
//
// Uses AES-256-GCM key generated inside the secure hardware.
// Each encrypt/decrypt operation requires fresh biometric auth
// via BiometricPrompt + CryptoObject (auth-per-use).
// ═══════════════════════════════════════════════════════════════

const pendingKeystoreCallbacks = new Map<string, {
  resolve: (data: string | null) => void
  reject: (e: Error) => void
}>()

// Global callback invoked from Kotlin via evaluateJavascript
window.__keystoreResolve = (id: string, success: boolean, error: string, data: string) => {
  const cb = pendingKeystoreCallbacks.get(id)
  if (!cb) return
  pendingKeystoreCallbacks.delete(id)
  if (success) {
    cb.resolve(data || null)
  } else {
    cb.reject(new Error(error || 'Keystore operation failed'))
  }
}

/** True when the Android Keystore bridge is available (storeKey/retrieveKey). */
export function hasAndroidKeystore(): boolean {
  return typeof window.AndroidBiometric?.storeKey === 'function'
}

/**
 * Store a secret in Android Keystore (TEE/StrongBox) with biometric protection.
 * Triggers BiometricPrompt — the AES key used for encryption requires fingerprint/face.
 */
export function androidKeystoreStore(account: string, plainB64: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (!window.AndroidBiometric?.storeKey) {
      reject(new Error('Android Keystore bridge unavailable'))
      return
    }
    const id = `ks_store_${++callbackCounter}_${Date.now()}`
    pendingKeystoreCallbacks.set(id, {
      resolve: () => resolve(),
      reject
    })
    try {
      window.AndroidBiometric.storeKey(account, plainB64, id)
    } catch (e) {
      pendingKeystoreCallbacks.delete(id)
      reject(e)
    }
    setTimeout(() => {
      if (pendingKeystoreCallbacks.has(id)) {
        pendingKeystoreCallbacks.delete(id)
        reject(new Error('Keystore store timeout'))
      }
    }, 60_000)
  })
}

/**
 * Retrieve and decrypt a secret from Android Keystore with biometric authentication.
 * Returns the plaintext base64 string. Triggers BiometricPrompt.
 */
export function androidKeystoreRetrieve(account: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!window.AndroidBiometric?.retrieveKey) {
      reject(new Error('Android Keystore bridge unavailable'))
      return
    }
    const id = `ks_get_${++callbackCounter}_${Date.now()}`
    pendingKeystoreCallbacks.set(id, {
      resolve: (data) => {
        if (data) {
          resolve(data)
        } else {
          reject(new Error('Keystore returned empty data'))
        }
      },
      reject
    })
    try {
      window.AndroidBiometric.retrieveKey(account, id)
    } catch (e) {
      pendingKeystoreCallbacks.delete(id)
      reject(e)
    }
    setTimeout(() => {
      if (pendingKeystoreCallbacks.has(id)) {
        pendingKeystoreCallbacks.delete(id)
        reject(new Error('Keystore retrieve timeout'))
      }
    }, 60_000)
  })
}

/**
 * Delete a key from Android Keystore.
 */
export function androidKeystoreDelete(account: string): boolean {
  try {
    return window.AndroidBiometric?.deleteKey(account) ?? false
  } catch {
    return false
  }
}

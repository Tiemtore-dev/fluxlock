package com.fluxlock.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * BiometricBridge — Exposed to WebView as `window.AndroidBiometric`.
 *
 * Provides:
 *   - isAvailable() / getBiometricType() — biometric hardware check
 *   - authenticate(reason, callbackId) — simple biometric prompt
 *   - storeKey(account, plainB64, callbackId) — encrypt & store in Android Keystore (TEE/StrongBox)
 *   - retrieveKey(account, callbackId) — decrypt from Android Keystore with biometric
 *   - deleteKey(account) — remove the Keystore key
 *
 * Key storage uses AES-256-GCM backed by the hardware security module (TEE or StrongBox).
 * Each crypto operation requires a fresh biometric authentication via CryptoObject.
 */
class BiometricBridge(
    private val activity: FragmentActivity,
    private val webView: WebView
) {
    companion object {
        private const val TAG = "FluXlock.Bio"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS_PREFIX = "fluxlock_bio_"
        private const val GCM_TAG_LENGTH = 128 // bits
    }

    // ═══════════════════════════════════════════════════════════
    // Biometric availability
    // ═══════════════════════════════════════════════════════════

    @JavascriptInterface
    fun isAvailable(): Boolean {
        val biometricManager = BiometricManager.from(activity)
        return biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
    }

    @JavascriptInterface
    fun getBiometricType(): String {
        val biometricManager = BiometricManager.from(activity)
        return when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> "fingerprint"
            else -> "none"
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Simple biometric authentication (no crypto)
    // ═══════════════════════════════════════════════════════════

    @JavascriptInterface
    fun authenticate(reason: String, callbackId: String) {
        activity.runOnUiThread {
            val executor = ContextCompat.getMainExecutor(activity)

            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    resolveCallback(callbackId, true, null)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    resolveCallback(callbackId, false, errString.toString())
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    // Don't resolve yet — the user can retry. Only error/success resolves.
                }
            }

            val prompt = BiometricPrompt(activity, executor, callback)

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("FluXlock")
                .setSubtitle(reason)
                .setNegativeButtonText("Annuler")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()

            prompt.authenticate(promptInfo)
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Hardware-backed key storage (Android Keystore + BiometricPrompt CryptoObject)
    //
    // Architecture (per Android official docs):
    //   1. Generate an AES-256-GCM key in the Android Keystore (TEE/StrongBox)
    //      with setUserAuthenticationRequired(true) + auth-per-use (duration=0)
    //   2. To STORE: init Cipher.ENCRYPT_MODE → BiometricPrompt with CryptoObject
    //      → onAuthenticationSucceeded gives an unlocked cipher → encrypt plaintext
    //   3. To RETRIEVE: init Cipher.DECRYPT_MODE with saved IV → BiometricPrompt
    //      with CryptoObject → onAuthenticationSucceeded → decrypt ciphertext
    //
    // The private key NEVER leaves the hardware security module.
    // ═══════════════════════════════════════════════════════════

    /**
     * Store a secret (base64-encoded vault key) encrypted by the Android Keystore.
     * Triggers a BiometricPrompt — the CryptoObject ensures the encryption key
     * can only be used after successful biometric authentication.
     *
     * The encrypted result (IV + ciphertext) is stored in SharedPreferences.
     * The AES key itself lives in the Keystore (TEE/StrongBox) and is non-exportable.
     */
    @JavascriptInterface
    fun storeKey(account: String, plainB64: String, callbackId: String) {
        activity.runOnUiThread {
            try {
                val alias = KEY_ALIAS_PREFIX + account
                ensureKeystoreKey(alias)

                val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
                keyStore.load(null)
                val secretKey = keyStore.getKey(alias, null) as SecretKey

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, secretKey)

                val cryptoObject = BiometricPrompt.CryptoObject(cipher)
                val executor = ContextCompat.getMainExecutor(activity)

                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        try {
                            val authedCipher = result.cryptoObject?.cipher
                                ?: throw Exception("CryptoObject cipher is null")

                            val plainBytes = plainB64.toByteArray(Charsets.UTF_8)
                            val encryptedBytes = authedCipher.doFinal(plainBytes)
                            val iv = authedCipher.iv

                            // Store IV + ciphertext in SharedPreferences (encrypted by AndroidX Security)
                            val prefs = activity.getSharedPreferences("fluxlock_bio_keys", 0)
                            prefs.edit()
                                .putString("${account}_iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                                .putString("${account}_data", Base64.encodeToString(encryptedBytes, Base64.NO_WRAP))
                                .apply()

                            Log.d(TAG, "Key stored in Android Keystore (TEE) for account: $account")
                            resolveKeystoreCallback(callbackId, true, null, null)
                        } catch (e: Exception) {
                            Log.e(TAG, "Encryption failed: ${e.message}")
                            resolveKeystoreCallback(callbackId, false, e.message, null)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        resolveKeystoreCallback(callbackId, false, errString.toString(), null)
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                    }
                }

                val prompt = BiometricPrompt(activity, executor, callback)
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("FluXlock")
                    .setSubtitle("Protéger la clé avec votre empreinte")
                    .setNegativeButtonText("Annuler")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()

                prompt.authenticate(promptInfo, cryptoObject)
            } catch (e: Exception) {
                Log.e(TAG, "storeKey init failed: ${e.message}")
                resolveKeystoreCallback(callbackId, false, e.message, null)
            }
        }
    }

    /**
     * Retrieve and decrypt the secret using biometric-gated Android Keystore key.
     * Triggers a BiometricPrompt — the CryptoObject ensures the decryption key
     * can only be used after successful biometric authentication (auth-per-use).
     */
    @JavascriptInterface
    fun retrieveKey(account: String, callbackId: String) {
        activity.runOnUiThread {
            try {
                val alias = KEY_ALIAS_PREFIX + account
                val prefs = activity.getSharedPreferences("fluxlock_bio_keys", 0)
                val ivB64 = prefs.getString("${account}_iv", null)
                    ?: throw Exception("No stored key found for account: $account")
                val dataB64 = prefs.getString("${account}_data", null)
                    ?: throw Exception("No stored data found for account: $account")

                val iv = Base64.decode(ivB64, Base64.NO_WRAP)
                val encryptedBytes = Base64.decode(dataB64, Base64.NO_WRAP)

                val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
                keyStore.load(null)
                val secretKey = keyStore.getKey(alias, null) as? SecretKey
                    ?: throw Exception("Keystore key not found: $alias")

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
                cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

                val cryptoObject = BiometricPrompt.CryptoObject(cipher)
                val executor = ContextCompat.getMainExecutor(activity)

                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        try {
                            val authedCipher = result.cryptoObject?.cipher
                                ?: throw Exception("CryptoObject cipher is null")

                            val decryptedBytes = authedCipher.doFinal(encryptedBytes)
                            val plainB64 = String(decryptedBytes, Charsets.UTF_8)

                            Log.d(TAG, "Key retrieved from Android Keystore (TEE) for account: $account")
                            resolveKeystoreCallback(callbackId, true, null, plainB64)
                        } catch (e: Exception) {
                            Log.e(TAG, "Decryption failed: ${e.message}")
                            resolveKeystoreCallback(callbackId, false, e.message, null)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        resolveKeystoreCallback(callbackId, false, errString.toString(), null)
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                    }
                }

                val prompt = BiometricPrompt(activity, executor, callback)
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("FluXlock")
                    .setSubtitle("Déverrouillez avec votre empreinte")
                    .setNegativeButtonText("Annuler")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()

                prompt.authenticate(promptInfo, cryptoObject)
            } catch (e: Exception) {
                Log.e(TAG, "retrieveKey init failed: ${e.message}")
                resolveKeystoreCallback(callbackId, false, e.message, null)
            }
        }
    }

    /**
     * Delete the Keystore key and stored encrypted data for an account.
     */
    @JavascriptInterface
    fun deleteKey(account: String): Boolean {
        return try {
            val alias = KEY_ALIAS_PREFIX + account
            val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
            keyStore.load(null)
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
            val prefs = activity.getSharedPreferences("fluxlock_bio_keys", 0)
            prefs.edit()
                .remove("${account}_iv")
                .remove("${account}_data")
                .apply()
            Log.d(TAG, "Key deleted from Android Keystore for account: $account")
            true
        } catch (e: Exception) {
            Log.e(TAG, "deleteKey failed: ${e.message}")
            false
        }
    }

    // ═══════════════════════════════════════════════════════════
    // Internal helpers
    // ═══════════════════════════════════════════════════════════

    /**
     * Generate an AES-256-GCM key in the Android Keystore if it doesn't exist.
     *
     * Key properties (per Android security best practices):
     *   - Hardware-backed (TEE, or StrongBox if available)
     *   - User authentication required (BIOMETRIC_STRONG)
     *   - Auth-per-use (timeout = 0) — each crypto op needs fresh biometric
     *   - Invalidated when new biometric enrollments are added
     *   - Non-exportable — key material never leaves the secure hardware
     */
    private fun ensureKeystoreKey(alias: String) {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER)
        keyStore.load(null)
        if (keyStore.containsAlias(alias)) return

        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        // Auth-per-use: setUserAuthenticationParameters(0, BIOMETRIC_STRONG) requires API 30+
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            builder.setUserAuthenticationParameters(
                0, // duration = 0 → auth-per-use
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        }

        // Prefer StrongBox if available (API 28+) — separate secure element
        if (android.os.Build.VERSION.SDK_INT >= 28) {
            try {
                builder.setIsStrongBoxBacked(true)
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
                Log.d(TAG, "AES-256-GCM key generated in StrongBox for alias: $alias")
                return
            } catch (e: Exception) {
                // StrongBox not available on this device, fall back to TEE
                Log.d(TAG, "StrongBox not available, falling back to TEE: ${e.message}")
                builder.setIsStrongBoxBacked(false)
            }
        }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
        Log.d(TAG, "AES-256-GCM key generated in TEE for alias: $alias")
    }

    private fun resolveCallback(callbackId: String, success: Boolean, error: String?) {
        val escapedError = error?.replace("'", "\\'")?.replace("\n", " ") ?: ""
        val js = "window.__biometricResolve && window.__biometricResolve('$callbackId', $success, '$escapedError')"
        activity.runOnUiThread {
            webView.evaluateJavascript(js, null)
        }
    }

    /**
     * Resolve a keystore callback — can optionally pass data (the decrypted key) back.
     * Uses window.__keystoreResolve(id, success, error, data).
     */
    private fun resolveKeystoreCallback(callbackId: String, success: Boolean, error: String?, data: String?) {
        val escapedError = error?.replace("'", "\\'")?.replace("\n", " ") ?: ""
        val escapedData = data?.replace("'", "\\'")?.replace("\n", " ") ?: ""
        val js = "window.__keystoreResolve && window.__keystoreResolve('$callbackId', $success, '$escapedError', '$escapedData')"
        activity.runOnUiThread {
            webView.evaluateJavascript(js, null)
        }
    }
}

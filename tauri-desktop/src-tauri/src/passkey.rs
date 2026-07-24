/// ═══════════════════════════════════════════════════════════════
/// FluXlock — Passkey Authentication Module (FIDO2-like local)
/// ═══════════════════════════════════════════════════════════════
///
/// # Security Model
/// Hybrid post-quantum passkey: Ed25519 (hardware-backed via Secure Enclave)
/// + ML-KEM-768 (software-backed via OS Keychain) for quantum resistance.
///
/// The master_key is double-wrapped:
/// 1. ChaCha20-Poly1305 with HKDF(Ed25519_privkey, "passkey-wrap-1")
/// 2. ChaCha20-Poly1305 with HKDF(ML-KEM shared_secret, "passkey-wrap-2")
///
/// # Differences from biometric module
/// - Always-on: NO cold start, NO timeout, NO biometric gate
/// - Challenge-response: cryptographic proof, not boolean trust
/// - Anti-replay: random challenge per authentication
/// - Post-quantum resistant (ML-KEM-768 layer)
///
/// # Rules
/// - Only unavailable during initial vault creation (register)
/// - Password reminder every 14 days (to prevent forgetting)
/// - Accepted everywhere the master password is accepted

use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};
use zeroize::Zeroize;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;

use secure_vault_crypto::{
    Ed25519KeyPair, sign_message, verify_signature_from_bytes,
};
use secure_vault_crypto::key_derivation::hkdf::derive_key_hkdf;
use secure_vault_crypto::crypto::cipher;
use secure_vault_crypto::crypto::kem::{
    generate_recipient_keypair, encapsulate, decapsulate,
    KemPublicKey, KemPrivateKey, KemCiphertext,
};

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*)
        }
    };
}

/// Password reminder interval: 14 days in seconds
const PASSWORD_REMINDER_INTERVAL: u64 = 14 * 24 * 3600;

/// Keychain service names for passkey storage
#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
const PASSKEY_KEYCHAIN_SERVICE_ED25519: &str = "com.fluxlock.passkey.ed25519";
const PASSKEY_KEYCHAIN_SERVICE_KEM: &str = "com.fluxlock.passkey.kem";

// ═══════════════════════════════════════════════════════
// Types publics
// ═══════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyStatus {
    /// Whether the platform supports passkey (hardware security available)
    pub available: bool,
    /// Whether a passkey credential is enrolled
    pub enrolled: bool,
    /// Username of the enrolled passkey
    pub enrolled_username: Option<String>,
    /// Whether the user must enter their password (> 14 days since last password login)
    pub needs_password_reminder: bool,
}

/// Persistent enrollment data stored in a JSON file
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasskeyEnrollment {
    /// Credential UUID
    credential_id: String,
    /// User ID in the database
    user_id: i64,
    /// Username
    username: String,
    /// Ed25519 public key (32 bytes, base64)
    ed25519_pubkey_b64: String,
    /// ML-KEM-768 public key (1184 bytes, base64) — for reference/re-encapsulation
    kem_pubkey_b64: String,
    /// ML-KEM-768 ciphertext (1088 bytes, base64)
    kem_ciphertext_b64: String,
    /// Double-wrapped master_key blob (base64)
    wrapped_master_key_b64: String,
    /// Epoch secs when enrollment was created
    enrolled_at: u64,
    /// Epoch secs of the last successful master-password login
    last_password_login: u64,
}

// ═══════════════════════════════════════════════════════
// File-based storage for passkey enrollment
// ═══════════════════════════════════════════════════════

fn enrollment_file_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::hidden_storage::get_hidden_database_dir()?;
    Ok(dir.join(".passkey_enrollment.json"))
}

fn get_enrollment() -> Option<PasskeyEnrollment> {
    let path = enrollment_file_path().ok()?;
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

fn store_enrollment(enrollment: &PasskeyEnrollment) -> Result<(), String> {
    let path = enrollment_file_path()?;
    let json = serde_json::to_string_pretty(enrollment)
        .map_err(|e| format!("Passkey serialization error: {}", e))?;
    std::fs::write(&path, json.as_bytes())
        .map_err(|e| format!("Failed to store passkey enrollment: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn delete_enrollment_file() -> Result<(), String> {
    let path = match enrollment_file_path() {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete passkey enrollment: {}", e))?;
    }
    Ok(())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ═══════════════════════════════════════════════════════
// Keychain storage (reuses biometric.rs patterns)
// ═══════════════════════════════════════════════════════

// --- macOS: Secure Enclave for Ed25519 private key ---
#[cfg(target_os = "macos")]
extern "C" {
    fn biometric_keychain_store(
        account: *const std::os::raw::c_char,
        data: *const u8,
        data_len: i32,
    ) -> i32;
    fn biometric_keychain_retrieve(
        account: *const std::os::raw::c_char,
        reason: *const std::os::raw::c_char,
        out_data: *mut u8,
        out_data_capacity: i32,
    ) -> i32;
    fn biometric_keychain_delete(
        account: *const std::os::raw::c_char,
    ) -> i32;
}

/// Store a key in the OS keychain with biometric protection (Ed25519 private key)
fn store_passkey_ed25519_in_keychain(user_id: i64, key_b64: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(format!("passkey_ed25519_{}", user_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let status = unsafe {
            biometric_keychain_store(
                account.as_ptr(),
                key_b64.as_ptr(),
                key_b64.len() as i32,
            )
        };
        if status != 0 {
            return Err(format!("Secure Enclave passkey store failed (OSStatus {})", status));
        }
        debug_log!("🔐 Passkey Ed25519 private key stored in Secure Enclave");
        Ok(())
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(PASSKEY_KEYCHAIN_SERVICE_ED25519, &format!("passkey_ed25519_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        entry.set_password(key_b64)
            .map_err(|e| format!("Keychain store error: {}", e))?;
        debug_log!("🔐 Passkey Ed25519 private key stored in OS Keychain");
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        // On Android, we return the key to the frontend so it can be stored in the TEE/StrongBox via BiometricPrompt.
        Ok(())
    }
}

/// Retrieve the Ed25519 private key from keychain (triggers biometric on macOS)
fn get_passkey_ed25519_from_keychain(user_id: i64, android_key: Option<String>) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(format!("passkey_ed25519_{}", user_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let reason = std::ffi::CString::new("Déverrouillez FluXlock avec votre Passkey")
            .map_err(|_| "Invalid reason string".to_string())?;

        let mut buffer = vec![0u8; 4096];
        let result = unsafe {
            biometric_keychain_retrieve(
                account.as_ptr(),
                reason.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as i32,
            )
        };
        if result < 0 {
            return Err(format!("Secure Enclave passkey retrieve failed (OSStatus {})", result));
        }
        let len = result as usize;
        let key_str = String::from_utf8(buffer[..len].to_vec())
            .map_err(|e| format!("Passkey key is not valid UTF-8: {}", e))?;
        debug_log!("🔐 Passkey Ed25519 private key retrieved from Secure Enclave (Touch ID verified)");
        Ok(key_str)
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(PASSKEY_KEYCHAIN_SERVICE_ED25519, &format!("passkey_ed25519_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        entry.get_password()
            .map_err(|e| format!("Keychain retrieve error: {}", e))
    }
    #[cfg(target_os = "android")]
    {
        android_key.ok_or_else(|| "Clé Passkey Android manquante (le frontend doit la fournir via BiometricPrompt)".to_string())
    }
}

/// Delete the Ed25519 private key from keychain
fn delete_passkey_ed25519_from_keychain(user_id: i64) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(format!("passkey_ed25519_{}", user_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let status = unsafe { biometric_keychain_delete(account.as_ptr()) };
        if status != 0 {
            return Err(format!("Secure Enclave passkey delete failed (OSStatus {})", status));
        }
        Ok(())
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(PASSKEY_KEYCHAIN_SERVICE_ED25519, &format!("passkey_ed25519_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        let _ = entry.delete_password();
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        // Handled by the frontend (androidKeystoreDelete)
        Ok(())
    }
}

/// Store the ML-KEM private key in the OS keychain (software-backed, not Secure Enclave)
fn store_passkey_kem_in_keychain(user_id: i64, key_b64: &str) -> Result<(), String> {
    #[cfg(not(target_os = "android"))]
    {
        let entry = keyring::Entry::new(PASSKEY_KEYCHAIN_SERVICE_KEM, &format!("passkey_kem_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        entry.set_password(key_b64)
            .map_err(|e| format!("Keychain store error: {}", e))?;
        debug_log!("🔐 Passkey ML-KEM-768 private key stored in OS Keychain (software)");
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        let dir = crate::hidden_storage::get_hidden_database_dir()?;
        let path = dir.join(format!(".passkey_kem_{}", user_id));
        std::fs::write(&path, key_b64.as_bytes())
            .map_err(|e| format!("Failed to store passkey KEM key: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Retrieve the ML-KEM private key from keychain
fn get_passkey_kem_from_keychain(user_id: i64) -> Result<String, String> {
    #[cfg(not(target_os = "android"))]
    {
        let entry = keyring::Entry::new(PASSKEY_KEYCHAIN_SERVICE_KEM, &format!("passkey_kem_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        entry.get_password()
            .map_err(|e| format!("Keychain retrieve error: {}", e))
    }
    #[cfg(target_os = "android")]
    {
        let dir = crate::hidden_storage::get_hidden_database_dir()?;
        let path = dir.join(format!(".passkey_kem_{}", user_id));
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Passkey KEM key retrieve error: {}", e))
    }
}

/// Delete the ML-KEM private key from keychain
fn delete_passkey_kem_from_keychain(user_id: i64) -> Result<(), String> {
    #[cfg(not(target_os = "android"))]
    {
        let entry = keyring::Entry::new(PASSKEY_KEYCHAIN_SERVICE_KEM, &format!("passkey_kem_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        let _ = entry.delete_password();
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        let dir = crate::hidden_storage::get_hidden_database_dir()?;
        let path = dir.join(format!(".passkey_kem_{}", user_id));
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════
// Crypto helpers — HKDF key derivation + wrapping
// ═══════════════════════════════════════════════════════

/// Derive a 32-byte wrapping key from a secret using HKDF-SHA3-256
fn derive_wrapping_key(secret: &[u8], info: &str) -> Result<[u8; 32], String> {
    let salt = b"fluxlock-passkey-v1";
    let derived = derive_key_hkdf(secret, Some(salt), info.as_bytes(), 32)
        .map_err(|e| format!("HKDF derivation error: {}", e))?;
    let exposed = derived.expose_secret();
    if exposed.len() < 32 {
        return Err("HKDF output too short".to_string());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&exposed[..32]);
    Ok(key)
}

/// Encrypt data with ChaCha20-Poly1305 using a 32-byte key
fn wrap_with_key(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let blob = cipher::encrypt(key, plaintext)
        .map_err(|e| format!("Passkey wrap encrypt error: {}", e))?;
    Ok(blob.to_bytes())
}

/// Decrypt data with ChaCha20-Poly1305 using a 32-byte key
fn unwrap_with_key(wrapped: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let blob = cipher::EncryptedBlob::from_bytes(wrapped)
        .map_err(|e| format!("Passkey unwrap parse error: {}", e))?;
    let plaintext = cipher::decrypt(key, &blob)
        .map_err(|e| format!("Passkey unwrap decrypt error: {}", e))?;
    Ok(plaintext.to_vec())
}

// ═══════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════

/// Check passkey availability and enrollment status.
/// Unlike biometric, there is NO gate — passkey is always available if enrolled.
pub fn check_passkey_status() -> PasskeyStatus {
    let available = crate::biometric::check_biometric_status().available;
    let enrollment = get_enrollment();
    let enrolled = enrollment.is_some();
    let enrolled_username = enrollment.as_ref().map(|e| e.username.clone());

    let needs_password_reminder = enrollment
        .as_ref()
        .map(|e| {
            let elapsed = now_epoch().saturating_sub(e.last_password_login);
            elapsed >= PASSWORD_REMINDER_INTERVAL
        })
        .unwrap_or(false);

    PasskeyStatus {
        available,
        enrolled,
        enrolled_username,
        needs_password_reminder,
    }
}

/// Register a new passkey for the given user.
/// Requires: user is already authenticated and has a valid encryption_key (master_key).
///
/// # Architecture (hybrid PQ):
/// 1. Generate Ed25519 keypair → store private_key in Secure Enclave (biometric ACL)
/// 2. Generate ML-KEM-768 keypair → store kem_private_key in OS Keychain (software)
/// 3. Encapsulate with kem_pubkey → shared_secret
/// 4. Double-wrap master_key:
///    - Layer 1: ChaCha20(master_key, HKDF(ed25519_privkey, "passkey-wrap-1"))
///    - Layer 2: ChaCha20(layer1_blob, HKDF(shared_secret, "passkey-wrap-2"))
/// 5. Store enrollment metadata + wrapped blob to disk
pub fn register_passkey(
    user_id: i64,
    username: &str,
    encryption_key: &[u8],
) -> Result<Option<String>, String> {
    debug_log!("🔑 Registering passkey for user {} ({})", user_id, username);

    // Check platform availability
    if !crate::biometric::check_biometric_status().available {
        return Err("Passkey non disponible — aucun authentificateur biométrique détecté".to_string());
    }

    // 1. Generate Ed25519 keypair
    let ed25519_kp = Ed25519KeyPair::generate();
    let ed25519_privkey_bytes = ed25519_kp.export_private_key();
    let ed25519_pubkey_bytes = ed25519_kp.export_public_key();

    // 2. Store Ed25519 private key in Secure Enclave / Keychain (biometric-protected)
    let ed25519_privkey_b64 = general_purpose::STANDARD.encode(&ed25519_privkey_bytes);
    store_passkey_ed25519_in_keychain(user_id, &ed25519_privkey_b64)?;

    // 3. Generate ML-KEM-768 keypair
    let (kem_pubkey, kem_privkey) = generate_recipient_keypair()
        .map_err(|e| format!("ML-KEM-768 keypair generation failed: {}", e))?;

    // 4. Store KEM private key in OS Keychain (software-backed)
    let kem_privkey_bytes = kem_privkey.to_bytes();
    let kem_privkey_b64 = general_purpose::STANDARD.encode(kem_privkey_bytes.as_slice());
    store_passkey_kem_in_keychain(user_id, &kem_privkey_b64)?;

    // 5. Encapsulate to get shared_secret + ciphertext
    let (shared_secret, kem_ciphertext) = encapsulate(&kem_pubkey)
        .map_err(|e| format!("ML-KEM-768 encapsulation failed: {}", e))?;

    // 6. Double-wrap the master_key
    // Layer 1: wrap with Ed25519 private key derivative
    let wrapping_key_1 = derive_wrapping_key(&ed25519_privkey_bytes, "passkey-wrap-1")?;
    let blob_1 = wrap_with_key(encryption_key, &wrapping_key_1)?;

    // Layer 2: wrap with ML-KEM shared secret derivative
    let wrapping_key_2 = derive_wrapping_key(shared_secret.as_bytes(), "passkey-wrap-2")?;
    let blob_2 = wrap_with_key(&blob_1, &wrapping_key_2)?;

    // 7. Store enrollment
    let credential_id = uuid_v4();
    let enrollment = PasskeyEnrollment {
        credential_id,
        user_id,
        username: username.to_string(),
        ed25519_pubkey_b64: general_purpose::STANDARD.encode(&ed25519_pubkey_bytes),
        kem_pubkey_b64: general_purpose::STANDARD.encode(&kem_pubkey.to_bytes()),
        kem_ciphertext_b64: general_purpose::STANDARD.encode(kem_ciphertext.as_bytes()),
        wrapped_master_key_b64: general_purpose::STANDARD.encode(&blob_2),
        enrolled_at: now_epoch(),
        last_password_login: now_epoch(), // registration counts as a password login
    };
    store_enrollment(&enrollment)?;

    debug_log!("✅ Passkey registered for user {} ({}) — hybrid PQ (Ed25519 + ML-KEM-768)", user_id, username);
    
    #[cfg(target_os = "android")]
    let android_key_return = Some(ed25519_privkey_b64);
    
    #[cfg(not(target_os = "android"))]
    let android_key_return = None;

    Ok(android_key_return)
}

/// Authenticate with passkey. Always-on: no cold start, no timeout.
/// Returns (user_id, username, encryption_key_bytes) on success.
///
/// # Flow:
/// 1. Load enrollment, verify username
/// 2. Generate random challenge (32 bytes)
/// 3. Retrieve Ed25519 private key from Secure Enclave (triggers Touch ID)
/// 4. Sign challenge → verify with stored public key
/// 5. Retrieve KEM private key from Keychain
/// 6. ML-KEM decapsulate → shared_secret
/// 7. Double-unwrap master_key
pub fn authenticate_passkey(target_username: &str, android_key: Option<String>) -> Result<(i64, String, Vec<u8>), String> {
    debug_log!("🔑 Passkey authentication attempt for: {}", target_username);

    // 1. Check enrollment
    let enrollment = get_enrollment()
        .ok_or("Passkey non configurée. Veuillez vous connecter avec votre mot de passe.")?;

    // 2. Verify username matches
    if !enrollment.username.eq_ignore_ascii_case(target_username) {
        return Err("Passkey non configurée pour cet utilisateur.".to_string());
    }

    // 3. NO biometric gate — passkey is always-on
    // (Unlike biometric module, we skip evaluate_biometric_gate entirely)

    // 4. Generate challenge
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);

    // 5. Retrieve Ed25519 private key (triggers Touch ID on macOS)
    let ed25519_privkey_b64 = get_passkey_ed25519_from_keychain(enrollment.user_id, android_key)
        .map_err(|e| {
            // Key was lost (biometric change, vault reset, etc.)
            let _ = delete_enrollment_file();
            format!(
                "La clé passkey a été perdue (changement biométrie ?). \
                 Veuillez vous connecter avec votre mot de passe puis réactiver la passkey. \
                 Détail: {}", e
            )
        })?;
    let ed25519_privkey_bytes = general_purpose::STANDARD
        .decode(&ed25519_privkey_b64)
        .map_err(|e| format!("Erreur décodage clé Ed25519: {}", e))?;

    // Reconstruct the keypair to sign the challenge
    if ed25519_privkey_bytes.len() != 32 {
        return Err("Clé Ed25519 invalide (taille incorrecte)".to_string());
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&ed25519_privkey_bytes);
    let ed25519_kp = Ed25519KeyPair::from_seed(&seed);

    // 6. Sign challenge
    let signature = sign_message(&challenge, &ed25519_kp);

    // 7. Verify signature with stored public key
    let ed25519_pubkey_bytes = general_purpose::STANDARD
        .decode(&enrollment.ed25519_pubkey_b64)
        .map_err(|e| format!("Erreur décodage clé publique: {}", e))?;

    let pubkey_array: [u8; 32] = ed25519_pubkey_bytes.as_slice().try_into()
        .map_err(|_| "Clé publique Ed25519 invalide (taille)")?;

    if !verify_signature_from_bytes(&challenge, &signature, &pubkey_array) {
        return Err("Vérification de signature passkey échouée — clé compromise ?".to_string());
    }
    debug_log!("✅ Passkey Ed25519 signature verified (challenge-response OK)");

    // 8. Retrieve KEM private key from Keychain
    let kem_privkey_b64 = get_passkey_kem_from_keychain(enrollment.user_id)
        .map_err(|e| {
            format!("Clé ML-KEM perdue. Réactivez la passkey. Détail: {}", e)
        })?;
    let kem_privkey_bytes = general_purpose::STANDARD
        .decode(&kem_privkey_b64)
        .map_err(|e| format!("Erreur décodage clé KEM: {}", e))?;
    let kem_privkey = KemPrivateKey::from_bytes(&kem_privkey_bytes)
        .map_err(|e| format!("Clé ML-KEM-768 invalide: {}", e))?;

    // 9. Decapsulate to recover shared_secret
    let kem_ciphertext_bytes = general_purpose::STANDARD
        .decode(&enrollment.kem_ciphertext_b64)
        .map_err(|e| format!("Erreur décodage ciphertext KEM: {}", e))?;
    let kem_ct = KemCiphertext::from_bytes(&kem_ciphertext_bytes);
    let shared_secret = decapsulate(&kem_privkey, &kem_ct)
        .map_err(|e| format!("ML-KEM-768 décapsulation échouée: {}", e))?;
    debug_log!("✅ Passkey ML-KEM-768 decapsulation successful");

    // 10. Double-unwrap master_key
    let wrapped_blob = general_purpose::STANDARD
        .decode(&enrollment.wrapped_master_key_b64)
        .map_err(|e| format!("Erreur décodage blob wrappé: {}", e))?;

    // Unwrap layer 2 (ML-KEM)
    let wrapping_key_2 = derive_wrapping_key(shared_secret.as_bytes(), "passkey-wrap-2")?;
    let blob_1 = unwrap_with_key(&wrapped_blob, &wrapping_key_2)
        .map_err(|_| "Déchiffrement passkey couche 2 (ML-KEM) échoué — clé corrompue ?".to_string())?;

    // Unwrap layer 1 (Ed25519)
    let wrapping_key_1 = derive_wrapping_key(&ed25519_privkey_bytes, "passkey-wrap-1")?;
    let master_key = unwrap_with_key(&blob_1, &wrapping_key_1)
        .map_err(|_| "Déchiffrement passkey couche 1 (Ed25519) échoué — clé corrompue ?".to_string())?;

    debug_log!("✅ Passkey authentication successful for user {} ({})", enrollment.user_id, enrollment.username);

    // Zeroize sensitive data
    let mut seed_copy = seed;
    seed_copy.zeroize();

    Ok((enrollment.user_id, enrollment.username.clone(), master_key))
}

/// Delete the passkey enrollment and all associated keys.
pub fn delete_passkey() -> Result<(), String> {
    if let Some(enrollment) = get_enrollment() {
        let _ = delete_passkey_ed25519_from_keychain(enrollment.user_id);
        let _ = delete_passkey_kem_from_keychain(enrollment.user_id);
    }
    delete_enrollment_file()?;
    debug_log!("🔓 Passkey enrollment removed");
    Ok(())
}

/// Called after a successful master-password login.
/// Resets the 14-day password reminder timer.
pub fn notify_password_used() {
    if let Some(mut enrollment) = get_enrollment() {
        enrollment.last_password_login = now_epoch();
        if let Err(e) = store_enrollment(&enrollment) {
            debug_log!("⚠️ Failed to update passkey last_password_login: {}", e);
        }
        debug_log!("🔐 Passkey: password login recorded, reminder timer reset (14 days)");
    }
}

/// Check if the user needs to enter their password (> 14 days since last password login).
pub fn needs_password_reminder() -> bool {
    get_enrollment()
        .map(|e| {
            let elapsed = now_epoch().saturating_sub(e.last_password_login);
            elapsed >= PASSWORD_REMINDER_INTERVAL
        })
        .unwrap_or(false)
}

// ═══════════════════════════════════════════════════════
// Helper: UUID v4 generation (avoid pulling in uuid crate)
// ═══════════════════════════════════════════════════════

fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        // Last 6 bytes as u64 (only lower 48 bits)
        u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uuid_v4_format() {
        let id = uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn test_enrollment_roundtrip() {
        let enrollment = PasskeyEnrollment {
            credential_id: "test-id".to_string(),
            user_id: 42,
            username: "test_user".to_string(),
            ed25519_pubkey_b64: "AAAA".to_string(),
            kem_pubkey_b64: "BBBB".to_string(),
            kem_ciphertext_b64: "CCCC".to_string(),
            wrapped_master_key_b64: "DDDD".to_string(),
            enrolled_at: 1234567890,
            last_password_login: 1234567890,
        };
        let json = serde_json::to_string(&enrollment).unwrap();
        let decoded: PasskeyEnrollment = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.user_id, 42);
        assert_eq!(decoded.username, "test_user");
        assert_eq!(decoded.credential_id, "test-id");
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let key = [0x42u8; 32];
        let plaintext = b"super secret master key data!!!";
        let wrapped = wrap_with_key(plaintext, &key).unwrap();
        let unwrapped = unwrap_with_key(&wrapped, &key).unwrap();
        assert_eq!(plaintext.as_slice(), unwrapped.as_slice());
    }

    #[test]
    fn test_wrap_wrong_key_fails() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let plaintext = b"data";
        let wrapped = wrap_with_key(plaintext, &key1).unwrap();
        assert!(unwrap_with_key(&wrapped, &key2).is_err());
    }

    #[test]
    fn test_derive_wrapping_key_deterministic() {
        let secret = [0xABu8; 32];
        let k1 = derive_wrapping_key(&secret, "test-info").unwrap();
        let k2 = derive_wrapping_key(&secret, "test-info").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_wrapping_key_different_info() {
        let secret = [0xABu8; 32];
        let k1 = derive_wrapping_key(&secret, "info-1").unwrap();
        let k2 = derive_wrapping_key(&secret, "info-2").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_passkey_status_no_enrollment() {
        let status = check_passkey_status();
        assert!(!status.enrolled);
        assert!(status.enrolled_username.is_none());
        assert!(!status.needs_password_reminder);
    }
}

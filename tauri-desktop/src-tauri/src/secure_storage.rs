/// Module pour le stockage sécurisé des clés de chiffrement via le credential store OS
///
/// Utilise:
/// - macOS: Keychain (protégé par hardware si Secure Enclave T2/M1+ disponible)
/// - Windows: Credential Manager (protégé par DPAPI, chiffrement logiciel lié au compte Windows)
/// - Linux: Secret Service (libsecret)
///
/// ⚠️ Sur Windows, ce n'est PAS un stockage hardware (TPM/Secure Enclave).
///    Pour un vrai stockage hardware, il faudrait Windows Hello / CNG + TPM 2.0.
///    Le Credential Manager reste néanmoins le standard recommandé pour les apps desktop.

use keyring::{Entry, Error as KeyringError};
use base64::{Engine as _, engine::general_purpose};
use zeroize::Zeroize;
#[cfg(target_os = "windows")]
use std::{thread, time::Duration};

// Macro pour logger uniquement en mode debug
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    };
}

const SERVICE_NAME: &str = "com.fluxlock.app";

/// Erreurs possibles lors des opérations de stockage sécurisé
#[derive(Debug)]
pub enum SecureStorageError {
    KeyringError(String),
    EncodingError(String),
}

impl std::fmt::Display for SecureStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SecureStorageError::KeyringError(msg) => write!(f, "Keyring error: {}", msg),
            SecureStorageError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for SecureStorageError {}

impl From<KeyringError> for SecureStorageError {
    fn from(err: KeyringError) -> Self {
        SecureStorageError::KeyringError(err.to_string())
    }
}

/// Stocke la clé de chiffrement dans l'enclave sécurisée du système
///
/// Sur macOS, cela utilise le Keychain qui peut utiliser le Secure Enclave
/// si disponible (T2/M1/M2 chips). La clé est protégée par hardware.
///
/// # Arguments
/// * `user_id` - L'ID utilisateur (utilisé comme identifiant unique)
/// * `encryption_key` - La clé de chiffrement AES-256 (32 bytes)
///
/// # Sécurité
/// - Clé protégée par le système d'exploitation
/// - Accès contrôlé par permissions système
/// - Chiffrement hardware si disponible (Secure Enclave)
/// - Pas de stockage en RAM non protégée
pub fn store_encryption_key(user_id: i64, encryption_key: &[u8]) -> Result<(), SecureStorageError> {
    // On mobile, keyring is unavailable — use private filesystem fallback
    if cfg!(target_os = "android") || cfg!(target_os = "ios") {
        return _store_key_file(user_id, encryption_key);
    }

    let username = format!("user_{}", user_id);
    let entry = Entry::new(SERVICE_NAME, &username)?;
    
    // Encoder la clé en base64 pour le stockage
    let mut key_b64 = general_purpose::STANDARD.encode(encryption_key);
    
    // Stocker dans le keychain/credential manager, puis zéroïser la copie b64
    let result = _store_key_b64(&entry, &key_b64);
    
    // Zéroïser la représentation base64 immédiatement
    unsafe { key_b64.as_bytes_mut().zeroize(); }
    
    result
}

/// Implémentation interne du stockage (platform-specific)
fn _store_key_b64(entry: &Entry, key_b64: &str) -> Result<(), SecureStorageError> {
    
    // Sur Windows, il est parfois préférable de supprimer l'entrée existante avant d'en créer une nouvelle
    // pour éviter des problèmes de mise à jour avec Credential Manager
    #[cfg(target_os = "windows")]
    {
        // Tentative de suppression avec retry
        for _ in 0..3 {
            if entry.delete_password().is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        // Petit délai pour laisser le système libérer la ressource
        thread::sleep(Duration::from_millis(50));
    }

    #[cfg(target_os = "windows")]
    {
        let mut last_error = None;
        for _ in 0..3 {
            match entry.set_password(&key_b64) {
                Ok(_) => {
                    debug_log!("🔐 Clé de chiffrement stockée dans l'enclave sécurisée (Credential Manager)");
                    return Ok(());
                },
                Err(e) => {
                    last_error = Some(e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        if let Some(e) = last_error {
            // Log l'erreur mais ne pas bloquer si c'est juste un problème de mise à jour
            debug_log!("⚠️ Attention: Erreur lors du stockage de la clé: {}", e);
            // On retourne quand même l'erreur car c'est critique pour la sécurité
            return Err(e.into());
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        entry.set_password(&key_b64)?;
        debug_log!("🔐 Clé de chiffrement stockée dans l'enclave sécurisée (Keychain)");
    }
    
    Ok(())
}

/// Récupère la clé de chiffrement depuis l'enclave sécurisée
/// Récupère la clé de chiffrement depuis l'enclave sécurisée (VERSION SÉCURISÉE)
///
/// ⚠️ UTILISER CETTE VERSION pour protéger la clé en mémoire
///
/// # Arguments
/// * `user_id` - L'ID utilisateur
///
/// # Returns
/// SecureKey avec zeroization automatique
///
/// # Sécurité
/// - Clé protégée par ZeroizeOnDrop
/// - Mémoire effacée automatiquement
/// - Protection contre memory dumps
use crate::secure_key::SecureKey;

/// Mobile fallback: store key in app-private filesystem
///
/// ## Sécurité
/// - Sur Android 10+ : le répertoire privé de l'app est chiffré au repos (FBE)
/// - Sur iOS : le répertoire Documents est protégé par Data Protection
/// - Permissions restrictives (0o600) empêchent la lecture par d'autres processus
/// - La suppression écrase le fichier avec des zéros avant deletion
/// - ⚠️ Un appareil rooté/jailbreaké peut contourner ces protections
/// - Pour une sécurité maximale, intégrer Android Keystore / iOS Keychain via un plugin Tauri natif
fn _mobile_key_path(user_id: i64) -> Result<std::path::PathBuf, SecureStorageError> {
    let dir = crate::hidden_storage::get_hidden_database_dir()
        .map_err(|e| SecureStorageError::KeyringError(e))?;
    let keys_dir = dir.join(".keys");
    std::fs::create_dir_all(&keys_dir)
        .map_err(|e| SecureStorageError::KeyringError(format!("Cannot create keys dir: {}", e)))?;
    Ok(keys_dir.join(format!("k_{}.bin", user_id)))
}

/// V-01 : Dérive une wrapping key unique par installation pour chiffrer le fichier clé.
///
/// Schéma : HKDF-SHA256(ikm = device_salt(32B random), info = "fluxlock-mobile-wrap-v1")
/// Le device_salt est un fichier de 32 octets aléatoires créé une seule fois,
/// stocké dans le répertoire `.keys/` avec un nom non-évident (`.d`).
///
/// Ce n'est PAS équivalent à Android Keystore/iOS Keychain (matériel HSM),
/// mais ça empêche l'extraction par simple `base64 -d` sur appareil rooté.
fn _get_or_create_device_wrapping_key(user_id: i64) -> Result<[u8; 32], SecureStorageError> {
    let dir = crate::hidden_storage::get_hidden_database_dir()
        .map_err(|e| SecureStorageError::KeyringError(e))?;
    let keys_dir = dir.join(".keys");
    std::fs::create_dir_all(&keys_dir)
        .map_err(|e| SecureStorageError::KeyringError(format!("Cannot create keys dir: {}", e)))?;
    let salt_path = keys_dir.join(".d");

    let salt: [u8; 32] = if salt_path.exists() {
        let data = std::fs::read(&salt_path)
            .map_err(|e| SecureStorageError::KeyringError(format!("Read device salt: {}", e)))?;
        if data.len() != 32 {
            return Err(SecureStorageError::KeyringError(
                "Corrupted device salt file".to_string(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&data);
        arr
    } else {
        use rand::RngCore;
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        std::fs::write(&salt_path, &salt)
            .map_err(|e| SecureStorageError::KeyringError(format!("Write device salt: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&salt_path, std::fs::Permissions::from_mode(0o600));
        }
        salt
    };

    // Derive wrapping key via HKDF-SHA256
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    // HKDF-Extract
    let prk = HmacSha256::new_from_slice(b"fluxlock-mobile-wrap-v1")
        .map_err(|e| SecureStorageError::KeyringError(format!("HMAC init: {}", e)))?
        .chain_update(&salt)
        .chain_update(&user_id.to_le_bytes())
        .finalize()
        .into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&prk);
    Ok(key)
}

fn _store_key_file(user_id: i64, encryption_key: &[u8]) -> Result<(), SecureStorageError> {
    let path = _mobile_key_path(user_id)?;

    // ═══ V-01 : Chiffrement de la clé avant écriture sur disque ═══
    // Dérive une "wrapping key" depuis un sel d'installation unique (device salt).
    // Empêche l'extraction triviale par simple base64 -d sur un appareil rooté.
    let wrapping_key = _get_or_create_device_wrapping_key(user_id)?;

    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, AeadCore};
    use chacha20poly1305::aead::{Aead, OsRng};
    let cipher = ChaCha20Poly1305::new((&wrapping_key[..]).into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, encryption_key)
        .map_err(|e| SecureStorageError::KeyringError(format!("Encrypt key file: {}", e)))?;

    // Format: nonce (12 bytes) || ciphertext+tag
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    let result = std::fs::write(&path, &blob)
        .map_err(|e| SecureStorageError::KeyringError(format!("File write error: {}", e)));
    result?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    debug_log!("🔐 Clé stockée chiffrée dans fichier privé (mobile fallback)");
    Ok(())
}

fn _retrieve_key_file(user_id: i64) -> Result<SecureKey, SecureStorageError> {
    let path = _mobile_key_path(user_id)?;
    let blob = std::fs::read(&path)
        .map_err(|e| SecureStorageError::KeyringError(format!("Key file not found: {}", e)))?;

    // ═══ V-01 : Déchiffrement de la clé depuis le fichier chiffré ═══
    if blob.len() < 12 + 16 {
        // Trop petit pour nonce(12) + tag(16) → probablement ancien format base64
        // Tentative de lecture legacy (base64 non chiffré)
        let mut key_b64 = String::from_utf8(blob)
            .map_err(|_| SecureStorageError::EncodingError("Invalid key file format".to_string()))?;
        let key = general_purpose::STANDARD
            .decode(key_b64.as_bytes())
            .map_err(|e| SecureStorageError::EncodingError(e.to_string()));
        unsafe { key_b64.as_bytes_mut().zeroize(); }
        let key = key?;
        debug_log!("🔓 Clé récupérée depuis fichier legacy (va être re-chiffrée)");
        // Re-encrypt in new format for future reads
        let secure_key = SecureKey::new(key);
        let _ = secure_key.use_key(|k| _store_key_file(user_id, k));
        return Ok(secure_key);
    }

    let wrapping_key = _get_or_create_device_wrapping_key(user_id)?;

    use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::aead::generic_array::GenericArray;
    let nonce = GenericArray::from_slice(&blob[..12]);
    let ciphertext = &blob[12..];

    let cipher = ChaCha20Poly1305::new((&wrapping_key[..]).into());
    let key = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| SecureStorageError::KeyringError(format!("Decrypt key file: {}", e)))?;

    debug_log!("🔓 Clé déchiffrée depuis fichier privé (mobile fallback)");
    Ok(SecureKey::new(key))
}

fn _delete_key_file(user_id: i64) -> Result<(), SecureStorageError> {
    let path = _mobile_key_path(user_id)?;
    if path.exists() {
        // Écraser le contenu avec des zéros avant suppression (effacement sécurisé)
        if let Ok(metadata) = std::fs::metadata(&path) {
            let zeros = vec![0u8; metadata.len() as usize];
            let _ = std::fs::write(&path, &zeros);
        }
        match std::fs::remove_file(&path) {
            Ok(_) => { debug_log!("🗑️ Clé fichier effacée et supprimée (mobile fallback)"); Ok(()) },
            Err(e) => Err(SecureStorageError::KeyringError(format!("Delete error: {}", e))),
        }
    } else {
        Ok(())
    }
}

pub fn retrieve_encryption_key_secure(user_id: i64) -> Result<SecureKey, SecureStorageError> {
    // On mobile, use filesystem fallback
    if cfg!(target_os = "android") || cfg!(target_os = "ios") {
        return _retrieve_key_file(user_id);
    }

    let username = format!("user_{}", user_id);
    let entry = Entry::new(SERVICE_NAME, &username)?;
    
    let mut key_b64 = entry.get_password()?;
    
    // Décoder la clé depuis base64
    let key = general_purpose::STANDARD
        .decode(&key_b64)
        .map_err(|e| SecureStorageError::EncodingError(e.to_string()));
    
    // Zéroïser la représentation base64 immédiatement (contient la clé en clair)
    // SAFETY: String est un Vec<u8> en interne
    unsafe { key_b64.as_bytes_mut().zeroize(); }
    
    let key = key?;
    
    #[cfg(debug_assertions)]
    debug_log!("🔓 Clé de chiffrement récupérée depuis l'enclave sécurisée (SecureKey)");
    
    Ok(SecureKey::new(key))
}

/// Supprime la clé de chiffrement de l'enclave sécurisée
///
/// À utiliser lors de la déconnexion pour garantir que la clé ne reste pas stockée
pub fn delete_encryption_key(user_id: i64) -> Result<(), SecureStorageError> {
    if cfg!(target_os = "android") || cfg!(target_os = "ios") {
        return _delete_key_file(user_id);
    }

    let username = format!("user_{}", user_id);
    let entry = Entry::new(SERVICE_NAME, &username)?;
    
    match entry.delete_password() {
        Ok(_) => {
            debug_log!("🗑️ Clé de chiffrement supprimée de l'enclave sécurisée");
            Ok(())
        },
        Err(keyring::Error::NoEntry) => {
            // Si l'entrée n'existe pas, c'est déjà bon
            Ok(())
        },
        Err(e) => Err(e.into())
    }
}

/// Statut de l'enclave sécurisée pour la plateforme courante
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnclaveStatus {
    pub platform: String,
    pub enclave_type: String,
    pub hardware_backed: bool,
    pub sync_disabled: bool,
    pub notes: String,
}

/// Retourne les informations sur l'enclave sécurisée de la plateforme
pub fn get_enclave_status_info() -> EnclaveStatus {
    #[cfg(target_os = "macos")]
    {
        // macOS utilise le Keychain via la crate keyring.
        // Les attributs kSecAttr ne sont pas configurés explicitement — 
        // la crate keyring utilise les défauts de SecItemAdd.
        // TODO: Migrer vers security-framework pour configurer :
        //   kSecAttrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        //   kSecAttrSynchronizable = false
        EnclaveStatus {
            platform: "macOS".to_string(),
            enclave_type: "Keychain (keyring crate)".to_string(),
            hardware_backed: true, // T2/M1+ ont Secure Enclave
            sync_disabled: false, // Non garanti — défaut iCloud Keychain peut sync
            notes: "Keychain via défauts keyring. Migration vers security-framework recommandée pour contrôle kSecAttr.".to_string(),
        }
    }
    #[cfg(target_os = "windows")]
    {
        EnclaveStatus {
            platform: "Windows".to_string(),
            enclave_type: "Credential Manager (DPAPI CURRENT_USER)".to_string(),
            hardware_backed: false, // DPAPI est logiciel
            sync_disabled: true, // CURRENT_USER ne sync pas
            notes: "DPAPI chiffrement logiciel lié au compte Windows. Pour hardware: intégrer Windows Hello + TPM 2.0.".to_string(),
        }
    }
    #[cfg(target_os = "linux")]
    {
        EnclaveStatus {
            platform: "Linux".to_string(),
            enclave_type: "Secret Service (libsecret)".to_string(),
            hardware_backed: false,
            sync_disabled: true,
            notes: "Secret Service via keyring. Alternative recommandée: kernel keyring (linux-keyutils crate) pour sessions root-only.".to_string(),
        }
    }
    #[cfg(target_os = "android")]
    {
        EnclaveStatus {
            platform: "Android".to_string(),
            enclave_type: "Fichier chiffré ChaCha20-Poly1305 (fallback)".to_string(),
            hardware_backed: false,
            sync_disabled: true,
            notes: "Fallback fichier avec wrapping key HKDF. Pour hardware: intégrer Android Keystore via JNI.".to_string(),
        }
    }
    #[cfg(target_os = "ios")]
    {
        EnclaveStatus {
            platform: "iOS".to_string(),
            enclave_type: "Fichier chiffré ChaCha20-Poly1305 (fallback)".to_string(),
            hardware_backed: false,
            sync_disabled: true,
            notes: "Fallback fichier. Pour hardware: intégrer iOS Keychain Services via un plugin Tauri natif.".to_string(),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux", target_os = "android", target_os = "ios")))]
    {
        EnclaveStatus {
            platform: std::env::consts::OS.to_string(),
            enclave_type: "Inconnu".to_string(),
            hardware_backed: false,
            sync_disabled: false,
            notes: "Plateforme non reconnue. Stockage par défaut keyring.".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve_key() {
        let user_id = 99999; // Test user
        let test_key = vec![0u8; 32]; // 32 bytes test key
        
        // Nettoyer d'abord au cas où un run précédent aurait laissé l'entrée
        let _ = delete_encryption_key(user_id);
        
        // Store
        store_encryption_key(user_id, &test_key).unwrap();
        
        // Retrieve using the secure version
        let retrieved = retrieve_encryption_key_secure(user_id).unwrap();
        assert_eq!(&*retrieved.to_vec(), &test_key[..]);
        
        // Cleanup
        let _ = delete_encryption_key(user_id);
        
        println!("✅ Test de stockage/récupération de clé réussi");
    }
}

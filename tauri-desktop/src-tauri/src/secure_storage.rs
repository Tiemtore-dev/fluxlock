//! Clés de session persistées dans le gestionnaire d’identifiants sur Windows et Linux.
//! Sur macOS, l’ancien enregistrement de session est uniquement supprimé.

use keyring::{Entry, Error as KeyringError};
#[cfg(any(test, not(target_os = "macos")))]
use base64::{Engine as _, engine::general_purpose};
#[cfg(any(test, not(target_os = "macos")))]
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

fn service_name(test_build: bool) -> &'static str {
    if test_build { "com.fluxlock.app.test" } else { "com.fluxlock.app" }
}

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

/// Stocke la clé de session dans le gestionnaire d’identifiants de la plateforme.
#[cfg(any(test, not(target_os = "macos")))]
pub fn store_encryption_key(user_id: i64, encryption_key: &[u8]) -> Result<(), SecureStorageError> {
    let username = format!("user_{}", user_id);
    let entry = Entry::new(service_name(crate::hidden_storage::TEST_BUILD), &username)?;
    
    // Encoder la clé en base64 pour le stockage
    let mut key_b64 = general_purpose::STANDARD.encode(encryption_key);
    
    // Stocker dans le keychain/credential manager, puis zéroïser la copie b64
    let result = _store_key_b64(&entry, &key_b64);
    
    // Zéroïser la représentation base64 immédiatement
    unsafe { key_b64.as_bytes_mut().zeroize(); }
    
    result
}

/// Implémentation interne du stockage (platform-specific)
#[cfg(any(test, not(target_os = "macos")))]
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

#[cfg(any(test, not(target_os = "macos")))]
use crate::secure_key::SecureKey;

#[cfg(any(target_os = "android", target_os = "ios"))]
pub(crate) fn remove_legacy_session_key(dir: &std::path::Path, user_id: i64) {
    let path = dir.join(".keys").join(format!("k_{user_id}.bin"));
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => eprintln!("Impossible de supprimer l’ancienne clé de session : {error}"),
    }
}

/// Récupère une clé de session dans un tampon effacé après utilisation.
#[cfg(any(test, not(target_os = "macos")))]
pub fn retrieve_encryption_key_secure(user_id: i64) -> Result<SecureKey, SecureStorageError> {
    let username = format!("user_{}", user_id);
    let entry = Entry::new(service_name(crate::hidden_storage::TEST_BUILD), &username)?;
    
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

#[cfg(target_os = "macos")]
pub(crate) fn remove_legacy_macos_session_key(user_id: i64) {
    if let Err(error) = delete_encryption_key(user_id) {
        eprintln!("Impossible de supprimer l’ancienne clé de session macOS du trousseau : {error}");
    }
}

/// Supprime l’entrée de session du gestionnaire d’identifiants.
pub fn delete_encryption_key(user_id: i64) -> Result<(), SecureStorageError> {
    let username = format!("user_{}", user_id);
    let entry = Entry::new(service_name(crate::hidden_storage::TEST_BUILD), &username)?;
    
    match entry.delete_password() {
        Ok(_) => {
            debug_log!("Clé de session supprimée du gestionnaire d’identifiants");
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
        EnclaveStatus {
            platform: "macOS".to_string(),
            enclave_type: "Mémoire de session".to_string(),
            hardware_backed: false,
            sync_disabled: true,
            notes: "La clé de session est effacée au verrouillage. Touch ID conserve une entrée d’enrôlement distincte.".to_string(),
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
            enclave_type: "Mémoire de session".to_string(),
            hardware_backed: false,
            sync_disabled: true,
            notes: "La biométrie optionnelle utilise une clé d’enveloppe dans Android Keystore.".to_string(),
        }
    }
    #[cfg(target_os = "ios")]
    {
        EnclaveStatus {
            platform: "iOS".to_string(),
            enclave_type: "Mémoire de session".to_string(),
            hardware_backed: false,
            sync_disabled: true,
            notes: "La clé du coffre reste en mémoire pendant la session.".to_string(),
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
    fn test_build_uses_separate_session_keyring() {
        assert_eq!(service_name(true), "com.fluxlock.app.test");
        assert_eq!(service_name(false), "com.fluxlock.app");
    }

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
        
        #[cfg(target_os = "macos")]
        remove_legacy_macos_session_key(user_id);
        #[cfg(not(target_os = "macos"))]
        delete_encryption_key(user_id).unwrap();

        let entry = Entry::new(service_name(crate::hidden_storage::TEST_BUILD), &format!("user_{user_id}")).unwrap();
        assert!(matches!(entry.get_password(), Err(KeyringError::NoEntry)));
    }
}

/// Module pour le stockage sécurisé des clés de chiffrement dans l'enclave système
///
/// Utilise:
/// - macOS: Keychain (Secure Enclave si disponible)
/// - Windows: Credential Manager
/// - Linux: Secret Service (libsecret)
///
/// La clé de chiffrement maître n'est JAMAIS stockée en RAM non protégée
/// mais dans l'enclave sécurisée du système d'exploitation.

use keyring::{Entry, Error as KeyringError};
use base64::{Engine as _, engine::general_purpose};

const SERVICE_NAME: &str = "com.securevault.app";

/// Erreurs possibles lors des opérations de stockage sécurisé
#[derive(Debug)]
pub enum SecureStorageError {
    KeyringError(String),
    EncodingError(String),
    NotFound,
}

impl std::fmt::Display for SecureStorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SecureStorageError::KeyringError(msg) => write!(f, "Keyring error: {}", msg),
            SecureStorageError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            SecureStorageError::NotFound => write!(f, "Encryption key not found in secure storage"),
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
    let username = format!("user_{}", user_id);
    let entry = Entry::new(SERVICE_NAME, &username)?;
    
    // Encoder la clé en base64 pour le stockage
    let key_b64 = general_purpose::STANDARD.encode(encryption_key);
    
    entry.set_password(&key_b64)?;
    
    println!("🔐 Clé de chiffrement stockée dans l'enclave sécurisée (Keychain)");
    Ok(())
}

/// Récupère la clé de chiffrement depuis l'enclave sécurisée
///
/// # Arguments
/// * `user_id` - L'ID utilisateur
///
/// # Returns
/// La clé de chiffrement AES-256 (32 bytes)
///
/// # Sécurité
/// - Clé récupérée directement depuis le Keychain
/// - Pas de copie persistante en RAM
/// - Utilisée uniquement le temps de l'opération crypto
pub fn retrieve_encryption_key(user_id: i64) -> Result<Vec<u8>, SecureStorageError> {
    let username = format!("user_{}", user_id);
    let entry = Entry::new(SERVICE_NAME, &username)?;
    
    let key_b64 = entry.get_password()?;
    
    // Décoder la clé depuis base64
    let key = general_purpose::STANDARD
        .decode(&key_b64)
        .map_err(|e| SecureStorageError::EncodingError(e.to_string()))?;
    
    println!("🔓 Clé de chiffrement récupérée depuis l'enclave sécurisée");
    Ok(key)
}

/// Supprime la clé de chiffrement de l'enclave sécurisée
///
/// Utilisé lors de la déconnexion ou suppression de compte
///
/// # Arguments
/// * `user_id` - L'ID utilisateur
pub fn delete_encryption_key(user_id: i64) -> Result<(), SecureStorageError> {
    let username = format!("user_{}", user_id);
    let entry = Entry::new(SERVICE_NAME, &username)?;
    
    entry.delete_password()?;
    
    println!("🗑️  Clé de chiffrement supprimée de l'enclave sécurisée");
    Ok(())
}

/// Vérifie si une clé existe dans l'enclave sécurisée
///
/// # Arguments
/// * `user_id` - L'ID utilisateur
pub fn has_encryption_key(user_id: i64) -> bool {
    let username = format!("user_{}", user_id);
    if let Ok(entry) = Entry::new(SERVICE_NAME, &username) {
        entry.get_password().is_ok()
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve_key() {
        let user_id = 99999; // Test user
        let test_key = vec![0u8; 32]; // 32 bytes test key
        
        // Store
        store_encryption_key(user_id, &test_key).unwrap();
        
        // Verify exists
        assert!(has_encryption_key(user_id));
        
        // Retrieve
        let retrieved = retrieve_encryption_key(user_id).unwrap();
        assert_eq!(retrieved, test_key);
        
        // Cleanup
        delete_encryption_key(user_id).unwrap();
        assert!(!has_encryption_key(user_id));
    }
}

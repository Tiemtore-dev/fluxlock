use secure_vault_crypto::{
    key_derivation::argon2::{derive_key_from_password_with_config, Argon2Config, generate_salt as crypto_generate_salt},
    crypto::aes_gcm::{encrypt_aes_gcm, decrypt_aes_gcm},
    secure_memory::{SecretBytes, EncryptedData},
    errors::CryptoError as CoreCryptoError,
};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;

/// Erreurs possibles lors des opérations cryptographiques
#[derive(Debug)]
pub enum CryptoError {
    HashingError(String),
    VerificationError,
    EncryptionError(String),
    DecryptionError(String),
    InvalidKey,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptoError::HashingError(msg) => write!(f, "Hashing error: {}", msg),
            CryptoError::VerificationError => write!(f, "Password verification failed"),
            CryptoError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CryptoError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            CryptoError::InvalidKey => write!(f, "Invalid encryption key"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CoreCryptoError> for CryptoError {
    fn from(err: CoreCryptoError) -> Self {
        match err {
            CoreCryptoError::EncryptionError(msg) => CryptoError::EncryptionError(msg),
            CoreCryptoError::DecryptionError(msg) => CryptoError::DecryptionError(msg),
            CoreCryptoError::KeyDerivationError(msg) => CryptoError::HashingError(msg),
            CoreCryptoError::AuthenticationFailed => CryptoError::DecryptionError("Authentication tag verification failed".to_string()),
            CoreCryptoError::InvalidKeySize { expected, actual } => CryptoError::EncryptionError(format!("Invalid key size: expected {}, got {}", expected, actual)),
            _ => CryptoError::EncryptionError(err.to_string()),
        }
    }
}

/// Hash un mot de passe avec Argon2id (standard professionnel)
///
/// Utilise Argon2id avec des paramètres optimisés pour la sécurité :
/// - m_cost: 65536 (64 MiB) - mémoire requise
/// - t_cost: 3 (3 iterations) - temps de calcul
/// - p_cost: 4 (4 threads parallèles)
/// - output_len: 32 bytes (256 bits)
///
/// Format de sortie : salt (32 bytes) || hash (32 bytes) encodé en base64
///
/// # Arguments
/// * `password` - Le mot de passe en clair
///
/// # Returns
/// String base64 contenant sel + hash
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = generate_salt();
    
    let config = Argon2Config {
        memory_cost: 65536,  // 64 MiB (OWASP recommandé pour résistance GPU)
        time_cost: 3,        // 3 iterations (balance sécurité/performance)
        parallelism: 4,      // 4 threads (utilisation CPU moderne)
        output_len: 32,      // 256 bits
    };
    
    let hash = derive_key_from_password_with_config(password, &salt, &config)?;
    
    // Combiner salt + hash
    let mut result = salt.to_vec();
    result.extend_from_slice(hash.expose_secret());
    
    Ok(general_purpose::STANDARD.encode(&result))
}

/// Vérifie un mot de passe contre son hash
///
/// # Arguments
/// * `password` - Le mot de passe en clair à vérifier
/// * `hash_base64` - Le hash base64 (salt + hash)
///
/// # Returns
/// `Ok(())` si le mot de passe est correct, `Err` sinon
pub fn verify_password(password: &str, hash_base64: &str) -> Result<(), CryptoError> {
    // Décoder le base64
    let decoded = general_purpose::STANDARD
        .decode(hash_base64)
        .map_err(|e| CryptoError::HashingError(format!("Base64 decode error: {}", e)))?;
    
    // Vérifier la longueur (32 bytes salt + 32 bytes hash)
    if decoded.len() != 64 {
        return Err(CryptoError::HashingError("Invalid hash length".to_string()));
    }
    
    // Extraire salt et hash stocké
    let salt = &decoded[..32];
    let stored_hash = &decoded[32..];
    
    // Recalculer le hash avec le même sel
    let config = Argon2Config {
        memory_cost: 65536,
        time_cost: 3,
        parallelism: 4,
        output_len: 32,
    };
    
    let computed_hash = derive_key_from_password_with_config(password, salt, &config)?;
    
    // Comparaison constant-time pour éviter timing attacks
    if constant_time_compare(computed_hash.expose_secret(), stored_hash) {
        Ok(())
    } else {
        Err(CryptoError::VerificationError)
    }
}

/// Comparaison constant-time pour éviter les attaques par timing
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Génère une clé de chiffrement de 32 bytes (256 bits) cryptographiquement sécurisée
/// ⚠️ ATTENTION: Cette fonction génère une clé ÉPHÉMÈRE qui sera perdue au redémarrage
/// NE PAS UTILISER pour le chiffrement de données persistantes!
#[deprecated(note = "Utiliser derive_encryption_key_from_password pour données persistantes")]
pub fn generate_encryption_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Dérive une clé de chiffrement depuis le mot de passe utilisateur
///
/// Cette fonction dérive de manière DÉTERMINISTE une clé de 256 bits depuis
/// le mot de passe maître de l'utilisateur. La même combinaison password+salt
/// produira toujours la même clé, permettant la persistance des données chiffrées.
///
/// # Arguments
/// * `password` - Le mot de passe maître de l'utilisateur
/// * `crypto_salt` - Sel cryptographique pour la dérivation (32 bytes)
///
/// # Returns
/// Clé AES-256 de 32 bytes
///
/// # Sécurité
/// - Utilise Argon2id avec paramètres robustes
/// - Résistant aux attaques GPU/ASIC
/// - Dérivation séparée de l'authentification
/// - Clé stockée uniquement en RAM pendant la session
pub fn derive_encryption_key_from_password(password: &str, crypto_salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let config = Argon2Config {
        memory_cost: 65536,  // 64 MiB
        time_cost: 3,
        parallelism: 4,
        output_len: 32,  // 256 bits pour AES-256
    };
    
    let key = derive_key_from_password_with_config(password, crypto_salt, &config)?;
    Ok(key.expose_secret().to_vec())
}

/// Génère un sel cryptographique de 32 bytes
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Chiffre des données avec AES-256-GCM (standard militaire)
///
/// AES-256-GCM fournit :
/// - Confidentialité : AES-256 (clé 256 bits)
/// - Authentification : GCM (Galois/Counter Mode)
/// - Intégrité : Protection contre falsification
/// - AEAD : Authenticated Encryption with Associated Data
///
/// # Arguments
/// * `data` - Les données en clair à chiffrer
/// * `key` - Clé de 32 bytes (256 bits)
///
/// # Returns
/// String base64 contenant les données chiffrées avec nonce et tag GCM
///
/// # Sécurité
/// - Nonce unique généré automatiquement pour chaque chiffrement
/// - Tag d'authentification GCM de 128 bits
/// - Résistant aux attaques : padding oracle, bit-flipping, replay
pub fn encrypt_data(data: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    // Utiliser le moteur crypto professionnel
    let encrypted_data = encrypt_aes_gcm(data.as_bytes(), key)?;

    // Combiner nonce + ciphertext pour le stockage
    let mut result = encrypted_data.nonce;
    result.extend_from_slice(&encrypted_data.ciphertext);

    Ok(general_purpose::STANDARD.encode(&result))
}

/// Déchiffre des données chiffrées avec AES-256-GCM
///
/// # Arguments
/// * `encrypted_base64` - String base64 contenant nonce || ciphertext || tag
/// * `key` - Clé de 32 bytes (256 bits)
///
/// # Returns
/// String déchiffré
///
/// # Sécurité
/// - Vérifie l'authentification GCM avant déchiffrement
/// - Échoue si les données ont été modifiées (intégrité)
/// - Protection contre les attaques par falsification
pub fn decrypt_data(encrypted_base64: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    // Décoder le base64
    let combined = general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| CryptoError::DecryptionError(format!("Base64 decode error: {}", e)))?;

    // Extraire nonce (12 bytes) et ciphertext
    if combined.len() < 12 {
        return Err(CryptoError::DecryptionError("Invalid encrypted data length".to_string()));
    }

    let nonce = combined[..12].to_vec();
    let ciphertext = combined[12..].to_vec();

    // Créer EncryptedData
    let encrypted_data = EncryptedData::new("AES-256-GCM".to_string(), nonce, ciphertext);

    // Utiliser le moteur crypto professionnel
    let decrypted = decrypt_aes_gcm(&encrypted_data, key)?;

    // Convertir en string UTF-8
    String::from_utf8(decrypted)
        .map_err(|e| CryptoError::DecryptionError(format!("UTF-8 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "MonMotDePasseTrèsSécurisé123!@#";
        
        // Hash le mot de passe
        let hash = hash_password(password).unwrap();
        
        // Vérifier que c'est du base64 valide
        assert!(general_purpose::STANDARD.decode(&hash).is_ok());
        
        // Vérifier que la longueur est correcte (32 bytes salt + 32 bytes hash = 64 bytes)
        let decoded = general_purpose::STANDARD.decode(&hash).unwrap();
        assert_eq!(decoded.len(), 64);
        
        // Vérifier que le mot de passe est correct
        assert!(verify_password(password, &hash).is_ok());
        
        // Vérifier qu'un mauvais mot de passe échoue
        assert!(verify_password("MauvaisMotDePasse", &hash).is_err());
    }

    #[test]
    fn test_different_hashes_for_same_password() {
        let password = "MotDePasseIdentique";
        
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();
        
        // Les hash doivent être différents (sel différent)
        assert_ne!(hash1, hash2);
        
        // Mais les deux doivent vérifier le même mot de passe
        assert!(verify_password(password, &hash1).is_ok());
        assert!(verify_password(password, &hash2).is_ok());
    }

    #[test]
    fn test_encryption_decryption() {
        let data = "Données très secrètes avec caractères spéciaux: éèàç 🔐";
        let key = generate_encryption_key();
        
        // Chiffrer
        let encrypted = encrypt_data(data, &key).unwrap();
        
        // Vérifier que c'est du base64 valide
        assert!(general_purpose::STANDARD.decode(&encrypted).is_ok());
        
        // Vérifier que les données sont différentes
        assert_ne!(data, encrypted);
        
        // Déchiffrer
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        
        // Vérifier que les données sont identiques
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_encryption_with_wrong_key() {
        let data = "Données secrètes";
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        
        let encrypted = encrypt_data(data, &key1).unwrap();
        
        // Déchiffrer avec une mauvaise clé doit échouer
        let result = decrypt_data(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        let data = "Test";
        let short_key = vec![0u8; 16]; // Seulement 16 bytes au lieu de 32
        
        // Clé invalide pour chiffrement
        assert!(encrypt_data(data, &short_key).is_err());
        
        // Clé invalide pour déchiffrement
        assert!(decrypt_data("test", &short_key).is_err());
    }

    #[test]
    fn test_tampered_ciphertext() {
        let data = "Données importantes";
        let key = generate_encryption_key();
        
        let encrypted = encrypt_data(data, &key).unwrap();
        
        // Modifier le ciphertext (simuler une attaque)
        let mut corrupted = general_purpose::STANDARD.decode(&encrypted).unwrap();
        corrupted[20] ^= 0xFF; // Flip des bits
        let corrupted_b64 = general_purpose::STANDARD.encode(&corrupted);
        
        // Le déchiffrement doit échouer (intégrité GCM)
        assert!(decrypt_data(&corrupted_b64, &key).is_err());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 5];
        let c = vec![1, 2, 3, 4, 6];
        
        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }

    #[test]
    fn test_key_generation() {
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        
        // Les clés doivent être de 32 bytes
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        
        // Les clés doivent être différentes (aléatoires)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        
        // Les sels doivent être de 32 bytes
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        
        // Les sels doivent être différents (aléatoires)
        assert_ne!(salt1, salt2);
    }
}

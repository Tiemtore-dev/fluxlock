use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AesOsRng},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use base64::{Engine as _, engine::general_purpose};

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

/// Hash un mot de passe avec Argon2id
///
/// Utilise Argon2id avec des paramètres sécurisés :
/// - m_cost: 19456 (19 MiB)
/// - t_cost: 2 (2 iterations)
/// - p_cost: 1 (1 parallelism)
///
/// # Arguments
/// * `password` - Le mot de passe en clair
///
/// # Returns
/// String PHC formaté (contient le sel et le hash)
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::HashingError(e.to_string()))
        .map(|hash| hash.to_string())
}

/// Vérifie un mot de passe contre son hash
///
/// # Arguments
/// * `password` - Le mot de passe en clair à vérifier
/// * `hash` - Le hash PHC formaté à comparer
///
/// # Returns
/// `Ok(())` si le mot de passe est correct, `Err` sinon
pub fn verify_password(password: &str, hash: &str) -> Result<(), CryptoError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| CryptoError::HashingError(e.to_string()))?;
    
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| CryptoError::VerificationError)
}

/// Génère une clé de chiffrement de 32 bytes (256 bits)
pub fn generate_encryption_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    key.to_vec()
}

/// Chiffre des données avec AES-256-GCM
///
/// AES-256-GCM fournit :
/// - Confidentialité (AES-256)
/// - Authentification (GCM)
/// - Protection contre la falsification
///
/// # Arguments
/// * `data` - Les données en clair à chiffrer
/// * `key` - Clé de 32 bytes (256 bits)
///
/// # Returns
/// String base64 contenant : nonce (12 bytes) || ciphertext || tag (16 bytes)
pub fn encrypt_data(data: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    // Initialiser le cipher AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    // Générer un nonce aléatoire de 96 bits (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Chiffrer les données
    let ciphertext = cipher
        .encrypt(nonce, data.as_bytes())
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

    // Combiner nonce + ciphertext (qui contient déjà le tag GCM)
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    // Encoder en base64
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
pub fn decrypt_data(encrypted_base64: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    // Décoder le base64
    let encrypted = general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| CryptoError::DecryptionError(format!("Base64 decode error: {}", e)))?;

    // Vérifier la longueur minimale (12 bytes nonce + au moins 16 bytes tag)
    if encrypted.len() < 28 {
        return Err(CryptoError::DecryptionError(
            "Invalid encrypted data length".to_string(),
        ));
    }

    // Extraire le nonce (12 premiers bytes)
    let nonce = Nonce::from_slice(&encrypted[..12]);
    
    // Le reste contient ciphertext + tag
    let ciphertext = &encrypted[12..];

    // Initialiser le cipher
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

    // Déchiffrer
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionError(format!("AES-GCM decrypt failed: {}", e)))?;

    // Convertir en string
    String::from_utf8(plaintext)
        .map_err(|e| CryptoError::DecryptionError(format!("UTF-8 decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "MonMotDePasseSuperSecret123!";
        let hash = hash_password(password).unwrap();
        
        // Vérifier que le hash commence par $argon2id$
        assert!(hash.starts_with("$argon2id$"));
        
        // Vérifier que le mot de passe est correct
        assert!(verify_password(password, &hash).is_ok());
        
        // Vérifier qu'un mauvais mot de passe échoue
        assert!(verify_password("MauvaisMotDePasse", &hash).is_err());
    }

    #[test]
    fn test_encryption_decryption() {
        let data = "Données secrètes à protéger";
        let key = generate_encryption_key();
        
        // Chiffrer
        let encrypted = encrypt_data(data, &key).unwrap();
        
        // Vérifier que c'est du base64 valide
        assert!(general_purpose::STANDARD.decode(&encrypted).is_ok());
        
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
        assert!(decrypt_data(&encrypted, &key2).is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        let data = "Test";
        let short_key = vec![0u8; 16]; // Seulement 16 bytes au lieu de 32
        
        assert!(encrypt_data(data, &short_key).is_err());
        assert!(decrypt_data("test", &short_key).is_err());
    }
}

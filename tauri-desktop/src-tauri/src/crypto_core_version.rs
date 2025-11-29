// Module crypto utilisant le rust-crypto-core professionnel
use secure_vault_crypto_core::{
    derive_key_from_password, encrypt_aes_gcm, decrypt_aes_gcm, 
    Argon2Config, CryptoError as CoreCryptoError, SecretBytes
};
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    HashingError(String),
    VerificationError(String),
    EncryptionError(String),
    DecryptionError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CryptoError::HashingError(msg) => write!(f, "Hashing error: {}", msg),
            CryptoError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            CryptoError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CryptoError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CoreCryptoError> for CryptoError {
    fn from(err: CoreCryptoError) -> Self {
        CryptoError::EncryptionError(err.to_string())
    }
}

/// Hash a password using Argon2id with the professional crypto core
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    // Utiliser une configuration sécurisée pour Argon2id
    let salt = generate_salt();
    
    let key = derive_key_from_password(password, &salt)
        .map_err(|e| CryptoError::HashingError(e.to_string()))?;
    
    // Encoder le salt + key en format stockable
    let mut result = Vec::new();
    result.extend_from_slice(&salt);
    result.extend_from_slice(key.expose_secret());
    
    Ok(base64::encode(&result))
}

/// Verify a password against a hash
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, CryptoError> {
    let decoded = base64::decode(password_hash)
        .map_err(|e| CryptoError::VerificationError(e.to_string()))?;
    
    if decoded.len() < 32 {
        return Err(CryptoError::VerificationError("Invalid hash format".to_string()));
    }
    
    let (salt, stored_key) = decoded.split_at(32);
    
    let derived_key = derive_key_from_password(password, salt)
        .map_err(|e| CryptoError::VerificationError(e.to_string()))?;
    
    // Comparaison en temps constant
    Ok(constant_time_compare(derived_key.expose_secret(), stored_key))
}

/// Generate a random salt
fn generate_salt() -> [u8; 32] {
    use rand::Rng;
    let mut salt = [0u8; 32];
    rand::thread_rng().fill(&mut salt);
    salt
}

/// Constant-time comparison
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

/// Generate a random encryption key (32 bytes for AES-256)
pub fn generate_encryption_key() -> Vec<u8> {
    use rand::Rng;
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill(&mut key[..]);
    key
}

/// Encrypt data using AES-256-GCM from the crypto core
pub fn encrypt_data(data: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::EncryptionError("Key must be 32 bytes".to_string()));
    }
    
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| CryptoError::EncryptionError("Invalid key size".to_string()))?;
    
    let encrypted = encrypt_aes_gcm(data.as_bytes(), &key_array)
        .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
    
    Ok(base64::encode(&encrypted))
}

/// Decrypt data using AES-256-GCM from the crypto core
pub fn decrypt_data(encrypted: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::DecryptionError("Key must be 32 bytes".to_string()));
    }
    
    let encrypted_bytes = base64::decode(encrypted)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| CryptoError::DecryptionError("Invalid key size".to_string()))?;
    
    let decrypted = decrypt_aes_gcm(&encrypted_bytes, &key_array)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    
    String::from_utf8(decrypted)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))
}

// Ré-exporter pour compatibilité
use rand;
use base64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();
        
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_encryption_decryption() {
        let data = "Sensitive information with AES-256-GCM!";
        let key = generate_encryption_key();
        
        let encrypted = encrypt_data(data, &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        
        assert_eq!(data, decrypted);
    }
    
    #[test]
    fn test_encryption_with_wrong_key() {
        let data = "Secret data";
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        
        let encrypted = encrypt_data(data, &key1).unwrap();
        let result = decrypt_data(&encrypted, &key2);
        
        assert!(result.is_err());
    }
}

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;
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

/// Hash a password using Argon2id
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CryptoError::HashingError(e.to_string()))?
        .to_string();
    
    Ok(password_hash)
}

/// Verify a password against a hash
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, CryptoError> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|e| CryptoError::VerificationError(e.to_string()))?;
    
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a random encryption key (32 bytes for AES-256)
pub fn generate_encryption_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut key = vec![0u8; 32];
    rng.fill(&mut key[..]);
    key
}

/// Simple XOR encryption for demo purposes
/// In production, use AES-GCM from rust-crypto-core
pub fn encrypt_data(data: &str, key: &[u8]) -> Result<String, CryptoError> {
    let data_bytes = data.as_bytes();
    let mut encrypted = Vec::with_capacity(data_bytes.len());
    
    for (i, byte) in data_bytes.iter().enumerate() {
        encrypted.push(byte ^ key[i % key.len()]);
    }
    
    Ok(base64::encode(&encrypted))
}

/// Simple XOR decryption for demo purposes
pub fn decrypt_data(encrypted: &str, key: &[u8]) -> Result<String, CryptoError> {
    let encrypted_bytes = base64::decode(encrypted)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
    
    let mut decrypted = Vec::with_capacity(encrypted_bytes.len());
    
    for (i, byte) in encrypted_bytes.iter().enumerate() {
        decrypted.push(byte ^ key[i % key.len()]);
    }
    
    String::from_utf8(decrypted)
        .map_err(|e| CryptoError::DecryptionError(e.to_string()))
}

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
        let data = "Sensitive information";
        let key = generate_encryption_key();
        
        let encrypted = encrypt_data(data, &key).unwrap();
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        
        assert_eq!(data, decrypted);
    }
}

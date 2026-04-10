//! Module de chiffrement ChaCha20-Poly1305
//! 
//! Alternative à AES-GCM, particulièrement efficace sur les systèmes
//! sans support matériel AES-NI.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce as ChaNonce,
};
use rand::RngCore;
use rand::rngs::OsRng;
use crate::errors::{CryptoError, Result};
use crate::secure_memory::EncryptedData;

/// Taille du nonce pour ChaCha20-Poly1305 (12 bytes)
const NONCE_SIZE: usize = 12;

/// Taille de la clé ChaCha20 (32 bytes)
const KEY_SIZE: usize = 32;

/// Cipher ChaCha20-Poly1305
pub struct ChaCha20Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Cipher {
    /// Crée un nouveau cipher avec une clé
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: KEY_SIZE,
                actual: key.len(),
            });
        }

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| CryptoError::EncryptionError(format!("Invalid key: {}", e)))?;

        Ok(ChaCha20Cipher { cipher })
    }

    /// Génère un nonce aléatoire
    fn generate_nonce(&self) -> Vec<u8> {
        let mut nonce = vec![0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Chiffre des données avec des données associées optionnelles
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedData> {
        let nonce_bytes = self.generate_nonce();
        let nonce = ChaNonce::from_slice(&nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };

        let ciphertext = self
            .cipher
            .encrypt(nonce, payload)
            .map_err(|e| CryptoError::EncryptionError(format!("ChaCha20 encryption failed: {}", e)))?;

        Ok(EncryptedData::new(
            "ChaCha20-Poly1305".to_string(),
            nonce_bytes,
            ciphertext,
        ))
    }

    /// Chiffre des données sans AAD
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        self.encrypt_with_aad(plaintext, &[])
    }

    /// Déchiffre des données avec des données associées optionnelles
    pub fn decrypt_with_aad(&self, encrypted: &EncryptedData, aad: &[u8]) -> Result<Vec<u8>> {
        if encrypted.nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: NONCE_SIZE,
                actual: encrypted.nonce.len(),
            });
        }

        let nonce = ChaNonce::from_slice(&encrypted.nonce);

        let payload = Payload {
            msg: &encrypted.ciphertext,
            aad,
        };

        self.cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    /// Déchiffre des données sans AAD
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        self.decrypt_with_aad(encrypted, &[])
    }
}

/// Fonction utilitaire pour chiffrer avec ChaCha20-Poly1305
///
/// # Arguments
/// * `plaintext` - Données à chiffrer
/// * `key` - Clé de chiffrement (32 bytes)
///
/// # Returns
/// Données chiffrées avec nonce et tag
///
/// # Exemple
/// ```rust
/// use secure_vault_crypto::crypto::chacha::encrypt_chacha20;
/// 
/// let key = [0u8; 32];
/// let data = b"Secret message";
/// let encrypted = encrypt_chacha20(data, &key).unwrap();
/// ```
pub fn encrypt_chacha20(plaintext: &[u8], key: &[u8]) -> Result<EncryptedData> {
    let cipher = ChaCha20Cipher::new(key)?;
    cipher.encrypt(plaintext)
}

/// Fonction utilitaire pour déchiffrer avec ChaCha20-Poly1305
///
/// # Exemple
/// ```rust
/// use secure_vault_crypto::crypto::chacha::{encrypt_chacha20, decrypt_chacha20};
/// 
/// let key = [0u8; 32];
/// let data = b"Secret message";
/// let encrypted = encrypt_chacha20(data, &key).unwrap();
/// let decrypted = decrypt_chacha20(&encrypted, &key).unwrap();
/// assert_eq!(data, decrypted.as_slice());
/// ```
pub fn decrypt_chacha20(encrypted: &EncryptedData, key: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Cipher::new(key)?;
    cipher.decrypt(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"Hello ChaCha20!";

        let encrypted = encrypt_chacha20(plaintext, &key).unwrap();
        let decrypted = decrypt_chacha20(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_with_aad() {
        let key = [0u8; 32];
        let plaintext = b"Message";
        let aad = b"Additional authenticated data";

        let cipher = ChaCha20Cipher::new(&key).unwrap();
        let encrypted = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        let decrypted = cipher.decrypt_with_aad(&encrypted, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aad_mismatch() {
        let key = [0u8; 32];
        let plaintext = b"Message";
        let aad = b"Correct AAD";
        let wrong_aad = b"Wrong AAD";

        let cipher = ChaCha20Cipher::new(&key).unwrap();
        let encrypted = cipher.encrypt_with_aad(plaintext, aad).unwrap();
        
        // Déchiffrement avec mauvais AAD doit échouer
        let result = cipher.decrypt_with_aad(&encrypted, wrong_aad);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_different_nonces() {
        let key = [0u8; 32];
        let plaintext = b"Test";

        let cipher = ChaCha20Cipher::new(&key).unwrap();
        let encrypted1 = cipher.encrypt(plaintext).unwrap();
        let encrypted2 = cipher.encrypt(plaintext).unwrap();

        assert_ne!(encrypted1.nonce, encrypted2.nonce);
    }

    #[test]
    fn test_large_data() {
        let key = [0u8; 32];
        let plaintext = vec![42u8; 100_000]; // 100 KB

        let encrypted = encrypt_chacha20(&plaintext, &key).unwrap();
        let decrypted = decrypt_chacha20(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_tampered_ciphertext() {
        let key = [0u8; 32];
        let plaintext = b"Original message";

        let mut encrypted = encrypt_chacha20(plaintext, &key).unwrap();
        encrypted.ciphertext[0] ^= 0x01; // Altérer un byte

        let result = decrypt_chacha20(&encrypted, &key);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }
}

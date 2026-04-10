//! Module de chiffrement AES-GCM
//!
//! Implémentation du chiffrement authentifié AES-256-GCM utilisant
//! la bibliothèque RustCrypto `aes-gcm`.

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use aes_gcm::aead::generic_array::GenericArray;
use crate::errors::{CryptoError, Result};
use zeroize::Zeroizing;
use crate::secure_memory::EncryptedData;

/// Taille du nonce pour AES-GCM (12 bytes recommandés)
const NONCE_SIZE: usize = 12;

/// Taille de la clé AES-256 (32 bytes)
const KEY_SIZE: usize = 32;

/// Cipher AES-GCM avec gestion d'état
///
/// La clé est protégée par `Zeroizing` pour effacement automatique à la destruction.
pub struct AesGcmCipher {
    key: Zeroizing<Vec<u8>>,
}

impl AesGcmCipher {
    /// Crée un nouveau cipher avec une clé
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: KEY_SIZE,
                actual: key.len(),
            });
        }

        Ok(AesGcmCipher {
            key: Zeroizing::new(key.to_vec()),
        })
    }

    /// Chiffre des données
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        use aes_gcm::AeadCore;
        use aes_gcm::aead::OsRng;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));

        // Générer un nonce aléatoire via OsRng (CSPRNG)
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_bytes = nonce.to_vec();

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionError("AES-256-GCM encryption failed".to_string()))?;

        Ok(EncryptedData::new(
            "AES-256-GCM".to_string(),
            nonce_bytes,
            ciphertext,
        ))
    }

    /// Déchiffre des données
    pub fn decrypt(&self, encrypted: &EncryptedData) -> Result<Vec<u8>> {
        if encrypted.nonce.len() != NONCE_SIZE {
            return Err(CryptoError::InvalidNonceSize {
                expected: NONCE_SIZE,
                actual: encrypted.nonce.len(),
            });
        }

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&self.key));
        let nonce = GenericArray::from_slice(&encrypted.nonce);

        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(plaintext)
    }
}



/// Fonction utilitaire pour chiffrer rapidement avec AES-GCM
///
/// # Arguments
/// * `plaintext` - Données à chiffrer
/// * `key` - Clé de chiffrement (32 bytes pour AES-256)
///
/// # Returns
/// Données chiffrées avec nonce et tag d'authentification
///
/// # Exemple
/// ```rust
/// use secure_vault_crypto::crypto::aes_gcm::encrypt_aes_gcm;
/// 
/// let key = [0u8; 32]; // Clé AES-256
/// let data = b"Secret data";
/// let encrypted = encrypt_aes_gcm(data, &key).unwrap();
/// ```
pub fn encrypt_aes_gcm(plaintext: &[u8], key: &[u8]) -> Result<EncryptedData> {
    let cipher = AesGcmCipher::new(key)?;
    cipher.encrypt(plaintext)
}

/// Fonction utilitaire pour déchiffrer rapidement avec AES-GCM
///
/// # Arguments
/// * `encrypted` - Données chiffrées avec nonce
/// * `key` - Clé de déchiffrement (32 bytes)
///
/// # Returns
/// Données déchiffrées en cas de succès
///
/// # Exemple
/// ```rust
/// use secure_vault_crypto::crypto::aes_gcm::{encrypt_aes_gcm, decrypt_aes_gcm};
/// 
/// let key = [0u8; 32];
/// let data = b"Secret data";
/// let encrypted = encrypt_aes_gcm(data, &key).unwrap();
/// let decrypted = decrypt_aes_gcm(&encrypted, &key).unwrap();
/// assert_eq!(data, decrypted.as_slice());
/// ```
pub fn decrypt_aes_gcm(encrypted: &EncryptedData, key: &[u8]) -> Result<Vec<u8>> {
    let cipher = AesGcmCipher::new(key)?;
    cipher.decrypt(encrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let plaintext = b"Hello, World!";

        let encrypted = encrypt_aes_gcm(plaintext, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_different_nonces() {
        let key = [0u8; 32];
        let plaintext = b"Test data";

        let encrypted1 = encrypt_aes_gcm(plaintext, &key).unwrap();
        let encrypted2 = encrypt_aes_gcm(plaintext, &key).unwrap();

        // Les nonces doivent être différents
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
    }

    #[test]
    fn test_invalid_key_size() {
        let key = [0u8; 16]; // Trop court
        let plaintext = b"Test";

        let result = encrypt_aes_gcm(plaintext, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0u8; 32];
        let plaintext = b"Test data";

        let mut encrypted = encrypt_aes_gcm(plaintext, &key).unwrap();
        
        // Modifier le ciphertext pour provoquer une erreur d'authentification
        encrypted.ciphertext[0] ^= 0x01;

        let result = decrypt_aes_gcm(&encrypted, &key);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_large_data() {
        let key = [0u8; 32];
        let plaintext = vec![42u8; 10_000]; // 10 KB

        let encrypted = encrypt_aes_gcm(&plaintext, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_empty_data() {
        let key = [0u8; 32];
        let plaintext = b"";

        let encrypted = encrypt_aes_gcm(plaintext, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&encrypted, &key).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_cipher_reuse() {
        let key = [0u8; 32];
        let cipher = AesGcmCipher::new(&key).unwrap();

        let plaintext1 = b"First message";
        let plaintext2 = b"Second message";

        let encrypted1 = cipher.encrypt(plaintext1).unwrap();
        let encrypted2 = cipher.encrypt(plaintext2).unwrap();

        let decrypted1 = cipher.decrypt(&encrypted1).unwrap();
        let decrypted2 = cipher.decrypt(&encrypted2).unwrap();

        assert_eq!(plaintext1, decrypted1.as_slice());
        assert_eq!(plaintext2, decrypted2.as_slice());
    }
}

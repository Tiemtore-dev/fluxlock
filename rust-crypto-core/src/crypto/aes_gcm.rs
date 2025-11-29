//! Module de chiffrement AES-GCM
//! 
//! Implémentation du chiffrement authentifié AES-256-GCM utilisant
//! la bibliothèque `ring` de Google (fork de BoringSSL).

use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};
use crate::errors::{CryptoError, Result};
use crate::secure_memory::EncryptedData;

/// Taille du nonce pour AES-GCM (12 bytes recommandés)
const NONCE_SIZE: usize = 12;

/// Taille de la clé AES-256 (32 bytes)
const KEY_SIZE: usize = 32;

/// Générateur de nonce unique pour chaque opération
struct NonceGenerator {
    rng: SystemRandom,
}

impl NonceGenerator {
    fn new() -> Self {
        NonceGenerator {
            rng: SystemRandom::new(),
        }
    }

    fn generate(&self) -> Result<Vec<u8>> {
        let mut nonce = vec![0u8; NONCE_SIZE];
        self.rng
            .fill(&mut nonce)
            .map_err(|_| CryptoError::RandomGenerationError("Failed to generate nonce".to_string()))?;
        Ok(nonce)
    }
}

impl NonceSequence for NonceGenerator {
    fn advance(&mut self) -> std::result::Result<Nonce, Unspecified> {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        self.rng.fill(&mut nonce_bytes)?;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// Cipher AES-GCM avec gestion d'état
pub struct AesGcmCipher {
    key: Vec<u8>,
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
            key: key.to_vec(),
        })
    }

    /// Chiffre des données
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        // Génér un nonce aléatoire
        let rng = SystemRandom::new();
        let mut nonce_bytes = vec![0u8; NONCE_SIZE];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| CryptoError::RandomGenerationError("Failed to generate nonce".to_string()))?;

        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| CryptoError::EncryptionError("Invalid nonce".to_string()))?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| CryptoError::EncryptionError("Invalid key".to_string()))?;

        // Utiliser LessSafeKey pour avoir le contrôle direct du nonce
        let key = ring::aead::LessSafeKey::new(unbound_key);

        let mut in_out = plaintext.to_vec();
        
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionError("Encryption failed".to_string()))?;

        Ok(EncryptedData::new(
            "AES-256-GCM".to_string(),
            nonce_bytes,
            in_out,
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

        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| CryptoError::DecryptionError("Invalid key".to_string()))?;

        let nonce = Nonce::try_assume_unique_for_key(&encrypted.nonce)
            .map_err(|_| CryptoError::DecryptionError("Invalid nonce".to_string()))?;

        // Utiliser LessSafeKey pour avoir le contrôle direct
        let key = ring::aead::LessSafeKey::new(unbound_key);

        let mut in_out = encrypted.ciphertext.clone();

        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(plaintext.to_vec())
    }
}

/// Nonce à usage unique pour le déchiffrement
struct SingleUseNonce(Option<Nonce>);

impl NonceSequence for SingleUseNonce {
    fn advance(&mut self) -> std::result::Result<Nonce, Unspecified> {
        self.0.take().ok_or(Unspecified)
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

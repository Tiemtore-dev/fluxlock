//! Gestion des erreurs cryptographiques

use thiserror::Error;

/// Type résultat personnalisé pour les opérations cryptographiques
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Erreurs possibles dans les opérations cryptographiques
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Erreur lors du chiffrement
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    /// Erreur lors du déchiffrement
    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    /// Erreur de dérivation de clé
    #[error("Key derivation failed: {0}")]
    KeyDerivationError(String),

    /// Erreur de signature
    #[error("Signature error: {0}")]
    SignatureError(String),

    /// Erreur de vérification de signature
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Erreur d'échange de clés
    #[error("Key exchange failed: {0}")]
    KeyExchangeError(String),

    /// Erreur de hachage
    #[error("Hashing error: {0}")]
    HashingError(String),

    /// Taille de clé invalide
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Taille de nonce/IV invalide
    #[error("Invalid nonce size: expected {expected}, got {actual}")]
    InvalidNonceSize { expected: usize, actual: usize },

    /// Données corrompues ou invalides
    #[error("Invalid or corrupted data: {0}")]
    InvalidData(String),

    /// Tag d'authentification invalide
    #[error("Authentication tag verification failed")]
    AuthenticationFailed,

    /// Erreur d'entrée/sortie
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Erreur de sérialisation
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Erreur de désérialisation
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Erreur générique
    #[error("Cryptographic error: {0}")]
    Generic(String),

    /// Erreur de génération aléatoire
    #[error("Random generation failed: {0}")]
    RandomGenerationError(String),

    /// Erreur HSM
    #[cfg(feature = "hsm")]
    #[error("HSM error: {0}")]
    HsmError(String),
}

// Note: aes_gcm::Error est le même type que chacha20poly1305::Error (aead::Error).
// La conversion est couverte par impl From<chacha20poly1305::Error> ci-dessous.

/// Conversion depuis argon2::Error
impl From<argon2::Error> for CryptoError {
    fn from(err: argon2::Error) -> Self {
        CryptoError::KeyDerivationError(format!("Argon2 error: {:?}", err))
    }
}

/// Conversion depuis ed25519_dalek::SignatureError
impl From<ed25519_dalek::SignatureError> for CryptoError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        CryptoError::SignatureError(format!("Ed25519 error: {}", err))
    }
}

/// Conversion depuis chacha20poly1305::Error
impl From<chacha20poly1305::Error> for CryptoError {
    fn from(err: chacha20poly1305::Error) -> Self {
        CryptoError::Generic(format!("ChaCha20-Poly1305 error: {}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptoError::EncryptionError("test error".to_string());
        assert_eq!(err.to_string(), "Encryption failed: test error");
    }

    #[test]
    fn test_invalid_key_size_error() {
        let err = CryptoError::InvalidKeySize {
            expected: 32,
            actual: 16,
        };
        assert!(err.to_string().contains("expected 32"));
        assert!(err.to_string().contains("got 16"));
    }
}

//! # Secure Vault Crypto Core
//! 
//! Core cryptographique de niveau militaire pour SecureVault Next-Gen.
//! 
//! ## Fonctionnalités
//! 
//! - **Chiffrement authentifié**: AES-256-GCM, ChaCha20-Poly1305
//! - **Dérivation de clés**: Argon2id (résistant GPU)
//! - **Signatures**: Ed25519 (courbes elliptiques)
//! - **Échange de clés**: X25519 (Diffie-Hellman)
//! - **Hachage**: BLAKE3, SHA-3, SHA-256
//! - **Effacement mémoire**: Zeroize pour sécurité maximale
//! 
//! ## Utilisation
//! 
//! ```rust
//! use secure_vault_crypto::*;
//! 
//! // Dériver une clé depuis un mot de passe
//! let key = derive_key_from_password("super_secret_password", &[0u8; 32])?;
//! 
//! // Chiffrer des données
//! let encrypted = encrypt_aes_gcm(b"données sensibles", &key)?;
//! 
//! // Déchiffrer
//! let decrypted = decrypt_aes_gcm(&encrypted, &key)?;
//! ```

// Modules publics
pub mod crypto;
pub mod key_derivation;
pub mod signatures;
pub mod key_exchange;
pub mod hashing;
pub mod secure_memory;
pub mod key_management;
pub mod errors;
pub mod utils;

// Réexporter les types principaux pour faciliter l'usage
pub use crypto::{
    aes_gcm::{encrypt_aes_gcm, decrypt_aes_gcm, AesGcmCipher},
    chacha::{encrypt_chacha20, decrypt_chacha20, ChaCha20Cipher},
};
pub use key_derivation::{
    argon2::{derive_key_from_password, Argon2Config},
    hkdf::derive_key_hkdf,
};
pub use signatures::ed25519::{KeyPair as Ed25519KeyPair, sign_message, verify_signature};
pub use key_exchange::x25519::{generate_keypair, compute_shared_secret};
pub use hashing::{blake3_hash, sha3_256_hash, sha256_hash};
pub use secure_memory::{SecretBytes, SecretString};
pub use errors::{CryptoError, Result};

// Version du crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_full_encryption_flow() {
        // Test d'un flux complet de chiffrement/déchiffrement
        let password = "test_password_1234";
        let salt = [0u8; 32];
        
        // Dérivation de clé
        let key = derive_key_from_password(password, &salt).expect("Key derivation failed");
        
        // Chiffrement
        let data = b"Donnees ultra secretes!";
        let encrypted = encrypt_aes_gcm(data, key.expose_secret()).expect("Encryption failed");
        
        // Déchiffrement
        let decrypted = decrypt_aes_gcm(&encrypted, key.expose_secret()).expect("Decryption failed");
        
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_signature_flow() {
        // Test du flux de signature
        let keypair = Ed25519KeyPair::generate();
        let message = b"Message important a signer";
        
        let signature = sign_message(message, &keypair);
        let is_valid = verify_signature(message, &signature, &keypair.public_key);
        
        assert!(is_valid);
    }

    #[test]
    fn test_key_exchange_flow() {
        // Test d'échange de clés Diffie-Hellman
        let (alice_secret, alice_public) = generate_keypair();
        let (bob_secret, bob_public) = generate_keypair();
        
        let alice_shared = compute_shared_secret(alice_secret, &bob_public).unwrap();
        let bob_shared = compute_shared_secret(bob_secret, &alice_public).unwrap();
        
        // Les deux parties doivent avoir le même secret partagé
        assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());
    }
}

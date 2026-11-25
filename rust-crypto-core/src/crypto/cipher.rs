//! Module de chiffrement symétrique AEAD.
//!
//! Utilise ChaCha20-Poly1305 comme algorithme principal pour le vault v2.
//!
//! ## Pourquoi ChaCha20-Poly1305 plutôt qu'AES-256-GCM ?
//! - **Constant-time garanti** : pas de dépendance à AES-NI hardware.
//! - **Performance uniforme** : rapide sur ARM (mobile), AMD, Intel.
//! - **RustCrypto natif** : pure Rust, pas de binding C/asm.
//! - **Résistance quantique** : 256 bits de clé → ~128 bits post-Grover (suffisant).
//! - **IETF standard** : RFC 8439.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::errors::CryptoError;

/// Taille du nonce en bytes (96 bits — RFC 8439)
pub const NONCE_SIZE: usize = 12;

/// Taille de la clé en bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Taille du tag d'authentification Poly1305 (128 bits)
pub const TAG_SIZE: usize = 16;

/// Blob chiffré contenant nonce + ciphertext (+ tag intégré dans ciphertext par ChaCha20Poly1305).
pub struct EncryptedBlob {
    /// Nonce unique utilisé pour ce chiffrement (12 bytes).
    pub nonce: [u8; NONCE_SIZE],
    /// Ciphertext + tag Poly1305 (16 derniers bytes).
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Longueur totale sérialisée : nonce + ciphertext.
    pub fn serialized_len(&self) -> usize {
        NONCE_SIZE + self.ciphertext.len()
    }

    /// Sérialise en `nonce || ciphertext`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialized_len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Désérialise depuis `nonce || ciphertext`.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < NONCE_SIZE + TAG_SIZE {
            return Err(CryptoError::DecryptionError(
                "Encrypted blob too short (must contain nonce + tag at minimum)".into(),
            ));
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[..NONCE_SIZE]);
        let ciphertext = data[NONCE_SIZE..].to_vec();
        Ok(Self { nonce, ciphertext })
    }
}

/// Chiffre un plaintext avec ChaCha20-Poly1305 sans AAD additionnelle.
///
/// # Arguments
/// * `key` - Clé de 256 bits (32 bytes).
/// * `plaintext` - Données en clair à chiffrer.
///
/// # Sécurité
/// - Nonce unique 96 bits généré via `OsRng` (CSPRNG).
/// - Tag Poly1305 128 bits intégré au ciphertext.
/// - Le plaintext n'est jamais copié inutilement.
pub fn encrypt(key: &[u8; KEY_SIZE], plaintext: &[u8]) -> Result<EncryptedBlob, CryptoError> {
    encrypt_with_aad(key, plaintext, &[])
}

/// Chiffre un plaintext avec ChaCha20-Poly1305 et des données associées authentifiées (AAD — RFC 8439).
///
/// L'AAD n'est pas chiffrée mais est liée cryptographiquement au tag Poly1305 :
/// toute modification du contexte (ex. `user_id`, table SQLite, nom de colonne) fait
/// échouer le déchiffrement avec `CryptoError::AuthenticationFailed`.
pub fn encrypt_with_aad(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedBlob, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionError(format!("Invalid key: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| CryptoError::RandomGenerationError(format!("Nonce generation failed: {}", e)))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionError(format!("ChaCha20-Poly1305 encrypt failed: {}", e)))?;

    Ok(EncryptedBlob {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Déchiffre un `EncryptedBlob` avec ChaCha20-Poly1305 sans AAD.
///
/// # Arguments
/// * `key` - Clé de 256 bits (32 bytes).
/// * `blob` - Blob chiffré (nonce + ciphertext + tag).
///
/// # Sécurité
/// - Vérifie le tag Poly1305 AVANT de retourner le plaintext.
/// - En cas d'échec, aucune donnée partielle n'est retournée.
/// - Le plaintext est retourné dans un `Zeroizing<Vec<u8>>` pour effacement automatique.
pub fn decrypt(key: &[u8; KEY_SIZE], blob: &EncryptedBlob) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    decrypt_with_aad(key, blob, &[])
}

/// Déchiffre un `EncryptedBlob` avec ChaCha20-Poly1305 en vérifiant l'AAD (RFC 8439).
pub fn decrypt_with_aad(
    key: &[u8; KEY_SIZE],
    blob: &EncryptedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionError(format!("Invalid key: {}", e)))?;

    let nonce = Nonce::from_slice(&blob.nonce);
    let payload = Payload {
        msg: blob.ciphertext.as_ref(),
        aad,
    };

    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AuthenticationFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"Hello, post-quantum world!";
        let blob = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let key = test_key();
        let plaintext = b"test";
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..10_000 {
            let blob = encrypt(&key, plaintext).unwrap();
            assert!(nonces.insert(blob.nonce), "Nonce collision detected!");
        }
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let key2 = test_key();
        let blob = encrypt(&key1, b"secret data").unwrap();
        let result = decrypt(&key2, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let mut blob = encrypt(&key, b"important data").unwrap();
        // Flip one bit in the ciphertext
        if let Some(byte) = blob.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }
        let result = decrypt(&key, &blob);
        assert!(matches!(result, Err(CryptoError::AuthenticationFailed)));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let blob = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();
        assert_eq!(&*decrypted, b"");
    }

    #[test]
    fn test_large_plaintext() {
        let key = test_key();
        let plaintext = vec![0xABu8; 1_000_000]; // 1 MB
        let blob = encrypt(&key, &plaintext).unwrap();
        let decrypted = decrypt(&key, &blob).unwrap();
        assert_eq!(&*decrypted, &plaintext);
    }

    #[test]
    fn test_blob_serialization_roundtrip() {
        let key = test_key();
        let blob = encrypt(&key, b"serialize me").unwrap();
        let bytes = blob.to_bytes();
        let restored = EncryptedBlob::from_bytes(&bytes).unwrap();
        let decrypted = decrypt(&key, &restored).unwrap();
        assert_eq!(&*decrypted, b"serialize me");
    }

    #[test]
    fn test_encrypt_decrypt_with_aad_roundtrip_and_mismatch_rejection() {
        let key = test_key();
        let aad = b"fluxlock/v2/user:1/table:passwords/field:password";
        let wrong_aad = b"fluxlock/v2/user:1/table:passwords/field:title";
        let blob = encrypt_with_aad(&key, b"top-secret", aad).unwrap();

        let decrypted = decrypt_with_aad(&key, &blob, aad).unwrap();
        assert_eq!(&*decrypted, b"top-secret");

        // Column swap / wrong AAD must fail authentication
        assert!(matches!(
            decrypt_with_aad(&key, &blob, wrong_aad),
            Err(CryptoError::AuthenticationFailed)
        ));
        // Missing AAD must also fail authentication
        assert!(matches!(
            decrypt(&key, &blob),
            Err(CryptoError::AuthenticationFailed)
        ));
    }
}

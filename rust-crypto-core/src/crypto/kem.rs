//! Module d'encapsulation de clé post-quantique ML-KEM-768 (FIPS 203).
//!
//! ## Pourquoi ML-KEM-768 ?
//! - **Standardisé NIST 2024** : FIPS 203 — premier KEM post-quantique officiel.
//! - **Niveau de sécurité 3** : ~192 bits classique, ~128 bits quantique.
//! - **Performance** : encapsulation < 1ms, décapsulation < 1ms.
//! - **Taille raisonnable** : clé publique 1184 bytes, ciphertext 1088 bytes.
//!
//! ## Usage dans le vault
//! Pour le partage multi-utilisateur ou l'export chiffré :
//! 1. Le destinataire génère une paire de clés ML-KEM-768.
//! 2. L'expéditeur encapsule un secret partagé avec la clé publique.
//! 3. Le secret partagé est utilisé comme clé ChaCha20-Poly1305.
//! 4. Le destinataire décapsule pour récupérer le même secret.

use ml_kem::MlKem768;
use ml_kem::{Kem, Encapsulate, Decapsulate};
use ml_kem::{KeyExport, TryKeyInit, KeyInit};
use zeroize::Zeroizing;

use crate::errors::CryptoError;

/// Clé publique ML-KEM-768 (1184 bytes).
pub struct KemPublicKey {
    key: ml_kem::EncapsulationKey<MlKem768>,
}

/// Clé privée ML-KEM-768 — zéroïsée on Drop.
///
/// N'implémente ni `Debug` ni `Clone`.
pub struct KemPrivateKey {
    key: ml_kem::DecapsulationKey<MlKem768>,
}

/// Sécurité : la DecapsulationKey contient ~2400 bytes secrets.
/// On force le zéroïsage en écrasant la mémoire brute au drop,
/// en couche de défense supplémentaire.
impl Drop for KemPrivateKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Interpréter la clé comme un slice mutable de bytes et zéroïser
        // via les écritures volatiles de zeroize (non-optimisables).
        let ptr = &mut self.key as *mut _ as *mut u8;
        let size = std::mem::size_of::<ml_kem::DecapsulationKey<MlKem768>>();
        let bytes = unsafe { std::slice::from_raw_parts_mut(ptr, size) };
        bytes.zeroize();
    }
}

/// Secret partagé issu de l'encapsulation (32 bytes).
pub struct SharedSecret {
    secret: Zeroizing<[u8; 32]>,
}

impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// Ciphertext ML-KEM-768 (1088 bytes).
pub struct KemCiphertext {
    data: Vec<u8>,
}

impl KemCiphertext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            data: bytes.to_vec(),
        }
    }
}

/// Génère une paire de clés ML-KEM-768.
///
/// # Retour
/// `(KemPublicKey, KemPrivateKey)` — la clé privée est zéroïsée on Drop.
pub fn generate_recipient_keypair() -> Result<(KemPublicKey, KemPrivateKey), CryptoError> {
    let (dk, ek) = MlKem768::generate_keypair();

    Ok((
        KemPublicKey { key: ek },
        KemPrivateKey { key: dk },
    ))
}

/// Encapsule un secret partagé pour un destinataire.
///
/// # Arguments
/// * `recipient_pubkey` - Clé publique ML-KEM-768 du destinataire.
///
/// # Retour
/// `(SharedSecret, KemCiphertext)` — le secret et le ciphertext à envoyer.
pub fn encapsulate(
    recipient_pubkey: &KemPublicKey,
) -> Result<(SharedSecret, KemCiphertext), CryptoError> {
    let (ct, shared_key) = recipient_pubkey.key.encapsulate();

    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    let sk_ref: &[u8] = shared_key.as_ref();
    if sk_ref.len() < 32 {
        return Err(CryptoError::KeyExchangeError(
            "Shared secret too short".into(),
        ));
    }
    secret_bytes.copy_from_slice(&sk_ref[..32]);

    Ok((
        SharedSecret {
            secret: secret_bytes,
        },
        KemCiphertext {
            data: <_ as AsRef<[u8]>>::as_ref(&ct).to_vec(),
        },
    ))
}

/// Décapsule un secret partagé reçu.
///
/// # Arguments
/// * `privkey` - Clé privée ML-KEM-768 du destinataire.
/// * `ciphertext` - Ciphertext reçu de l'expéditeur.
///
/// # Retour
/// `SharedSecret` — le secret partagé (32 bytes), identique à celui de l'expéditeur.
pub fn decapsulate(
    privkey: &KemPrivateKey,
    ciphertext: &KemCiphertext,
) -> Result<SharedSecret, CryptoError> {
    let shared_key = privkey
        .key
        .decapsulate_slice(&ciphertext.data)
        .map_err(|_| CryptoError::KeyExchangeError("ML-KEM-768 decapsulation failed".into()))?;

    let mut secret_bytes = Zeroizing::new([0u8; 32]);
    let sk_ref: &[u8] = shared_key.as_ref();
    if sk_ref.len() < 32 {
        return Err(CryptoError::KeyExchangeError(
            "Shared secret too short".into(),
        ));
    }
    secret_bytes.copy_from_slice(&sk_ref[..32]);

    Ok(SharedSecret {
        secret: secret_bytes,
    })
}

/// Sérialise la clé publique pour stockage/transmission.
impl KemPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let key_bytes = KeyExport::to_bytes(&self.key);
        let slice: &[u8] = key_bytes.as_ref();
        slice.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let ek = <ml_kem::EncapsulationKey<MlKem768> as TryKeyInit>::new_from_slice(bytes)
            .map_err(|_| CryptoError::KeyExchangeError("Invalid ML-KEM-768 public key".into()))?;
        Ok(Self { key: ek })
    }
}

/// Sérialise la clé privée pour stockage sécurisé.
impl KemPrivateKey {
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let seed = KeyExport::to_bytes(&self.key);
        let slice: &[u8] = seed.as_ref();
        Zeroizing::new(slice.to_vec())
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let dk = <ml_kem::DecapsulationKey<MlKem768> as KeyInit>::new_from_slice(bytes)
            .map_err(|_| CryptoError::KeyExchangeError("Invalid ML-KEM-768 private key".into()))?;
        Ok(Self { key: dk })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_encapsulate_decapsulate() {
        let (pubkey, privkey) = generate_recipient_keypair().unwrap();
        let (sender_secret, ciphertext) = encapsulate(&pubkey).unwrap();
        let receiver_secret = decapsulate(&privkey, &ciphertext).unwrap();
        assert_eq!(sender_secret.as_bytes(), receiver_secret.as_bytes());
    }

    #[test]
    fn test_kem_different_keypairs_different_secrets() {
        let (pubkey1, _privkey1) = generate_recipient_keypair().unwrap();
        let (pubkey2, _privkey2) = generate_recipient_keypair().unwrap();
        let (secret1, _ct1) = encapsulate(&pubkey1).unwrap();
        let (secret2, _ct2) = encapsulate(&pubkey2).unwrap();
        assert_ne!(secret1.as_bytes(), secret2.as_bytes());
    }

    #[test]
    fn test_kem_wrong_privkey_produces_different_secret() {
        let (pubkey, _privkey) = generate_recipient_keypair().unwrap();
        let (_pubkey2, wrong_privkey) = generate_recipient_keypair().unwrap();
        let (_secret, ciphertext) = encapsulate(&pubkey).unwrap();
        // ML-KEM uses implicit rejection: wrong key produces a random-looking secret
        let wrong_secret = decapsulate(&wrong_privkey, &ciphertext).unwrap();
        let correct_secret = decapsulate(&_privkey, &ciphertext).unwrap();
        assert_ne!(wrong_secret.as_bytes(), correct_secret.as_bytes());
    }

    #[test]
    fn test_kem_key_serialization_roundtrip() {
        let (pubkey, privkey) = generate_recipient_keypair().unwrap();

        let pub_bytes = pubkey.to_bytes();
        let restored_pub = KemPublicKey::from_bytes(&pub_bytes).unwrap();

        let priv_bytes = privkey.to_bytes();
        let restored_priv = KemPrivateKey::from_bytes(&priv_bytes).unwrap();

        let (sender_secret, ct) = encapsulate(&restored_pub).unwrap();
        let receiver_secret = decapsulate(&restored_priv, &ct).unwrap();
        assert_eq!(sender_secret.as_bytes(), receiver_secret.as_bytes());
    }
}

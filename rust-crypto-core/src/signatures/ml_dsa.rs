//! Signatures post-quantiques ML-DSA-65 (FIPS 204).
//!
//! ## Pourquoi ML-DSA-65 ?
//! - **Standardisé NIST 2024** : FIPS 204 — première signature PQ officielle.
//! - **Niveau de sécurité 3** : ~128 bits quantique, aligné avec ML-KEM-768.
//! - **Performance** : signature < 1ms, vérification < 1ms.
//!
//! ## Tailles
//! - Clé de vérification (SPKI DER) : ~1970 bytes
//! - Seed (clé privée compacte) : 32 bytes
//! - Signature : 3309 bytes
//!
//! ## Usage dans FluXlock
//! Chaque entrée du trust store est signée par l'appareil qui l'a créée.
//! Les pairs vérifient les signatures pendant la synchronisation P2P
//! pour empêcher l'injection d'entrées falsifiées.

use ml_dsa::{MlDsa65, KeyGen};
use ml_dsa::signature::{Keypair, Signer, Verifier, SignatureEncoding};
use ml_dsa::pkcs8::{EncodePublicKey, DecodePublicKey, EncodePrivateKey, DecodePrivateKey};
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
use std::mem::MaybeUninit;
use zeroize::Zeroizing;

use crate::errors::{CryptoError, Result};

/// Taille de la seed = clé de signature (32 bytes, toutes catégories ML-DSA)
pub const SIGNING_SEED_SIZE: usize = 32;

/// Paire de clés ML-DSA-65
pub struct MlDsaKeyPair {
    signing_key: Box<MaybeUninit<ml_dsa::SigningKey<MlDsa65>>>,
}

impl MlDsaKeyPair {
    fn new(signing_key: ml_dsa::SigningKey<MlDsa65>) -> Self {
        Self {
            signing_key: Box::new(MaybeUninit::new(signing_key)),
        }
    }

    fn key(&self) -> &ml_dsa::SigningKey<MlDsa65> {
        // SAFETY: initialisé dans `new` et détruit uniquement dans `Drop::drop`.
        unsafe { self.signing_key.assume_init_ref() }
    }

    /// Génère une nouvelle paire de clés ML-DSA-65
    pub fn generate() -> Result<Self> {
        let mut rng = UnwrapErr(SysRng);
        let signing_key = MlDsa65::key_gen(&mut rng);
        Ok(Self::new(signing_key))
    }

    /// Signe un message avec ML-DSA-65
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let sig = self.key().sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    /// Exporte la clé de vérification (publique) en SPKI DER
    pub fn verifying_key_bytes(&self) -> Result<Vec<u8>> {
        let vk = self.key().verifying_key();
        let der = vk.to_public_key_der()
            .map_err(|e| CryptoError::SignatureError(format!("ML-DSA encode vk: {}", e)))?;
        Ok(der.as_ref().to_vec())
    }

    /// Exporte la seed (clé privée compacte, 32 bytes) — SENSIBLE (zéroïsée au Drop)
    pub fn signing_seed_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.key().to_seed().to_vec())
    }

    /// Sérialise la clé de signature en PKCS#8 DER — SENSIBLE (zéroïsée au Drop)
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let doc = self.key().to_pkcs8_der()
            .map_err(|e| CryptoError::SignatureError(format!("ML-DSA encode sk: {}", e)))?;
        Ok(Zeroizing::new(doc.as_bytes().to_vec()))
    }

    /// Reconstruit une paire de clés depuis un PKCS#8 DER
    pub fn from_pkcs8_der(der_bytes: &[u8]) -> Result<Self> {
        let signing_key = ml_dsa::SigningKey::<MlDsa65>::from_pkcs8_der(der_bytes)
            .map_err(|e| CryptoError::SignatureError(format!("ML-DSA decode sk: {}", e)))?;
        Ok(Self::new(signing_key))
    }
}

impl Drop for MlDsaKeyPair {
    fn drop(&mut self) {
        // Exécute le destructeur formel puis efface toute l'allocation (y compris représentations NTT)
        unsafe {
            std::ptr::drop_in_place(self.signing_key.as_mut_ptr());
            let ptr = self.signing_key.as_mut_ptr().cast::<u8>();
            for i in 0..std::mem::size_of::<ml_dsa::SigningKey<MlDsa65>>() {
                ptr.add(i).write_volatile(0);
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
}

pub fn validate_verifying_key(vk_der: &[u8]) -> Result<()> {
    ml_dsa::VerifyingKey::<MlDsa65>::from_public_key_der(vk_der)
        .map(|_| ())
        .map_err(|error| CryptoError::SignatureError(format!("ML-DSA import vk: {error}")))
}

/// Vérifie une signature ML-DSA-65 avec une clé de vérification SPKI DER
pub fn verify_ml_dsa(
    vk_der: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool> {
    let vk = ml_dsa::VerifyingKey::<MlDsa65>::from_public_key_der(vk_der)
        .map_err(|e| CryptoError::SignatureError(format!("ML-DSA import vk: {}", e)))?;

    let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature_bytes)
        .map_err(|e| CryptoError::SignatureError(format!("ML-DSA import sig: {}", e)))?;

    match vk.verify(message, &sig) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let msg = b"Hello, post-quantum world!";
        let sig = kp.sign(msg).unwrap();
        let vk = kp.verifying_key_bytes().unwrap();
        assert!(verify_ml_dsa(&vk, msg, &sig).unwrap());
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let sig = kp.sign(b"original").unwrap();
        let vk = kp.verifying_key_bytes().unwrap();
        assert!(!verify_ml_dsa(&vk, b"tampered", &sig).unwrap());
    }

    #[test]
    fn test_pkcs8_roundtrip() {
        let kp = MlDsaKeyPair::generate().unwrap();
        let msg = b"pkcs8 persistence test";
        let vk = kp.verifying_key_bytes().unwrap();

        let der = kp.to_pkcs8_der().unwrap();
        let kp2 = MlDsaKeyPair::from_pkcs8_der(&der).unwrap();
        let sig2 = kp2.sign(msg).unwrap();

        assert!(verify_ml_dsa(&vk, msg, &sig2).unwrap());
    }
}

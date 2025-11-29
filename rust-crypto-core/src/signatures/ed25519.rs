//! Signatures numériques Ed25519
//! 
//! Ed25519 est un système de signature à courbe elliptique moderne,
//! rapide et sécurisé.

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use crate::errors::{CryptoError, Result};

/// Paire de clés Ed25519
#[derive(Clone)]
pub struct KeyPair {
    pub signing_key: SigningKey,
    pub public_key: VerifyingKey,
}

impl KeyPair {
    /// Génère une nouvelle paire de clés aléatoire
    pub fn generate() -> Self {
        // Générer 32 bytes aléatoires pour la clé privée
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key();
        
        KeyPair {
            signing_key,
            public_key,
        }
    }

    /// Crée une paire de clés depuis une graine de 32 bytes
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let public_key = signing_key.verifying_key();
        
        KeyPair {
            signing_key,
            public_key,
        }
    }

    /// Exporte la clé privée
    pub fn export_private_key(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Exporte la clé publique
    pub fn export_public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.public_key.to_bytes()
    }

    /// Importe une paire de clés depuis des bytes
    pub fn from_bytes(private_key: &[u8; SECRET_KEY_LENGTH]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(private_key);
        let public_key = signing_key.verifying_key();
        
        Ok(KeyPair {
            signing_key,
            public_key,
        })
    }

    /// Signe un message
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key.sign(message).to_bytes().to_vec()
    }

    /// Vérifie une signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(CryptoError::SignatureError(
                format!("Invalid signature length: expected {}, got {}", SIGNATURE_LENGTH, signature.len())
            ));
        }

        let sig = Signature::from_bytes(signature.try_into().unwrap());
        
        match self.public_key.verify(message, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519KeyPair {{ public_key: {:?}, private_key: [REDACTED] }}", 
               self.public_key.to_bytes())
    }
}

/// Signe un message avec une paire de clés
pub fn sign_message(message: &[u8], keypair: &KeyPair) -> Vec<u8> {
    keypair.sign(message)
}

/// Vérifie une signature
pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &VerifyingKey) -> bool {
    if signature.len() != SIGNATURE_LENGTH {
        return false;
    }

    let sig = match Signature::try_from(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    public_key.verify(message, &sig).is_ok()
}

/// Structure pour la clé publique sérialisable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyExport {
    pub key_bytes: Vec<u8>,
    pub algorithm: String,
}

impl PublicKeyExport {
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        PublicKeyExport {
            key_bytes: key.to_bytes().to_vec(),
            algorithm: "Ed25519".to_string(),
        }
    }

    pub fn to_verifying_key(&self) -> Result<VerifyingKey> {
        if self.key_bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(CryptoError::InvalidData(
                format!("Invalid public key length: {}", self.key_bytes.len())
            ));
        }

        let key_array: [u8; PUBLIC_KEY_LENGTH] = self.key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidData("Failed to convert to array".to_string()))?;

        VerifyingKey::from_bytes(&key_array)
            .map_err(|e| CryptoError::SignatureError(format!("Invalid public key: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = KeyPair::generate();
        assert_eq!(keypair.export_private_key().len(), SECRET_KEY_LENGTH);
        assert_eq!(keypair.export_public_key().len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KeyPair::generate();
        let message = b"Important message to sign";
        
        let signature = keypair.sign(message);
        assert_eq!(signature.len(), SIGNATURE_LENGTH);
        
        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let keypair = KeyPair::generate();
        let message = b"Original message";
        let wrong_message = b"Tampered message";
        
        let signature = keypair.sign(message);
        
        let is_valid = keypair.verify(wrong_message, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [42u8; 32];
        
        let keypair1 = KeyPair::from_seed(&seed);
        let keypair2 = KeyPair::from_seed(&seed);
        
        assert_eq!(keypair1.export_private_key(), keypair2.export_private_key());
        assert_eq!(keypair1.export_public_key(), keypair2.export_public_key());
    }

    #[test]
    fn test_export_import() {
        let keypair = KeyPair::generate();
        let private_bytes = keypair.export_private_key();
        
        let restored = KeyPair::from_bytes(&private_bytes).unwrap();
        
        assert_eq!(keypair.export_public_key(), restored.export_public_key());
    }

    #[test]
    fn test_sign_verify_functions() {
        let keypair = KeyPair::generate();
        let message = b"Test message";
        
        let signature = sign_message(message, &keypair);
        let is_valid = verify_signature(message, &signature, &keypair.public_key);
        
        assert!(is_valid);
    }

    #[test]
    fn test_public_key_export() {
        let keypair = KeyPair::generate();
        let export = PublicKeyExport::from_verifying_key(&keypair.public_key);
        
        assert_eq!(export.algorithm, "Ed25519");
        assert_eq!(export.key_bytes.len(), PUBLIC_KEY_LENGTH);
        
        let restored_key = export.to_verifying_key().unwrap();
        assert_eq!(keypair.export_public_key(), restored_key.to_bytes());
    }

    #[test]
    fn test_tampered_signature() {
        let keypair = KeyPair::generate();
        let message = b"Message";
        
        let mut signature = keypair.sign(message);
        signature[0] ^= 0x01; // Altérer un bit
        
        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(!is_valid);
    }
}

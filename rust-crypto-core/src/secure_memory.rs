//! Gestion sécurisée de la mémoire
//! 
//! Ce module fournit des wrappers pour manipuler des données sensibles
//! de manière sécurisée, avec effacement automatique de la mémoire.

use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Wrapper sécurisé pour des bytes secrets (clés, mots de passe, etc.)
/// 
/// Les données sont automatiquement effacées de la mémoire lors de la destruction.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Crée un nouveau SecretBytes à partir d'un Vec<u8>
    pub fn new(data: Vec<u8>) -> Self {
        SecretBytes(data)
    }

    /// Crée un SecretBytes à partir d'une slice
    pub fn from_slice(data: &[u8]) -> Self {
        SecretBytes(data.to_vec())
    }

    /// Accède aux bytes (usage limité, potentiellement dangereux)
    pub fn expose_secret(&self) -> &[u8] {
        &self.0
    }

    /// Retourne la longueur des données
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Vérifie si vide
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convertit en Vec<u8> (consomme self)
    pub fn into_vec(mut self) -> Vec<u8> {
        let vec = std::mem::take(&mut self.0);
        vec
    }

    /// Clone sécurisé des données
    pub fn clone_secret(&self) -> Self {
        SecretBytes::new(self.0.clone())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([REDACTED {} bytes])", self.0.len())
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(data: Vec<u8>) -> Self {
        SecretBytes::new(data)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(data: &[u8]) -> Self {
        SecretBytes::from_slice(data)
    }
}

/// Wrapper sécurisé pour des chaînes de caractères secrètes
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    /// Crée un nouveau SecretString
    pub fn new(data: String) -> Self {
        SecretString(data)
    }

    /// Accède à la chaîne (usage limité)
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Retourne la longueur
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Vérifie si vide
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Convertit en String (consomme self)
    pub fn into_string(mut self) -> String {
        std::mem::take(&mut self.0)
    }

    /// Convertit en bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([REDACTED {} chars])", self.0.len())
    }
}

impl From<String> for SecretString {
    fn from(data: String) -> Self {
        SecretString::new(data)
    }
}

impl From<&str> for SecretString {
    fn from(data: &str) -> Self {
        SecretString::new(data.to_string())
    }
}

/// Clé cryptographique avec protection mémoire
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CryptoKey {
    key: Vec<u8>,
    algorithm: KeyAlgorithm,
}

/// Algorithmes de clé supportés
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub enum KeyAlgorithm {
    /// AES-256
    Aes256,
    /// ChaCha20
    ChaCha20,
    /// HMAC-SHA256
    HmacSha256,
    /// Ed25519
    Ed25519,
    /// X25519
    X25519,
}

impl CryptoKey {
    /// Crée une nouvelle clé
    pub fn new(key: Vec<u8>, algorithm: KeyAlgorithm) -> Self {
        CryptoKey { key, algorithm }
    }

    /// Accède aux bytes de la clé
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Retourne l'algorithme
    pub fn algorithm(&self) -> &KeyAlgorithm {
        &self.algorithm
    }

    /// Retourne la longueur de la clé
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Vérifie si vide
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    /// Génère une clé aléatoire pour un algorithme
    pub fn generate(algorithm: KeyAlgorithm) -> crate::Result<Self> {
        use rand::RngCore;
        
        let key_size = match algorithm {
            KeyAlgorithm::Aes256 => 32,
            KeyAlgorithm::ChaCha20 => 32,
            KeyAlgorithm::HmacSha256 => 32,
            KeyAlgorithm::Ed25519 => 32,
            KeyAlgorithm::X25519 => 32,
        };

        let mut key = vec![0u8; key_size];
        rand::thread_rng().fill_bytes(&mut key);

        Ok(CryptoKey::new(key, algorithm))
    }
}

impl fmt::Debug for CryptoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CryptoKey {{ algorithm: {:?}, size: {} bytes, data: [REDACTED] }}",
            self.algorithm,
            self.key.len()
        )
    }
}

/// Structure pour les données chiffrées avec métadonnées
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Algorithme utilisé
    pub algorithm: String,
    /// Nonce/IV
    pub nonce: Vec<u8>,
    /// Données chiffrées avec tag d'authentification
    pub ciphertext: Vec<u8>,
    /// Salt (pour dérivation de clé si applicable)
    pub salt: Option<Vec<u8>>,
    /// Version du format
    pub version: u8,
}

impl EncryptedData {
    /// Crée une nouvelle structure de données chiffrées
    pub fn new(algorithm: String, nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        EncryptedData {
            algorithm,
            nonce,
            ciphertext,
            salt: None,
            version: 1,
        }
    }

    /// Ajoute un salt
    pub fn with_salt(mut self, salt: Vec<u8>) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Sérialise en JSON
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string(self)
            .map_err(|e| crate::CryptoError::SerializationError(e.to_string()))
    }

    /// Désérialise depuis JSON
    pub fn from_json(json: &str) -> crate::Result<Self> {
        serde_json::from_str(json)
            .map_err(|e| crate::CryptoError::DeserializationError(e.to_string()))
    }

    /// Sérialise en binaire
    pub fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| crate::CryptoError::SerializationError(e.to_string()))
    }

    /// Désérialise depuis binaire
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| crate::CryptoError::DeserializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_bytes_zeroize() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = SecretBytes::new(data.clone());
        
        assert_eq!(secret.expose_secret(), &[1, 2, 3, 4, 5]);
        assert_eq!(secret.len(), 5);
        
        drop(secret);
        // Les données devraient être effacées automatiquement
    }

    #[test]
    fn test_secret_string_debug() {
        let secret = SecretString::new("password123".to_string());
        let debug_str = format!("{:?}", secret);
        
        assert!(!debug_str.contains("password123"));
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_crypto_key_generation() {
        let key = CryptoKey::generate(KeyAlgorithm::Aes256).unwrap();
        assert_eq!(key.len(), 32);
        assert_eq!(*key.algorithm(), KeyAlgorithm::Aes256);
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let data = EncryptedData::new(
            "AES-256-GCM".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        let json = data.to_json().unwrap();
        let deserialized = EncryptedData::from_json(&json).unwrap();

        assert_eq!(data.algorithm, deserialized.algorithm);
        assert_eq!(data.nonce, deserialized.nonce);
        assert_eq!(data.ciphertext, deserialized.ciphertext);
    }

    #[test]
    fn test_encrypted_data_with_salt() {
        let data = EncryptedData::new(
            "AES-256-GCM".to_string(),
            vec![1, 2, 3],
            vec![4, 5, 6],
        )
        .with_salt(vec![7, 8, 9]);

        assert!(data.salt.is_some());
        assert_eq!(data.salt.unwrap(), vec![7, 8, 9]);
    }
}

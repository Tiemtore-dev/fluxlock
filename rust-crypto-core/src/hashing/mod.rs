//! Fonctions de hachage cryptographiques

use blake3::Hasher as Blake3Hasher;
use sha2::{Sha256, Digest as Sha2Digest};
use sha3::Sha3_256;

/// Calcule le hachage BLAKE3 (rapide et moderne)
///
/// # Exemple
/// ```rust
/// use secure_vault_crypto::hashing::blake3_hash;
/// 
/// let data = b"data to hash";
/// let hash = blake3_hash(data);
/// ```
pub fn blake3_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

/// Calcule le hachage SHA-256
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calcule le hachage SHA3-256
pub fn sha3_256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Calcule le hachage avec un algorithme spécifié
pub fn hash_with_algorithm(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Blake3 => blake3_hash(data),
        HashAlgorithm::Sha256 => sha256_hash(data),
        HashAlgorithm::Sha3_256 => sha3_256_hash(data),
    }
}

/// Algorithmes de hachage supportés
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Blake3,
    Sha256,
    Sha3_256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3() {
        let data = b"test data";
        let hash = blake3_hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha256() {
        let data = b"test";
        let hash = sha256_hash(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_deterministic() {
        let data = b"same data";
        let hash1 = blake3_hash(data);
        let hash2 = blake3_hash(data);
        assert_eq!(hash1, hash2);
    }
}

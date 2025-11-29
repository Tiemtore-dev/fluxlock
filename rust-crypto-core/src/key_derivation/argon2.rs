//! Module de dérivation de clés avec Argon2id
//! 
//! Argon2id est le standard moderne pour le hachage de mots de passe,
//! résistant aux attaques GPU et par canal auxiliaire.

use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, ParamsBuilder, Version,
};
use rand::rngs::OsRng;
use crate::errors::{CryptoError, Result};
use crate::secure_memory::SecretBytes;

/// Configuration Argon2 par défaut (haute sécurité)
const DEFAULT_M_COST: u32 = 65536;  // 64 MiB de mémoire
const DEFAULT_T_COST: u32 = 3;       // 3 itérations
const DEFAULT_P_COST: u32 = 4;       // 4 threads parallèles
const OUTPUT_LEN: usize = 32;        // 32 bytes (256 bits)

/// Configuration pour Argon2id
#[derive(Debug, Clone)]
pub struct Argon2Config {
    /// Coût mémoire en KiB
    pub memory_cost: u32,
    /// Nombre d'itérations
    pub time_cost: u32,
    /// Nombre de threads parallèles
    pub parallelism: u32,
    /// Longueur de la clé dérivée
    pub output_len: usize,
}

impl Default for Argon2Config {
    fn default() -> Self {
        Argon2Config {
            memory_cost: DEFAULT_M_COST,
            time_cost: DEFAULT_T_COST,
            parallelism: DEFAULT_P_COST,
            output_len: OUTPUT_LEN,
        }
    }
}

impl Argon2Config {
    /// Configuration pour sécurité maximale (serveur)
    pub fn high_security() -> Self {
        Argon2Config {
            memory_cost: 131072,  // 128 MiB
            time_cost: 4,
            parallelism: 8,
            output_len: OUTPUT_LEN,
        }
    }

    /// Configuration pour appareils mobiles (mémoire limitée)
    pub fn mobile() -> Self {
        Argon2Config {
            memory_cost: 32768,   // 32 MiB
            time_cost: 2,
            parallelism: 2,
            output_len: OUTPUT_LEN,
        }
    }

    /// Configuration pour tests (rapide)
    pub fn test() -> Self {
        Argon2Config {
            memory_cost: 8192,    // 8 MiB
            time_cost: 1,
            parallelism: 1,
            output_len: OUTPUT_LEN,
        }
    }
}

/// Dérive une clé cryptographique depuis un mot de passe
///
/// Utilise Argon2id avec un salt. Le salt doit être unique par utilisateur
/// et stocké avec la clé dérivée.
///
/// # Arguments
/// * `password` - Mot de passe en texte clair
/// * `salt` - Salt aléatoire (minimum 16 bytes recommandés)
///
/// # Returns
/// Clé dérivée de 32 bytes
///
/// # Exemple
/// ```rust
/// use secure_vault_crypto::key_derivation::argon2::derive_key_from_password;
/// 
/// let password = "super_secret_password";
/// let salt = [0u8; 32]; // En production, utiliser un salt aléatoire
/// let key = derive_key_from_password(password, &salt).unwrap();
/// ```
pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<SecretBytes> {
    derive_key_from_password_with_config(password, salt, &Argon2Config::default())
}

/// Dérive une clé avec une configuration personnalisée
pub fn derive_key_from_password_with_config(
    password: &str,
    salt: &[u8],
    config: &Argon2Config,
) -> Result<SecretBytes> {
    // Construire les paramètres Argon2
    let params = ParamsBuilder::new()
        .m_cost(config.memory_cost)
        .t_cost(config.time_cost)
        .p_cost(config.parallelism)
        .output_len(config.output_len)
        .build()
        .map_err(|e| CryptoError::KeyDerivationError(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params,
    );

    // Dériver la clé
    let mut output = vec![0u8; config.output_len];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| CryptoError::KeyDerivationError(format!("Argon2 derivation failed: {}", e)))?;

    Ok(SecretBytes::from(output))
}

/// Génère un salt aléatoire sécurisé
///
/// # Returns
/// Salt de 32 bytes
pub fn generate_salt() -> Vec<u8> {
    use rand::RngCore;
    let mut salt = vec![0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Dérive une clé avec génération automatique du salt
///
/// # Returns
/// Tuple (clé dérivée, salt utilisé)
///
/// # Exemple
/// ```rust
/// use secure_vault_crypto::key_derivation::argon2::derive_key_with_new_salt;
/// 
/// let password = "my_password";
/// let (key, salt) = derive_key_with_new_salt(password).unwrap();
/// // Stocker le salt avec les données chiffrées
/// ```
pub fn derive_key_with_new_salt(password: &str) -> Result<(SecretBytes, Vec<u8>)> {
    let salt = generate_salt();
    let key = derive_key_from_password(password, &salt)?;
    Ok((key, salt))
}

/// Vérifie un mot de passe contre une clé dérivée
///
/// # Arguments
/// * `password` - Mot de passe à vérifier
/// * `expected_key` - Clé attendue
/// * `salt` - Salt utilisé lors de la dérivation originale
///
/// # Returns
/// `true` si le mot de passe correspond
pub fn verify_password(password: &str, expected_key: &[u8], salt: &[u8]) -> Result<bool> {
    let derived_key = derive_key_from_password(password, salt)?;
    
    // Comparaison à temps constant pour éviter les attaques par timing
    Ok(constant_time_compare(derived_key.expose_secret(), expected_key))
}

/// Comparaison à temps constant de deux slices
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key() {
        let password = "test_password";
        let salt = [0u8; 32];

        let key = derive_key_from_password(password, &salt).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_deterministic_derivation() {
        let password = "same_password";
        let salt = [1u8; 32];

        let key1 = derive_key_from_password(password, &salt).unwrap();
        let key2 = derive_key_from_password(password, &salt).unwrap();

        assert_eq!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = "password";
        let salt1 = [1u8; 32];
        let salt2 = [2u8; 32];

        let key1 = derive_key_from_password(password, &salt1).unwrap();
        let key2 = derive_key_from_password(password, &salt2).unwrap();

        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = [0u8; 32];
        
        let key1 = derive_key_from_password("password1", &salt).unwrap();
        let key2 = derive_key_from_password("password2", &salt).unwrap();

        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        assert_ne!(salt1, salt2); // Probabilité infime de collision
    }

    #[test]
    fn test_derive_with_new_salt() {
        let password = "test_password";
        
        let (key1, salt1) = derive_key_with_new_salt(password).unwrap();
        let (key2, salt2) = derive_key_with_new_salt(password).unwrap();

        assert_ne!(salt1, salt2);
        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_verify_password() {
        let password = "correct_password";
        let salt = generate_salt();
        
        let key = derive_key_from_password(password, &salt).unwrap();
        
        assert!(verify_password(password, key.expose_secret(), &salt).unwrap());
        assert!(!verify_password("wrong_password", key.expose_secret(), &salt).unwrap());
    }

    #[test]
    fn test_mobile_config() {
        let password = "mobile_test";
        let salt = [0u8; 32];
        let config = Argon2Config::mobile();

        let key = derive_key_from_password_with_config(password, &salt, &config).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_high_security_config() {
        let password = "server_test";
        let salt = [0u8; 32];
        let config = Argon2Config::high_security();

        let key = derive_key_from_password_with_config(password, &salt, &config).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [1, 2, 3, 4];
        let b = [1, 2, 3, 4];
        let c = [1, 2, 3, 5];

        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }
}

//! Module de dérivation de clé maître depuis mot de passe utilisateur.
//!
//! Utilise Argon2id (OWASP recommandations 2024) avec des paramètres
//! résistants aux attaques GPU/ASIC.
//!
//! ## Paramètres minimaux (NIST SP 800-63B + OWASP 2024)
//! - Mémoire : 64 MiB (m_cost = 65536)
//! - Itérations : 3 (t_cost = 3)
//! - Parallélisme : 4 threads (p_cost = 4)
//! - Output : 256 bits (32 bytes)

use argon2::{Argon2, Algorithm, Version, ParamsBuilder};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::errors::CryptoError;

/// Taille du sel en bytes
pub const SALT_SIZE: usize = 32;

/// Taille de la clé dérivée en bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// Paramètres minimaux Argon2id recommandés
const DEFAULT_M_COST: u32 = 65536; // 64 MiB
const DEFAULT_T_COST: u32 = 3;     // 3 itérations
const DEFAULT_P_COST: u32 = 4;     // 4 threads

/// Clé maître dérivée — zéroïsée automatiquement on Drop.
///
/// N'implémente PAS `Debug` ni `Clone` pour éviter toute fuite.
pub struct MasterKey {
    key: Zeroizing<[u8; KEY_SIZE]>,
}

impl MasterKey {
    /// Accès en lecture seule à la clé dérivée.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
}

/// Configuration des paramètres Argon2id.
#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: DEFAULT_M_COST,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

/// Dérive une clé maître 256 bits depuis un mot de passe et un sel.
///
/// # Arguments
/// * `password` - Le mot de passe utilisateur (en bytes UTF-8).
/// * `salt` - Sel cryptographique de 32 bytes (doit être unique par vault).
///
/// # Sécurité
/// - Utilise Argon2id (résistant aux side-channel + GPU/ASIC).
/// - La clé retournée est enveloppée dans `MasterKey` (zéroïsé on Drop).
/// - Les paramètres respectent les minimums OWASP 2024.
pub fn derive_master_key(password: &[u8], salt: &[u8; SALT_SIZE]) -> Result<MasterKey, CryptoError> {
    derive_master_key_with_params(password, salt, &KdfParams::default())
}

/// Dérive une clé maître avec des paramètres personnalisés.
pub fn derive_master_key_with_params(
    password: &[u8],
    salt: &[u8; SALT_SIZE],
    params: &KdfParams,
) -> Result<MasterKey, CryptoError> {
    // Vérification des paramètres minimaux
    if params.m_cost < DEFAULT_M_COST {
        return Err(CryptoError::KeyDerivationError(format!(
            "m_cost ({}) inférieur au minimum requis ({})",
            params.m_cost, DEFAULT_M_COST
        )));
    }
    if params.t_cost < DEFAULT_T_COST {
        return Err(CryptoError::KeyDerivationError(format!(
            "t_cost ({}) inférieur au minimum requis ({})",
            params.t_cost, DEFAULT_T_COST
        )));
    }

    let argon2_params = ParamsBuilder::new()
        .m_cost(params.m_cost)
        .t_cost(params.t_cost)
        .p_cost(params.p_cost)
        .output_len(KEY_SIZE)
        .build()
        .map_err(|e| CryptoError::KeyDerivationError(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = Zeroizing::new([0u8; KEY_SIZE]);
    argon2
        .hash_password_into(password, salt, output.as_mut())
        .map_err(|e| CryptoError::KeyDerivationError(format!("Argon2id error: {}", e)))?;

    Ok(MasterKey { key: output })
}

/// Génère un sel cryptographique aléatoire de 32 bytes.
pub fn generate_salt() -> Result<[u8; SALT_SIZE], CryptoError> {
    let mut salt = [0u8; SALT_SIZE];
    rand::rngs::OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| CryptoError::RandomGenerationError(format!("Salt generation failed: {}", e)))?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key_roundtrip() {
        let password = b"correct horse battery staple";
        let salt = generate_salt().unwrap();
        let key1 = derive_master_key(password, &salt).unwrap();
        let key2 = derive_master_key(password, &salt).unwrap();
        // Deterministic: same password + salt = same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_passwords_different_keys() {
        let salt = generate_salt().unwrap();
        let key1 = derive_master_key(b"password1", &salt).unwrap();
        let key2 = derive_master_key(b"password2", &salt).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_different_salts_different_keys() {
        let password = b"same_password";
        let salt1 = generate_salt().unwrap();
        let salt2 = generate_salt().unwrap();
        let key1 = derive_master_key(password, &salt1).unwrap();
        let key2 = derive_master_key(password, &salt2).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_argon2_params_meet_minimum() {
        let params = KdfParams::default();
        assert!(params.m_cost >= 65536, "m_cost must be >= 64 MiB");
        assert!(params.t_cost >= 3, "t_cost must be >= 3");
        assert!(params.p_cost >= 1, "p_cost must be >= 1");
    }

    #[test]
    fn test_reject_weak_params() {
        let password = b"test";
        let salt = generate_salt().unwrap();
        let weak = KdfParams {
            m_cost: 1024, // Too low
            t_cost: 3,
            p_cost: 4,
        };
        assert!(derive_master_key_with_params(password, &salt, &weak).is_err());
    }
}

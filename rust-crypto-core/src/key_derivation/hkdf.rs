//! HKDF (HMAC-based Key Derivation Function)
//! 
//! Utilisé pour dériver plusieurs clés depuis un secret maître.

use hkdf::Hkdf;
use sha2::Sha256;
use crate::errors::{CryptoError, Result};
use crate::secure_memory::SecretBytes;

/// Dérive une clé en utilisant HKDF-SHA256
///
/// # Arguments
/// * `input_key_material` - Matériel de clé d'entrée (IKM)
/// * `salt` - Salt optionnel
/// * `info` - Information contextuelle
/// * `output_length` - Longueur de la clé dérivée
///
/// # Exemple
/// ```rust
/// use secure_vault_crypto::key_derivation::hkdf::derive_key_hkdf;
/// 
/// let ikm = b"secret_key_material";
/// let salt = b"unique_salt";
/// let info = b"app_context";
/// let key = derive_key_hkdf(ikm, Some(salt), info, 32).unwrap();
/// ```
pub fn derive_key_hkdf(
    input_key_material: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_length: usize,
) -> Result<SecretBytes> {
    let hk = Hkdf::<Sha256>::new(salt, input_key_material);
    
    let mut output = vec![0u8; output_length];
    hk.expand(info, &mut output)
        .map_err(|e| CryptoError::KeyDerivationError(format!("HKDF expansion failed: {}", e)))?;

    Ok(SecretBytes::from(output))
}

/// Dérive plusieurs clés depuis un secret maître
///
/// # Arguments
/// * `master_key` - Clé maître
/// * `contexts` - Liste de contextes pour chaque clé
/// * `key_length` - Longueur de chaque clé
///
/// # Returns
/// Vec de clés dérivées
pub fn derive_multiple_keys(
    master_key: &[u8],
    contexts: &[&[u8]],
    key_length: usize,
) -> Result<Vec<SecretBytes>> {
    let mut keys = Vec::with_capacity(contexts.len());
    
    for context in contexts {
        let key = derive_key_hkdf(master_key, None, context, key_length)?;
        keys.push(key);
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derivation() {
        let ikm = b"secret_material";
        let salt = b"salt";
        let info = b"context";
        
        let key = derive_key_hkdf(ikm, Some(salt), info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_deterministic() {
        let ikm = b"master_secret";
        let info = b"app_id";
        
        let key1 = derive_key_hkdf(ikm, None, info, 32).unwrap();
        let key2 = derive_key_hkdf(ikm, None, info, 32).unwrap();
        
        assert_eq!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_different_contexts() {
        let ikm = b"master";
        
        let key1 = derive_key_hkdf(ikm, None, b"context1", 32).unwrap();
        let key2 = derive_key_hkdf(ikm, None, b"context2", 32).unwrap();
        
        assert_ne!(key1.expose_secret(), key2.expose_secret());
    }

    #[test]
    fn test_multiple_keys() {
        let master = b"master_key";
        let contexts = vec![b"encryption".as_slice(), b"authentication".as_slice(), b"signing".as_slice()];
        
        let keys = derive_multiple_keys(master, &contexts, 32).unwrap();
        
        assert_eq!(keys.len(), 3);
        // Toutes les clés doivent être différentes
        assert_ne!(keys[0].expose_secret(), keys[1].expose_secret());
        assert_ne!(keys[1].expose_secret(), keys[2].expose_secret());
    }
}

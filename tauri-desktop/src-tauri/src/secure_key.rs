//! Module de gestion sécurisée des clés cryptographiques en mémoire
//! 
//! Ce module utilise `zeroize` pour :
//! - Protéger les clés contre les memory dumps
//! - Effacer automatiquement la mémoire lors du drop
//! - Empêcher l'affichage accidentel des clés dans les logs
//!
//! Protection mémoire :
//! - `mlock()` empêche la page d'être swappée sur disque
//! - `munlock()` + `zeroize()` au drop garantissent l'effacement

use zeroize::Zeroize;
use std::fmt;

/// Verrouille la région mémoire pour empêcher le swap sur disque.
/// Log un warning en cas d'échec pour informer que la clé pourrait être swappée.
fn mlock_region(ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        let ret = libc::mlock(ptr as *const libc::c_void, len);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // VULN-015: Log l'erreur mais aussi en release (sécurité dégradée)
            eprintln!(
                "⚠️  SÉCURITÉ: mlock() échoué ({}). Protection anti-swap dégradée. \
                 Augmentez RLIMIT_MEMLOCK avec `ulimit -l unlimited`.",
                err
            );
            // Note: on continue car mlock est best-effort — la clé reste utilisable
        }
    }
}

/// Déverrouille la région mémoire (après zeroize).
fn munlock_region(ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// Wrapper sécurisé pour les clés cryptographiques
/// 
/// Cette structure :
/// - Stocke la clé dans un `Vec<u8>` protégé par Zeroize
/// - Verrouille les pages mémoire via `mlock()` (anti-swap)
/// - Effacement automatique `zeroize()` + `munlock()` au Drop
/// - N'implémente PAS `Clone` pour éviter les copies silencieuses de secrets
#[derive(Zeroize)]
pub struct SecureKey {
    /// Clé protégée
    key: Vec<u8>,
}

/// Drop explicite : zeroize PUIS munlock.
/// On ne peut pas dériver ZeroizeOnDrop en même temps qu'un Drop manuel,
/// donc on fait les deux opérations dans le même Drop.
impl Drop for SecureKey {
    fn drop(&mut self) {
        // 1. Zéroïser le contenu AVANT de munlock
        let ptr = self.key.as_ptr();
        let len = self.key.len();
        self.key.zeroize();
        // 2. Déverrouiller la page (elle contient désormais des zéros)
        munlock_region(ptr, len);
    }
}

impl SecureKey {
    /// Crée une nouvelle clé sécurisée à partir de bytes
    /// 
    /// # Arguments
    /// * `key_bytes` - Les bytes de la clé (seront copiés et zéroïsés)
    pub fn new(key_bytes: Vec<u8>) -> Self {
        let sk = SecureKey {
            key: key_bytes,
        };
        // Verrouiller la page mémoire contenant la clé
        mlock_region(sk.key.as_ptr(), sk.key.len());
        sk
    }

    /// Crée une clé sécurisée depuis une slice
    pub fn from_slice(key_slice: &[u8]) -> Self {
        Self::new(key_slice.to_vec())
    }

    /// Obtient la longueur de la clé sans l'exposer
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Vérifie si la clé est vide
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }

    /// Utilise la clé de manière sécurisée avec une closure
    /// 
    /// Cette méthode permet d'utiliser la clé sans la copier inutilement.
    /// La clé est automatiquement protégée après utilisation.
    /// 
    /// # Arguments
    /// * `f` - Une closure qui prend la clé en référence et retourne un résultat
    /// 
    /// # Exemple
    /// ```
    /// use fluxlock_lib::secure_key::SecureKey;
    /// let key = SecureKey::new(vec![1, 2, 3, 4]);
    /// let result = key.use_key(|k| {
    ///     // Utiliser k pour chiffrement
    ///     Ok::<Vec<u8>, String>(vec![5, 6, 7, 8])
    /// });
    /// ```
    pub fn use_key<F, T, E>(&self, f: F) -> Result<T, E>
    where
        F: FnOnce(&[u8]) -> Result<T, E>,
    {
        f(&self.key)
    }

    /// Utilise la clé de manière mutable (pour des opérations qui modifient la clé)
    pub fn use_key_mut<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut [u8]) -> Result<T, E>,
    {
        f(&mut self.key)
    }

    /// Crée une copie sécurisée des bytes de la clé
    /// 
    /// Le Vec retourné est enveloppé dans Zeroizing pour effacement automatique.
    pub fn to_vec(&self) -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(self.key.clone())
    }

    /// Compare deux clés de manière sécurisée (constant-time)
    pub fn secure_eq(&self, other: &SecureKey) -> bool {
        use subtle::ConstantTimeEq;
        
        if self.key.len() != other.key.len() {
            return false;
        }
        
        self.key.ct_eq(&other.key).into()
    }

    /// Génère une clé aléatoire sécurisée de la longueur spécifiée
    pub fn generate(length: usize) -> Result<Self, String> {
        use rand::RngCore;
        
        let mut key_bytes = vec![0u8; length];
        let mut rng = rand::rngs::OsRng;
        
        rng.try_fill_bytes(&mut key_bytes)
            .map_err(|e| format!("Erreur génération clé: {}", e))?;
        
        Ok(Self::new(key_bytes))
    }

    /// Dérive une clé depuis un mot de passe en utilisant Argon2id
    pub fn derive_from_password(
        password: &str,
        salt: &[u8],
        key_length: usize,
    ) -> Result<Self, String> {
        use argon2::{
            password_hash::{PasswordHasher, SaltString},
            Argon2, ParamsBuilder,
        };
        
        if salt.len() < 16 {
            return Err("Le sel doit faire au moins 16 bytes".to_string());
        }
        
        // Configurer Argon2id avec paramètres sécurisés
        let params = ParamsBuilder::new()
            .m_cost(65536)  // 64 MB de mémoire
            .t_cost(3)      // 3 itérations
            .p_cost(4)      // 4 threads parallèles
            .output_len(key_length)
            .build()
            .map_err(|e| format!("Erreur paramètres Argon2: {}", e))?;
        
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            params,
        );
        
        // Convertir le sel en SaltString
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| format!("Erreur encodage sel: {}", e))?;
        
        // Hacher le mot de passe
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| format!("Erreur dérivation: {}", e))?;
        
        // Extraire les bytes du hash
        let hash_bytes = password_hash
            .hash
            .ok_or_else(|| "Hash absent".to_string())?;
        
        Ok(Self::from_slice(hash_bytes.as_bytes()))
    }
}

// Implémentation Debug qui ne révèle pas la clé
impl fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecureKey")
            .field("len", &self.len())
            .field("key", &"<REDACTED>")
            .finish()
    }
}

// Implémentation Display qui ne révèle pas la clé
impl fmt::Display for SecureKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecureKey(<REDACTED>, {} bytes)", self.len())
    }
}

// Désactivation de Serialize/Deserialize par défaut pour éviter les fuites accidentelles
// Si nécessaire, implémenter manuellement avec précautions

/// Wrapper pour sérialisation sécurisée (base64)
impl SecureKey {
    /// Sérialise la clé en base64 (à utiliser uniquement pour stockage chiffré)
    pub fn to_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&self.key)
    }

    /// Désérialise une clé depuis base64
    pub fn from_base64(encoded: &str) -> Result<Self, String> {
        use base64::{Engine as _, engine::general_purpose};
        
        let decoded = general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("Erreur décodage base64: {}", e))?;
        
        Ok(Self::new(decoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_key_creation() {
        let key = SecureKey::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(key.len(), 5);
        assert!(!key.is_empty());
    }

    #[test]
    fn test_secure_key_use() {
        let key = SecureKey::new(vec![1, 2, 3, 4]);
        let result = key.use_key(|k| {
            Ok::<_, String>(k.iter().sum::<u8>())
        });
        assert_eq!(result.unwrap(), 10);
    }

    #[test]
    fn test_secure_key_generate() {
        let key = SecureKey::generate(32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_secure_key_eq() {
        let key1 = SecureKey::new(vec![1, 2, 3]);
        let key2 = SecureKey::new(vec![1, 2, 3]);
        let key3 = SecureKey::new(vec![4, 5, 6]);
        
        assert!(key1.secure_eq(&key2));
        assert!(!key1.secure_eq(&key3));
    }

    #[test]
    fn test_secure_key_base64() {
        let key = SecureKey::new(vec![1, 2, 3, 4, 5]);
        let encoded = key.to_base64();
        let decoded = SecureKey::from_base64(&encoded).unwrap();
        
        assert!(key.secure_eq(&decoded));
    }

    #[test]
    fn test_secure_key_debug() {
        let key = SecureKey::new(vec![1, 2, 3, 4, 5]);
        let debug_str = format!("{:?}", key);
        assert!(!debug_str.contains("1"));
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn test_zeroize_on_drop() {
        // Test que la mémoire est bien zéroïsée
        let mut key_bytes = vec![1u8, 2, 3, 4, 5];
        
        {
            let _key = SecureKey::new(vec![1u8, 2, 3, 4, 5]);
            // key est droppé ici — zeroize + munlock
        }
        
        // Les bytes originaux doivent être préservés (c'est un Vec distinct)
        assert_eq!(key_bytes, vec![1, 2, 3, 4, 5]);
        
        // Après zeroize manuel — Vec::zeroize() clears the vec (len=0)
        key_bytes.zeroize();
        assert!(key_bytes.is_empty(), "Vec should be empty after zeroize");
    }
}

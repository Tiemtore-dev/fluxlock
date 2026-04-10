//! Cache sécurisé de la clé de chiffrement du vault en mémoire
//!
//! Implémente les bonnes pratiques NIST SP 800-57 et OWASP :
//! - **Key splitting** (NIST) : la clé est XOR-masquée avec un masque aléatoire
//!   (key_masked = key ⊕ mask), les deux composants stockés séparément
//! - **mlock** : les deux buffers sont verrouillés en mémoire (anti-swap)
//! - **Zeroize on Drop** : effacement sécurisé via `write_volatile` + `compiler_fence`
//! - **TTL borné** (OWASP Secrets Management §2.5) : invalidation automatique après 3 min
//! - **Destruction immédiate** au logout/auto-lock (NIST §Key Compromise)
//! - **Types primitifs** (OWASP) : `Vec<u8>` uniquement, pas de `String`
//! - **Pas de Clone** : empêche les copies silencieuses
//!
//! Le process Rust Tauri est dans la trust boundary (Tauri v2 Security Model) :
//! les secrets en mémoire du core ont le même niveau de confiance que le Keychain.

use std::time::{Duration, Instant};
use zeroize::Zeroize;
use rand::RngCore;

/// Durée maximale par défaut de la clé en cache (OWASP: minimiser la fenêtre en clair)
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3 * 60); // 3 minutes

/// Intervalle par défaut de rotation du masque XOR
const DEFAULT_MASK_ROTATION: Duration = Duration::from_secs(30);

/// Verrouille une région mémoire pour empêcher le swap sur disque.
fn mlock_region(ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        let ret = libc::mlock(ptr as *const libc::c_void, len);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "⚠️  SÉCURITÉ: mlock() échoué pour vault_key_cache ({}). Protection anti-swap dégradée.",
                err
            );
        }
    }
}

/// Déverrouille une région mémoire (après zeroize).
fn munlock_region(ptr: *const u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        let _ = libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// Composant XOR-masqué d'une clé (NIST SP 800-57 : key splitting)
///
/// Stocke `key ⊕ mask` ; la clé originale ne réside jamais en clair dans cette struct.
/// Les deux vecteurs sont mlockés individuellement et zéroïsés au Drop.
struct MaskedKeyComponent {
    /// key_masked = original_key ⊕ mask
    key_masked: Vec<u8>,
    /// Masque aléatoire (OsRng)
    mask: Vec<u8>,
}

impl MaskedKeyComponent {
    /// Crée un nouveau composant masqué à partir de la clé originale.
    /// La clé originale n'est PAS conservée — seuls key⊕mask et mask sont stockés.
    fn new(key: &[u8]) -> Self {
        let len = key.len();
        let mut mask = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut mask);
        mlock_region(mask.as_ptr(), len);

        let mut key_masked = vec![0u8; len];
        for i in 0..len {
            key_masked[i] = key[i] ^ mask[i];
        }
        mlock_region(key_masked.as_ptr(), len);

        MaskedKeyComponent { key_masked, mask }
    }

    /// Reconstruit la clé originale dans un buffer zéroïsable.
    /// Le résultat est `Zeroizing<Vec<u8>>` pour effacement automatique après usage.
    fn reconstruct(&self) -> zeroize::Zeroizing<Vec<u8>> {
        let len = self.key_masked.len();
        let mut key = vec![0u8; len];
        for i in 0..len {
            key[i] = self.key_masked[i] ^ self.mask[i];
        }
        zeroize::Zeroizing::new(key)
    }

    /// Re-masque avec un nouveau masque aléatoire (NIST: "frequently updated").
    fn rotate_mask(&mut self) {
        let len = self.key_masked.len();
        // Reconstruire temporairement la clé
        let key = self.reconstruct();
        // Générer un nouveau masque
        let mut new_mask = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut new_mask);
        mlock_region(new_mask.as_ptr(), len);
        // Recalculer key_masked avec le nouveau masque
        let mut new_masked = vec![0u8; len];
        for i in 0..len {
            new_masked[i] = key[i] ^ new_mask[i];
        }
        mlock_region(new_masked.as_ptr(), len);
        // Zéroïser et munlock les anciens buffers
        let old_masked_ptr = self.key_masked.as_ptr();
        let old_mask_ptr = self.mask.as_ptr();
        self.key_masked.zeroize();
        self.mask.zeroize();
        munlock_region(old_masked_ptr, len);
        munlock_region(old_mask_ptr, len);
        // Remplacer
        self.key_masked = new_masked;
        self.mask = new_mask;
        // key est Zeroizing<Vec<u8>>, sera zéroïsé automatiquement au drop
    }
}

impl Drop for MaskedKeyComponent {
    fn drop(&mut self) {
        let masked_ptr = self.key_masked.as_ptr();
        let masked_len = self.key_masked.len();
        let mask_ptr = self.mask.as_ptr();
        let mask_len = self.mask.len();
        // Zéroïser AVANT de munlock
        self.key_masked.zeroize();
        self.mask.zeroize();
        // Déverrouiller les pages (contiennent des zéros maintenant)
        munlock_region(masked_ptr, masked_len);
        munlock_region(mask_ptr, mask_len);
    }
}

/// Entrée du cache pour un utilisateur.
struct CacheEntry {
    /// Composant XOR-masqué de la clé
    component: MaskedKeyComponent,
    /// Timestamp de mise en cache
    cached_at: Instant,
    /// Timestamp du dernier accès (pour rotation du masque)
    last_access: Instant,
    /// ID utilisateur associé (pour vérification de cohérence)
    user_id: i64,
}

/// Cache sécurisé de clé de vault.
///
/// Ce cache est détenu par `AppState` derrière un `tokio::sync::Mutex`.
/// Il ne contient qu'une seule entrée (l'utilisateur actuellement connecté).
pub struct VaultKeyCache {
    entry: Option<CacheEntry>,
    ttl: Duration,
    mask_rotation: Duration,
}

impl VaultKeyCache {
    /// Crée un cache vide avec les valeurs par défaut.
    pub fn new() -> Self {
        VaultKeyCache { entry: None, ttl: DEFAULT_CACHE_TTL, mask_rotation: DEFAULT_MASK_ROTATION }
    }
    
    /// Crée un cache vide avec un TTL et un intervalle de rotation personnalisés.
    pub fn with_config(ttl_secs: u64, mask_rotation_secs: u64) -> Self {
        VaultKeyCache {
            entry: None,
            ttl: Duration::from_secs(ttl_secs),
            mask_rotation: Duration::from_secs(mask_rotation_secs),
        }
    }

    /// Stocke une clé dans le cache pour l'utilisateur donné.
    /// Si une entrée existe déjà, elle est invalidée d'abord (zeroize + munlock).
    pub fn store(&mut self, user_id: i64, key: &[u8]) {
        // Invalider l'entrée précédente si elle existe
        self.invalidate();
        self.entry = Some(CacheEntry {
            component: MaskedKeyComponent::new(key),
            cached_at: Instant::now(),
            last_access: Instant::now(),
            user_id,
        });
        debug_log!("🔐 Clé vault mise en cache (TTL: {}s, XOR-masked + mlock)", self.ttl.as_secs());
    }

    /// Récupère la clé depuis le cache si elle est valide (bon user_id + TTL non expiré).
    /// Retourne `None` si le cache est vide, expiré, ou pour un autre utilisateur.
    /// 
    /// La clé reconstruite est retournée dans un `Zeroizing<Vec<u8>>` pour effacement
    /// automatique après usage par l'appelant.
    pub fn get(&mut self, user_id: i64) -> Option<crate::secure_key::SecureKey> {
        let entry = self.entry.as_mut()?;

        // Vérifier que c'est le bon utilisateur
        if entry.user_id != user_id {
            debug_log!("⚠️  Cache vault: user_id mismatch ({} != {})", user_id, entry.user_id);
            return None;
        }

        // Vérifier le TTL
        if entry.cached_at.elapsed() >= self.ttl {
            debug_log!("⏰ Cache vault expiré (TTL: {}s dépassé)", self.ttl.as_secs());
            self.invalidate();
            return None;
        }

        // Rotation du masque (NIST: "frequently updated")
        if entry.last_access.elapsed() >= self.mask_rotation {
            entry.component.rotate_mask();
            entry.last_access = Instant::now();
            debug_log!("🔄 Rotation du masque XOR effectuée");
        }

        // Reconstruire et retourner sous forme de SecureKey (mlock + zeroize on drop)
        let key_data = entry.component.reconstruct();
        Some(crate::secure_key::SecureKey::new(key_data.to_vec()))
    }

    /// Invalide le cache : zéroïse et déverrouille toute la mémoire.
    /// Appelé au logout, auto-lock, ou quand le TTL expire.
    pub fn invalidate(&mut self) {
        if self.entry.is_some() {
            debug_log!("🗑️  Cache vault invalidé (zeroize + munlock)");
        }
        // Drop de CacheEntry → Drop de MaskedKeyComponent → zeroize + munlock
        self.entry = None;
    }

    /// Vérifie si le cache contient une entrée valide pour l'utilisateur donné.
    pub fn is_valid(&self, user_id: i64) -> bool {
        match &self.entry {
            Some(entry) => entry.user_id == user_id && entry.cached_at.elapsed() < self.ttl,
            None => false,
        }
    }
}

impl Drop for VaultKeyCache {
    fn drop(&mut self) {
        self.invalidate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masked_key_component_roundtrip() {
        let original_key = vec![0x42u8; 32];
        let component = MaskedKeyComponent::new(&original_key);
        let reconstructed = component.reconstruct();
        assert_eq!(&*reconstructed, &original_key);
    }

    #[test]
    fn test_masked_key_component_mask_differs() {
        let original_key = vec![0xABu8; 32];
        let component = MaskedKeyComponent::new(&original_key);
        // key_masked ne doit PAS être égal à la clé originale (sauf si mask = 0, p≈0)
        assert_ne!(&component.key_masked, &original_key);
    }

    #[test]
    fn test_mask_rotation_preserves_key() {
        let original_key = vec![0x13u8; 32];
        let mut component = MaskedKeyComponent::new(&original_key);
        let old_masked = component.key_masked.clone();
        component.rotate_mask();
        let reconstructed = component.reconstruct();
        assert_eq!(&*reconstructed, &original_key);
        // Le masqué a changé (nouveau masque)
        assert_ne!(&component.key_masked, &old_masked);
    }

    #[test]
    fn test_cache_store_and_get() {
        let mut cache = VaultKeyCache::new();
        let key = vec![0xFFu8; 32];
        cache.store(1, &key);
        let retrieved = cache.get(1);
        assert!(retrieved.is_some());
        let sk = retrieved.unwrap();
        let result = sk.use_key(|k| {
            assert_eq!(k, &key[..]);
            Ok::<(), String>(())
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_cache_wrong_user() {
        let mut cache = VaultKeyCache::new();
        cache.store(1, &vec![0xFFu8; 32]);
        assert!(cache.get(2).is_none());
    }

    #[test]
    fn test_cache_invalidate() {
        let mut cache = VaultKeyCache::new();
        cache.store(1, &vec![0xFFu8; 32]);
        cache.invalidate();
        assert!(cache.get(1).is_none());
    }

    #[test]
    fn test_cache_is_valid() {
        let mut cache = VaultKeyCache::new();
        assert!(!cache.is_valid(1));
        cache.store(1, &vec![0xFFu8; 32]);
        assert!(cache.is_valid(1));
        assert!(!cache.is_valid(2));
    }
}

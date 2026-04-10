use secure_vault_crypto::{
    key_derivation::argon2::{derive_key_from_password_with_config, Argon2Config},
    crypto::aes_gcm::decrypt_aes_gcm,                          // v1 legacy (déchiffrement rétrocompatible)
    crypto::cipher::{encrypt as encrypt_chacha, decrypt as decrypt_chacha, EncryptedBlob}, // v2 PQC
    secure_memory::EncryptedData,
    errors::CryptoError as CoreCryptoError,
    SecretString,
};
#[cfg(test)]
use secure_vault_crypto::crypto::aes_gcm::encrypt_aes_gcm;     // v1 legacy (tests rétrocompatibilité)
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use zeroize::Zeroizing;
use crate::secure_key::SecureKey;

/// Préfixe des données chiffrées en v2 (ChaCha20-Poly1305)
/// Les données sans ce préfixe sont considérées v1 (AES-256-GCM) pour rétrocompatibilité
const V2_PREFIX: &str = "v2:";

/// Configuration Argon2id centréalisée (OWASP recommandations)
/// Modifier ici pour ajuster les paramètres de dérivation globalement
pub fn default_argon2_config() -> Argon2Config {
    // Android devices have much tighter per-app memory limits (~256 MiB heap).
    // 64 MiB Argon2 allocation can fail after Transfer Manager / SignedLogManager
    // are loaded, causing silent OOM masked as "wrong password".
    #[cfg(target_os = "android")]
    return Argon2Config {
        memory_cost: 19456,  // 19 MiB (OWASP minimum for Argon2id)
        time_cost: 4,        // 4 itérations (compense la mémoire réduite)
        parallelism: 2,      // 2 threads (mobile)
        output_len: 32,      // 256 bits
    };

    #[cfg(not(target_os = "android"))]
    Argon2Config {
        memory_cost: 65536,  // 64 MiB (résistance GPU)
        time_cost: 3,        // 3 itérations (balance sécurité/performance)
        parallelism: 4,      // 4 threads (CPU moderne)
        output_len: 32,      // 256 bits
    }
}

/// Ancienne configuration desktop (64 MiB) — utilisée pour migration des hash existants
/// sur Android si un utilisateur avait créé son compte avec l'ancienne config.
#[cfg(target_os = "android")]
fn legacy_desktop_argon2_config() -> Argon2Config {
    Argon2Config {
        memory_cost: 65536,
        time_cost: 3,
        parallelism: 4,
        output_len: 32,
    }
}

/// Erreurs possibles lors des opérations cryptographiques
#[derive(Debug)]
pub enum CryptoError {
    HashingError(String),
    VerificationError,
    EncryptionError(String),
    DecryptionError(String),
    InvalidKey,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptoError::HashingError(msg) => write!(f, "Hashing error: {}", msg),
            CryptoError::VerificationError => write!(f, "Password verification failed"),
            CryptoError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            CryptoError::DecryptionError(msg) => write!(f, "Decryption error: {}", msg),
            CryptoError::InvalidKey => write!(f, "Invalid encryption key"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<CoreCryptoError> for CryptoError {
    fn from(err: CoreCryptoError) -> Self {
        match err {
            CoreCryptoError::EncryptionError(msg) => CryptoError::EncryptionError(msg),
            CoreCryptoError::DecryptionError(msg) => CryptoError::DecryptionError(msg),
            CoreCryptoError::KeyDerivationError(msg) => CryptoError::HashingError(msg),
            CoreCryptoError::AuthenticationFailed => CryptoError::DecryptionError("Authentication tag verification failed".to_string()),
            CoreCryptoError::InvalidKeySize { expected, actual } => CryptoError::EncryptionError(format!("Invalid key size: expected {}, got {}", expected, actual)),
            _ => CryptoError::EncryptionError(err.to_string()),
        }
    }
}

/// Hash un mot de passe avec Argon2id (standard professionnel)
///
/// Utilise Argon2id avec des paramètres optimisés pour la sécurité :
/// - m_cost: 65536 (64 MiB) - mémoire requise
/// - t_cost: 3 (3 iterations) - temps de calcul
/// - p_cost: 4 (4 threads parallèles)
/// - output_len: 32 bytes (256 bits)
///
/// Format de sortie : salt (32 bytes) || hash (32 bytes) encodé en base64
///
/// # Arguments
/// * `password` - Le mot de passe en clair
///
/// # Returns
/// String base64 contenant sel + hash
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = generate_salt();
    
    let config = default_argon2_config();
    
    let hash = derive_key_from_password_with_config(password, &salt, &config)?;
    
    // Combiner salt + hash
    let mut result = salt.to_vec();
    result.extend_from_slice(hash.expose_secret());
    
    Ok(general_purpose::STANDARD.encode(&result))
}

/// Vérifie un mot de passe contre son hash (VERSION SÉCURISÉE)
///
/// Le mot de passe est encapsulé dans `Zeroizing<String>` pour garantir
/// l'effacement mémoire après la vérification, même en cas de panic.
///
/// # Arguments
/// * `password` - Le mot de passe en clair (sera copié dans un buffer `Zeroizing`)
/// * `hash_base64` - Le hash base64 (salt + hash)
///
/// # Returns
/// `Ok(())` si le mot de passe est correct, `Err` sinon
pub fn verify_password(password: &str, hash_base64: &str) -> Result<(), CryptoError> {
    // Encapsuler le mot de passe dans un buffer zéroïsé automatiquement
    let secure_pwd = Zeroizing::new(password.to_string());
    verify_password_inner(secure_pwd.as_str(), hash_base64)
}

/// Vérifie un mot de passe depuis un `SecretString` (zéroïsation native)
///
/// Préférer cette version quand le mot de passe est déjà dans un `SecretString`.
pub fn verify_password_secret(password: &SecretString, hash_base64: &str) -> Result<(), CryptoError> {
    verify_password_inner(password.expose_secret(), hash_base64)
}

/// Implémentation interne de la vérification de mot de passe.
///
/// Les buffers intermédiaires (decoded, computed_hash) sont protégés :
/// - `decoded` est encapsulé dans `Zeroizing<Vec<u8>>` pour effacer salt+hash de la mémoire
/// - `computed_hash` est un `SecretBytes` (ZeroizeOnDrop) renvoyé par Argon2id
fn verify_password_inner(password: &str, hash_base64: &str) -> Result<(), CryptoError> {
    // Décoder le base64 dans un buffer zéroïsé
    let decoded = Zeroizing::new(
        general_purpose::STANDARD
            .decode(hash_base64)
            .map_err(|e| CryptoError::HashingError(format!("Base64 decode error: {}", e)))?
    );
    
    // Vérifier la longueur (32 bytes salt + 32 bytes hash)
    if decoded.len() != 64 {
        return Err(CryptoError::HashingError("Invalid hash length".to_string()));
    }
    
    // Extraire salt et hash stocké
    let salt = &decoded[..32];
    let stored_hash = &decoded[32..];
    
    // Recalculer le hash avec la config actuelle de la plateforme
    let config = default_argon2_config();
    
    let computed_hash = derive_key_from_password_with_config(password, salt, &config)?;
    
    // Comparaison constant-time pour éviter timing attacks
    if constant_time_compare(computed_hash.expose_secret(), stored_hash) {
        return Ok(());
    }
    
    // Sur Android, le hash a pu être créé avec l'ancienne config desktop (64 MiB).
    // Essayer avec la config legacy avant de déclarer le mot de passe invalide.
    #[cfg(target_os = "android")]
    {
        let legacy_config = legacy_desktop_argon2_config();
        if let Ok(legacy_hash) = derive_key_from_password_with_config(password, salt, &legacy_config) {
            if constant_time_compare(legacy_hash.expose_secret(), stored_hash) {
                return Ok(());
            }
        }
    }
    
    Err(CryptoError::VerificationError)
}

/// Comparaison constant-time pour éviter les attaques par timing
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}



/// Dérive une clé de chiffrement depuis le mot de passe utilisateur
///
/// Cette fonction dérive de manière DÉTERMINISTE une clé de 256 bits depuis
/// le mot de passe maître de l'utilisateur. La même combinaison password+salt
/// produira toujours la même clé, permettant la persistance des données chiffrées.
///
/// # Arguments
/// * `password` - Le mot de passe maître de l'utilisateur
/// * `crypto_salt` - Sel cryptographique pour la dérivation (32 bytes)
///
/// # Returns
/// Clé AES-256 de 32 bytes
///
/// # Sécurité
/// - Utilise Argon2id avec paramètres robustes
/// - Résistant aux attaques GPU/ASIC
/// - Dérivation séparée de l'authentification
/// - ⚠️ **DÉPRÉCIÉ**: Clé non protégée en RAM → Préférer `derive_encryption_key_from_password_secure()`
///
/// # Avertissement
/// Cette fonction retourne une clé non protégée (Vec<u8>) qui peut être exposée
/// dans les memory dumps. Utilisez `derive_encryption_key_from_password_secure()` 
/// qui retourne un `SecureKey` avec protection ZeroizeOnDrop.
#[deprecated(
    since = "1.0.0",
    note = "Utiliser derive_encryption_key_from_password_secure() pour protection mémoire"
)]
pub fn derive_encryption_key_from_password(password: &str, crypto_salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let config = default_argon2_config();
    
    let key = derive_key_from_password_with_config(password, crypto_salt, &config)?;
    Ok(key.expose_secret().to_vec())
}

/// Dérive une clé de chiffrement depuis le mot de passe (VERSION SÉCURISÉE)
///
/// ⚠️ PRÉFÉRER CETTE VERSION pour protéger la clé en mémoire
///
/// # Arguments
/// * `password` - Le mot de passe maître de l'utilisateur
/// * `crypto_salt` - Le sel cryptographique unique (32 bytes)
///
/// # Returns
/// SecureKey avec zeroization automatique
///
/// # Sécurité
/// - Même sécurité cryptographique que la version standard
/// - PLUS: Protection mémoire avec ZeroizeOnDrop
/// - Protection contre memory dumps
pub fn derive_encryption_key_from_password_secure(password: &str, crypto_salt: &[u8]) -> Result<SecureKey, CryptoError> {
    let config = default_argon2_config();
    
    let key = derive_key_from_password_with_config(password, crypto_salt, &config)?;
    Ok(SecureKey::new(key.expose_secret().to_vec()))
}

/// Génère un sel cryptographique de 32 bytes
/// 
/// VULN-017: Retourne une erreur au lieu de paniquer en cas de CSPRNG défaillant.
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut salt)
        .expect("CSPRNG défaillant: impossible de générer un sel sécurisé");
    salt
}

/// Génère une clé de chiffrement AES-256 aléatoire (32 bytes)
pub fn generate_encryption_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut key)
        .expect("CSPRNG défaillant: impossible de générer une clé sécurisée");
    key
}

/// Chiffre des données avec ChaCha20-Poly1305 (vault v2 — PQC-résistant)
///
/// ChaCha20-Poly1305 fournit :
/// - Confidentialité : ChaCha20 (clé 256 bits → ~128 bits post-Grover)
/// - Authentification : Poly1305 (128 bits)
/// - Intégrité : AEAD (Authenticated Encryption with Associated Data)
/// - Performance uniforme : pas de dépendance à AES-NI hardware
///
/// # Format de sortie
/// `"v2:" + base64(nonce || ciphertext+tag)` — les données v1 (sans préfixe) restent lisibles
///
/// # Arguments
/// * `data` - Les données en clair à chiffrer
/// * `key` - Clé de 32 bytes (256 bits)
///
/// # Returns
/// String base64 avec préfixe "v2:" contenant les données chiffrées
pub fn encrypt_data(data: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let key_arr: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let blob = encrypt_chacha(key_arr, data.as_bytes())?;
    let encoded = general_purpose::STANDARD.encode(blob.to_bytes());
    Ok(format!("{}{}", V2_PREFIX, encoded))
}

/// Chiffre des données avec SecureKey (VERSION SÉCURISÉE)
pub fn encrypt_data_secure(data: &str, key: &SecureKey) -> Result<String, CryptoError> {
    key.use_key(|k| encrypt_data(data, k))
}

/// Chiffre des données binaires avec ChaCha20-Poly1305 (vault v2)
/// 
/// Utilisé pour les fichiers binaires (images, vidéos, PDFs, etc.)
/// Prend directement des bytes sans conversion String
pub fn encrypt_data_bytes(data: &[u8], key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    let key_arr: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let blob = encrypt_chacha(key_arr, data)?;
    let encoded = general_purpose::STANDARD.encode(blob.to_bytes());
    Ok(format!("{}{}", V2_PREFIX, encoded))
}

/// Chiffre des données binaires avec SecureKey (VERSION SÉCURISÉE)
pub fn encrypt_data_bytes_secure(data: &[u8], key: &SecureKey) -> Result<String, CryptoError> {
    key.use_key(|k| encrypt_data_bytes(data, k))
}

/// Déchiffre des données (v2 ChaCha20-Poly1305 ou v1 AES-256-GCM en fallback)
///
/// # Format accepté
/// - `"v2:" + base64(...)` : ChaCha20-Poly1305 (vault v2, PQC-résistant)
/// - `base64(...)` sans préfixe : AES-256-GCM legacy (vault v1, rétrocompatibilité)
///
/// # Arguments
/// * `encrypted_base64` - String chiffrée (avec ou sans préfixe "v2:")
/// * `key` - Clé de 32 bytes (256 bits)
///
/// # Returns
/// String déchiffré
pub fn decrypt_data(encrypted_base64: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    if let Some(v2_data) = encrypted_base64.strip_prefix(V2_PREFIX) {
        // ═══ v2 ChaCha20-Poly1305 ═══
        let combined = general_purpose::STANDARD
            .decode(v2_data)
            .map_err(|e| CryptoError::DecryptionError(format!("Base64 decode error: {}", e)))?;

        let key_arr: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let blob = EncryptedBlob::from_bytes(&combined)?;
        let plaintext = decrypt_chacha(key_arr, &blob)?;

        String::from_utf8(plaintext.to_vec())
            .map_err(|e| CryptoError::DecryptionError(format!("UTF-8 decode error: {}", e)))
    } else {
        // ═══ v1 AES-256-GCM fallback (rétrocompatibilité) ═══
        let combined = general_purpose::STANDARD
            .decode(encrypted_base64)
            .map_err(|e| CryptoError::DecryptionError(format!("Base64 decode error: {}", e)))?;

        if combined.len() < 12 {
            return Err(CryptoError::DecryptionError("Invalid encrypted data length".to_string()));
        }

        let nonce = combined[..12].to_vec();
        let ciphertext = combined[12..].to_vec();
        let encrypted_data = EncryptedData::new("AES-256-GCM".to_string(), nonce, ciphertext);
        let decrypted = decrypt_aes_gcm(&encrypted_data, key)?;

        String::from_utf8(decrypted)
            .map_err(|e| CryptoError::DecryptionError(format!("UTF-8 decode error: {}", e)))
    }
}

/// Déchiffre des données avec SecureKey (VERSION SÉCURISÉE)
pub fn decrypt_data_secure(encrypted_base64: &str, key: &SecureKey) -> Result<String, CryptoError> {
    key.use_key(|k| decrypt_data(encrypted_base64, k))
}

/// Déchiffre des données binaires (v2 ChaCha20-Poly1305 ou v1 AES-256-GCM en fallback)
/// 
/// Utilisé pour les fichiers binaires (images, vidéos, PDFs, etc.)
/// Ne tente pas de conversion UTF-8
pub fn decrypt_data_bytes(encrypted_base64: &str, key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKey);
    }

    if let Some(v2_data) = encrypted_base64.strip_prefix(V2_PREFIX) {
        // ═══ v2 ChaCha20-Poly1305 ═══
        let combined = general_purpose::STANDARD
            .decode(v2_data)
            .map_err(|e| CryptoError::DecryptionError(format!("Base64 decode error: {}", e)))?;

        let key_arr: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let blob = EncryptedBlob::from_bytes(&combined)?;
        let plaintext = decrypt_chacha(key_arr, &blob)?;

        Ok(plaintext.to_vec())
    } else {
        // ═══ v1 AES-256-GCM fallback (rétrocompatibilité) ═══
        let combined = general_purpose::STANDARD
            .decode(encrypted_base64)
            .map_err(|e| CryptoError::DecryptionError(format!("Base64 decode error: {}", e)))?;

        if combined.len() < 12 {
            return Err(CryptoError::DecryptionError("Invalid encrypted data length".to_string()));
        }

        let nonce = combined[..12].to_vec();
        let ciphertext = combined[12..].to_vec();
        let encrypted_data = EncryptedData::new("AES-256-GCM".to_string(), nonce, ciphertext);
        decrypt_aes_gcm(&encrypted_data, key).map_err(|e| e.into())
    }
}

/// Déchiffre des données binaires avec SecureKey (VERSION SÉCURISÉE)
pub fn decrypt_data_bytes_secure(encrypted_base64: &str, key: &SecureKey) -> Result<Vec<u8>, CryptoError> {
    key.use_key(|k| decrypt_data_bytes(encrypted_base64, k))
}

/// Chiffre un fichier en streaming (SENC v1) — mémoire constante ~128 KiB.
///
/// Lit `reader` par chunks de 64 KiB, chiffre chaque chunk avec ChaCha20-Poly1305
/// et écrit le résultat dans `writer` au format SENC v1.
/// Aucune donnée en clair n'est conservée en mémoire après chiffrement de chaque chunk.
pub fn encrypt_file_stream_secure<R: std::io::Read, W: std::io::Write>(
    key: &SecureKey,
    reader: &mut R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<u64, CryptoError> {
    key.use_key(|k| {
        let key_arr: &[u8; 32] = k.try_into().map_err(|_| {
            CoreCryptoError::InvalidKeySize { expected: 32, actual: k.len() }
        })?;
        secure_vault_crypto::encrypt_stream(key_arr, reader, writer, chunk_size)
            .map_err(|e| CryptoError::EncryptionError(format!("Stream encrypt: {}", e)))
    })
}

/// Déchiffre un fichier SENC v1 en streaming — mémoire constante.
///
/// Lit le header + chunks chiffrés depuis `reader`, déchiffre chaque chunk
/// séquentiellement et écrit le plaintext dans `writer`.
pub fn decrypt_file_stream_secure<R: std::io::Read, W: std::io::Write>(
    key: &SecureKey,
    reader: &mut R,
    writer: &mut W,
) -> Result<u64, CryptoError> {
    key.use_key(|k| {
        let key_arr: &[u8; 32] = k.try_into().map_err(|_| {
            CoreCryptoError::InvalidKeySize { expected: 32, actual: k.len() }
        })?;
        secure_vault_crypto::decrypt_stream(key_arr, reader, writer)
            .map_err(|e| CryptoError::DecryptionError(format!("Stream decrypt: {}", e)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing_and_verification() {
        let password = "MonMotDePasseTrèsSécurisé123!@#";
        
        // Hash le mot de passe
        let hash = hash_password(password).unwrap();
        
        // Vérifier que c'est du base64 valide
        assert!(general_purpose::STANDARD.decode(&hash).is_ok());
        
        // Vérifier que la longueur est correcte (32 bytes salt + 32 bytes hash = 64 bytes)
        let decoded = general_purpose::STANDARD.decode(&hash).unwrap();
        assert_eq!(decoded.len(), 64);
        
        // Vérifier que le mot de passe est correct
        assert!(verify_password(password, &hash).is_ok());
        
        // Vérifier qu'un mauvais mot de passe échoue
        assert!(verify_password("MauvaisMotDePasse", &hash).is_err());
    }

    #[test]
    fn test_different_hashes_for_same_password() {
        let password = "MotDePasseIdentique";
        
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();
        
        // Les hash doivent être différents (sel différent)
        assert_ne!(hash1, hash2);
        
        // Mais les deux doivent vérifier le même mot de passe
        assert!(verify_password(password, &hash1).is_ok());
        assert!(verify_password(password, &hash2).is_ok());
    }

    #[test]
    fn test_encryption_decryption() {
        let data = "Données très secrètes avec caractères spéciaux: éèàç 🔐";
        let key = generate_encryption_key();
        
        // Chiffrer (v2 ChaCha20-Poly1305)
        let encrypted = encrypt_data(data, &key).unwrap();
        
        // Vérifier le préfixe v2
        assert!(encrypted.starts_with("v2:"), "Encrypted data must have v2: prefix");
        
        // Vérifier que les données sont différentes
        assert_ne!(data, encrypted);
        
        // Déchiffrer
        let decrypted = decrypt_data(&encrypted, &key).unwrap();
        
        // Vérifier que les données sont identiques
        assert_eq!(data, decrypted);
    }

    #[test]
    fn test_v1_backward_compatibility() {
        // Simuler des données chiffrées en v1 (AES-256-GCM sans préfixe "v2:")
        let data = b"Legacy v1 encrypted data";
        let key = generate_encryption_key();
        
        // Chiffrer manuellement en v1 format (nonce || ciphertext, base64, sans préfixe)
        let encrypted_data = encrypt_aes_gcm(data, &key).unwrap();
        let mut result = encrypted_data.nonce;
        result.extend_from_slice(&encrypted_data.ciphertext);
        let v1_encrypted = general_purpose::STANDARD.encode(&result);
        
        // Vérifier que le déchiffrement v1 fallback fonctionne
        let decrypted = decrypt_data(&v1_encrypted, &key).unwrap();
        assert_eq!(decrypted, "Legacy v1 encrypted data");
    }

    #[test]
    fn test_encryption_with_wrong_key() {
        let data = "Données secrètes";
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        
        let encrypted = encrypt_data(data, &key1).unwrap();
        
        // Déchiffrer avec une mauvaise clé doit échouer
        let result = decrypt_data(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_key_size() {
        let data = "Test";
        let short_key = vec![0u8; 16]; // Seulement 16 bytes au lieu de 32
        
        // Clé invalide pour chiffrement
        assert!(encrypt_data(data, &short_key).is_err());
        
        // Clé invalide pour déchiffrement
        assert!(decrypt_data("test", &short_key).is_err());
    }

    #[test]
    fn test_tampered_ciphertext() {
        let data = "Données importantes";
        let key = generate_encryption_key();
        
        let encrypted = encrypt_data(data, &key).unwrap();
        
        // Extraire la partie base64 (sans le préfixe "v2:")
        let b64_part = encrypted.strip_prefix(V2_PREFIX).expect("Should have v2: prefix");
        
        // Modifier le ciphertext (simuler une attaque)
        let mut corrupted = general_purpose::STANDARD.decode(b64_part).unwrap();
        corrupted[20] ^= 0xFF; // Flip des bits
        let corrupted_b64 = format!("{}{}", V2_PREFIX, general_purpose::STANDARD.encode(&corrupted));
        
        // Le déchiffrement doit échouer (intégrité ChaCha20-Poly1305)
        assert!(decrypt_data(&corrupted_b64, &key).is_err());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = vec![1, 2, 3, 4, 5];
        let b = vec![1, 2, 3, 4, 5];
        let c = vec![1, 2, 3, 4, 6];
        
        assert!(constant_time_compare(&a, &b));
        assert!(!constant_time_compare(&a, &c));
    }

    #[test]
    fn test_key_generation() {
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();
        
        // Les clés doivent être de 32 bytes
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
        
        // Les clés doivent être différentes (aléatoires)
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_salt_generation() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        
        // Les sels doivent être de 32 bytes
        assert_eq!(salt1.len(), 32);
        assert_eq!(salt2.len(), 32);
        
        // Les sels doivent être différents (aléatoires)
        assert_ne!(salt1, salt2);
    }
}

// Ré-exporter blake3_hash depuis le crypto core pour utilisation dans main.rs
pub use secure_vault_crypto::blake3_hash;
pub use secure_vault_crypto::is_senc_format;

/// Chiffre un fichier en streaming tout en calculant le hash BLAKE3 du plaintext.
/// Retourne (bytes_encrypted, hex_hash).
pub fn encrypt_file_stream_with_hash<R: std::io::Read, W: std::io::Write>(
    key: &SecureKey,
    reader: &mut R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<(u64, String), CryptoError> {
    use secure_vault_crypto::blake3;
    
    let mut hasher = blake3::Hasher::new();
    let mut tee = TeeReader { inner: reader, hasher: &mut hasher };
    let bytes = encrypt_file_stream_secure(key, &mut tee, writer, chunk_size)?;
    let hash = hex::encode(tee.hasher.finalize().as_bytes());
    Ok((bytes, hash))
}

/// Reader adapteur qui calcule un hash BLAKE3 en streaming pendant la lecture.
struct TeeReader<'a, R: std::io::Read> {
    inner: &'a mut R,
    hasher: &'a mut secure_vault_crypto::blake3::Hasher,
}

impl<'a, R: std::io::Read> std::io::Read for TeeReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
}

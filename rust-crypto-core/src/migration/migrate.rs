//! Implémentation de la migration vault v1 → v2.

use std::path::Path;
use std::fs;
use std::io::Write;

use crate::crypto::vault::{
    self, VaultData, VaultEntry, VaultMeta, SealedVault, VAULT_MAGIC,
};
use crate::errors::CryptoError;

/// Rapport de migration retourné après une migration réussie.
#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub entries_migrated: usize,
    pub old_algo: String,
    pub new_algo: String,
    pub timestamp: i64,
    pub vault_v2_checksum: String,
}

/// Erreurs spécifiques à la migration.
#[derive(Debug)]
pub enum MigrationError {
    /// Le fichier vault est introuvable.
    VaultNotFound(String),
    /// Le format du vault n'est pas reconnu.
    UnknownFormat(String),
    /// Le vault est déjà en v2.
    AlreadyV2,
    /// Erreur cryptographique pendant la migration.
    CryptoError(CryptoError),
    /// Erreur d'I/O.
    IoError(std::io::Error),
    /// La vérification post-migration a échoué.
    VerificationFailed(String),
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MigrationError::VaultNotFound(p) => write!(f, "Vault not found: {}", p),
            MigrationError::UnknownFormat(d) => write!(f, "Unknown vault format: {}", d),
            MigrationError::AlreadyV2 => write!(f, "Vault is already v2 format"),
            MigrationError::CryptoError(e) => write!(f, "Crypto error: {}", e),
            MigrationError::IoError(e) => write!(f, "I/O error: {}", e),
            MigrationError::VerificationFailed(d) => write!(f, "Verification failed: {}", d),
        }
    }
}

impl std::error::Error for MigrationError {}

impl From<CryptoError> for MigrationError {
    fn from(e: CryptoError) -> Self {
        MigrationError::CryptoError(e)
    }
}

impl From<std::io::Error> for MigrationError {
    fn from(e: std::io::Error) -> Self {
        MigrationError::IoError(e)
    }
}

/// Détecte la version d'un fichier vault.
#[derive(Debug, PartialEq)]
pub enum VaultVersion {
    V1, // Format legacy (base64, pas de magic bytes)
    V2, // Format PQC (magic bytes VAULT\x02)
}

/// Détecte la version d'un vault depuis ses premiers bytes.
pub fn detect_version(data: &[u8]) -> VaultVersion {
    if data.len() >= 6 && &data[0..6] == VAULT_MAGIC {
        VaultVersion::V2
    } else {
        VaultVersion::V1
    }
}

/// Migre un vault v1 vers le format v2.
///
/// # Arguments
/// * `vault_path` - Chemin du vault v1 source.
/// * `password` - Mot de passe utilisateur (pour déchiffrer v1 et re-chiffrer v2).
/// * `output_path` - Chemin du vault v2 de sortie (ne doit pas être le même que vault_path).
///
/// # Processus
/// 1. Lire le fichier vault v1.
/// 2. Déchiffrer les données v1 (AES-256-GCM legacy).
/// 3. Construire un `VaultData` structuré.
/// 4. Re-chiffrer en vault v2 (ChaCha20-Poly1305 + Argon2id + HMAC-SHA3).
/// 5. Écrire dans un fichier temporaire, puis `rename()` atomique.
/// 6. Vérifier l'intégrité du vault v2.
///
/// # Sécurité
/// - Le vault original n'est **jamais** modifié.
/// - L'écriture est atomique (temp file → rename).
/// - Vérification post-migration obligatoire.
pub fn migrate_v1_to_v2(
    vault_path: &Path,
    password: &[u8],
    output_path: &Path,
) -> Result<MigrationReport, MigrationError> {
    // 1. Vérifier que le fichier existe
    if !vault_path.exists() {
        return Err(MigrationError::VaultNotFound(
            vault_path.display().to_string(),
        ));
    }

    // 2. Lire le fichier
    let raw_data = fs::read(vault_path)?;

    // 3. Détecter la version
    let version = detect_version(&raw_data);
    if version == VaultVersion::V2 {
        return Err(MigrationError::AlreadyV2);
    }

    // 4. Déchiffrer le vault v1 (format legacy: chaque entrée est stockée
    //    séparément en SQLite avec base64(nonce+ciphertext). Pour la migration
    //    fichier, on s'attend à un JSON/bincode sérialisé chiffré.)
    let vault_data = decrypt_v1_vault(&raw_data, password)?;

    let entries_count = vault_data.entries.len();

    // 5. Re-chiffrer en vault v2
    let sealed_v2 = vault::encrypt_vault(password, &vault_data)?;

    // 6. Écriture atomique
    let temp_path = output_path.with_extension("tmp.migrating");
    {
        let mut file = fs::File::create(&temp_path)?;
        file.write_all(&sealed_v2.to_bytes())?;
        file.sync_all()?;
    }

    // 7. Rename atomique
    fs::rename(&temp_path, output_path)?;

    // 8. Vérification post-migration
    let v2_bytes = fs::read(output_path)?;
    let restored = SealedVault::from_bytes(&v2_bytes).map_err(|e| {
        MigrationError::VerificationFailed(format!("Failed to parse v2: {}", e))
    })?;
    let _verified = vault::decrypt_vault(password, &restored).map_err(|e| {
        MigrationError::VerificationFailed(format!("Failed to decrypt v2: {}", e))
    })?;

    // 9. Calculer checksum pour le rapport
    let checksum = crate::hashing::blake3_hash(&v2_bytes);
    let checksum_hex = hex::encode(&checksum);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    Ok(MigrationReport {
        entries_migrated: entries_count,
        old_algo: "AES-256-GCM".into(),
        new_algo: "ChaCha20-Poly1305 + Argon2id + HMAC-SHA3-256".into(),
        timestamp: now,
        vault_v2_checksum: checksum_hex,
    })
}

/// Déchiffre un vault v1 legacy.
///
/// Le format v1 est un blob base64 contenant `nonce(12) || ciphertext+tag`.
/// Chiffré avec AES-256-GCM, clé dérivée par Argon2id.
fn decrypt_v1_vault(raw_data: &[u8], password: &[u8]) -> Result<VaultData, MigrationError> {
    use base64::{Engine as _, engine::general_purpose};

    // Le vault v1 peut être un fichier base64 ou binaire brut.
    // Essayons d'abord le base64.
    let data = if let Ok(decoded) = general_purpose::STANDARD.decode(raw_data) {
        decoded
    } else if let Ok(text) = std::str::from_utf8(raw_data) {
        general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|_| MigrationError::UnknownFormat("Not valid base64".into()))?
    } else {
        // Données binaires brutes
        raw_data.to_vec()
    };

    // Format v1 attendu: salt(32) || nonce(12) || ciphertext+tag
    if data.len() < 32 + 12 + 16 {
        return Err(MigrationError::UnknownFormat(
            "V1 vault too short (need at least salt+nonce+tag)".into(),
        ));
    }

    let salt = &data[..32];
    let nonce = &data[32..44];
    let ciphertext_with_tag = &data[44..];

    // Dériver la clé v1 avec Argon2id (mêmes paramètres que l'ancien code)
    let mut salt_array = [0u8; 32];
    salt_array.copy_from_slice(salt);
    let master_key = crate::crypto::kdf::derive_master_key(password, &salt_array)?;

    // Déchiffrer avec AES-256-GCM (legacy)
    let encrypted = crate::secure_memory::EncryptedData::new(
        "AES-256-GCM".to_string(),
        nonce.to_vec(),
        ciphertext_with_tag.to_vec(),
    );

    let plaintext = crate::crypto::aes_gcm::decrypt_aes_gcm(&encrypted, master_key.as_bytes())
        .map_err(|e| MigrationError::CryptoError(e))?;

    // Essayer de désérialiser comme JSON (v1 utilisait JSON)
    if let Ok(entries_json) = serde_json::from_slice::<Vec<serde_json::Value>>(&plaintext) {
        let entries: Vec<VaultEntry> = entries_json
            .iter()
            .enumerate()
            .map(|(i, v)| VaultEntry {
                id: v["id"]
                    .as_str()
                    .unwrap_or(&format!("migrated-{}", i))
                    .to_string(),
                title: v["title"].as_str().unwrap_or("Sans titre").to_string(),
                username: v["username"].as_str().map(String::from),
                password: v["password"].as_str().map(String::from),
                url: v["url"].as_str().map(String::from),
                notes: v["notes"].as_str().map(String::from),
                category: v["category"]
                    .as_str()
                    .unwrap_or("passwords")
                    .to_string(),
                created_at: v["created_at"].as_i64().unwrap_or(0),
                updated_at: v["updated_at"].as_i64().unwrap_or(0),
            })
            .collect();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        return Ok(VaultData {
            entries: entries.clone(),
            metadata: VaultMeta {
                created_at: now,
                updated_at: now,
                entry_count: entries.len(),
                format_version: 2,
                sequence: 0,
            },
        });
    }

    // Essayer comme MessagePack (si v1 utilisait déjà msgpack)
    if let Ok(data) = rmp_serde::from_slice::<VaultData>(&plaintext) {
        return Ok(data);
    }

    // Essayer comme bincode
    if let Ok(data) = bincode::deserialize::<VaultData>(&plaintext) {
        return Ok(data);
    }

    Err(MigrationError::UnknownFormat(
        "Could not deserialize v1 vault data (tried JSON, MessagePack, bincode)".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Crée un vault v1 synthétique pour les tests.
    fn create_synthetic_v1_vault(password: &[u8]) -> Vec<u8> {
        use crate::crypto::kdf;
        use crate::crypto::aes_gcm::encrypt_aes_gcm;
        use base64::{Engine as _, engine::general_purpose};

        // 1. Générer un sel
        let salt = kdf::generate_salt().unwrap();

        // 2. Dériver la clé
        let master_key = kdf::derive_master_key(password, &salt).unwrap();

        // 3. Créer des données JSON (format v1)
        let entries = serde_json::json!([
            {
                "id": "v1-entry-1",
                "title": "Old GitHub Account",
                "username": "legacy@example.com",
                "password": "old_password_123",
                "url": "https://github.com",
                "notes": null,
                "category": "passwords",
                "created_at": 1600000000,
                "updated_at": 1600000000
            },
            {
                "id": "v1-entry-2",
                "title": "Legacy Note",
                "username": null,
                "password": null,
                "url": null,
                "notes": "Secret note from v1",
                "category": "notes",
                "created_at": 1600000001,
                "updated_at": 1600000001
            }
        ]);

        let plaintext = serde_json::to_vec(&entries).unwrap();

        // 4. Chiffrer avec AES-256-GCM
        let encrypted = encrypt_aes_gcm(&plaintext, master_key.as_bytes()).unwrap();

        // 5. Combiner: salt || nonce || ciphertext+tag
        let mut result = Vec::new();
        result.extend_from_slice(&salt);
        result.extend_from_slice(&encrypted.nonce);
        result.extend_from_slice(&encrypted.ciphertext);

        // 6. Encoder en base64 (format v1)
        general_purpose::STANDARD.encode(&result).into_bytes()
    }

    #[test]
    fn test_detect_version_v1() {
        let data = b"SGVsbG8gd29ybGQ="; // base64 text
        assert_eq!(detect_version(data), VaultVersion::V1);
    }

    #[test]
    fn test_detect_version_v2() {
        let mut data = Vec::new();
        data.extend_from_slice(VAULT_MAGIC);
        data.extend_from_slice(&[0u8; 100]);
        assert_eq!(detect_version(&data), VaultVersion::V2);
    }

    #[test]
    fn test_migration_v1_to_v2() {
        let password = b"migration_test_password";
        let temp_dir = TempDir::new().unwrap();

        // Create a v1 vault file
        let v1_path = temp_dir.path().join("vault.v1");
        let v1_data = create_synthetic_v1_vault(password);
        fs::write(&v1_path, &v1_data).unwrap();

        // Migrate
        let v2_path = temp_dir.path().join("vault.v2");
        let report = migrate_v1_to_v2(&v1_path, password, &v2_path).unwrap();

        // Verify report
        assert_eq!(report.entries_migrated, 2);
        assert_eq!(report.old_algo, "AES-256-GCM");
        assert!(report.new_algo.contains("ChaCha20-Poly1305"));
        assert!(!report.vault_v2_checksum.is_empty());

        // Verify the v2 vault can be decrypted
        let v2_bytes = fs::read(&v2_path).unwrap();
        let sealed = SealedVault::from_bytes(&v2_bytes).unwrap();
        let decrypted = vault::decrypt_vault(password, &sealed).unwrap();

        assert_eq!(decrypted.entries.len(), 2);
        assert_eq!(decrypted.entries[0].title, "Old GitHub Account");
        assert_eq!(decrypted.entries[0].password.as_deref(), Some("old_password_123"));
        assert_eq!(decrypted.entries[1].title, "Legacy Note");

        // Verify original v1 is untouched
        assert!(v1_path.exists());
        assert_eq!(fs::read(&v1_path).unwrap(), v1_data);
    }

    #[test]
    fn test_migration_already_v2_fails() {
        let password = b"already_v2_test";
        let temp_dir = TempDir::new().unwrap();

        // Create a v2 vault
        let data = VaultData {
            entries: vec![],
            metadata: VaultMeta {
                created_at: 0,
                updated_at: 0,
                entry_count: 0,
                format_version: 2,
                sequence: 0,
            },
        };
        let sealed = vault::encrypt_vault(password, &data).unwrap();
        let v2_path = temp_dir.path().join("vault.v2");
        fs::write(&v2_path, sealed.to_bytes()).unwrap();

        // Attempt migration — should fail
        let output = temp_dir.path().join("vault.v2.out");
        let result = migrate_v1_to_v2(&v2_path, password, &output);
        assert!(matches!(result, Err(MigrationError::AlreadyV2)));
    }

    #[test]
    fn test_migration_vault_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let result = migrate_v1_to_v2(
            &temp_dir.path().join("nonexistent"),
            b"pass",
            &temp_dir.path().join("out"),
        );
        assert!(matches!(result, Err(MigrationError::VaultNotFound(_))));
    }
}

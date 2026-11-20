// MODULE DE BACKUP ET RESTAURATION
// Gère l'export et l'import sécurisé des données du coffre-fort

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use std::io::{Read, Write};
use std::collections::HashSet;
use crate::secure_key::SecureKey;
use chrono::Utc;

// Import depuis le module crypto (rendu public dans main.rs)
use crate::crypto::{
    encrypt_data_secure, decrypt_data_secure,
    derive_encryption_key_from_password_secure, derive_key_with_config, supported_argon2_profiles,
    generate_salt,
};
use secure_vault_crypto::{compute_header_mac, verify_header_mac};

// Macro pour logger uniquement en mode debug
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub version: String,
    pub created_at: String,
    pub username: String,
    pub device_name: String,
    pub file_count: usize,
    pub password_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupData {
    pub metadata: BackupMetadata,
    /// HMAC-SHA3-256 des métadonnées sérialisées (base64).
    /// Empêche la falsification de file_count/password_count/username.
    /// Absent (default "") pour les backups créés avant cette version.
    #[serde(default)]
    pub metadata_mac: String,
    /// HMAC-SHA3-256 du contenu chiffré complet (database_encrypted + files_encrypted) (base64).
    /// Vérifié AVANT toute tentative de déchiffrement pour éviter les oracles.
    /// Absent (default "") pour les backups créés avant cette version.
    #[serde(default)]
    pub content_mac: String,
    pub backup_salt: String,                 // Sel cryptographique aléatoire (base64, 32 bytes)
    pub database_encrypted: String,          // Base de données SQLite chiffrée
    pub files_encrypted: Vec<FileBackup>,    // Fichiers cryptés + métadonnées
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileBackup {
    pub filename: String,
    pub encrypted_content: String,
    pub size: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupInfo {
    pub path: String,
    pub metadata: BackupMetadata,
}

const MAX_BACKUP_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SNAPSHOT_INPUT_BYTES: u64 = 12 * 1024 * 1024;

fn is_legacy_file_metadata(filename: &str) -> bool {
    let stem = filename.strip_prefix('.').unwrap_or(filename);
    let Some(id) = stem.strip_suffix(".enc.metadata") else {
        return false;
    };
    uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
}

fn read_bounded_backup(path: &Path) -> Result<String, String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Le fichier de sauvegarde doit être un fichier ordinaire".into());
    }
    let mut data = String::new();
    file.take(MAX_BACKUP_BYTES + 1).read_to_string(&mut data).map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_BACKUP_BYTES {
        return Err("Sauvegarde trop volumineuse".into());
    }
    Ok(data)
}

fn authenticated_backup_key(data: &BackupData, password: &str, salt: &[u8]) -> Result<SecureKey, String> {
    if salt.len() != 32 {
        return Err("Sel de sauvegarde invalide".into());
    }
    let metadata = serde_json::to_vec(&data.metadata).map_err(|e| e.to_string())?;
    let mac = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &data.metadata_mac)
        .map_err(|e| e.to_string())?;
    let mac: [u8; 32] = mac.try_into().map_err(|_| "MAC de sauvegarde invalide")?;
    for profile in supported_argon2_profiles() {
        let key = derive_key_with_config(password, salt, &profile).map_err(|e| e.to_string())?;
        let authenticated = key.use_key(|bytes| {
            let bytes: &[u8; 32] = bytes.try_into().map_err(|_| "Clé invalide")?;
            Ok::<_, String>(verify_header_mac(bytes, &metadata, &mac).is_ok())
        })?;
        if authenticated {
            return Ok(key);
        }
    }
    Err("Mot de passe de la sauvegarde incorrect ou métadonnées altérées".into())
}

/// Crée un backup complet du coffre-fort
pub async fn create_backup(
    database: &crate::database::Database,
    files_dir: &Path,
    master_password: &str,
    username: &str,
    backup_dir: &Path,
) -> Result<PathBuf, String> {
    debug_log!("📦 Création du backup...");
    
    fs::create_dir_all(backup_dir).map_err(|e| e.to_string())?;
    let staging = tempfile::tempdir_in(backup_dir).map_err(|e| e.to_string())?;
    let snapshot = staging.path().join("snapshot.db");
    let path = snapshot.to_str().ok_or("Chemin de sauvegarde invalide")?;
    sqlx::query("VACUUM INTO ?").bind(path).execute(&database.pool).await
        .map_err(|e| format!("Capture SQLite impossible: {e}"))?;
    let mut raw_bytes = fs::metadata(&snapshot).map_err(|e| e.to_string())?.len();
    if raw_bytes > MAX_SNAPSHOT_INPUT_BYTES {
        return Err("La sauvegarde dépasse la taille maximale prise en charge".into());
    }
    let db_content = fs::read(snapshot).map_err(|e| e.to_string())?;

    // Générer un sel aléatoire unique pour ce backup (32 bytes CSPRNG)
    let salt = generate_salt();
    let salt_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &salt);
    let encryption_key = derive_encryption_key_from_password_secure(master_password, &salt)
        .map_err(|e| format!("Erreur dérivation clé: {:?}", e))?;
    
    // Chiffrer la base de données
    let db_base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &db_content);
    let db_encrypted = encrypt_data_secure(&db_base64, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement DB: {}", e))?;
    
    // Collecter et chiffrer tous les fichiers
    let mut files_encrypted = Vec::new();
    let mut file_count = 0;
    
    if files_dir.exists() {
        for entry in fs::read_dir(files_dir)
            .map_err(|e| format!("Erreur lecture dossier fichiers: {}", e))? 
        {
            if let Ok(entry) = entry {
                let path = entry.path();
                if entry.file_type().map_err(|e| e.to_string())?.is_file() {
                    if let Some(filename) = path.file_name().filter(|name| {
                        let name = name.to_string_lossy();
                        !name.starts_with('.') && !is_legacy_file_metadata(&name)
                    }) {
                        raw_bytes = raw_bytes.saturating_add(entry.metadata().map_err(|e| e.to_string())?.len());
                        if raw_bytes > MAX_SNAPSHOT_INPUT_BYTES {
                            return Err("La sauvegarde dépasse la taille maximale prise en charge".into());
                        }
                        let content = fs::read(&path)
                            .map_err(|e| format!("Erreur lecture fichier {}: {}", filename.to_string_lossy(), e))?;
                        
                        let content_base64 = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD, 
                            &content
                        );
                        let encrypted = encrypt_data_secure(&content_base64, &encryption_key)
                            .map_err(|e| format!("Erreur chiffrement fichier: {}", e))?;
                        
                        files_encrypted.push(FileBackup {
                            filename: filename.to_string_lossy().to_string(),
                            encrypted_content: encrypted,
                            size: content.len() as i64,
                        });
                        
                        file_count += 1;
                    }
                }
            }
        }
    }
    
    // Obtenir le nom de la machine
    let device_name = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "Unknown".to_string());
    
    // Créer les métadonnées
    let metadata = BackupMetadata {
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: Utc::now().to_rfc3339(),
        username: username.to_string(),
        device_name,
        file_count,
        password_count: 0, // Sera mis à jour par l'appelant si nécessaire
    };
    
    // Calculer le MAC des métadonnées (anti-falsification F-02)
    let metadata_json = serde_json::to_string(&metadata)
        .map_err(|e| format!("Erreur sérialisation métadonnées: {}", e))?;
    let metadata_mac = encryption_key.use_key(|k| {
        let key_arr: &[u8; 32] = k.try_into().map_err(|_| "Clé invalide".to_string())?;
        let mac = compute_header_mac(key_arr, metadata_json.as_bytes())
            .map_err(|e| format!("Erreur calcul MAC métadonnées: {:?}", e))?;
        Ok::<String, String>(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &mac))
    }).map_err(|e| format!("Erreur MAC: {}", e))?;

    // Calculer le MAC du contenu chiffré (database + fichiers) — vérifié AVANT toute tentative de déchiffrement
    let content_for_mac = {
        let files_json = serde_json::to_string(&files_encrypted)
            .map_err(|e| format!("Erreur sérialisation fichiers pour MAC: {}", e))?;
        format!("{}||{}", db_encrypted, files_json)
    };
    let content_mac = encryption_key.use_key(|k| {
        let key_arr: &[u8; 32] = k.try_into().map_err(|_| "Clé invalide".to_string())?;
        let mac = compute_header_mac(key_arr, content_for_mac.as_bytes())
            .map_err(|e| format!("Erreur calcul MAC contenu: {:?}", e))?;
        Ok::<String, String>(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &mac))
    }).map_err(|e| format!("Erreur MAC contenu: {}", e))?;

    // Créer la structure de backup
    let backup_data = BackupData {
        metadata,
        metadata_mac,
        content_mac,
        backup_salt: salt_b64,
        database_encrypted: db_encrypted,
        files_encrypted,
    };
    
    // Sérialiser en JSON
    let json = serde_json::to_string_pretty(&backup_data)
        .map_err(|e| format!("Erreur sérialisation: {}", e))?;
    
    fs::create_dir_all(backup_dir)
        .map_err(|e| format!("Erreur création répertoire backup: {}", e))?;
    
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let backup_path = backup_dir.join(format!("FluXlock_{}_{}.svbackup", timestamp, uuid::Uuid::new_v4()));
    crate::commands::files::publish_new_file(&backup_path, |file| {
        file.write_all(json.as_bytes()).map_err(|e| e.to_string())
    })?;

    debug_log!("✅ Backup créé: {:?}", backup_path);
    debug_log!("📊 {} fichiers sauvegardés", file_count);
    
    Ok(backup_path)
}

/// Restaure un backup du coffre-fort
pub async fn restore_backup(
    backup_path: &Path,
    master_password: &str,
    target_db_path: &Path,
    target_files_dir: &Path,
) -> Result<BackupMetadata, String> {
    debug_log!("🔄 Restauration du backup: {:?}", backup_path);
    
    // Lire le fichier backup
    let json = read_bounded_backup(backup_path)?;
    
    // Désérialiser
    let backup_data: BackupData = serde_json::from_str(&json)
        .map_err(|e| format!("Erreur désérialisation backup: {}", e))?;
    
    // Extraire le sel du backup (aléatoire, stocké dans le JSON)
    let salt = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        backup_data.backup_salt.as_bytes()
    ).map_err(|e| format!("Erreur décodage sel backup: {}", e))?;
    let encryption_key = authenticated_backup_key(&backup_data, master_password, &salt)?;

    // Vérifier le MAC du contenu chiffré AVANT toute tentative de déchiffrement
    // Empêche les oracles de déchiffrement et détecte les modifications du contenu
    if !backup_data.content_mac.is_empty() {
        let content_for_mac = {
            let files_json = serde_json::to_string(&backup_data.files_encrypted)
                .map_err(|e| format!("Erreur sérialisation fichiers pour MAC: {}", e))?;
            format!("{}||{}", backup_data.database_encrypted, files_json)
        };
        let expected_content_mac = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            backup_data.content_mac.as_bytes()
        ).map_err(|e| format!("Erreur décodage MAC contenu: {}", e))?;
        let content_mac_arr: [u8; 32] = expected_content_mac.try_into()
            .map_err(|_| "MAC contenu invalide (taille incorrecte)".to_string())?;
        encryption_key.use_key(|k| {
            let key_arr: &[u8; 32] = k.try_into().map_err(|_| "Clé invalide".to_string())?;
            verify_header_mac(key_arr, content_for_mac.as_bytes(), &content_mac_arr)
                .map_err(|_| "Contenu du backup falsifié (MAC contenu invalide)".to_string())
        }).map_err(|e| format!("{}", e))?;
        debug_log!("✅ MAC du contenu chiffré vérifié");
    } else {
        // VULN-016: Rejeter les backups legacy sans MAC de contenu
        return Err("⚠️ Backup incompatible: pas de MAC de contenu. \
Ce backup a été créé avec une ancienne version et son intégrité ne peut pas être vérifiée.".to_string());
    }

    // Déchiffrer et vérifier la base de données
    let db_base64 = decrypt_data_secure(&backup_data.database_encrypted, &encryption_key)
        .map_err(|_| "Mot de passe maître incorrect ou backup corrompu".to_string())?;
    
    let db_content = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        db_base64.as_bytes()
    ).map_err(|e| format!("Erreur décodage DB: {}", e))?;
    
    let parent = target_db_path.parent().ok_or("Répertoire du coffre invalide")?;
    let workspace = tempfile::tempdir_in(parent).map_err(|e| e.to_string())?;
    let staged_db = workspace.path().join("staged.db");
    fs::write(&staged_db, &db_content).map_err(|e| e.to_string())?;
    let staged_files = workspace.path().join("files");
    fs::create_dir(&staged_files).map_err(|e| e.to_string())?;
    let mut filenames = HashSet::new();

    // Restaurer les fichiers
    for file_backup in backup_data.files_encrypted {
        // Older versions archived the sidecars created by platform_security.
        // The archive MAC covers them, but they contain no data used by the vault.
        if is_legacy_file_metadata(&file_backup.filename) {
            continue;
        }
        // Validation anti-path-traversal : rejeter les noms de fichiers dangereux
        if file_backup.filename.contains("..") 
            || file_backup.filename.contains('/') 
            || file_backup.filename.contains('\\')
            || file_backup.filename.starts_with('.')
            || file_backup.filename.is_empty()
            || !filenames.insert(file_backup.filename.clone())
        {
            return Err(format!(
                "Nom de fichier invalide dans le backup : '{}' (path traversal potentiel)",
                file_backup.filename
            ));
        }

        let content_base64 = decrypt_data_secure(&file_backup.encrypted_content, &encryption_key)
            .map_err(|e| format!("Erreur déchiffrement fichier {}: {}", file_backup.filename, e))?;
        
        let content = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            content_base64.as_bytes()
        ).map_err(|e| format!("Erreur décodage fichier: {}", e))?;
        
        if file_backup.size != content.len() as i64 {
            return Err("Taille du fichier restauré incohérente".into());
        }
        fs::write(staged_files.join(&file_backup.filename), &content).map_err(|e| e.to_string())?;
    }

    let db = crate::database::Database::new(&staged_db).await.map_err(|e| e.to_string())?;
    let integrity: String = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_one(&db.pool).await.map_err(|e| e.to_string())?;
    if integrity != "ok" || db.get_vault_owner().await.map_err(|e| e.to_string())?.is_none() {
        return Err("Base de données de sauvegarde invalide".into());
    }
    let paths: Vec<(i64, String)> = sqlx::query_as("SELECT id, file_path FROM secure_files")
        .fetch_all(&db.pool).await.map_err(|e| e.to_string())?;
    for (id, path) in paths {
        let name = path.rsplit(['/', '\\']).next().ok_or("Nom absent")?;
        if !filenames.contains(name) {
            return Err("Un fichier du coffre est absent de la sauvegarde".into());
        }
        sqlx::query("UPDATE secure_files SET file_path = ? WHERE id = ?")
            .bind(target_files_dir.join(name).to_string_lossy().as_ref()).bind(id)
            .execute(&db.pool).await.map_err(|e| e.to_string())?;
    }
    db.pool.close().await;

    let previous_files = workspace.path().join("previous-files");
    let had_files = target_files_dir.exists();
    if had_files {
        fs::rename(target_files_dir, &previous_files).map_err(|e| e.to_string())?;
    }
    if let Err(error) = fs::rename(&staged_files, target_files_dir) {
        if had_files {
            let _ = fs::rename(&previous_files, target_files_dir);
        }
        return Err(error.to_string());
    }
    if let Err(error) = fs::rename(&staged_db, target_db_path) {
        let _ = fs::rename(target_files_dir, &staged_files);
        if had_files {
            let _ = fs::rename(&previous_files, target_files_dir);
        }
        return Err(error.to_string());
    }

    Ok(backup_data.metadata)
}

/// Lit les métadonnées d'un fichier backup sans le déchiffrer complètement
pub fn read_backup_metadata(backup_path: &Path) -> Result<BackupMetadata, String> {
    let json = read_bounded_backup(backup_path)?;
    
    let backup_data: BackupData = serde_json::from_str(&json)
        .map_err(|e| format!("Erreur désérialisation: {}", e))?;
    
    Ok(backup_data.metadata)
}

/// Recherche tous les fichiers de backup disponibles
pub fn find_all_backups(extra_dirs: &[PathBuf]) -> Vec<BackupInfo> {
    let mut locations = crate::hidden_storage::get_backup_search_locations();
    locations.extend(extra_dirs.iter().cloned());
    let backup_paths = crate::hidden_storage::search_backup_files(locations);
    
    let mut backups = Vec::new();
    let mut seen_paths = std::collections::HashSet::new();
    
    for path in backup_paths {
        // Obtenir le chemin canonique pour dédupliquer
        let canonical_path = if let Ok(canonical) = path.canonicalize() {
            canonical
        } else {
            path.clone()
        };
        
        // Vérifier si déjà traité
        if !seen_paths.insert(canonical_path.to_string_lossy().to_string()) {
            continue; // Skip les doublons
        }
        
        if let Ok(metadata) = read_backup_metadata(&path) {
            backups.push(BackupInfo {
                path: path.to_string_lossy().to_string(),
                metadata,
            });
        }
    }
    
    // Trier par date de création (plus récent en premier)
    backups.sort_by(|a, b| b.metadata.created_at.cmp(&a.metadata.created_at));
    
    backups
}

pub fn import_backup_content(content: &str, backup_dir: &Path) -> Result<PathBuf, String> {
    if content.len() as u64 > MAX_BACKUP_BYTES {
        return Err("Sauvegarde trop volumineuse".into());
    }

    let backup_data: BackupData = serde_json::from_str(content)
        .map_err(|_| "Fichier invalide : ce n'est pas un backup .svbackup".to_string())?;
    fs::create_dir_all(backup_dir)
        .map_err(|e| format!("Erreur création répertoire backup: {}", e))?;
    let safe_user: String = backup_data
        .metadata
        .username
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let path = backup_dir.join(format!("SecureVault_{}_imported_{}.svbackup", safe_user, timestamp));
    fs::write(&path, content).map_err(|e| format!("Erreur écriture backup importé: {}", e))?;
    Ok(path)
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[tokio::test]
    async fn restores_legacy_archive_with_platform_metadata_and_rejects_other_hidden_entries() {
        const PASSWORD: &str = "mot de passe de test";
        const FILE: &str = "dc82dc81-76f5-4c20-b2ad-d1b55dc4e91f.enc";
        const SIDECAR: &str = ".dc82dc81-76f5-4c20-b2ad-d1b55dc4e91f.enc.metadata";
        let dir = tempfile::tempdir().unwrap();
        let db = Database::new(&dir.path().join("origin.db")).await.unwrap();
        db.initialize().await.unwrap();
        let user = db.create_user("compte-test", "email", "hash", "salt").await.unwrap();
        let files = dir.path().join("source-files");
        fs::create_dir(&files).unwrap();
        let source = files.join(FILE);
        let payload = b"encrypted file payload";
        fs::write(&source, payload).unwrap();
        db.create_secure_file(user, "document.txt", source.to_str().unwrap(), payload.len() as i64, None, None)
            .await.unwrap();
        crate::platform_security::add_legitimate_encryption_metadata(&source).unwrap();
        let metadata = fs::read(files.join(if cfg!(windows) { &SIDECAR[1..] } else { SIDECAR })).unwrap();

        let archive = create_backup(&db, &files, PASSWORD, "compte-test", &dir.path().join("backup")).await.unwrap();
        let mut data: BackupData = serde_json::from_str(&fs::read_to_string(&archive).unwrap()).unwrap();
        assert_eq!(data.metadata.file_count, 1);
        assert_eq!(data.files_encrypted.len(), 1);
        assert_eq!(data.files_encrypted[0].filename, FILE);
        let key = authenticated_backup_key(&data, PASSWORD, &STANDARD.decode(&data.backup_salt).unwrap()).unwrap();
        data.files_encrypted.push(FileBackup {
            filename: SIDECAR.to_string(),
            encrypted_content: encrypt_data_secure(&STANDARD.encode(&metadata), &key).unwrap(),
            size: metadata.len() as i64,
        });
        let write_authenticated_archive = |data: &mut BackupData| {
            let files = serde_json::to_string(&data.files_encrypted).unwrap();
            let content = format!("{}||{}", data.database_encrypted, files);
            data.content_mac = key.use_key(|bytes| {
                compute_header_mac(bytes.try_into().unwrap(), content.as_bytes()).map(|mac| STANDARD.encode(mac))
            }).unwrap();
            fs::write(&archive, serde_json::to_vec(data).unwrap()).unwrap();
        };

        let destination = dir.path().join("destination.db");
        let restored_files = dir.path().join("destination-files");
        fs::write(&destination, b"preserved database").unwrap();
        fs::create_dir(&restored_files).unwrap();
        fs::write(restored_files.join("existing.enc"), b"preserved file").unwrap();

        data.files_encrypted.last_mut().unwrap().filename = ".unexpected.metadata".into();
        write_authenticated_archive(&mut data);
        let error = restore_backup(&archive, PASSWORD, &destination, &restored_files).await.unwrap_err();
        assert!(error.contains("Nom de fichier invalide"));
        assert_eq!(fs::read(&destination).unwrap(), b"preserved database");
        assert_eq!(fs::read(restored_files.join("existing.enc")).unwrap(), b"preserved file");

        data.files_encrypted.last_mut().unwrap().filename = SIDECAR.into();
        write_authenticated_archive(&mut data);
        restore_backup(&archive, PASSWORD, &destination, &restored_files).await.unwrap();
        assert_eq!(fs::read(restored_files.join(FILE)).unwrap(), payload);
        assert!(!restored_files.join(SIDECAR).exists());
        let restored = Database::new(&destination).await.unwrap();
        let restored_path: String = sqlx::query_scalar("SELECT file_path FROM secure_files")
            .fetch_one(&restored.pool).await.unwrap();
        assert_eq!(Path::new(&restored_path), restored_files.join(FILE));
    }

    #[test]
    fn legacy_metadata_names_match_the_platform_convention() {
        assert!(is_legacy_file_metadata(".dc82dc81-76f5-4c20-b2ad-d1b55dc4e91f.enc.metadata"));
        assert!(is_legacy_file_metadata("dc82dc81-76f5-4c20-b2ad-d1b55dc4e91f.enc.metadata"));
        for name in [
            "..dc82dc81-76f5-4c20-b2ad-d1b55dc4e91f.enc.metadata",
            "../dc82dc81-76f5-4c20-b2ad-d1b55dc4e91f.enc.metadata",
            ".dc82dc81-76f5-4c20-b2ad-d1b55dc4e91f.enc.metadata/extra",
            ".document.enc.metadata",
        ] {
            assert!(!is_legacy_file_metadata(name));
        }
    }

    #[tokio::test]
    async fn snapshots_restore_sqlite_rows_and_wrong_password_preserves_target() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::new(&dir.path().join("origin.db")).await.unwrap();
        db.initialize().await.unwrap();
        let id = db.create_user("compte-test", "email", "hash", "salt").await.unwrap();
        db.create_password(id, "nom", None, "chiffré", None, None, None).await.unwrap();
        let files = dir.path().join("source-files");
        let backups = dir.path().join("archives");
        let archive = create_backup(&db, &files, "mot de passe de test", "compte-test", &backups).await.unwrap();
        let destination = dir.path().join("destination.db");
        let restored_files = dir.path().join("destination-files");
        fs::write(&destination, b"preserved").unwrap();
        assert!(restore_backup(&archive, "incorrect", &destination, &restored_files).await.is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"preserved");
        restore_backup(&archive, "mot de passe de test", &destination, &restored_files).await.unwrap();
        let restored = Database::new(&destination).await.unwrap();
        assert_eq!(restored.get_passwords(id).await.unwrap().len(), 1);
    }
}

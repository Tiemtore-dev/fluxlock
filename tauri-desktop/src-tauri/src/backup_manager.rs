// MODULE DE BACKUP ET RESTAURATION
// Gère l'export et l'import sécurisé des données du coffre-fort

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use chrono::Utc;

// Import depuis le module crypto (rendu public dans main.rs)
use crate::crypto::{
    encrypt_data_secure, decrypt_data_secure,
    derive_encryption_key_from_password_secure,
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

/// Crée un backup complet du coffre-fort
pub async fn create_backup(
    database_path: &Path,
    files_dir: &Path,
    master_password: &str,
    username: &str,
) -> Result<PathBuf, String> {
    debug_log!("📦 Création du backup...");
    
    // Lire la base de données
    let db_content = fs::read(database_path)
        .map_err(|e| format!("Erreur lecture DB: {}", e))?;
    
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
                if path.is_file() {
                    if let Some(filename) = path.file_name() {
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
    
    // Créer le répertoire de backup par défaut
    let backup_dir = crate::hidden_storage::get_default_backup_dir()?;
    
    // Générer le nom du fichier backup
    let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
    let backup_filename = format!("SecureVault_{}_{}.svbackup", username, timestamp);
    let backup_path = backup_dir.join(&backup_filename);
    
    // Écrire le fichier backup
    fs::write(&backup_path, json)
        .map_err(|e| format!("Erreur écriture backup: {}", e))?;
    
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
    let json = fs::read_to_string(backup_path)
        .map_err(|e| format!("Erreur lecture backup: {}", e))?;
    
    // Désérialiser
    let backup_data: BackupData = serde_json::from_str(&json)
        .map_err(|e| format!("Erreur désérialisation backup: {}", e))?;
    
    // Extraire le sel du backup (aléatoire, stocké dans le JSON)
    let salt = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        backup_data.backup_salt.as_bytes()
    ).map_err(|e| format!("Erreur décodage sel backup: {}", e))?;
    let encryption_key = derive_encryption_key_from_password_secure(master_password, &salt)
        .map_err(|e| format!("Erreur dérivation clé: {:?}", e))?;
    
    // Vérifier le MAC des métadonnées si présent (F-02 — anti-falsification)
    if !backup_data.metadata_mac.is_empty() {
        let metadata_json = serde_json::to_string(&backup_data.metadata)
            .map_err(|e| format!("Erreur sérialisation métadonnées: {}", e))?;
        let expected_mac = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            backup_data.metadata_mac.as_bytes()
        ).map_err(|e| format!("Erreur décodage MAC métadonnées: {}", e))?;
        let mac_arr: [u8; 32] = expected_mac.try_into()
            .map_err(|_| "MAC métadonnées invalide (taille incorrecte)".to_string())?;
        encryption_key.use_key(|k| {
            let key_arr: &[u8; 32] = k.try_into().map_err(|_| "Clé invalide".to_string())?;
            verify_header_mac(key_arr, metadata_json.as_bytes(), &mac_arr)
                .map_err(|_| "Métadonnées du backup falsifiées (MAC invalide)".to_string())
        }).map_err(|e| format!("{}", e))?;
        debug_log!("✅ MAC des métadonnées vérifié");
    } else {
        // VULN-016: Rejeter les backups legacy sans MAC — risque d'intégrité
        return Err("⚠️ Backup incompatible: pas de MAC de métadonnées. \
Ce backup a été créé avec une ancienne version et ne peut pas être vérifié. \
Créez un nouveau backup depuis la version actuelle.".to_string());
    }

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
    
    // Créer le répertoire parent si nécessaire
    if let Some(parent) = target_db_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Erreur création répertoire DB: {}", e))?;
    }
    
    // Restaurer la base de données
    fs::write(target_db_path, &db_content)
        .map_err(|e| format!("Erreur écriture DB restaurée: {}", e))?;
    
    debug_log!("✅ Base de données restaurée");
    
    // Créer le répertoire des fichiers
    fs::create_dir_all(target_files_dir)
        .map_err(|e| format!("Erreur création répertoire fichiers: {}", e))?;
    
    // Compter les fichiers avant de les déplacer
    let file_count = backup_data.files_encrypted.len();
    
    // Restaurer les fichiers
    for file_backup in backup_data.files_encrypted {
        // Validation anti-path-traversal : rejeter les noms de fichiers dangereux
        if file_backup.filename.contains("..") 
            || file_backup.filename.contains('/') 
            || file_backup.filename.contains('\\')
            || file_backup.filename.starts_with('.')
            || file_backup.filename.is_empty()
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
        
        let file_path = target_files_dir.join(&file_backup.filename);
        // Vérification supplémentaire : le chemin résolu DOIT rester dans target_files_dir
        // (ceinture et bretelles — le check de nom ci-dessus devrait suffire)
        if let Ok(canonical_target) = target_files_dir.canonicalize() {
            let resolved = canonical_target.join(&file_backup.filename);
            if !resolved.starts_with(&canonical_target) {
                return Err(format!(
                    "Chemin de fichier restauré hors du répertoire cible : '{}'",
                    file_backup.filename
                ));
            }
        }
        fs::write(&file_path, &content)
            .map_err(|e| format!("Erreur écriture fichier {}: {}", file_backup.filename, e))?;
        
        debug_log!("📄 Fichier restauré: {}", file_backup.filename);
    }
    
    debug_log!("✅ Restauration terminée: {} fichiers", file_count);
    
    Ok(backup_data.metadata)
}

/// Lit les métadonnées d'un fichier backup sans le déchiffrer complètement
pub fn read_backup_metadata(backup_path: &Path) -> Result<BackupMetadata, String> {
    let json = fs::read_to_string(backup_path)
        .map_err(|e| format!("Erreur lecture backup: {}", e))?;
    
    let backup_data: BackupData = serde_json::from_str(&json)
        .map_err(|e| format!("Erreur désérialisation: {}", e))?;
    
    Ok(backup_data.metadata)
}

/// Recherche tous les fichiers de backup disponibles
pub fn find_all_backups() -> Vec<BackupInfo> {
    let locations = crate::hidden_storage::get_backup_search_locations();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    #[tokio::test]
    async fn test_backup_restore_cycle() {
        // Ce test nécessiterait une DB réelle, donc skip en CI
        // Test manuel recommandé
    }
}

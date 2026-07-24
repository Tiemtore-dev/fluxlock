use crate::AppState;
use crate::crypto::verify_password;
use crate::{hidden_storage, backup_manager};
use crate::database::Database;
use crate::security_monitor::get_security_monitor;
use crate::filesystem_monitor::get_filesystem_monitor;
use serde::{Deserialize, Serialize};
use tauri::State;
use sqlx::SqlitePool;

// ========== COMMANDES BACKUP & RESTORE ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBackupRequest {
    pub master_password: Option<String>,
    /// Authentication method: "passkey" to use passkey, null for password.
    pub auth_method: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBackupResponse {
    pub success: bool,
    pub backup_path: Option<String>,
    pub message: String,
}

#[tauri::command]
pub async fn create_backup(
    request: CreateBackupRequest,
    state: State<'_, AppState>,
) -> Result<CreateBackupResponse, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer le nom d'utilisateur
    let user = db.get_user_by_id(user_id)
        .await
        .map_err(|e| format!("Erreur récupération utilisateur: {}", e))?
        .ok_or("Utilisateur non trouvé")?;

    // Authenticate: passkey, password, or biometric
    let master_password_for_backup = if request.auth_method.as_deref() == Some("passkey") {
        // Passkey auth — authenticate and use a dummy password for backup encryption
        // The backup is encrypted with the master_password, so we need it.
        // With passkey, we derive a backup-specific key from the vault key.
        let (_pk_uid, _pk_name, _key_bytes) =
            crate::passkey::authenticate_passkey(&user.username, None)
                .map_err(|e| format!("Échec passkey: {}", e))?;
        // For backup compatibility, we still need the user's password.
        // Since passkey wraps the vault key (not the password), we use
        // the vault key directly to create the backup.
        return Err("Les backups nécessitent le mot de passe maître pour le chiffrement. \
                    La passkey ne peut pas être utilisée pour créer un backup car le backup \
                    doit être déchiffrable avec le mot de passe sur un autre appareil.".to_string());
    } else {
        request.master_password
            .as_ref()
            .ok_or("Mot de passe maître requis pour le backup")?
            .clone()
    };

    // Obtenir les chemins
    let db_path = hidden_storage::get_hidden_database_path()?;
    let files_dir = hidden_storage::get_hidden_files_dir()?;

    // Créer le backup
    let backup_path = backup_manager::create_backup(
        &db_path,
        &files_dir,
        &master_password_for_backup,
        &user.username,
    )
    .await?;

    Ok(CreateBackupResponse {
        success: true,
        backup_path: Some(backup_path.to_string_lossy().to_string()),
        message: "Backup créé avec succès".to_string(),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchBackupsResponse {
    pub backups: Vec<backup_manager::BackupInfo>,
}

#[tauri::command]
pub async fn search_backups() -> Result<SearchBackupsResponse, String> {
    let backups = backup_manager::find_all_backups();
    Ok(SearchBackupsResponse { backups })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreBackupRequest {
    pub backup_path: String,
    pub master_password: String,
    // Note: restore always requires the master password because
    // the backup file is encrypted with it. Passkey cannot be used here.
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreBackupResponse {
    pub success: bool,
    pub message: String,
    pub metadata: Option<backup_manager::BackupMetadata>,
}

#[tauri::command]
pub async fn restore_backup(
    request: RestoreBackupRequest,
    state: State<'_, AppState>,
) -> Result<RestoreBackupResponse, String> {
    // Fermer les connexions actuelles
    *state.current_user_id.lock().await = None;
    *state.db.lock().await = None;

    let backup_path = std::path::PathBuf::from(&request.backup_path);
    let db_path = hidden_storage::get_hidden_database_path()?;
    let files_dir = hidden_storage::get_hidden_files_dir()?;

    // Restaurer le backup
    let metadata = backup_manager::restore_backup(
        &backup_path,
        &request.master_password,
        &db_path,
        &files_dir,
    )
    .await?;

    Ok(RestoreBackupResponse {
        success: true,
        message: format!("Backup restauré avec succès (créé le {})", metadata.created_at),
        metadata: Some(metadata),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetBackupMetadataRequest {
    pub backup_path: String,
}

#[tauri::command]
pub async fn get_backup_metadata(
    request: GetBackupMetadataRequest,
) -> Result<backup_manager::BackupMetadata, String> {
    let backup_path = std::path::PathBuf::from(&request.backup_path);
    backup_manager::read_backup_metadata(&backup_path)
}

// ========== COMMANDE RESET VAULT ==========

/// CFG-003: Réinitialisation complète avec vérification du mot de passe ou passkey
#[tauri::command]
pub async fn reset_vault_completely(
    password: Option<String>,
    auth_method: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    debug_log!("⚠️ Réinitialisation complète du coffre-fort demandée");
    
    // CFG-003: Vérifier l'identité avant la destruction
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié — session requise pour réinitialiser le coffre")?;
    
    {
        let db_guard = state.db.lock().await;
        let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
        let user = db.get_user_by_id(user_id)
            .await
            .map_err(|e| format!("Erreur récupération utilisateur: {}", e))?
            .ok_or("Utilisateur non trouvé")?;
        
        if auth_method.as_deref() == Some("passkey") {
            // Passkey authentication for reset
            let (pk_uid, _, _) = crate::passkey::authenticate_passkey(&user.username, None)
                .map_err(|e| format!("Échec passkey: {}", e))?;
            if pk_uid != user_id {
                return Err("❌ Incohérence de compte — réinitialisation refusée".to_string());
            }
        } else {
            let pw = password.as_ref().ok_or("❌ Mot de passe requis")?;
            if verify_password(pw, &user.password_hash).is_err() {
                debug_log!("❌ Mot de passe incorrect pour réinitialisation du coffre");
                return Err("❌ Mot de passe incorrect — réinitialisation refusée".to_string());
            }
        }
    }
    
    // Nettoyer l'ID utilisateur courant
    *state.current_user_id.lock().await = None;
    
    // Fermer la connexion à la base de données
    *state.db.lock().await = None;
    
    // Obtenir le répertoire de données (stocké par init_local_db)
    // Fallback: hidden_storage pour rétrocompatibilité desktop
    let app_data_dir = {
        let stored = state.data_dir.lock().await;
        if let Some(dir) = stored.as_ref() {
            dir.clone()
        } else {
            hidden_storage::get_hidden_database_dir()
                .map_err(|e| format!("Impossible de trouver le répertoire de données: {}", e))?
        }
    };
    
    // Supprimer tout le répertoire de l'application
    if app_data_dir.exists() {
        debug_log!("🗑️ Suppression de: {:?}", app_data_dir);
        std::fs::remove_dir_all(&app_data_dir)
            .map_err(|e| format!("Erreur lors de la suppression de la base de données: {}", e))?;
    }
    
    // Réinitialiser les moniteurs de sécurité
    let security_monitor = get_security_monitor();
    security_monitor.reset_all().await;
    
    let fs_monitor = get_filesystem_monitor();
    {
        let guard = fs_monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
        guard.reset_stats();
    } // guard est dropped ici, avant le .await
    
    // Réinitialiser la base de données après suppression
    debug_log!("🔄 Réinitialisation de la base de données...");
    let db_path = app_data_dir.join("sv.db");
    
    // Créer le répertoire s'il n'existe pas
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Erreur création répertoire: {}", e))?;
    }
    
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let pool = SqlitePool::connect(&db_url)
        .await
        .map_err(|e| format!("Erreur connexion DB: {}", e))?;

    // Créer les tables
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            crypto_salt TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled BOOLEAN DEFAULT 0,
            totp_verified_at DATETIME,
            backup_codes TEXT,
            account_locked BOOLEAN DEFAULT 0,
            locked_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Erreur création table users: {}", e))?;

    // Créer les autres tables nécessaires
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            username TEXT,
            password TEXT NOT NULL,
            url TEXT,
            notes TEXT,
            category TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )"
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Erreur création table passwords: {}", e))?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS secure_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT,
            integrity_hash TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )"
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Erreur création table secure_files: {}", e))?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS secure_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            key_name TEXT NOT NULL,
            key_type TEXT NOT NULL,
            key_data TEXT NOT NULL,
            algorithm TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )"
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Erreur création table secure_keys: {}", e))?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )"
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("Erreur création table audit_logs: {}", e))?;

    // Créer l'instance Database à partir du SqlitePool (pas de db_path car déjà connecté)
    let database = Database {
        pool,
    };
    
    *state.db.lock().await = Some(database);
    
    debug_log!("✅ Coffre-fort complètement réinitialisé et base de données prête");
    Ok("Coffre-fort complètement réinitialisé".to_string())
}

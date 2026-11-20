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

/// Resolves the data directory (Android: app_data_dir stored at init; desktop: hidden storage).
async fn resolve_data_dir(state: &AppState) -> Result<std::path::PathBuf, String> {
    if let Some(dir) = state.data_dir.lock().await.as_ref() {
        return Ok(dir.clone());
    }
    hidden_storage::get_hidden_database_dir()
}

/// Directory where backups are created. On Android this is a private staging area; the
/// frontend then copies the file to public storage so it survives an uninstall.
async fn resolve_backup_dir(state: &AppState) -> Result<std::path::PathBuf, String> {
    if cfg!(target_os = "android") {
        Ok(resolve_data_dir(state).await?.join("backups"))
    } else {
        hidden_storage::get_default_backup_dir()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBackupRequest {
    pub master_password: String,
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

    verify_password(&request.master_password, &user.password_hash)
        .map_err(|_| "Mot de passe incorrect")?;

    // Obtenir les chemins
    let data_dir = resolve_data_dir(&state).await?;
    let files_dir = data_dir.join("files");
    let backup_dir = resolve_backup_dir(&state).await?;

    // Créer le backup
    let backup_path = backup_manager::create_backup(
        db,
        &files_dir,
        &request.master_password,
        &user.username,
        &backup_dir,
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
pub async fn search_backups(state: State<'_, AppState>) -> Result<SearchBackupsResponse, String> {
    let extra_dirs = vec![resolve_backup_dir(&state).await?];
    let backups = backup_manager::find_all_backups(&extra_dirs);
    Ok(SearchBackupsResponse { backups })
}

/// Stores backup content picked by the user (Android file picker) so it can be restored.
#[tauri::command]
pub async fn import_backup_content(
    content: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let backup_dir = resolve_backup_dir(&state).await?;
    let path = backup_manager::import_backup_content(&content, &backup_dir)?;
    Ok(path.to_string_lossy().to_string())
}

/// Writes exported text (e.g. CSV) to the user's Downloads folder (desktop) and returns the path.
#[tauri::command]
pub async fn export_text_to_downloads(filename: String, content: String) -> Result<String, String> {
    let safe_name: String = filename
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '_' | '-' | '.'))
        .collect();
    if safe_name.is_empty() || safe_name.starts_with('.') {
        return Err("Nom de fichier invalide".to_string());
    }
    let dir = dirs::download_dir()
        .or_else(dirs::document_dir)
        .ok_or("Dossier Téléchargements introuvable")?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("Erreur création dossier: {}", e))?;

    let (stem, ext) = match safe_name.rsplit_once('.') {
        Some((s, e)) => (s.to_string(), format!(".{}", e)),
        None => (safe_name.clone(), String::new()),
    };
    let mut path = dir.join(&safe_name);
    let mut n = 1;
    while path.exists() {
        path = dir.join(format!("{} ({}){}", stem, n, ext));
        n += 1;
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("Erreur écriture fichier: {}", e))?;
        f.write_all(content.as_bytes()).map_err(|e| format!("Erreur écriture fichier: {}", e))?;
    }
    #[cfg(not(unix))]
    std::fs::write(&path, content).map_err(|e| format!("Erreur écriture fichier: {}", e))?;

    Ok(path.to_string_lossy().to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RestoreBackupRequest {
    pub backup_path: String,
    pub master_password: String,
    pub current_password: String,
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
    let _lifecycle = state.auth_lifecycle.lock().await;
    let id = crate::validate_session(&state).await?;
    let mut db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let owner = db.get_user_by_id(id).await.map_err(|e| e.to_string())?.ok_or("Compte introuvable")?;
    verify_password(&request.current_password, &owner.password_hash)
        .map_err(|_| "Mot de passe actuel incorrect")?;

    let path = std::path::Path::new(&request.backup_path);
    let data_dir = resolve_data_dir(&state).await?;
    let db_path = data_dir.join("sv.db");
    let files_dir = data_dir.join("files");
    db.pool.close().await;
    let result = backup_manager::restore_backup(path, &request.master_password, &db_path, &files_dir).await;

    let replacement = Database::new(&db_path).await.map_err(|e| e.to_string())?;
    *db_guard = Some(replacement);
    drop(db_guard);
    let metadata = result?;
    *state.current_user_id.lock().await = None;
    *state.session_token.lock().await = None;
    super::session::clear_session_key(&state, id).await;
    super::session::clear_transfer_state(&state).await;
    let _ = crate::biometric::disable_biometric(&data_dir);

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

/// CFG-003: Réinitialisation complète avec vérification du mot de passe
#[tauri::command]
pub async fn reset_vault_completely(
    password: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let _lifecycle = state.auth_lifecycle.lock().await;
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
        
        verify_password(&password, &user.password_hash)
            .map_err(|_| "Mot de passe incorrect. Réinitialisation refusée.")?;
    }

    *state.current_user_id.lock().await = None;
    *state.session_token.lock().await = None;
    super::session::clear_session_key(&state, user_id).await;
    super::session::clear_transfer_state(&state).await;
    crate::biometric::disable_biometric(&resolve_data_dir(&state).await?)?;
    let mut database = state.db.lock().await;
    if let Some(db) = database.take() {
        db.pool.close().await;
    }
    drop(database);

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

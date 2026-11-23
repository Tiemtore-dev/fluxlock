use crate::AppState;
use crate::crypto::verify_password;
use crate::{hidden_storage, backup_manager};
use crate::database::Database;
use serde::{Deserialize, Serialize};
use tauri::State;

// ========== COMMANDES BACKUP & RESTORE ==========

/// Resolves the data directory (Android: app_data_dir stored at init; desktop: hidden storage).
async fn resolve_data_dir(state: &AppState) -> Result<std::path::PathBuf, String> {
    state.data_dir.lock().await.clone().ok_or_else(|| "Aucun coffre sélectionné".into())
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
    context: crate::vault::VaultContext,
) -> Result<CreateBackupResponse, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
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
    let vault = state.selected_vault.lock().await.as_ref().map(|v| v.descriptor.clone());
    let backup_path = backup_manager::create_backup_for_vault(
        db,
        &files_dir,
        &request.master_password,
        &user.username,
        &backup_dir,
        vault.as_ref(),
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
pub async fn search_backups(state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<SearchBackupsResponse, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let extra_dirs = vec![resolve_backup_dir(&state).await?];
    let backups = backup_manager::find_all_backups(&extra_dirs);
    Ok(SearchBackupsResponse { backups })
}

/// Stores backup content picked by the user (Android file picker) so it can be restored.
#[tauri::command]
pub async fn import_backup_content(
    content: String,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let backup_dir = resolve_backup_dir(&state).await?;
    let path = backup_manager::import_backup_content(&content, &backup_dir)?;
    Ok(path.to_string_lossy().to_string())
}

/// Writes exported text (e.g. CSV) to the user's Downloads folder (desktop) and returns the path.
#[tauri::command]
pub async fn export_text_to_downloads(filename: String, content: String,
    state: tauri::State<'_, crate::AppState>,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
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
    context: crate::vault::VaultContext,
) -> Result<RestoreBackupResponse, String> {
    let _lifecycle = state.auth_lifecycle.write().await;
    crate::vault::check_context(&state, &context, true).await?;
    let id = crate::validate_session(&state).await?;
    let mut db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let owner = db.get_user_by_id(id).await.map_err(|e| e.to_string())?.ok_or("Compte introuvable")?;
    verify_password(&request.current_password, &owner.password_hash)
        .map_err(|_| "Mot de passe actuel incorrect")?;
    state.autofill.reset_vault(&context.vault_id).await?;

    let path = std::path::Path::new(&request.backup_path);
    let data_dir = resolve_data_dir(&state).await?;
    let db_path = data_dir.join("sv.db");
    let files_dir = data_dir.join("files");
    super::session::clear_transfer_state(&state).await;
    db.pool.close().await;
    let result = backup_manager::restore_backup(path, &request.master_password, &db_path, &files_dir).await;

    let replacement = match Database::new(&db_path).await {
        Ok(db) => db,
        Err(error) => {
            drop(db_guard);
            super::session::lock_session(&state).await;
            return Err(error.to_string());
        }
    };
    *db_guard = Some(replacement);
    drop(db_guard);
    let metadata = match result {
        Ok(metadata) => metadata,
        Err(error) => {
            // A rejected archive leaves the original vault and its session usable.
            let key = crate::get_or_fetch_vault_key(&state, id).await?;
            if let Some(manager) = state.transfer_manager.lock().await.as_ref() {
                let _ = manager.trust_store.lock().await.unlock(&key);
            }
            return Err(error);
        }
    };
    super::session::lock_session(&state).await;
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
    state: tauri::State<'_, crate::AppState>,
    context: crate::vault::VaultContext,
) -> Result<backup_manager::BackupMetadata, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let backup_path = std::path::PathBuf::from(&request.backup_path);
    backup_manager::read_backup_metadata(&backup_path)
}

// ========== COMMANDE RESET VAULT ==========

/// CFG-003: Réinitialisation complète avec vérification du mot de passe
#[tauri::command]
pub async fn reset_vault_completely(
    password: String,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = state.auth_lifecycle.write().await;
    crate::vault::check_context(&state, &context, true).await?;
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

    let dir = resolve_data_dir(&state).await?;
    crate::biometric::disable_biometric(&dir)?;
    state.autofill.reset_vault(&context.vault_id).await?;
    super::session::lock_session(&state).await;
    *state.transfer_manager.lock().await = None;
    *state.signed_log_manager.lock().await = None;
    if let Some(db) = state.db.lock().await.take() { db.pool.close().await; }
    reset_storage(&dir)?;
    let db = Database::new(&dir.join("sv.db")).await.map_err(|e| e.to_string())?;
    db.initialize().await.map_err(|e| e.to_string())?;
    *state.db.lock().await = Some(db);
    let selected = state.selected_vault.lock().await.clone().ok_or("Aucun coffre sélectionné")?;
    crate::vault::mount(&state, selected).await?;
    Ok("Le contenu de ce coffre a été effacé".into())
}

/// Never delete a vault's parent directory: the legacy vault shares the catalog root.
pub(crate) fn reset_storage(dir: &std::path::Path) -> Result<(), String> {
    for name in ["sv.db", "sv.db-wal", "sv.db-shm", "sv.db-journal", "files", "signed_logs", "trust_store.enc", ".biometric_enrollment.json", "threat_blocked.json"] {
        let path = dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    std::fs::remove_dir_all(&path)
                } else { std::fs::remove_file(&path) }.map_err(|e| e.to_string())?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

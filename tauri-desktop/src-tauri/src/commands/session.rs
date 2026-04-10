use crate::AppState;
use crate::secure_cleanup_decrypted_files;
use crate::secure_storage;
use tauri::State;

#[tauri::command]
pub async fn local_logout(state: State<'_, AppState>) -> Result<(), String> {
    let mut user_id_guard = state.current_user_id.lock().await;
    
    if let Some(user_id) = *user_id_guard {
        debug_log!("🚪 Déconnexion de l'utilisateur {}", user_id);
        
        // M01 — Nettoyage sécurisé des fichiers déchiffrés temporaires
        secure_cleanup_decrypted_files(&state.decrypted_temp_files).await;
        
        // Invalider le cache de clé vault (XOR-masked, zeroize + munlock)
        state.vault_key_cache.lock().await.invalidate();
        
        // Supprimer la clé de chiffrement de l'enclave sécurisée
        if let Err(_e) = secure_storage::delete_encryption_key(user_id) {
            debug_log!("⚠️ Erreur lors de la suppression de la clé: {}", _e);
            // On continue quand même la déconnexion
        }
        
        // Invalider le token de session
        *state.session_token.lock().await = None;
        
        *user_id_guard = None;
        Ok(())
    } else {
        Ok(())
    }
}

/// Met à jour le timestamp d'activité (appelé par le frontend sur interaction utilisateur)
#[tauri::command]
pub async fn notify_activity(state: State<'_, AppState>) -> Result<(), String> {
    *state.last_activity.lock().await = std::time::Instant::now();
    Ok(())
}

/// Configure le délai d'auto-lock en minutes
#[tauri::command]
pub async fn set_auto_lock_timeout(minutes: u64, state: State<'_, AppState>) -> Result<(), String> {
    *state.auto_lock_minutes.lock().await = minutes;
    debug_log!("⏰ Auto-lock configuré à {} minutes", minutes);
    Ok(())
}

/// Vérifie si l'inactivité a dépassé le seuil et verrouille automatiquement
/// Le frontend doit appeler cette commande périodiquement (toutes les 30s)
#[tauri::command]
pub async fn check_auto_lock(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let user_id = *state.current_user_id.lock().await;
    
    // Pas connecté = pas d'auto-lock
    if user_id.is_none() {
        return Ok(serde_json::json!({ "locked": false, "reason": "not_authenticated" }));
    }
    let user_id = user_id.unwrap();
    
    let last_activity = *state.last_activity.lock().await;
    let timeout_minutes = *state.auto_lock_minutes.lock().await;
    
    // 0 = désactivé
    if timeout_minutes == 0 {
        return Ok(serde_json::json!({ "locked": false, "reason": "disabled" }));
    }
    
    let elapsed = last_activity.elapsed();
    let timeout = std::time::Duration::from_secs(timeout_minutes * 60);
    
    if elapsed >= timeout {
        debug_log!("🔒 Auto-lock déclenché : {} minutes d'inactivité", elapsed.as_secs() / 60);
        
        // M01 — Nettoyage sécurisé des fichiers déchiffrés temporaires
        secure_cleanup_decrypted_files(&state.decrypted_temp_files).await;
                // Invalider le cache de clé vault (XOR-masked, zeroize + munlock)
        state.vault_key_cache.lock().await.invalidate();
                // Supprimer la clé de chiffrement
        if let Err(_e) = secure_storage::delete_encryption_key(user_id) {
            debug_log!("⚠️ Erreur suppression clé auto-lock: {}", _e);
        }
        
        // Invalider la session
        *state.session_token.lock().await = None;
        *state.current_user_id.lock().await = None;
        
        // Log l'événement
        if let Some(db) = state.db.lock().await.as_ref() {
            let _ = db.log_action(user_id, "AUTO_LOCK", "session", None).await;
        }
        
        Ok(serde_json::json!({
            "locked": true,
            "reason": "inactivity",
            "elapsed_minutes": elapsed.as_secs() / 60
        }))
    } else {
        let remaining = timeout.saturating_sub(elapsed);
        Ok(serde_json::json!({
            "locked": false,
            "remaining_seconds": remaining.as_secs()
        }))
    }
}

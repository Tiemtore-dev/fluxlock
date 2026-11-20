use crate::AppState;
use crate::secure_cleanup_decrypted_files;
use crate::secure_storage;
use tauri::State;

pub(crate) async fn clear_session_key(state: &AppState, user_id: i64) {
    state.vault_key_cache.lock().await.invalidate();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = user_id;
        state.mobile_session_key.lock().await.take();
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Err(error) = secure_storage::delete_encryption_key(user_id) {
        debug_log!("Erreur de suppression de la clé de session : {}", error);
    }
}

pub(crate) async fn clear_transfer_state(state: &AppState) {
    if let Some(manager) = state.transfer_manager.lock().await.as_ref() {
        *manager.visible.lock().await = false;
        manager.discovery.unregister_mdns_service().await;
        manager.trust_store.lock().await.lock();
        manager.active_transfers.lock().await.clear();
        manager.active_sessions.lock().await.clear();
        manager.active_connections.lock().await.clear();
        manager.transfer_roles.lock().await.clear();
        manager.pending_items.lock().await.clear();
        manager.active_listener.lock().await.take();
    }
}

#[tauri::command]
pub async fn local_logout(state: State<'_, AppState>) -> Result<(), String> {
    let _lifecycle = state.auth_lifecycle.lock().await;
    let mut user = state.current_user_id.lock().await;
    if let Some(id) = user.take() {
        *state.session_token.lock().await = None;
        clear_session_key(&state, id).await;
        secure_cleanup_decrypted_files(&state.decrypted_temp_files).await;
        drop(user);
        clear_transfer_state(&state).await;
    }
    Ok(())
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
    crate::validate_session(&state).await?;
    if minutes > 60 {
        return Err("Le délai de verrouillage doit être compris entre 0 et 60 minutes".into());
    }
    *state.auto_lock_minutes.lock().await = minutes;
    debug_log!("⏰ Auto-lock configuré à {} minutes", minutes);
    Ok(())
}

/// Vérifie si l'inactivité a dépassé le seuil et verrouille automatiquement
/// Le frontend doit appeler cette commande périodiquement (toutes les 30s)
#[tauri::command]
pub async fn check_auto_lock(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let _lifecycle = state.auth_lifecycle.lock().await;
    let mut user = state.current_user_id.lock().await;
    
    let Some(user_id) = *user else {
        return Ok(serde_json::json!({ "locked": true, "reason": "not_authenticated" }));
    };

    let last_activity = *state.last_activity.lock().await;
    let timeout_minutes = *state.auto_lock_minutes.lock().await;
    
    // 0 = désactivé
    if timeout_minutes == 0 {
        return Ok(serde_json::json!({ "locked": false, "reason": "disabled" }));
    }
    
    let elapsed = last_activity.elapsed();
    let timeout = std::time::Duration::from_secs(timeout_minutes.saturating_mul(60));
    
    if elapsed >= timeout {
        debug_log!("🔒 Auto-lock déclenché : {} minutes d'inactivité", elapsed.as_secs() / 60);
        
        *state.session_token.lock().await = None;
        *user = None;
        clear_session_key(&state, user_id).await;
        secure_cleanup_decrypted_files(&state.decrypted_temp_files).await;
        drop(user);
        clear_transfer_state(&state).await;

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

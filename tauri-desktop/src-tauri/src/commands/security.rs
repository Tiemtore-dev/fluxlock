use crate::{AppState, SecurityEvent};
use crate::validate_session;
use crate::crypto::verify_password;
use crate::security_monitor::{get_security_monitor, SecurityState};
use crate::filesystem_monitor::{get_filesystem_monitor, MonitoringStats};
use tauri::State;

#[tauri::command]
pub async fn get_security_events(state: State<'_, AppState>) -> Result<Vec<SecurityEvent>, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer les événements de sécurité depuis les logs d'action
    let events = db
        .get_user_action_logs(user_id, Some(50))
        .await
        .map_err(|e| format!("Erreur récupération événements: {}", e))?;

    // Convertir les logs d'action en événements de sécurité
    let security_events: Vec<SecurityEvent> = events
        .into_iter()
        .map(|log| SecurityEvent {
            id: log.id,
            user_id: log.user_id,
            event_type: log.action_type.clone(),
            description: format!("{} sur {}", log.action_type, log.resource_type),
            severity: None,
            ip_address: None,
            timestamp: log.timestamp,
        })
        .collect();

    Ok(security_events)
}

// CFG-002: Commande de test — retourne une erreur en mode release
#[tauri::command]
pub async fn create_test_logs(state: State<'_, AppState>) -> Result<String, String> {
    // Bloquer l'exécution en production
    #[cfg(not(debug_assertions))]
    return Err("Commande de test non disponible en production".to_string());

    #[cfg(debug_assertions)]
    {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Créer plusieurs logs de test
    let _ = db.log_action(user_id, "LOGIN", "session", None).await;
    let _ = db.log_action(user_id, "CREATE", "password", Some(1)).await;
    let _ = db.log_action(user_id, "UPDATE", "password", Some(1)).await;
    let _ = db.log_action(user_id, "ACCESS", "file", Some(1)).await;
    let _ = db.log_action(user_id, "CREATE", "key", Some(1)).await;
    let _ = db.log_action(user_id, "DELETE", "password", Some(2)).await;

    Ok("6 logs de test créés avec succès".to_string())
    }
}

// ========== COMMANDES DE SÉCURITÉ NATIVE ==========

/// Vérifie l'état de sécurité global
#[tauri::command]
pub async fn get_security_status() -> Result<SecurityState, String> {
    let monitor = get_security_monitor();
    Ok(monitor.get_security_state().await)
}

/// Désactive le mode lecture seule (avec vérification mot de passe)
#[tauri::command]
pub async fn disable_readonly_mode(password: String, state: State<'_, AppState>) -> Result<String, String> {
    debug_log!("🔓 Demande de désactivation du mode lecture seule");
    
    // Récupérer la base de données depuis le state
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref()
        .ok_or("Base de données non initialisée".to_string())?;
    
    // Récupérer l'ID utilisateur depuis la session active (EXP-001 fix)
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié — session requise pour désactiver le mode lecture seule")?;
    
    // Vérifier le mot de passe
    let user = db.get_user_by_id(user_id)
        .await
        .map_err(|e| format!("Erreur récupération utilisateur: {}", e))?
        .ok_or("Utilisateur non trouvé".to_string())?;
    
    if verify_password(&password, &user.password_hash).is_err() {
        debug_log!("❌ Mot de passe incorrect pour désactivation mode lecture seule");
        return Err("❌ Mot de passe incorrect".to_string());
    }
    
    // Désactiver le mode lecture seule
    drop(db_guard); // Libérer le lock avant l'appel async
    
    let monitor = get_security_monitor();
    monitor.disable_readonly("admin").await?;
    
    // Logger l'action
    let db_guard = state.db.lock().await;
    if let Some(db) = db_guard.as_ref() {
        let _ = db.log_action(user_id, "DISABLE_READONLY", "security", None).await;
    }
    
    debug_log!("✅ Mode lecture seule désactivé par l'utilisateur {}", user.username);
    Ok("Mode lecture seule désactivé avec succès".to_string())
}

/// Retourne le délai restant avant la prochaine tentative de déverrouillage.
#[tauri::command]
pub async fn check_login_delay(state: State<'_, AppState>) -> Result<u64, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    match db.get_vault_owner().await.map_err(|e| e.to_string())? {
        Some(user) => super::auth::login_delay(db, &user).await,
        None => Ok(0),
    }
}

/// Réinitialise tous les compteurs de sécurité
#[tauri::command]
pub async fn reset_security_counters(state: State<'_, AppState>) -> Result<String, String> {
    // VULN-001 + VULN-002: Validation complète de session
    validate_session(&state).await?;
    let monitor = get_security_monitor();
    monitor.reset_all().await;
    Ok("Compteurs de sécurité réinitialisés".to_string())
}

// ========== COMMANDES FILESYSTEM MONITOR ==========

#[tauri::command]
pub async fn get_filesystem_stats(state: State<'_, AppState>) -> Result<MonitoringStats, String> {
    // VULN-001 + VULN-002: Validation complète de session
    validate_session(&state).await?;
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    Ok(guard.get_stats())
}

#[tauri::command]
pub async fn disable_filesystem_readonly(state: State<'_, AppState>) -> Result<String, String> {
    // VULN-001 + VULN-002: Validation complète de session
    validate_session(&state).await?;
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.disable_readonly();
    Ok("Mode lecture seule système désactivé".to_string())
}

#[tauri::command]
pub async fn reset_filesystem_stats(state: State<'_, AppState>) -> Result<String, String> {
    // VULN-001 + VULN-002: Validation complète de session
    validate_session(&state).await?;
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.reset_stats();
    Ok("Statistiques système réinitialisées".to_string())
}

#[tauri::command]
pub async fn enable_filesystem_monitoring(state: State<'_, AppState>) -> Result<String, String> {
    // VULN-001 + VULN-002: Validation complète de session
    validate_session(&state).await?;
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.enable_monitoring();
    Ok("Surveillance des fichiers activée".to_string())
}

#[tauri::command]
pub async fn disable_filesystem_monitoring(state: State<'_, AppState>) -> Result<String, String> {
    // VULN-001 + VULN-002: Validation complète de session
    validate_session(&state).await?;
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.disable_monitoring();
    Ok("Surveillance des fichiers désactivée".to_string())
}

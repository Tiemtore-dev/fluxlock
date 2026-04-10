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

/// Vérifie le délai d'attente pour un utilisateur (en secondes)
/// Retourne 0 si aucun délai, sinon le nombre de secondes à attendre
#[tauri::command]
pub async fn check_login_delay(username: String, state: State<'_, AppState>) -> Result<u64, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    
    // VULN-007: Ne pas révéler si l'utilisateur existe ou non
    let user = match db.get_user_by_username(&username).await {
        Ok(Some(u)) => u,
        _ => return Ok(0), // Utilisateur inexistant → même réponse que 0 tentatives
    };
    
    // Vérifier si le compte est bloqué
    let is_locked = db.check_account_locked(user.id).await
        .map_err(|e| format!("Erreur DB: {}", e))?;
    
    if is_locked {
        // Compte bloqué = délai maximum de 1 heure
        return Ok(3600);
    }
    
    // Compter les tentatives échouées récentes (dernières 2 minutes)
    let failed_count = db.count_failed_logins(user.id, 2).await
        .map_err(|e| format!("Erreur DB: {}", e))?;
    
    // Calculer le délai selon le nombre de tentatives
    let delay = match failed_count {
        0..=2 => 0,           // 0-2 tentatives : pas de délai
        3..=4 => 15,          // 3-4 tentatives : 15 secondes
        5..=7 => 30,          // 5-7 tentatives : 30 secondes
        8..=10 => 60,         // 8-10 tentatives : 1 minute
        _ => 120,             // 11+ tentatives : 2 minutes
    };
    
    if delay > 0 {
        // Vérifier le temps écoulé depuis la dernière tentative
        if let Ok(Some(elapsed)) = db.get_time_since_last_failed_login(user.id).await {
            if elapsed >= delay {
                // Délai expiré
                debug_log!("✅ check_login_delay: Délai expiré ({}s écoulées)", elapsed);
                return Ok(0);
            } else {
                // Délai actif - retourner le temps restant
                let remaining = (delay - elapsed) as u64;
                debug_log!("⏱️ check_login_delay: {}s restantes sur {}s ({} tentatives)", remaining, delay, failed_count);
                return Ok(remaining);
            }
        }
    }
    
    debug_log!("🔐 check_login_delay pour {}: {} tentatives → délai: {}s", username, failed_count, delay);
    Ok(delay as u64)
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

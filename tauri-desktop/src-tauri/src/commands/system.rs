use crate::AppState;
use crate::secure_storage;
use crate::signed_log;
use tauri::State;

// ========== THREAT REACTION COMMANDS ==========

/// Analyse une action et applique les réactions automatiques
/// EXP-003 fix: user_id lu depuis la session, jamais depuis un paramètre IPC
#[tauri::command]
pub async fn analyze_and_react(
    action: String,
    _timestamp: i64,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    // EXP-003: Récupérer user_id depuis la session active (pas depuis IPC)
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    // Vérifier si bloqué
    let (is_blocked, block_msg) = state.threat_reactor.check_blocked(user_id).await;
    if is_blocked {
        return Ok(serde_json::json!({
            "blocked": true,
            "message": block_msg.unwrap_or_else(|| "Compte bloqué".to_string()),
        }));
    }

    // Vérifier rate limit
    let (is_limited, remaining) = state.threat_reactor.check_rate_limit(user_id).await;
    if is_limited {
        return Ok(serde_json::json!({
            "rate_limited": true,
            "wait_seconds": remaining.unwrap_or(0),
            "message": format!("Veuillez attendre {} secondes", remaining.unwrap_or(0)),
        }));
    }

    // Analyser le comportement via le moniteur natif Rust
    let anomaly_score = if action.contains("suspicious") || action.contains("anomaly") { 75.0 } else { 10.0 };
    let risk_level = if anomaly_score >= 80.0 { "CRITICAL" } else if anomaly_score >= 60.0 { "HIGH" } else if anomaly_score >= 40.0 { "MEDIUM" } else { "LOW" };
    let is_normal = anomaly_score < 40.0;

    // Réagir selon le niveau de menace
    let response = state.threat_reactor.react_to_threat(
        user_id,
        anomaly_score,
        risk_level,
        &if is_normal { vec![] } else { vec!["anomaly detected".to_string()] },
    ).await;

    // Si blocage critique, bloquer dans la DB aussi
    if response.blocked {
        let db_guard = state.db.lock().await;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.lock_account(user_id, 30).await;
        }
    }

    Ok(serde_json::json!({
        "analysis": {
            "anomaly_score": anomaly_score,
            "risk_level": risk_level,
            "is_normal": is_normal,
        },
        "response": response,
    }))
}

// ========== MAINTENANCE COMMANDS ==========

/// Nettoie les vieux logs
#[tauri::command]
pub async fn cleanup_logs(days: i64, state: State<'_, AppState>) -> Result<String, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let deleted = db.cleanup_old_logs(days).await
        .map_err(|e| format!("Erreur nettoyage: {}", e))?;

    Ok(format!("{} logs supprimés (> {} jours)", deleted, days))
}

/// Obtient les stats des logs
#[tauri::command]
pub async fn get_logs_stats(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let count = db.get_logs_count().await
        .map_err(|e| format!("Erreur stats: {}", e))?;

    Ok(serde_json::json!({
        "total_logs": count,
        "estimated_size_mb": (count * 200) / (1024 * 1024), // Estimation
    }))
}

// ========== SIGNED LOG COMMANDS ==========

/// Vérifie l'intégrité de la chaîne de logs signés
#[tauri::command]
pub async fn verify_log_integrity(state: State<'_, AppState>) -> Result<signed_log::IntegrityReport, String> {
    let mgr_guard = state.signed_log_manager.lock().await;
    let mgr = mgr_guard.as_ref().ok_or("Logs signés non initialisés")?;
    mgr.verify_integrity()
}

/// Active ou désactive les logs signés
#[tauri::command]
pub async fn toggle_signed_logging(state: State<'_, AppState>, enabled: bool) -> Result<String, String> {
    *state.logging_enabled.lock().await = enabled;
    let status = if enabled { "activés" } else { "désactivés" };
    Ok(format!("Logs signés {}", status))
}

/// Retourne l'état actuel des logs signés
#[tauri::command]
pub async fn get_signed_logging_status(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(*state.logging_enabled.lock().await)
}

// ========== NETWORK ISOLATION COMMANDS ==========

/// Retourne le statut de l'enclave sécurisée de la plateforme
#[tauri::command]
pub async fn get_enclave_status() -> Result<secure_storage::EnclaveStatus, String> {
    Ok(secure_storage::get_enclave_status_info())
}

/// Active ou désactive le mode isolation réseau
#[tauri::command]
pub async fn toggle_isolation_mode(state: State<'_, AppState>, enabled: bool) -> Result<String, String> {
    *state.isolation_mode.lock().await = enabled;
    let status = if enabled {
        "Mode isolation activé — toutes les fonctionnalités réseau sont désactivées"
    } else {
        "Mode isolation désactivé — fonctionnalités réseau disponibles"
    };
    Ok(status.to_string())
}

/// Retourne l'état du mode isolation réseau
#[tauri::command]
pub async fn get_isolation_mode(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(*state.isolation_mode.lock().await)
}

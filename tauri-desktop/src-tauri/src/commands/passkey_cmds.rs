use crate::{AppState, LoginResponse};
use crate::generate_session_token;
use crate::crypto::decrypt_data_secure;
use crate::secure_storage::store_encryption_key;
use crate::passkey;
use tauri::State;

// ========== PASSKEY COMMANDS ==========

/// Check passkey availability and enrollment status.
/// Unlike biometric, there is NO gate — passkey is always available if enrolled.
#[tauri::command]
pub async fn check_passkey() -> Result<passkey::PasskeyStatus, String> {
    Ok(passkey::check_passkey_status())
}

/// Register a new passkey for the current user.
/// Requires an active session (user must be logged in with password first).
#[tauri::command]
pub async fn register_passkey(state: State<'_, AppState>) -> Result<String, String> {
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié — session requise pour enregistrer une passkey")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let user = db.get_user_by_id(user_id).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur introuvable")?;

    // Retrieve current encryption key from session cache
    let secure_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    let key_vec = secure_key.to_vec();

    // Register the passkey (generates Ed25519 + ML-KEM-768, wraps master_key)
    let key_b64_opt = passkey::register_passkey(user_id, &user.username, &key_vec)?;

    let _ = db.log_action(user_id, "PASSKEY_REGISTERED", "security", None).await;

    // On Android, return the key so the frontend can store it in Android Keystore
    match key_b64_opt {
        Some(key_b64) => {
            let response = serde_json::json!({
                "message": "Passkey enregistrée avec succès",
                "key_b64": key_b64
            });
            Ok(response.to_string())
        }
        None => Ok("Passkey enregistrée avec succès".to_string()),
    }
}

/// Login using passkey authentication.
/// Always-on: no cold start, no timeout. The only restriction is the 14-day
/// password reminder, which is enforced by the frontend (not blocked here).
#[tauri::command]
pub async fn passkey_login(
    username: String,
    android_key: Option<String>,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("Nom d'utilisateur requis pour la connexion passkey.".to_string());
    }

    // 1. Authenticate with passkey (challenge-response + double-unwrap master_key)
    let (user_id, enrolled_username, key_bytes) = passkey::authenticate_passkey(&username, android_key)?;

    // 2. Verify user still exists in database
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let user = db.get_user_by_username(&enrolled_username).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur introuvable. Passkey désactivée.")?;

    if user.id != user_id {
        passkey::delete_passkey()?;
        return Err("Incohérence de compte détectée. Passkey désactivée.".to_string());
    }

    // 3. Check if account is locked
    if user.account_locked {
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: "Compte verrouillé".to_string(),
            user_id: None,
            email: None,
        });
    }

    // 4. Store encryption key in session keychain
    store_encryption_key(user_id, &key_bytes)
        .map_err(|e| format!("Erreur stockage clé: {}", e))?;

    debug_log!("🔐 Passkey login: clé restaurée dans l'enclave pour user {}", user_id);

    // 4b. Wrap key_bytes in SecureKey for trust store unlock
    let encryption_key = crate::secure_key::SecureKey::from_slice(&key_bytes);

    // 5. Set up session
    *state.current_user_id.lock().await = Some(user.id);
    // Also notify biometric module so biometric quick-unlock becomes available
    crate::biometric::notify_password_login_success();
    let token = generate_session_token();
    *state.session_token.lock().await = Some(token.clone());

    // 5b. Populate vault key cache
    if state.cache_enabled {
        state.vault_key_cache.lock().await.store(user.id, &key_bytes);
    }

    // 5c. Unlock trust store and start mDNS discovery
    if let Some(tm) = state.transfer_manager.lock().await.as_mut() {
        tm.set_peer_name(&user.username);
        if let Err(e) = tm.trust_store.lock().await.unlock(&encryption_key) {
            debug_log!("⚠️  Trust store unlock failed (passkey): {}", e);
        } else {
            debug_log!("🔒 Trust store déverrouillé via passkey (ChaCha20-Poly1305)");
        }
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[TRANSFER] Auto-start mDNS failed at passkey login: {}", e);
        }
    }

    let _ = db.log_action(user.id, "PASSKEY_LOGIN", "session", None).await;

    Ok(LoginResponse {
        success: true,
        token: Some(token),
        message: enrolled_username,
        user_id: Some(user.id),
        // VULN-004: Déchiffrer l'email chiffré en base
        email: decrypt_data_secure(&user.email, &encryption_key).ok()
            .or(Some(user.email.clone())),
    })
}

/// Re-authenticate using passkey for sensitive operations (CSV import/export, backup, etc.).
/// Returns the vault key on success (same as authenticate_for_csv_op biometric path).
#[tauri::command]
pub async fn passkey_authenticate(
    android_key: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié — session requise")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let user = db.get_user_by_id(user_id).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur introuvable")?;

    // Authenticate with passkey
    let (pk_user_id, _, key_bytes) = passkey::authenticate_passkey(&user.username, android_key)?;

    // Verify identity matches current session
    if pk_user_id != user_id {
        return Err(
            "Incohérence d'identité — le compte passkey ne correspond pas à la session".to_string()
        );
    }

    // Store key in session cache for the operation that follows
    store_encryption_key(user_id, &key_bytes)
        .map_err(|e| format!("Erreur stockage clé: {}", e))?;

    if state.cache_enabled {
        state.vault_key_cache.lock().await.store(user_id, &key_bytes);
    }

    Ok("Authentification passkey réussie".to_string())
}

/// Delete the passkey enrollment and associated keys.
#[tauri::command]
pub async fn delete_passkey(state: State<'_, AppState>) -> Result<String, String> {
    passkey::delete_passkey()?;

    if let Some(user_id) = *state.current_user_id.lock().await {
        let db_guard = state.db.lock().await;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_action(user_id, "PASSKEY_DELETED", "security", None).await;
        }
    }

    Ok("Passkey supprimée".to_string())
}

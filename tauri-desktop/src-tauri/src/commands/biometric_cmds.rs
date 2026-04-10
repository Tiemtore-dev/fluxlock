use crate::{AppState, LoginResponse};
use crate::generate_session_token;
use crate::crypto::decrypt_data_secure;
use crate::secure_storage::store_encryption_key;
use crate::biometric;
use tauri::State;

// ========== BIOMETRIC COMMANDS ==========

/// Check biometric hardware availability and enrollment status
#[tauri::command]
pub async fn check_biometric() -> Result<biometric::BiometricStatus, String> {
    Ok(biometric::check_biometric_status())
}

/// Enable biometric authentication for the current user.
/// On desktop: returns a success message (key stored in OS keychain).
/// On Android: returns JSON `{"message":"...","key_b64":"..."}` so the frontend
/// can store the key in Android Keystore (TEE/StrongBox).
#[tauri::command]
pub async fn enable_biometric(state: State<'_, AppState>) -> Result<String, String> {
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let user = db.get_user_by_id(user_id).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur introuvable")?;

    // Retrieve current encryption key from session cache (XOR-masked, TTL 3min)
    let secure_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Enable biometric (prompts Touch ID, stores key in biometric keychain on desktop)
    let key_vec = secure_key.to_vec();
    let key_b64_opt = biometric::enable_biometric(user_id, &user.username, &key_vec)?;

    let _ = db.log_action(user_id, "BIOMETRIC_ENABLED", "security", None).await;

    // On Android, return the key so the frontend can store it in Android Keystore
    match key_b64_opt {
        Some(key_b64) => {
            let response = serde_json::json!({
                "message": "Biométrie activée avec succès",
                "key_b64": key_b64
            });
            Ok(response.to_string())
        }
        None => Ok("Biométrie activée avec succès".to_string()),
    }
}

/// Disable biometric authentication
#[tauri::command]
pub async fn disable_biometric(state: State<'_, AppState>) -> Result<String, String> {
    biometric::disable_biometric()?;

    if let Some(user_id) = *state.current_user_id.lock().await {
        let db_guard = state.db.lock().await;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_action(user_id, "BIOMETRIC_DISABLED", "security", None).await;
        }
    }

    Ok("Biométrie désactivée".to_string())
}

/// Login using biometric authentication (Touch ID / Face ID / Windows Hello)
/// Requires the username to be provided — biometric never bypasses user identification.
#[tauri::command]
pub async fn biometric_login(username: String, state: State<'_, AppState>) -> Result<LoginResponse, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("Nom d'utilisateur requis pour la connexion biométrique.".to_string());
    }

    // 1. Biometric authenticate and retrieve stored credentials for this username
    let (user_id, enrolled_username, key_bytes) = biometric::biometric_login(&username)?;

    // 2. Verify user still exists in database
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let user = db.get_user_by_username(&enrolled_username).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur introuvable. Biométrie désactivée.")?;

    if user.id != user_id {
        biometric::disable_biometric()?;
        return Err("Incohérence de compte détectée. Biométrie désactivée.".to_string());
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

    debug_log!("🔐 Biometric login: clé restaurée dans l'enclave pour user {}", user_id);

    // 4b. Wrap key_bytes in SecureKey for trust store unlock + mDNS auto-start
    let encryption_key = crate::secure_key::SecureKey::from_slice(&key_bytes);

    // 5. Set up session — also refresh the biometric timer
    *state.current_user_id.lock().await = Some(user.id);
    biometric::notify_password_login_success();
    let token = generate_session_token();
    *state.session_token.lock().await = Some(token.clone());

    // 5b. Unlock trust store and start mDNS discovery (same as local_login)
    if let Some(tm) = state.transfer_manager.lock().await.as_mut() {
        tm.set_peer_name(&user.username);
        if let Err(e) = tm.trust_store.lock().await.unlock(&encryption_key) {
            debug_log!("⚠️  Trust store unlock failed (biometric): {}", e);
        } else {
            debug_log!("🔒 Trust store déverrouillé via biometric (ChaCha20-Poly1305)");
        }
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[TRANSFER] Auto-start mDNS failed at biometric login: {}", e);
        }
    }

    let _ = db.log_action(user.id, "BIOMETRIC_LOGIN", "session", None).await;

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

/// Login using biometric for Android — the frontend already retrieved the key
/// from Android Keystore (TEE/StrongBox) via BiometricPrompt + CryptoObject.
/// This command skips the OS keychain read (key is provided directly) but
/// still enforces the biometric gate (cold start, timeout, emergency lock).
#[tauri::command]
pub async fn biometric_login_with_key(
    username: String,
    key_b64: String,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("Nom d'utilisateur requis pour la connexion biométrique.".to_string());
    }
    if key_b64.is_empty() {
        return Err("Clé de chiffrement requise.".to_string());
    }

    // 1. Biometric gate + enrollment check (no platform auth — already done by Android Keystore)
    let (user_id, enrolled_username, key_bytes) = biometric::biometric_login_with_key(&username, &key_b64)?;

    // 2. Verify user still exists in database
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let user = db.get_user_by_username(&enrolled_username).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur introuvable. Biométrie désactivée.")?;

    if user.id != user_id {
        biometric::disable_biometric()?;
        return Err("Incohérence de compte détectée. Biométrie désactivée.".to_string());
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

    debug_log!("🔐 Biometric login (Android Keystore): clé restaurée pour user {}", user_id);

    // 4b. Wrap key_bytes in SecureKey for trust store unlock + mDNS auto-start
    let encryption_key = crate::secure_key::SecureKey::from_slice(&key_bytes);

    // 5. Set up session — also refresh the biometric timer
    *state.current_user_id.lock().await = Some(user.id);
    biometric::notify_password_login_success();
    let token = generate_session_token();
    *state.session_token.lock().await = Some(token.clone());

    // 5b. Unlock trust store and start mDNS discovery
    if let Some(tm) = state.transfer_manager.lock().await.as_mut() {
        tm.set_peer_name(&user.username);
        if let Err(e) = tm.trust_store.lock().await.unlock(&encryption_key) {
            debug_log!("⚠️  Trust store unlock failed (biometric android): {}", e);
        } else {
            debug_log!("🔒 Trust store déverrouillé via biometric Android Keystore (ChaCha20-Poly1305)");
        }
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[TRANSFER] Auto-start mDNS failed at biometric android login: {}", e);
        }
    }

    let _ = db.log_action(user.id, "BIOMETRIC_LOGIN_ANDROID_KEYSTORE", "session", None).await;

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

/// Emergency lock — instantly disable biometric until next password login
#[tauri::command]
pub async fn biometric_emergency_lock(state: State<'_, AppState>) -> Result<String, String> {
    biometric::emergency_lock();

    if let Some(user_id) = *state.current_user_id.lock().await {
        let db_guard = state.db.lock().await;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_action(user_id, "BIOMETRIC_EMERGENCY_LOCK", "security", None).await;
        }
    }

    Ok("Verrouillage d'urgence activé".to_string())
}

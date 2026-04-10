use crate::{AppState, LoginResponse};
use crate::generate_session_token;
use crate::crypto::{encrypt_data_secure, decrypt_data_secure, verify_password};
use crate::security_monitor::get_security_monitor;
use crate::totp::{generate_totp_secret, verify_totp_code, verify_backup_code};
use serde::{Deserialize, Serialize};
use tauri::State;

// ========== 2FA COMMANDS ==========

#[derive(Debug, Serialize, Deserialize)]
pub struct Enable2FAResponse {
    pub success: bool,
    pub secret: String,
    pub qr_code: String,
    pub backup_codes: Vec<String>,
    pub message: String,
}

/// Génère un secret TOTP et QR code pour activer 2FA
#[tauri::command]
pub async fn setup_2fa(state: State<'_, AppState>) -> Result<Enable2FAResponse, String> {
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer l'utilisateur
    let user = db.get_user_by_id(user_id).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur non trouvé")?;

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    // Déchiffrer l'email pour le QR code TOTP
    let decrypted_email = decrypt_data_secure(&user.email, &encryption_key)
        .unwrap_or_else(|_| user.email.clone());

    // Générer le secret TOTP
    let setup = generate_totp_secret(&decrypted_email, "SecureVault")
        .map_err(|e| format!("Erreur génération TOTP: {}", e))?;

    Ok(Enable2FAResponse {
        success: true,
        secret: setup.secret,
        qr_code: setup.qr_code_base64,
        backup_codes: setup.backup_codes.clone(),
        message: "Scannez le QR code avec votre application d'authentification".to_string(),
    })
}

/// Vérifie un code TOTP et active 2FA
#[tauri::command]
pub async fn verify_and_enable_2fa(
    code: String,
    secret: String,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié")?;

    // Vérifier le code
    let verified = verify_totp_code(&secret, &code)
        .map_err(|e| format!("Erreur vérification: {}", e))?;

    if !verified {
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: "Code TOTP invalide".to_string(),
            user_id: None,
            email: None,
        });
    }

    // Générer les backup codes
    let setup = generate_totp_secret("temp@temp.com", "SecureVault")
        .map_err(|e| format!("Erreur génération: {}", e))?;
    let backup_codes_json = serde_json::to_string(&setup.backup_codes)
        .map_err(|e| format!("Erreur sérialisation: {}", e))?;

    // Chiffrer le secret TOTP et les backup codes avant stockage en DB
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    let encrypted_secret = encrypt_data_secure(&secret, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement secret TOTP: {}", e))?;
    let encrypted_backup_codes = encrypt_data_secure(&backup_codes_json, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement backup codes: {}", e))?;

    // Activer 2FA dans la DB (données chiffrées)
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    
    db.enable_2fa(user_id, &encrypted_secret, &encrypted_backup_codes).await
        .map_err(|e| format!("Erreur DB: {}", e))?;

    debug_log!("✅ 2FA activé pour l'utilisateur {}", user_id);

    Ok(LoginResponse {
        success: true,
        token: Some("2fa_enabled".to_string()),
        message: "2FA activé avec succès".to_string(),
        user_id: Some(user_id),
        email: None,
    })
}

/// Désactive 2FA
#[tauri::command]
pub async fn disable_2fa(
    password: String,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Vérifier le mot de passe
    let user = db.get_user_by_id(user_id).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur non trouvé")?;

    if verify_password(&password, &user.password_hash).is_err() {
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: "Mot de passe incorrect".to_string(),
            user_id: None,
            email: None,
        });
    }

    // Désactiver 2FA
    db.disable_2fa(user_id).await
        .map_err(|e| format!("Erreur DB: {}", e))?;

    #[cfg(debug_assertions)]
    debug_log!("❌ 2FA désactivé pour l'utilisateur {}", user_id);

    Ok(LoginResponse {
        success: true,
        token: None,
        message: "2FA désactivé".to_string(),
        user_id: Some(user_id),
        email: None,
    })
}

/// Vérifie un code 2FA lors du login
#[tauri::command]
pub async fn verify_2fa_login(
    username: String,
    code: String,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let user = db.get_user_by_username(&username).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur non trouvé")?;

    // Vérifier si le compte est bloqué
    let is_locked = db.check_account_locked(user.id).await
        .map_err(|e| format!("Erreur DB: {}", e))?;

    if is_locked {
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: "Compte temporairement bloqué pour raisons de sécurité".to_string(),
            user_id: None,
            email: None,
        });
    }

    // VULN-010: Rate limiting sur les tentatives 2FA (mêmes compteurs anti-brute-force)
    let monitor = get_security_monitor();
    if let Some(remaining) = monitor.is_user_locked(&username).await {
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: format!("Trop de tentatives 2FA. Réessayez dans {} secondes.", remaining),
            user_id: None,
            email: None,
        });
    }

    if let Some(encrypted_secret) = user.totp_secret {
        // Déchiffrer le secret TOTP depuis la DB
        let encryption_key = crate::get_or_fetch_vault_key(&state, user.id).await?;
        let secret = decrypt_data_secure(&encrypted_secret, &encryption_key)
            .map_err(|e| format!("Erreur déchiffrement secret TOTP: {}", e))?;

        // Vérifier le code TOTP
        let verified = verify_totp_code(&secret, &code)
            .map_err(|e| format!("Erreur vérification: {}", e))?;

        if verified {
            // Authentifié avec succès
            *state.current_user_id.lock().await = Some(user.id);
            
            // EXP-002 fix: token cryptographiquement aléatoire
            let session_token = generate_session_token();
            *state.session_token.lock().await = Some(session_token.clone());
            
            debug_log!("✅ 2FA vérifié pour {}", username);

            return Ok(LoginResponse {
                success: true,
                token: Some(session_token),
                message: "Authentification 2FA réussie".to_string(),
                user_id: Some(user.id),
                // VULN-004: Déchiffrer l'email
                email: decrypt_data_secure(&user.email, &encryption_key).ok()
                    .or(Some(user.email.clone())),
            });
        }

        // Si code invalide, essayer backup code
        if let Some(encrypted_backup_codes) = user.backup_codes {
            let backup_codes = decrypt_data_secure(&encrypted_backup_codes, &encryption_key)
                .map_err(|e| format!("Erreur déchiffrement backup codes: {}", e))?;
            let (verified, remaining_codes) = verify_backup_code(&backup_codes, &code)
                .map_err(|e| format!("Erreur backup code: {}", e))?;

            if verified {
                // Rechiffrer et mettre à jour les backup codes restants
                let new_codes = serde_json::to_string(&remaining_codes)
                    .map_err(|e| format!("Erreur sérialisation: {}", e))?;
                let encrypted_new_codes = encrypt_data_secure(&new_codes, &encryption_key)
                    .map_err(|e| format!("Erreur chiffrement backup codes: {}", e))?;
                db.update_backup_codes(user.id, &encrypted_new_codes).await
                    .map_err(|e| format!("Erreur DB: {}", e))?;

                *state.current_user_id.lock().await = Some(user.id);

                // EXP-002 fix: token cryptographiquement aléatoire
                let session_token = generate_session_token();
                *state.session_token.lock().await = Some(session_token.clone());

                debug_log!("✅ Backup code utilisé pour {}", username);

                return Ok(LoginResponse {
                    success: true,
                    token: Some(session_token),
                    message: format!("Backup code accepté. {} codes restants", remaining_codes.len()),
                    user_id: Some(user.id),
                    // VULN-004: Déchiffrer l'email
                    email: decrypt_data_secure(&user.email, &encryption_key).ok()
                        .or(Some(user.email.clone())),
                });
            }
        }
    }

    // VULN-010: Enregistrer l'échec 2FA pour le rate limiting
    monitor.record_failed_attempt(&username).await;
    let _ = db.log_action(user.id, "2FA_FAILED", "auth", None).await;

    Ok(LoginResponse {
        success: false,
        token: None,
        message: "Code 2FA invalide".to_string(),
        user_id: None,
        email: None,
    })
}

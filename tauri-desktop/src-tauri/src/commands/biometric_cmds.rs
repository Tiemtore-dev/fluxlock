use crate::{AppState, LoginResponse};
use crate::generate_session_token;
use crate::crypto::{decrypt_data_secure, verify_password};
use crate::database::User;
use crate::secure_key::SecureKey;
use crate::biometric;
use std::path::PathBuf;
use tauri::State;

// ========== BIOMETRIC COMMANDS ==========

pub(super) async fn biometric_dir(state: &AppState) -> Result<PathBuf, String> {
    state.data_dir.lock().await.clone().ok_or_else(|| "Coffre non initialisé".into())
}

/// Check biometric hardware availability and enrollment status
#[tauri::command]
pub async fn check_biometric(state: State<'_, AppState>) -> Result<biometric::BiometricStatus, String> {
    Ok(biometric::check_biometric_status(&biometric_dir(&state).await?))
}

/// Enable biometric authentication for the current user.
/// On desktop: returns a success message (key stored in OS keychain).
/// On Android: returns JSON `{"message":"...","key_b64":"..."}` so the frontend
/// can store the key in Android Keystore (TEE/StrongBox).
#[tauri::command]
pub async fn enable_biometric(password: String, state: State<'_, AppState>) -> Result<String, String> {
    let _lifecycle = state.auth_lifecycle.lock().await;
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let user = db.get_user_by_id(user_id).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur introuvable")?;

    verify_password(&password, &user.password_hash).map_err(|_| "Mot de passe incorrect")?;

    // Retrieve current encryption key from session cache (XOR-masked, TTL 3min)
    let secure_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    validate_enrolled_key(&user, user_id, &secure_key)?;

    // Enable biometric (prompts Touch ID, stores key in biometric keychain on desktop)
    let key_vec = secure_key.to_vec();
    let key_b64_opt = biometric::enable_biometric(&biometric_dir(&state).await?, user_id, &user.username, &key_vec)?;

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
    let _lifecycle = state.auth_lifecycle.lock().await;
    let user_id = crate::validate_session(&state).await?;
    biometric::disable_biometric(&biometric_dir(&state).await?)?;

    {
        let db_guard = state.db.lock().await;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_action(user_id, "BIOMETRIC_DISABLED", "security", None).await;
        }
    }

    Ok("Biométrie désactivée".to_string())
}

/// Déverrouille l’unique compte via l’authentification native de l’appareil.
#[tauri::command]
pub async fn biometric_login(state: State<'_, AppState>) -> Result<LoginResponse, String> {
    #[cfg(target_os = "android")]
    {
        let _ = state;
        Err("Utilisez le capteur biométrique Android.".into())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _lifecycle = state.auth_lifecycle.lock().await;
        let db_guard = state.db.lock().await;
        let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
        let user = available_owner(db).await?;
        let (id, _, key) = biometric::biometric_login(&biometric_dir(&state).await?, &user.username)?;
        finish_biometric_login(&state, db, user, id, SecureKey::new(key)).await
    }
}

/// Sur Android, le CryptoObject du BiometricPrompt déchiffre la clé enrôlée.
#[tauri::command]
pub async fn biometric_login_with_key(
    key_b64: String,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    let _lifecycle = state.auth_lifecycle.lock().await;
    #[cfg(not(target_os = "android"))]
    {
        let _key = zeroize::Zeroizing::new(key_b64);
        Err("Cette commande est réservée à Android".into())
    }

    #[cfg(target_os = "android")]
    {
        let key_b64 = zeroize::Zeroizing::new(key_b64);
        if key_b64.len() != 44 {
            return Err("Clé biométrique invalide".into());
        }
        let db_guard = state.db.lock().await;
        let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
        let user = available_owner(db).await?;
        let (id, _, key) = biometric::biometric_login_with_key(&biometric_dir(&state).await?, &user.username, &key_b64)?;
        finish_biometric_login(&state, db, user, id, SecureKey::new(key)).await
    }
}

async fn available_owner(db: &crate::database::Database) -> Result<User, String> {
    let user = db.get_vault_owner().await.map_err(|e| e.to_string())?
        .ok_or("Aucun compte n’est configuré sur cet appareil")?;
    if db.check_account_locked(user.id).await.map_err(|e| e.to_string())? {
        return Err("Compte verrouillé".into());
    }
    if super::auth::login_delay(db, &user).await? > 0 {
        return Err("Trop de tentatives. Réessayez après le délai indiqué.".into());
    }
    Ok(user)
}

fn validate_enrolled_key(user: &User, enrolled_id: i64, key: &SecureKey) -> Result<String, String> {
    if enrolled_id != user.id || key.len() != 32 {
        return Err("Clé biométrique invalide. Utilisez votre mot de passe.".into());
    }

    decrypt_data_secure(&user.email, key)
        .map_err(|_| "Clé biométrique invalide. Utilisez votre mot de passe.".into())
}

async fn finish_biometric_login(
    state: &AppState,
    db: &crate::database::Database,
    user: User,
    enrolled_id: i64,
    key: SecureKey,
) -> Result<LoginResponse, String> {
    let email = validate_enrolled_key(&user, enrolled_id, &key)?;
    crate::store_session_key(state, user.id, &key).await?;
    *state.last_activity.lock().await = std::time::Instant::now();
    let token = generate_session_token();

    if let Some(tm) = state.transfer_manager.lock().await.as_mut() {
        if let Err(error) = tm.trust_store.lock().await.unlock(&key) {
            debug_log!("Échec du déverrouillage des appareils de confiance : {}", error);
        }
    }

    *state.session_token.lock().await = Some(token.clone());
    *state.current_user_id.lock().await = Some(user.id);
    let _ = db.log_action(user.id, "BIOMETRIC_LOGIN", "session", None).await;

    Ok(LoginResponse {
        success: true,
        token: Some(token),
        message: "Coffre déverrouillé".into(),
        user_id: Some(user.id),
        username: Some(user.username),
        email: Some(email),
    })
}

/// Emergency lock — instantly disable biometric until next password login
#[tauri::command]
pub async fn biometric_emergency_lock(state: State<'_, AppState>) -> Result<String, String> {
    let _lifecycle = state.auth_lifecycle.lock().await;
    let user_id = crate::validate_session(&state).await?;
    biometric::emergency_lock(&biometric_dir(&state).await?)?;

    {
        let db_guard = state.db.lock().await;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.log_action(user_id, "BIOMETRIC_EMERGENCY_LOCK", "security", None).await;
        }
    }

    Ok("Verrouillage d'urgence activé".to_string())
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt_data_secure;

    #[test]
    fn biometric_session_requires_the_enrolled_account_and_its_vault_key() {
        let key = SecureKey::from_slice(&[1; 32]);
        let wrong_key = SecureKey::from_slice(&[2; 32]);
        let user = User {
            id: 1,
            username: "utilisateur".into(),
            email: encrypt_data_secure("test@example.org", &key).unwrap(),
            password_hash: String::new(),
            crypto_salt: String::new(),
            totp_secret: None,
            totp_enabled: false,
            totp_verified_at: None,
            backup_codes: None,
            account_locked: false,
            locked_until: None,
            created_at: String::new(),
        };
        assert_eq!(validate_enrolled_key(&user, 1, &key).unwrap(), "test@example.org");
        assert!(validate_enrolled_key(&user, 2, &key).is_err());
        assert!(validate_enrolled_key(&user, 1, &wrong_key).is_err());
    }
}

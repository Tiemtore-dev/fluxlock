use crate::{AppState, LoginRequest, LoginResponse, RegisterRequest};
use crate::generate_session_token;
use crate::database::Database;
use crate::secure_key::SecureKey;
use crate::crypto::{
    hash_password, verified_argon2_config, derive_key_with_config, CryptoError,
    encrypt_data_secure, decrypt_data_secure,
    generate_salt, derive_encryption_key_from_password_secure,
};
use crate::store_session_key;
use crate::security_monitor::get_security_monitor;
use crate::{biometric, hidden_storage};
use tauri::State;
use base64::{Engine as _, engine::general_purpose};

#[tauri::command]
pub fn get_app_version() -> String {
    "2.0.0".to_string()
}

#[tauri::command]
pub async fn check_backend_status() -> Result<String, String> {
    Ok("Backend intégré démarré".to_string())
}

#[tauri::command]
pub async fn init_local_db(
    _app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let _lifecycle = state.auth_lifecycle.write().await;
    if state.vault_catalog.lock().await.is_some() {
        // A webview reload has lost its IPC token: close the orphaned session.
        super::session::lock_session(&state).await;
        return Ok("Coffres déjà initialisés".into());
    }
    #[cfg(target_os = "android")]
    let root = {
        use tauri::Manager;
        _app_handle.path().app_data_dir().map_err(|e| e.to_string())?.join("SecureVault")
    };
    #[cfg(not(target_os = "android"))]
    let root = hidden_storage::get_hidden_database_dir()?;
    crate::vault::initialize(&state, &root).await?;
    Ok("Coffres initialisés".into())
}

// Vérifier si le coffre sélectionné possède un propriétaire.
#[tauri::command]
pub async fn has_existing_user(state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<bool, String> {
    let _lifecycle = state.auth_lifecycle.read().await;
    crate::vault::check_context(&state, &context, false).await?;
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;

    // Compter le nombre d'utilisateurs dans la base
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&db.pool)
        .await
        .map_err(|e| format!("Erreur comptage utilisateurs: {}", e))?;
    
    Ok(count.0 > 0)
}

#[tauri::command]
pub async fn local_register(
    credentials: RegisterRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<LoginResponse, String> {
    let _lifecycle = state.auth_lifecycle.write().await;
    
    crate::vault::check_context(&state, &context, false).await?;
    crate::vault::require_locked(&state).await?;
    register_account(credentials, &state).await
}

pub(crate) async fn register_account(
    credentials: RegisterRequest, state: &AppState,
) -> Result<LoginResponse, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;

    if db.get_vault_owner().await.map_err(|e| e.to_string())?.is_some() {
        return Err("Ce coffre possède déjà un propriétaire".into());
    }

    let password = zeroize::Zeroizing::new(credentials.password);
    let username = credentials.username.trim();
    if username.is_empty() || username.len() > 256 || credentials.email.len() > 320
        || password.chars().count() < 12 || password.len() > 4096
    {
        return Err("Nom d’utilisateur, adresse e-mail ou mot de passe invalide".into());
    }

    // Hasher le mot de passe
    #[cfg(debug_assertions)]
    debug_log!("🔐 Hashage du mot de passe...");
    let password_hash = hash_password(&password)
        .map_err(|e| format!("Erreur de hashage: {}", e))?;
    
    #[cfg(debug_assertions)]
    debug_log!("Vérificateur du mot de passe généré");
    
    // Générer un sel unique pour la dérivation de clé de chiffrement
    let crypto_salt = generate_salt();
    let crypto_salt_b64 = general_purpose::STANDARD.encode(&crypto_salt);
    debug_log!("🔑 Sel crypto généré pour dérivation de clé");

    // Dériver la clé de chiffrement AVANT la création de l'utilisateur
    // pour pouvoir chiffrer l'email (VULN-004)
    let encryption_key = derive_encryption_key_from_password_secure(&password, &crypto_salt)
        .map_err(|e| format!("Erreur dérivation clé: {}", e))?;

    // VULN-004: Chiffrer l'email avant stockage en base
    let encrypted_email = encrypt_data_secure(&credentials.email, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement email: {}", e))?;

    // Créer l'utilisateur avec l'email chiffré
    let user_id = db
        .create_user(username, &encrypted_email, &password_hash, &crypto_salt_b64)
        .await
        .map_err(|e| format!("Erreur création utilisateur: {}", e))?;

    #[cfg(debug_assertions)]
    debug_log!("✅ Utilisateur créé");
    
    store_session_key(&state, user_id, &encryption_key).await?;
    *state.last_activity.lock().await = std::time::Instant::now();

    // Déverrouiller le trust store pour la nouvelle session
    if let Some(tm) = state.transfer_manager.lock().await.as_mut() {
        if let Err(e) = tm.trust_store.lock().await.unlock(&encryption_key) {
            debug_log!("⚠️  Trust store unlock failed (register): {}", e);
        } else {
            debug_log!("🔒 Trust store déverrouillé (register)");
        }
    }

    // Générer et stocker le token de session
    let token = generate_session_token();
    *state.session_token.lock().await = Some(token.clone());
    *state.current_user_id.lock().await = Some(user_id);
    
    // Log l'événement d'inscription
    let _ = db.log_action(user_id, "REGISTER", "user", Some(user_id)).await;

    Ok(LoginResponse {
        success: true,
        token: Some(token),
        message: "Compte créé avec succès".to_string(),
        user_id: Some(user_id),
        username: Some(username.to_owned()),
        email: Some(credentials.email),
    })
}

#[tauri::command]
pub async fn local_login(
    credentials: LoginRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<LoginResponse, String> {
    let _lifecycle = state.auth_lifecycle.write().await;
    unlock(&state, &context, credentials).await
}

pub(crate) async fn unlock(state: &AppState, context: &crate::vault::VaultContext, credentials: LoginRequest) -> Result<LoginResponse, String> {
    let password = zeroize::Zeroizing::new(credentials.password);
    crate::vault::check_context(&state, &context, false).await?;
    crate::vault::require_locked(&state).await?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let user = db.get_vault_owner().await.map_err(|e| e.to_string())?
        .ok_or("Aucun compte n’est configuré sur cet appareil")?;

    let encryption_key = match verify_vault_password(db, &user, &password).await {
        Ok(key) => key,
        Err(message) => return Ok(rejected_login(&message)),
    };

    let email = read_account_email(db, user.id, &user.email, &encryption_key).await?;

    store_session_key(&state, user.id, &encryption_key).await?;
    *state.last_activity.lock().await = std::time::Instant::now();

    // Charger le registre des appareils dans la session locale
    if let Some(tm) = state.transfer_manager.lock().await.as_mut() {
        // Déverrouiller le trust store chiffré avec la vault_key
        if let Err(e) = tm.trust_store.lock().await.unlock(&encryption_key) {
            debug_log!("⚠️  Trust store unlock failed: {}", e);
        } else {
            debug_log!("🔒 Trust store déverrouillé (ChaCha20-Poly1305)");
        }
    }
    
    if let Ok(dir) = super::biometric_cmds::biometric_dir(&state).await {
        if let Err(error) = biometric::notify_password_login_success(&dir) {
            eprintln!("Impossible de réactiver le déverrouillage biométrique : {error}");
        }
    }
    
    // Générer et stocker le token de session
    let token = generate_session_token();
    *state.session_token.lock().await = Some(token.clone());
    *state.current_user_id.lock().await = Some(user.id);
    
    // Log l'événement de connexion
    let _ = db.log_action(user.id, "LOGIN", "session", None).await;

    Ok(LoginResponse {
        success: true,
        token: Some(token),
        message: "Connexion réussie".to_string(),
        user_id: Some(user.id),
        username: Some(user.username),
        // VULN-004: Déchiffrer l'email avant de le renvoyer au frontend
        email: Some(email),
    })
}

/// Authentication shared by manual unlock and the one-shot native autofill route.
/// This helper never publishes a session token or a vault key to a webview.
pub(crate) async fn verify_vault_password(db: &Database, user: &crate::database::User, password: &str) -> Result<SecureKey, String> {
    if db.check_account_locked(user.id).await.map_err(|e|e.to_string())? { return Err("Compte verrouillé".into()); }
    let delay = login_delay(db, user).await?;
    if delay > 0 { return Err(format!("Trop de tentatives. Réessayez dans {delay} secondes.")); }
    if password.is_empty() || password.len()>4096 { return Err("Mot de passe incorrect".into()); }
    let config = match verified_argon2_config(password, &user.password_hash) {
        Ok(config) => config,
        Err(CryptoError::VerificationError) => {
            db.log_action(user.id, "login_failed", "auth", None).await.map_err(|e|e.to_string())?;
            return Err("Mot de passe incorrect".into());
        },
        Err(_) => return Err("Vérification du coffre impossible".into()),
    };
    let salt = general_purpose::STANDARD.decode(&user.crypto_salt).map_err(|_|"Sel du coffre invalide")?;
    let key = derive_key_with_config(password, &salt, &config).map_err(|_|"Dérivation du coffre impossible")?;
    read_account_email(db, user.id, &user.email, &key).await?;
    db.clear_failed_logins(user.id).await.map_err(|e|e.to_string())?;
    Ok(key)
}

fn rejected_login(message: &str) -> LoginResponse {
    LoginResponse {
        success: false,
        token: None,
        message: message.to_owned(),
        user_id: None,
        username: None,
        email: None,
    }
}

pub(crate) async fn login_delay(db: &Database, user: &crate::database::User) -> Result<u64, String> {
    if let Some(seconds) = get_security_monitor().is_user_locked(&user.username).await {
        return Ok(seconds);
    }
    let count = db.count_failed_logins(user.id, 2).await.map_err(|e| e.to_string())?;
    let delay: i64 = match count {
        0..=2 => return Ok(0),
        3..=4 => 15,
        5..=7 => 30,
        8..=10 => 60,
        _ => 120,
    };
    let elapsed = db.get_time_since_last_failed_login(user.id).await
        .map_err(|e| e.to_string())?.unwrap_or_default().max(0);
    Ok(delay.saturating_sub(elapsed).max(0) as u64)
}

/// Called only after verifying the password and deriving the account's vault key.
async fn read_account_email(db: &Database, id: i64, stored: &str, key: &SecureKey) -> Result<String, String> {
    if let Ok(email) = decrypt_data_secure(stored, key) {
        return Ok(email);
    }
    if stored.starts_with("v2:") {
        return Err("Le coffre ne peut pas être déchiffré avec le profil de la sauvegarde".into());
    }

    // Historical accounts could store this address in plain text. Authenticate it
    // with the recovered vault key so biometric unlock can validate that key later.
    let is_plain_email = stored.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && !domain.is_empty() && !stored.chars().any(char::is_whitespace)
    });
    if is_plain_email || stored.is_empty() {
        let encrypted = encrypt_data_secure(stored, key).map_err(|e| e.to_string())?;
        sqlx::query("UPDATE users SET email = ? WHERE id = ? AND email = ?")
            .bind(encrypted).bind(id).bind(stored)
            .execute(&db.pool).await.map_err(|e| e.to_string())?;
    }
    Ok(stored.to_owned())
}

#[cfg(test)]
mod biometric_compatibility_tests {
    use super::*;

    #[tokio::test]
    async fn password_unlock_authenticates_the_legacy_plaintext_email() {
        let files = tempfile::tempdir().unwrap();
        let db = Database::new(&files.path().join("vault.db")).await.unwrap();
        db.initialize().await.unwrap();
        let email = "coffre@example.org";
        let id = db.create_user("compte", email, "hash", "salt").await.unwrap();
        let key = SecureKey::from_slice(&[1; 32]);
        let wrong_key = SecureKey::from_slice(&[2; 32]);

        assert_eq!(read_account_email(&db, id, email, &key).await.unwrap(), email);
        let stored = db.get_user_by_id(id).await.unwrap().unwrap().email;
        assert_eq!(decrypt_data_secure(&stored, &key).unwrap(), email);
        assert!(read_account_email(&db, id, &stored, &wrong_key).await.is_err());
        assert_eq!(db.get_user_by_id(id).await.unwrap().unwrap().email, stored);
    }
}

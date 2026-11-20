use crate::{AppState, LoginRequest, LoginResponse, RegisterRequest};
use crate::{generate_session_token, init_signed_log_manager};
use crate::database::Database;
use crate::secure_key::SecureKey;
use crate::crypto::{
    hash_password, verified_argon2_config, derive_key_with_config, CryptoError,
    encrypt_data_secure, decrypt_data_secure,
    generate_salt, derive_encryption_key_from_password_secure,
};
use crate::store_session_key;
use crate::security_monitor::get_security_monitor;
use crate::{biometric, hidden_storage, transfer};
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
    static INIT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _init = INIT_LOCK.lock().await;
    if state.db.lock().await.is_some() {
        return Ok("Base de données déjà initialisée".into());
    }

    // Android: utiliser app_data_dir() de Tauri (seul chemin writable garanti)
    // Desktop: utiliser hidden_storage pour rétrocompatibilité
    #[cfg(target_os = "android")]
    let db_dir = {
        use tauri::Manager;
        let dir = _app_handle.path().app_data_dir()
            .map_err(|e| format!("Erreur obtention répertoire Android: {}", e))?;
        let sv_dir = dir.join("SecureVault");
        std::fs::create_dir_all(&sv_dir)
            .map_err(|e| format!("Erreur création répertoire Android: {}", e))?;
        sv_dir
    };
    #[cfg(not(target_os = "android"))]
    let db_dir = hidden_storage::get_hidden_database_dir()
        .map_err(|e| format!("Erreur obtention chemin DB caché: {}", e))?;

    let db_path = db_dir.join("sv.db");

    // Stocker le répertoire de données dans AppState pour reset_vault
    *state.data_dir.lock().await = Some(db_dir.clone());
    
    // Create an empty file if it doesn't exist to ensure we have write permissions
    if !db_path.exists() {
        std::fs::File::create(&db_path)
            .map_err(|e| format!("Impossible de créer le fichier DB (permissions?): {}", e))?;
    }

    let db = Database::new(&db_path)
        .await
        .map_err(|e| format!("Erreur création database: {}", e))?;

    db.initialize()
        .await
        .map_err(|e| format!("Erreur initialisation database: {}", e))?;

    #[cfg(target_os = "macos")]
    match db.get_vault_owner().await {
        Ok(Some(owner)) => crate::secure_storage::remove_legacy_macos_session_key(owner.id),
        Ok(None) => {}
        Err(error) => debug_log!("Impossible de vérifier l’ancienne clé de session macOS : {error}"),
    }

    *state.db.lock().await = Some(db);
    
    // Initialiser le Transfer Manager
    let app_data_dir = db_dir.clone();
    let peer_name = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "FluXlock".to_string());
    match transfer::commands::TransferManager::new(&app_data_dir, &peer_name) {
        Ok(tm) => {
            *state.transfer_manager.lock().await = Some(tm);
            debug_log!("🔀 Transfer Manager initialisé");
        }
        Err(_e) => {
            debug_log!("⚠️  Transfer Manager non disponible: {}", _e);
        }
    }

    // Initialiser le gestionnaire de logs signés
    match init_signed_log_manager(&state).await {
        Ok(_) => {
            debug_log!("📝 Logs signés initialisés (hash chain SHA3-256 + ML-DSA-65)");
        }
        Err(_e) => {
            debug_log!("⚠️  Logs signés non disponibles: {}", _e);
        }
    }

    // Note: La clé de chiffrement sera dérivée lors de la connexion
    // depuis le mot de passe utilisateur, pas générée aléatoirement
    debug_log!("✅ Base de données initialisée (clé de chiffrement sera dérivée à la connexion)");

    Ok(format!("Base de données initialisée: {:?}", db_path))
}

// Vérifier si un utilisateur existe déjà (limite: 1 utilisateur par appareil)
#[tauri::command]
pub async fn has_existing_user(state: State<'_, AppState>) -> Result<bool, String> {
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
) -> Result<LoginResponse, String> {
    let _lifecycle = state.auth_lifecycle.lock().await;
    
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;

    if db.get_vault_owner().await.map_err(|e| e.to_string())?.is_some() {
        return Err("Un compte existe déjà sur cet appareil".into());
    }

    let username = credentials.username.trim();
    if username.is_empty() || username.len() > 256 || credentials.email.len() > 320
        || credentials.password.chars().count() < 12 || credentials.password.len() > 4096
    {
        return Err("Nom d’utilisateur, adresse e-mail ou mot de passe invalide".into());
    }

    // Hasher le mot de passe
    #[cfg(debug_assertions)]
    debug_log!("🔐 Hashage du mot de passe...");
    let password_hash = hash_password(&credentials.password)
        .map_err(|e| format!("Erreur de hashage: {}", e))?;
    
    #[cfg(debug_assertions)]
    debug_log!("Vérificateur du mot de passe généré");
    
    // Générer un sel unique pour la dérivation de clé de chiffrement
    let crypto_salt = generate_salt();
    let crypto_salt_b64 = general_purpose::STANDARD.encode(&crypto_salt);
    debug_log!("🔑 Sel crypto généré pour dérivation de clé");

    // Dériver la clé de chiffrement AVANT la création de l'utilisateur
    // pour pouvoir chiffrer l'email (VULN-004)
    let encryption_key = derive_encryption_key_from_password_secure(&credentials.password, &crypto_salt)
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
) -> Result<LoginResponse, String> {
    let _lifecycle = state.auth_lifecycle.lock().await;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let user = db.get_vault_owner().await.map_err(|e| e.to_string())?
        .ok_or("Aucun compte n’est configuré sur cet appareil")?;

    if db.check_account_locked(user.id).await.map_err(|e| e.to_string())? {
        return Ok(rejected_login("Compte verrouillé"));
    }
    let remaining = login_delay(db, &user).await?;
    if remaining > 0 {
        return Ok(rejected_login(&format!("Trop de tentatives. Réessayez dans {remaining} secondes.")));
    }

    if credentials.password.is_empty() || credentials.password.len() > 4096 {
        return Ok(rejected_login("Mot de passe incorrect"));
    }

    // Vérifier le mot de passe
    #[cfg(debug_assertions)]
    debug_log!("🔐 Vérification du mot de passe (hash length: {})", user.password_hash.len());
    let config = match verified_argon2_config(&credentials.password, &user.password_hash) {
        Ok(config) => config,
        Err(CryptoError::VerificationError) => {
            debug_log!("❌ Mot de passe incorrect pour l'utilisateur {}", user.id);
            
            db.log_action(user.id, "login_failed", "auth", None).await
                .map_err(|e| format!("Erreur DB: {e}"))?;
            return Ok(rejected_login("Mot de passe incorrect"));
        }
        Err(e) => {
            // Erreur opérationnelle (OOM Argon2, décodage base64, etc.)
            // NE PAS masquer comme "identifiants incorrects"
            eprintln!("🚨 Erreur vérification mot de passe: {}", e);
            return Err(format!("Erreur interne de vérification: {}", e));
        }
    };

    debug_log!("✅ Mot de passe vérifié");
    
    // Nettoyer les anciennes tentatives échouées pour cet utilisateur
    let _ = db.clear_failed_logins(user.id).await;
    #[cfg(debug_assertions)]
    debug_log!("🧹 Tentatives échouées réinitialisées pour l'utilisateur {}", user.id);
    
    // Décoder le sel crypto et dériver la clé de chiffrement (VERSION SÉCURISÉE)
    let crypto_salt = general_purpose::STANDARD
        .decode(&user.crypto_salt)
        .map_err(|e| format!("Erreur décodage sel crypto: {}", e))?;
    
    let encryption_key = derive_key_with_config(&credentials.password, &crypto_salt, &config)
        .map_err(|e| format!("Erreur dérivation clé: {}", e))?;
    
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

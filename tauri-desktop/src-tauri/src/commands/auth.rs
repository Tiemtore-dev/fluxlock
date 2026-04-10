use crate::{AppState, LoginRequest, LoginResponse, RegisterRequest};
use crate::{generate_session_token, init_signed_log_manager};
use crate::database::Database;
use crate::crypto::{
    hash_password, verify_password, CryptoError,
    encrypt_data_secure, decrypt_data_secure,
    generate_salt, derive_encryption_key_from_password_secure,
};
use crate::secure_storage::store_encryption_key;
use crate::security_monitor::get_security_monitor;
use crate::{biometric, hidden_storage, transfer};
use tauri::State;
use base64::{Engine as _, engine::general_purpose};
use std::sync::atomic::{AtomicBool, Ordering};

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
    // Atomic guard against double initialization (frontend may call twice concurrently)
    static DB_INIT_STARTED: AtomicBool = AtomicBool::new(false);
    if DB_INIT_STARTED.swap(true, Ordering::SeqCst) {
        debug_log!("ℹ️ Base de données déjà en cours d'initialisation, skip");
        return Ok("Base de données déjà initialisée".to_string());
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
    debug_log!("📝 Tentative d'enregistrement pour: {}", credentials.username);
    
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;

    // Vérifier si l'utilisateur existe déjà
    if let Ok(Some(_)) = db.get_user_by_username(&credentials.username).await {
        #[cfg(debug_assertions)]
        debug_log!("⚠️  Utilisateur {} existe déjà", credentials.username);
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: "Nom d'utilisateur déjà utilisé".to_string(),
            user_id: None,
            email: None,
        });
    }

    // Hasher le mot de passe
    #[cfg(debug_assertions)]
    debug_log!("🔐 Hashage du mot de passe...");
    let password_hash = hash_password(&credentials.password)
        .map_err(|e| format!("Erreur de hashage: {}", e))?;
    
    #[cfg(debug_assertions)]
    debug_log!("💾 Hash généré (longueur: {})", password_hash.len());
    
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
        .create_user(&credentials.username, &encrypted_email, &password_hash, &crypto_salt_b64)
        .await
        .map_err(|e| format!("Erreur création utilisateur: {}", e))?;

    #[cfg(debug_assertions)]
    debug_log!("✅ Utilisateur créé");
    
    // Stocker la clé dans l'enclave sécurisée (Keychain) au lieu de la RAM
    let result = encryption_key.use_key(|k| {
        store_encryption_key(user_id, k)
            .map_err(|e| format!("Erreur stockage clé sécurisée: {}", e))
    });
    result?;
    
    debug_log!("🔐 Clé de chiffrement stockée dans l'enclave sécurisée (Keychain)");
    *state.current_user_id.lock().await = Some(user_id);

    // Peupler le cache vault sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    if std::env::var("UTILISATION_CACHE").map(|v| v.to_lowercase() != "false").unwrap_or(true) {
        let key_bytes = encryption_key.to_vec();
        state.vault_key_cache.lock().await.store(user_id, &key_bytes);
    }

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
    
    // Log l'événement d'inscription
    let _ = db.log_action(user_id, "REGISTER", "user", Some(user_id)).await;

    Ok(LoginResponse {
        success: true,
        token: Some(token),
        message: "Compte créé avec succès".to_string(),
        user_id: Some(user_id),
        email: Some(credentials.email),
    })
}

#[tauri::command]
pub async fn local_login(
    credentials: LoginRequest,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    debug_log!("🔑 Tentative de connexion pour: {}", credentials.username);
    
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;

    // Récupérer l'utilisateur
    let user = match db.get_user_by_username(&credentials.username).await {
        Ok(Some(u)) => {
            debug_log!("👤 Utilisateur trouvé: {} (ID: {})", u.username, u.id);
            u
        },
        Ok(None) => {
            debug_log!("❌ Aucun utilisateur trouvé avec le nom: {}", credentials.username);
            return Ok(LoginResponse {
                success: false,
                token: None,
                message: "Identifiants incorrects".to_string(),
                user_id: None,
                email: None,
            })
        }
        Err(e) => {
            debug_log!("❌ Erreur DB: {}", e);
            return Err(format!("Erreur base de données: {}", e));
        }
    };

    // Vérifier si l'utilisateur est verrouillé (anti-brute force)
    let monitor = get_security_monitor();
    if let Some(remaining) = monitor.is_user_locked(&credentials.username).await {
        #[cfg(debug_assertions)]
        debug_log!("🔒 Utilisateur verrouillé (brute force) - {} secondes restantes", remaining);
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: format!("Compte temporairement verrouillé. Réessayez dans {} secondes.", remaining),
            user_id: None,
            email: None,
        });
    }

    // Vérifier le délai basé sur les tentatives échouées récentes
    let failed_count = db.count_failed_logins(user.id, 2).await
        .map_err(|e| format!("Erreur DB: {}", e))?;
    
    let delay_seconds = match failed_count {
        0..=2 => 0,
        3..=4 => 15,
        5..=7 => 30,
        8..=10 => 60,
        _ => 120,
    };
    
    if delay_seconds > 0 {
        // Vérifier le temps écoulé depuis la dernière tentative échouée
        if let Ok(Some(elapsed)) = db.get_time_since_last_failed_login(user.id).await {
            if elapsed >= delay_seconds {
                // Le délai est expiré, on peut tester le mot de passe
                debug_log!("✅ Délai expiré ({}s écoulées sur {}s requis) - tentative autorisée", elapsed, delay_seconds);
            } else {
                // Le délai est toujours actif
                let remaining = delay_seconds - elapsed;
                debug_log!("⏱️ Délai actif: {}s restantes sur {}s requis ({} tentatives)", remaining, delay_seconds, failed_count);
                return Ok(LoginResponse {
                    success: false,
                    token: None,
                    message: format!("⏱️ Trop de tentatives échouées. Veuillez patienter {} secondes avant de réessayer.", remaining),
                    user_id: None,
                    email: None,
                });
            }
        } else {
            // Pas de dernière tentative trouvée, mais des échecs comptés - probablement expiré
            debug_log!("⚠️ Échecs comptés mais pas de dernière tentative trouvée - autorisation");
        }
    }

    // Vérifier le mot de passe
    #[cfg(debug_assertions)]
    debug_log!("🔐 Vérification du mot de passe (hash length: {})", user.password_hash.len());
    let password_valid = verify_password(&credentials.password, &user.password_hash);

    match password_valid {
        Ok(()) => { /* mot de passe correct, on continue */ }
        Err(CryptoError::VerificationError) => {
            debug_log!("❌ Mot de passe incorrect pour l'utilisateur {}", user.id);
            
            // Enregistrer la tentative échouée dans audit_logs
            let _ = db.log_action(user.id, "login_failed", "auth", None).await;
            
            return Ok(LoginResponse {
                success: false,
                token: None,
                message: "Identifiants incorrects".to_string(),
                user_id: None,
                email: None,
            });
        }
        Err(e) => {
            // Erreur opérationnelle (OOM Argon2, décodage base64, etc.)
            // NE PAS masquer comme "identifiants incorrects"
            eprintln!("🚨 Erreur vérification mot de passe: {}", e);
            return Err(format!("Erreur interne de vérification: {}", e));
        }
    }

    debug_log!("✅ Mot de passe vérifié");
    
    // Nettoyer les anciennes tentatives échouées pour cet utilisateur
    let _ = db.clear_failed_logins(user.id).await;
    #[cfg(debug_assertions)]
    debug_log!("🧹 Tentatives échouées réinitialisées pour l'utilisateur {}", user.id);
    
    // Décoder le sel crypto et dériver la clé de chiffrement (VERSION SÉCURISÉE)
    let crypto_salt = general_purpose::STANDARD
        .decode(&user.crypto_salt)
        .map_err(|e| format!("Erreur décodage sel crypto: {}", e))?;
    
    let encryption_key = derive_encryption_key_from_password_secure(&credentials.password, &crypto_salt)
        .map_err(|e| format!("Erreur dérivation clé: {}", e))?;
    
    // Stocker la clé dans l'enclave sécurisée (Keychain) pour la session
    let result = encryption_key.use_key(|k| {
        store_encryption_key(user.id, k)
            .map_err(|e| format!("Erreur stockage clé sécurisée: {}", e))
    });
    result?;
    
    debug_log!("🔑 Clé de chiffrement stockée dans l'enclave sécurisée (Keychain)");
    
    debug_log!("✅ Connexion réussie pour {}", user.username);
    *state.current_user_id.lock().await = Some(user.id);

    // Peupler le cache vault sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    if std::env::var("UTILISATION_CACHE").map(|v| v.to_lowercase() != "false").unwrap_or(true) {
        let key_bytes = encryption_key.to_vec();
        state.vault_key_cache.lock().await.store(user.id, &key_bytes);
    }

    // Update transfer peer name with actual username and auto-start mDNS discovery
    if let Some(tm) = state.transfer_manager.lock().await.as_mut() {
        tm.set_peer_name(&user.username);
        // Déverrouiller le trust store chiffré avec la vault_key
        if let Err(e) = tm.trust_store.lock().await.unlock(&encryption_key) {
            debug_log!("⚠️  Trust store unlock failed: {}", e);
        } else {
            debug_log!("🔒 Trust store déverrouillé (ChaCha20-Poly1305)");
        }
        // Auto-start mDNS so this device is discoverable immediately
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[TRANSFER] Auto-start mDNS failed at login: {}", e);
        }
    }
    
    // Notify biometric module that a master-password login succeeded
    // This enables biometric quick-unlock for the configured timeout period
    biometric::notify_password_login_success();
    
    // Générer et stocker le token de session
    let token = generate_session_token();
    *state.session_token.lock().await = Some(token.clone());
    
    // Log l'événement de connexion
    let _ = db.log_action(user.id, "LOGIN", "session", None).await;

    Ok(LoginResponse {
        success: true,
        token: Some(token),
        message: "Connexion réussie".to_string(),
        user_id: Some(user.id),
        // VULN-004: Déchiffrer l'email avant de le renvoyer au frontend
        email: decrypt_data_secure(&user.email, &encryption_key).ok()
            .or(Some(user.email.clone())),
    })
}

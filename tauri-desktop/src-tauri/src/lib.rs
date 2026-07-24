// Macro pour logger uniquement en mode debug
macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    }
}

pub mod database;
pub mod crypto;
mod secure_storage;
mod totp;
mod threat_reactor;
pub mod config;
mod security_monitor;
mod filesystem_monitor;
mod platform_security;
mod hidden_storage;
mod backup_manager;
mod path_validator;
pub mod secure_key;
pub mod transfer;
mod biometric;
mod passkey;
mod signed_log;
pub mod commands;
pub mod vault_key_cache;

use database::Database;
use threat_reactor::ThreatReactor;
use config::Config;
use vault_key_cache::VaultKeyCache;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
#[cfg(debug_assertions)]
use tauri::Manager;
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;

// Re-export all command functions for generate_handler![]
use commands::*;

/// Génère un token de session cryptographiquement aléatoire
pub fn generate_session_token() -> String {
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes)
}

/// VULN-002: Validation de session — vérifie que l'utilisateur est authentifié
/// avec un token de session actif et une activité récente.
/// Retourne le user_id si la session est valide.
pub async fn validate_session(state: &AppState) -> Result<i64, String> {
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié — aucune session active")?;
    
    // Vérifier que le token de session existe (généré au login)
    if state.session_token.lock().await.is_none() {
        return Err("Session invalide — token absent".to_string());
    }
    
    // Vérifier l'expiration de la session (max 24h même sans auto-lock)
    let last_activity = *state.last_activity.lock().await;
    if last_activity.elapsed() > std::time::Duration::from_secs(24 * 3600) {
        // Invalider la session expirée
        *state.session_token.lock().await = None;
        *state.current_user_id.lock().await = None;
        return Err("Session expirée — reconnexion requise".to_string());
    }
    
    Ok(user_id)
}

/// Génère 32 bytes aléatoires cryptographiquement sécurisés (pour clés SSH/API/GPG)
pub fn generate_random_key_bytes() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut key)
        .expect("🚨 ERREUR CRITIQUE: Impossible de générer une clé sécurisée");
    key
}

/// Récupère la clé vault depuis le cache sécurisé, ou depuis le Keychain si le cache
/// est vide/expiré, puis met en cache le résultat.
///
/// Ce helper centralise la logique cache-or-fetch pour éviter de dupliquer
/// le pattern dans les 20+ commandes Tauri.
///
/// **Variable d'environnement** : `UTILISATION_CACHE`
/// - `true` (défaut) : utilise le cache XOR-masked en mémoire
/// - `false` : accès direct au Keychain à chaque appel (ancien comportement)
///
/// **Sécurité** :
/// - Le cache utilise XOR-masking (NIST SP 800-57 key splitting)
/// - mlock sur tous les buffers (anti-swap)
/// - TTL de 3 minutes (OWASP: minimiser le temps en clair)
/// - Rotation du masque toutes les 30s
/// - Zeroize + munlock au drop
pub async fn get_or_fetch_vault_key(state: &AppState, user_id: i64) -> Result<secure_key::SecureKey, String> {
    if !state.cache_enabled {
        // Mode sans cache : accès direct au Keychain (ancien comportement)
        return secure_storage::retrieve_encryption_key_secure(user_id)
            .map_err(|e| format!("Erreur récupération clé: {}", e));
    }

    // 1. Essayer le cache d'abord
    {
        let mut cache = state.vault_key_cache.lock().await;
        if let Some(key) = cache.get(user_id) {
            return Ok(key);
        }
    }

    // 2. Cache miss : aller chercher dans le Keychain
    let key_from_keychain = secure_storage::retrieve_encryption_key_secure(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;

    // 3. Mettre en cache (XOR-masked + mlock)
    {
        let key_bytes = key_from_keychain.to_vec();
        let mut cache = state.vault_key_cache.lock().await;
        cache.store(user_id, &key_bytes);
        // key_bytes est Zeroizing<Vec<u8>>, sera zéroïsé automatiquement ici
    }

    // 4. Retourner depuis le cache (pour garantir la cohérence du chemin)
    {
        let mut cache = state.vault_key_cache.lock().await;
        cache.get(user_id).ok_or_else(|| "Erreur interne: cache vault vide après store".to_string())
    }
}

// État global de l'application
pub struct AppState {
    pub db: Arc<Mutex<Option<Database>>>,
    pub current_user_id: Arc<Mutex<Option<i64>>>,
    pub session_token: Arc<Mutex<Option<String>>>,
    pub session: Arc<Mutex<Option<String>>>, // Alias for session_token used by transfer module
    pub last_activity: Arc<Mutex<std::time::Instant>>,
    pub auto_lock_minutes: Arc<Mutex<u64>>,
    pub threat_reactor: Arc<ThreatReactor>,
    pub transfer_manager: Arc<Mutex<Option<transfer::commands::TransferManager>>>,
    /// Fichiers déchiffrés temporaires à nettoyer (M01 — audit sécurité)
    /// Clé: chemin absolu, Valeur: timestamp de création
    pub decrypted_temp_files: Arc<Mutex<Vec<String>>>,
    /// Répertoire de données résolu au démarrage (Android: app_data_dir; Desktop: hidden_storage)
    pub data_dir: Arc<Mutex<Option<std::path::PathBuf>>>,
    /// Gestionnaire de logs signés (hash chain SHA3-256 + ML-DSA-65)
    pub signed_log_manager: Arc<Mutex<Option<signed_log::SignedLogManager>>>,
    /// Activation des logs signés (persisté dans config)
    pub logging_enabled: Arc<Mutex<bool>>,
    /// Mode isolation réseau — bloque toute activité réseau
    pub isolation_mode: Arc<Mutex<bool>>,
    /// Cache sécurisé de la clé vault (XOR-masked + mlock + TTL configurable)
    /// Conforme NIST SP 800-57 (key splitting) + OWASP Secrets Management §2.5
    pub vault_key_cache: Arc<Mutex<VaultKeyCache>>,
    /// Cache activé ou non (configurable via UTILISATION_CACHE)
    pub cache_enabled: bool,
}

// Structures pour les requêtes
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub token: Option<String>,
    pub message: String,
    pub user_id: Option<i64>,
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePasswordRequest {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatePasswordRequest {
    pub id: i64,
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub key_name: String,
    pub key_type: String,
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportKeyRequest {
    pub key_name: String,
    pub key_type: String,
    pub key_data: String,
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareFileRequest {
    pub file_id: i64,
    pub recipient_email: String,
    pub expiration_days: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareFileResponse {
    pub success: bool,
    pub share_token: String,
    pub share_link: String,
    pub expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub user_id: i64,
    pub event_type: String,
    pub description: String,
    pub severity: Option<String>,
    pub ip_address: Option<String>,
    pub timestamp: String,
}

// Commandes Tauri


/// Nettoyage sécurisé des fichiers déchiffrés temporaires (M01 — audit sécurité)
/// Écrase le contenu avec des zéros avant suppression pour empêcher la récupération
pub async fn secure_cleanup_decrypted_files(temp_files: &Arc<Mutex<Vec<String>>>) {
    let mut files = temp_files.lock().await;
    for path in files.drain(..) {
        if let Ok(metadata) = std::fs::metadata(&path) {
            let size = metadata.len() as usize;
            // Écraser avec des zéros avant suppression
            if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path) {
                use std::io::Write;
                let zeros = vec![0u8; size.min(1024 * 1024)]; // Blocs de 1 MiB max
                let mut remaining = size;
                while remaining > 0 {
                    let chunk = remaining.min(zeros.len());
                    if file.write_all(&zeros[..chunk]).is_err() {
                        break;
                    }
                    remaining -= chunk;
                }
                let _ = file.flush();
            }
            let _ = std::fs::remove_file(&path);
            debug_log!("🧹 Fichier temporaire nettoyé de manière sécurisée: {}", path);
        }
    }
}


// ========== SIGNED LOG HELPERS ==========

/// Initialise le gestionnaire de logs signés (appelé après init_local_db)
pub async fn init_signed_log_manager(state: &AppState) -> Result<(), String> {
    let data_dir_guard = state.data_dir.lock().await;
    let data_dir = data_dir_guard.as_ref().ok_or("Répertoire de données non initialisé")?.clone();
    drop(data_dir_guard);

    // ML-DSA-65 key generation/loading uses very large stack frames (post-quantum crypto).
    // Run on a blocking thread (8 MB OS stack) to avoid stack overflow in tokio workers.
    let manager = tokio::task::spawn_blocking(move || {
        signed_log::SignedLogManager::init(&data_dir)
    })
    .await
    .map_err(|e| format!("Erreur thread init logs signés: {}", e))??;

    *state.signed_log_manager.lock().await = Some(manager);
    Ok(())
}

/// Ajoute une entrée signée au journal d'audit (usage interne)
#[allow(dead_code)]
pub async fn append_signed_log(state: &AppState, event: &str, metadata: serde_json::Value) -> Result<(), String> {
    let enabled = *state.logging_enabled.lock().await;
    if !enabled {
        return Ok(());
    }
    let mut mgr_guard = state.signed_log_manager.lock().await;
    if let Some(ref mut mgr) = *mgr_guard {
        mgr.append(event, metadata)?;
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Configure custom tokio runtime with larger worker thread stack size.
    // ML-DSA-65 post-quantum crypto operations (SignedLogManager, TrustStore)
    // require more stack space than the default ~2 MB tokio worker threads provide.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_stack_size(8 * 1024 * 1024) // 8 MB
        .enable_all()
        .build()
        .expect("Failed to create Tokio runtime");
    tauri::async_runtime::set(runtime.handle().clone());
    // Leak runtime so it lives for the entire process lifetime
    std::mem::forget(runtime);

    // IMPORTANT: Charger les variables d'environnement en tout premier
    // Le .env est à la racine du projet (secure-vault-next-gen/.env)
    // CARGO_MANIFEST_DIR = src-tauri/ à la compilation → ../../.env = racine projet
    let env_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.env");
    
    debug_log!("🔍 Tentative de chargement .env depuis: {:?}", env_path.canonicalize().unwrap_or(env_path.clone()));
    
    match dotenv::from_path(&env_path) {
        Ok(_) => {
            debug_log!("✅ Variables d'environnement chargées depuis .env");
            // Afficher les variables SMTP pour debug
            if let Ok(_host) = std::env::var("EMAIL_SMTP_HOST") {
                debug_log!("   EMAIL_SMTP_HOST: {}", _host);
            }
            if let Ok(_user) = std::env::var("EMAIL_SMTP_USERNAME") {
                debug_log!("   EMAIL_SMTP_USERNAME: {}", _user);
            }
            if let Ok(_pass) = std::env::var("EMAIL_SMTP_PASSWORD") {
                #[cfg(debug_assertions)]
                debug_log!("   EMAIL_SMTP_PASSWORD: {} chars", _pass.len());
            }
        },
        Err(_e) => {
            if cfg!(debug_assertions) {
                eprintln!("⚠️ Impossible de charger .env: {}", _e);
            }
            // Essayer dotenv() par défaut
            if let Ok(_) = dotenv::dotenv() {
                debug_log!("✅ Variables chargées depuis .env (chemin par défaut)");
            } else {
                if cfg!(debug_assertions) {
                    eprintln!("❌ Aucun fichier .env trouvé!");
                }
            }
        }
    }
    
    // Les moniteurs de sécurité sont initialisés automatiquement (Lazy)
    debug_log!("🛡️  Moniteur de sécurité prêt (Lazy init)");
    debug_log!("🔍 Surveillance du système de fichiers prête (Lazy init)");
    
    // Charger configuration
    let config = Config::from_env();
    
    // Valider la configuration au démarrage
    if let Err(warnings) = config.validate() {
        eprintln!("⚠️  Configuration invalide: {}", warnings);
    }
    
    // Créer services
    let session_token = Arc::new(Mutex::new(None));
    let app_state = AppState {
        db: Arc::new(Mutex::new(None)),
        current_user_id: Arc::new(Mutex::new(None)),
        session_token: session_token.clone(),
        session: session_token, // shared Arc with session_token
        last_activity: Arc::new(Mutex::new(std::time::Instant::now())),
        auto_lock_minutes: Arc::new(Mutex::new(15)), // 15 minutes par défaut
        threat_reactor: Arc::new({
            // VULN-011: Persist blocked users across restarts
            #[cfg(not(target_os = "android"))]
            {
                match hidden_storage::get_hidden_database_dir() {
                    Ok(dir) => ThreatReactor::with_persistence(dir),
                    Err(_) => ThreatReactor::new(),
                }
            }
            #[cfg(target_os = "android")]
            ThreatReactor::new()
        }),
        transfer_manager: Arc::new(Mutex::new(None)), // Initialisé après init_local_db
        decrypted_temp_files: Arc::new(Mutex::new(Vec::new())),
        data_dir: Arc::new(Mutex::new(None)),
        signed_log_manager: Arc::new(Mutex::new(None)),
        logging_enabled: Arc::new(Mutex::new(config.signed_logging_enabled)),
        isolation_mode: Arc::new(Mutex::new(config.isolation_enabled)),
        vault_key_cache: Arc::new(Mutex::new(VaultKeyCache::with_config(
            config.cache_ttl_secs,
            config.cache_mask_rotation_secs,
        ))),
        cache_enabled: config.cache_enabled,
    };

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init());

    // Updater is desktop-only (not available on Android/iOS)
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());

    builder
        .manage(app_state)
        .invoke_handler({
            // Android JavaBridge thread has a small stack (~512KB).
            // Our 80+ Tauri commands generate a large future enum that
            // overflows it. Use stacker to dynamically grow the stack.
            let handler: Box<dyn Fn(tauri::ipc::Invoke<tauri::Wry>) -> bool + Send + Sync> =
                Box::new(tauri::generate_handler![
                get_app_version,
                check_backend_status,
                init_local_db,
                has_existing_user,
                local_login,
                local_logout,
                local_register,
            // Auto-lock commands
            notify_activity,
            set_auto_lock_timeout,
            check_auto_lock,
            create_password,
            get_passwords,
            get_password,
            decrypt_password,
            update_password,
            delete_password,
            create_secure_file,
            create_secure_file_from_path,
            get_secure_files,
            decrypt_file,
            decrypt_file_to_path,
            cleanup_decrypted_files,
            delete_secure_file,
            share_file,
            get_user_shares,
            revoke_share,
            create_secure_key,
            import_secure_key,
            get_secure_keys,
            decrypt_key,
            delete_secure_key,
            get_security_events,
            create_test_logs,
            // 2FA commands
            setup_2fa,
            verify_and_enable_2fa,
            disable_2fa,
            verify_2fa_login,
            // Biometric commands
            check_biometric,
            enable_biometric,
            disable_biometric,
            biometric_login,
            biometric_login_with_key,
            biometric_emergency_lock,
            // Passkey commands
            check_passkey,
            register_passkey,
            passkey_login,
            passkey_authenticate,
            delete_passkey,
            // Threat reaction commands
            analyze_and_react,
            // Maintenance commands
            cleanup_logs,
            get_logs_stats,
            // Native Security commands
            get_security_status,
            check_login_delay,
            disable_readonly_mode,
            reset_security_counters,
            // Filesystem Monitor commands
            get_filesystem_stats,
            disable_filesystem_readonly,
            reset_filesystem_stats,
            enable_filesystem_monitoring,
            disable_filesystem_monitoring,
            // Backup & Restore commands
            create_backup,
            search_backups,
            restore_backup,
            get_backup_metadata,
            // Vault reset command
            reset_vault_completely,
            // CSV import/export commands
            import_passwords_csv,
            export_passwords_csv,
            // Signed log commands
            verify_log_integrity,
            toggle_signed_logging,
            get_signed_logging_status,
            // Network isolation commands
            toggle_isolation_mode,
            get_isolation_mode,
            // Enclave status command
            get_enclave_status,
            // Vault Secure Transfer commands
            transfer::commands::transfer_create_offer,
            transfer::commands::transfer_connect,
            transfer::commands::transfer_confirm_and_execute,
            transfer::commands::transfer_scan_local_network,
            transfer::commands::transfer_get_trusted_peers,
            transfer::commands::transfer_revoke_trust,
            transfer::commands::transfer_add_trusted_peer,
            transfer::commands::transfer_get_status,
            transfer::commands::transfer_cancel,
            transfer::commands::transfer_set_visibility,
            transfer::commands::transfer_get_visibility,
            transfer::commands::transfer_sync_trust_store,
            transfer::commands::transfer_get_sync_settings,
            transfer::commands::transfer_set_sync_enabled,
            transfer::commands::transfer_add_sync_device,
            transfer::commands::transfer_remove_sync_device,
            transfer::commands::transfer_start_sync_pairing,
            transfer::commands::transfer_join_sync_pairing,
            transfer::commands::transfer_auto_sync_with_peer,
            ]);
            move |invoke| {
                stacker::maybe_grow(2 * 1024 * 1024, 4 * 1024 * 1024, || {
                    handler(invoke)
                })
            }
        })
        .setup(|_app| {
            debug_log!("🔐 SecureVault démarré");
            #[cfg(debug_assertions)]
            debug_log!("📁 Répertoire de données: {:?}", 
                _app.path().app_data_dir());
            Ok(())
        })
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("❌ Erreur lancement application: {}", e);
            std::process::exit(1);
        });
}

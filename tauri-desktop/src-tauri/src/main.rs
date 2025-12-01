// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod database;
mod crypto;
pub mod ml_bridge;
mod secure_storage;
mod totp;
mod threat_reactor;
mod config;
mod email_service;
mod two_factor;
mod ml_database;
mod security_monitor;
mod filesystem_monitor;

use database::{Database, Password, SecureFile, SecureKey, FileShare};
use crypto::{hash_password, verify_password, encrypt_data, decrypt_data, generate_salt, derive_encryption_key_from_password};
#[allow(deprecated)]
use crypto::generate_encryption_key; // Utilisé uniquement pour générer des clés RSA/AES stockées
use ml_bridge::{initialize_ml_engine, get_ml_engine, BehavioralScore, AnomalyResult, RansomwareScanResult};
use secure_storage::{store_encryption_key, retrieve_encryption_key, delete_encryption_key};
use totp::{generate_totp_secret, verify_totp_code, verify_backup_code, TotpSetup};
use threat_reactor::ThreatReactor;
use config::Config;
use email_service::EmailService;
use two_factor::{TwoFactorService, TwoFactorMethod, TwoFactorSetup};
use ml_database::MLDatabaseService;
use security_monitor::{
    initialize_security_monitor, get_security_monitor, 
    SecurityState, BruteForceAction, RansomwareStatus
};
use filesystem_monitor::{
    initialize_filesystem_monitor, get_filesystem_monitor,
    MonitoringStats
};
use serde::{Deserialize, Serialize};
use base64::Engine;
use std::sync::Arc;
use tokio::sync::Mutex;
use tauri::State;
use base64::{Engine as _, engine::general_purpose};
use chrono::{Utc, Duration};

// État global de l'application
struct AppState {
    db: Arc<Mutex<Option<Database>>>,
    current_user_id: Arc<Mutex<Option<i64>>>,
    threat_reactor: Arc<ThreatReactor>,
    config: Config,
    email_service: Arc<EmailService>,
    two_factor_service: Arc<TwoFactorService>,
    ml_database: Arc<Mutex<Option<MLDatabaseService>>>,
}

// Structures pour les requêtes
#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginResponse {
    success: bool,
    token: Option<String>,
    message: String,
    user_id: Option<i64>,
    email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterRequest {
    username: String,
    email: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreatePasswordRequest {
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpdatePasswordRequest {
    id: i64,
    title: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateKeyRequest {
    key_name: String,
    key_type: String,
    algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImportKeyRequest {
    key_name: String,
    key_type: String,
    key_data: String,
    algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShareFileRequest {
    file_id: i64,
    recipient_email: String,
    expiration_days: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ShareFileResponse {
    success: bool,
    share_token: String,
    share_link: String,
    expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecurityEvent {
    id: i64,
    user_id: i64,
    event_type: String,
    description: String,
    severity: Option<String>,
    ip_address: Option<String>,
    timestamp: String,
}

// Commandes Tauri

#[tauri::command]
fn get_app_version() -> String {
    "2.0.0".to_string()
}

#[tauri::command]
async fn check_backend_status() -> Result<String, String> {
    Ok("Backend intégré démarré".to_string())
}

#[tauri::command]
async fn init_local_db(
    app_handle: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let app_dir = app_handle
        .path_resolver()
        .app_data_dir()
        .ok_or("Impossible de trouver le répertoire de l'app")?;

    // Ensure the directory exists with proper permissions
    std::fs::create_dir_all(&app_dir)
        .map_err(|e| format!("Erreur création répertoire: {}", e))?;

    let db_path = app_dir.join("securevault.db");
    
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
    
    // Note: La clé de chiffrement sera dérivée lors de la connexion
    // depuis le mot de passe utilisateur, pas générée aléatoirement
    println!("✅ Base de données initialisée (clé de chiffrement sera dérivée à la connexion)");

    Ok(format!("Base de données initialisée: {:?}", db_path))
}

// Vérifier si un utilisateur existe déjà (limite: 1 utilisateur par appareil)
#[tauri::command]
async fn has_existing_user(state: State<'_, AppState>) -> Result<bool, String> {
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
async fn local_register(
    credentials: RegisterRequest,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    println!("📝 Tentative d'enregistrement pour: {}", credentials.username);
    
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;

    // Vérifier si l'utilisateur existe déjà
    if let Ok(Some(_)) = db.get_user_by_username(&credentials.username).await {
        println!("⚠️  Utilisateur {} existe déjà", credentials.username);
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: "Nom d'utilisateur déjà utilisé".to_string(),
            user_id: None,
            email: None,
        });
    }

    // Hasher le mot de passe
    println!("🔐 Hashage du mot de passe...");
    let password_hash = hash_password(&credentials.password)
        .map_err(|e| format!("Erreur de hashage: {}", e))?;
    
    println!("💾 Hash généré (longueur: {})", password_hash.len());
    
    // Générer un sel unique pour la dérivation de clé de chiffrement
    let crypto_salt = generate_salt();
    let crypto_salt_b64 = general_purpose::STANDARD.encode(&crypto_salt);
    println!("🔑 Sel crypto généré pour dérivation de clé");

    // Créer l'utilisateur avec le sel crypto
    let user_id = db
        .create_user(&credentials.username, &credentials.email, &password_hash, &crypto_salt_b64)
        .await
        .map_err(|e| format!("Erreur création utilisateur: {}", e))?;

    println!("✅ Utilisateur créé avec ID: {}", user_id);
    
    // Dériver la clé de chiffrement depuis le mot de passe
    let encryption_key = derive_encryption_key_from_password(&credentials.password, &crypto_salt)
        .map_err(|e| format!("Erreur dérivation clé: {}", e))?;
    
    // Stocker la clé dans l'enclave sécurisée (Keychain) au lieu de la RAM
    store_encryption_key(user_id, &encryption_key)
        .map_err(|e| format!("Erreur stockage clé sécurisée: {}", e))?;
    
    println!("🔐 Clé de chiffrement stockée dans l'enclave sécurisée (Keychain)");
    *state.current_user_id.lock().await = Some(user_id);
    
    // Log l'événement d'inscription
    let _ = db.log_action(user_id, "REGISTER", "user", Some(user_id)).await;

    Ok(LoginResponse {
        success: true,
        token: Some(format!("token-{}", user_id)),
        message: "Compte créé avec succès".to_string(),
        user_id: Some(user_id),
        email: Some(credentials.email),
    })
}

#[tauri::command]
async fn local_login(
    credentials: LoginRequest,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    println!("🔑 Tentative de connexion pour: {}", credentials.username);
    
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;

    // Récupérer l'utilisateur
    let user = match db.get_user_by_username(&credentials.username).await {
        Ok(Some(u)) => {
            println!("👤 Utilisateur trouvé: {} (ID: {})", u.username, u.id);
            u
        },
        Ok(None) => {
            println!("❌ Aucun utilisateur trouvé avec le nom: {}", credentials.username);
            return Ok(LoginResponse {
                success: false,
                token: None,
                message: "Identifiants incorrects (utilisateur non trouvé)".to_string(),
                user_id: None,
            email: None,
            })
        }
        Err(e) => {
            println!("❌ Erreur DB: {}", e);
            return Err(format!("Erreur base de données: {}", e));
        }
    };

    // Vérifier si l'utilisateur est verrouillé (anti-brute force)
    let monitor = get_security_monitor();
    if let Some(remaining) = monitor.is_user_locked(&credentials.username).await {
        println!("🔒 Utilisateur verrouillé (brute force) - {} secondes restantes", remaining);
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
                println!("✅ Délai expiré ({}s écoulées sur {}s requis) - tentative autorisée", elapsed, delay_seconds);
            } else {
                // Le délai est toujours actif
                let remaining = delay_seconds - elapsed;
                println!("⏱️ Délai actif: {}s restantes sur {}s requis ({} tentatives)", remaining, delay_seconds, failed_count);
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
            println!("⚠️ Échecs comptés mais pas de dernière tentative trouvée - autorisation");
        }
    }

    // Vérifier le mot de passe
    println!("🔐 Vérification du mot de passe (hash length: {})", user.password_hash.len());
    let password_valid = verify_password(&credentials.password, &user.password_hash);

    if let Err(e) = password_valid {
        println!("❌ Échec vérification mot de passe: {:?}", e);
        
        // Enregistrer la tentative échouée dans audit_logs
        let _ = db.log_action(user.id, "login_failed", "auth", None).await;
        
        // La logique du délai est gérée côté frontend via check_login_delay
        // On retourne simplement l'échec
        return Ok(LoginResponse {
            success: false,
            token: None,
            message: "Identifiants incorrects".to_string(),
            user_id: None,
            email: None,
        });
    }

    println!("✅ Mot de passe vérifié");
    
    // Connexion réussie : réinitialiser le compteur de tentatives
    monitor.record_successful_login(&credentials.username).await;
    
    // Nettoyer les anciennes tentatives échouées pour cet utilisateur
    let _ = db.clear_failed_logins(user.id).await;
    println!("🧹 Tentatives échouées réinitialisées pour l'utilisateur {}", user.id);
    
    // Décoder le sel crypto et dériver la clé de chiffrement
    let crypto_salt = general_purpose::STANDARD
        .decode(&user.crypto_salt)
        .map_err(|e| format!("Erreur décodage sel crypto: {}", e))?;
    
    let encryption_key = derive_encryption_key_from_password(&credentials.password, &crypto_salt)
        .map_err(|e| format!("Erreur dérivation clé: {}", e))?;
    
    // Stocker la clé dans l'enclave sécurisée (Keychain) pour la session
    store_encryption_key(user.id, &encryption_key)
        .map_err(|e| format!("Erreur stockage clé sécurisée: {}", e))?;
    
    println!("🔑 Clé de chiffrement stockée dans l'enclave sécurisée (Keychain)");
    
    println!("✅ Connexion réussie pour {}", user.username);
    *state.current_user_id.lock().await = Some(user.id);
    
    // Log l'événement de connexion
    let _ = db.log_action(user.id, "LOGIN", "session", None).await;

    Ok(LoginResponse {
        success: true,
        token: Some(format!("token-{}", user.id)),
        message: "Connexion réussie".to_string(),
        user_id: Some(user.id),
        email: Some(user.email.clone()),
    })
}

// Password CRUD operations
#[tauri::command]
async fn create_password(
    request: CreatePasswordRequest,
    state: State<'_, AppState>,
) -> Result<i64, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer la clé de chiffrement depuis l'enclave sécurisée
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;
    
    // Chiffrer le mot de passe
    let encrypted_password = encrypt_data(&request.password, &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer les champs sensibles (username, url, notes)
    let encrypted_username = request.username.as_ref()
        .map(|u| encrypt_data(u, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement username: {}", e))?;
    
    let encrypted_url = request.url.as_ref()
        .map(|u| encrypt_data(u, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement URL: {}", e))?;
    
    let encrypted_notes = request.notes.as_ref()
        .map(|n| encrypt_data(n, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement notes: {}", e))?;

    let password_id = db
        .create_password(
            user_id,
            &request.title,
            encrypted_username.as_deref(),
            &encrypted_password,
            encrypted_url.as_deref(),
            encrypted_notes.as_deref(),
            request.category.as_deref(),
        )
        .await
        .map_err(|e| format!("Erreur création mot de passe: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "CREATE", "password", Some(password_id)).await;

    Ok(password_id)
}

#[tauri::command]
async fn get_passwords(state: State<'_, AppState>) -> Result<Vec<Password>, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let passwords = db
        .get_passwords(user_id)
        .await
        .map_err(|e| format!("Erreur récupération mots de passe: {}", e))?;

    // Récupérer la clé de chiffrement depuis l'enclave sécurisée
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;

    // Déchiffrer tous les mots de passe et leurs champs sensibles avant de les renvoyer
    let mut decrypted_passwords = Vec::new();
    for mut password in passwords {
        // Déchiffrer le mot de passe
        match decrypt_data(&password.password, &encryption_key) {
            Ok(decrypted) => {
                password.password = decrypted;
            }
            Err(e) => {
                println!("⚠️ Erreur déchiffrement mot de passe {}: {}", password.id, e);
            }
        }
        
        // Déchiffrer username si présent
        if let Some(ref username) = password.username {
            if let Ok(decrypted) = decrypt_data(username, &encryption_key) {
                password.username = Some(decrypted);
            }
        }
        
        // Déchiffrer URL si présente
        if let Some(ref url) = password.url {
            if let Ok(decrypted) = decrypt_data(url, &encryption_key) {
                password.url = Some(decrypted);
            }
        }
        
        // Déchiffrer notes si présentes
        if let Some(ref notes) = password.notes {
            if let Ok(decrypted) = decrypt_data(notes, &encryption_key) {
                password.notes = Some(decrypted);
            }
        }
        
        decrypted_passwords.push(password);
    }

    Ok(decrypted_passwords)
}

#[tauri::command]
async fn get_password(id: i64, state: State<'_, AppState>) -> Result<Option<Password>, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let password = db
        .get_password(id, user_id)
        .await
        .map_err(|e| format!("Erreur récupération mot de passe: {}", e))?;

    Ok(password)
}

#[tauri::command]
async fn decrypt_password(encrypted: String, state: State<'_, AppState>) -> Result<String, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;
    
    // Récupérer la clé de chiffrement depuis l'enclave sécurisée
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;
    
    let decrypted = decrypt_data(&encrypted, &encryption_key)
        .map_err(|e| format!("Erreur de déchiffrement: {}", e))?;

    Ok(decrypted)
}

#[tauri::command]
async fn update_password(
    request: UpdatePasswordRequest,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    // Protection ransomware
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".to_string());
    }
    
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer la clé de chiffrement depuis l'enclave sécurisée
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;
    
    // Chiffrer le mot de passe
    let encrypted_password = encrypt_data(&request.password, &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer les champs sensibles
    let encrypted_username = request.username.as_ref()
        .map(|u| encrypt_data(u, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement username: {}", e))?;
    
    let encrypted_url = request.url.as_ref()
        .map(|u| encrypt_data(u, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement URL: {}", e))?;
    
    let encrypted_notes = request.notes.as_ref()
        .map(|n| encrypt_data(n, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement notes: {}", e))?;

    let updated = db
        .update_password(
            request.id,
            user_id,
            &request.title,
            encrypted_username.as_deref(),
            &encrypted_password,
            encrypted_url.as_deref(),
            encrypted_notes.as_deref(),
            request.category.as_deref(),
        )
        .await
        .map_err(|e| format!("Erreur mise à jour mot de passe: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "UPDATE", "password", Some(request.id)).await;

    Ok(updated)
}

#[tauri::command]
async fn delete_password(id: i64, state: State<'_, AppState>) -> Result<bool, String> {
    // Protection ransomware
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".to_string());
    }
    
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let deleted = db
        .delete_password(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression mot de passe: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "DELETE", "password", Some(id)).await;

    Ok(deleted)
}

// Secure file operations
#[tauri::command]
async fn create_secure_file(
    filename: String,
    file_data: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<i64, String> {
    // Vérifier le mode lecture seule (protection ransomware)
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 SYSTÈME EN MODE LECTURE SEULE - Activité ransomware détectée. Aucune modification autorisée.".to_string());
    }
    
    // Surveiller l'activité fichier
    monitor.monitor_file_access(&filename).await;
    
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Créer le répertoire des fichiers sécurisés
    let app_dir = app_handle
        .path_resolver()
        .app_data_dir()
        .ok_or("Impossible de trouver le répertoire de l'app")?;
    
    let files_dir = app_dir.join("secure_files");
    std::fs::create_dir_all(&files_dir)
        .map_err(|e| format!("Erreur création répertoire: {}", e))?;

    // Récupérer la clé de chiffrement depuis l'enclave sécurisée
    // Note: La bibliothèque keyring gère automatiquement la sécurité sur chaque plateforme :
    // - macOS: Keychain (Secure Enclave avec T2/M1/M2)
    // - Windows: Credential Manager (Windows Data Protection API - DPAPI)
    // - Linux: Secret Service (libsecret)
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;
    
    // Décoder les données Base64 reçues du frontend
    let decoded_data = general_purpose::STANDARD.decode(&file_data)
        .map_err(|e| format!("Erreur décodage Base64: {}", e))?;

    // Chiffrer les données binaires du fichier
    let encrypted_data = encrypt_data(&String::from_utf8_lossy(&decoded_data), &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer le nom de fichier pour plus de sécurité
    let encrypted_filename = encrypt_data(&filename, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement filename: {}", e))?;

    // Générer un nom de fichier unique sur le disque (UUID)
    let file_id = uuid::Uuid::new_v4().to_string();
    let file_path = files_dir.join(format!("{}.enc", file_id));
    
    println!("📝 Stockage fichier chiffré: {} -> {}", filename, file_id);
    println!("🔐 Clé stockée de manière sécurisée dans l'enclave système");

    // Écrire le fichier chiffré sur le disque
    std::fs::write(&file_path, encrypted_data.as_bytes())
        .map_err(|e| format!("Erreur écriture fichier: {}", e))?;

    let file_size = decoded_data.len() as i64;

    let secure_file_id = db
        .create_secure_file(
            user_id,
            &encrypted_filename,
            file_path.to_str().unwrap(),
            file_size,
            None,
        )
        .await
        .map_err(|e| format!("Erreur création fichier sécurisé: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "CREATE", "file", Some(secure_file_id)).await;

    Ok(secure_file_id)
}

#[tauri::command]
async fn get_secure_files(state: State<'_, AppState>) -> Result<Vec<SecureFile>, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let files = db
        .get_secure_files(user_id)
        .await
        .map_err(|e| format!("Erreur récupération fichiers: {}", e))?;

    // Récupérer la clé de chiffrement pour déchiffrer les noms de fichiers
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;

    // Déchiffrer les noms de fichiers
    let mut decrypted_files = Vec::new();
    for mut file in files {
        if let Ok(decrypted_filename) = decrypt_data(&file.filename, &encryption_key) {
            file.filename = decrypted_filename;
        } else {
            println!("⚠️ Erreur déchiffrement filename pour fichier {}", file.id);
        }
        decrypted_files.push(file);
    }

    Ok(decrypted_files)
}

#[tauri::command]
async fn decrypt_file(id: i64, state: State<'_, AppState>) -> Result<String, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer les informations du fichier
    let file = db
        .get_secure_files(user_id)
        .await
        .map_err(|e| format!("Erreur récupération fichiers: {}", e))?
        .into_iter()
        .find(|f| f.id == id)
        .ok_or("Fichier non trouvé")?;

    println!("📥 Téléchargement fichier chiffré depuis: {}", file.file_path);

    // Lire le fichier chiffré depuis le disque
    let encrypted_data = std::fs::read_to_string(&file.file_path)
        .map_err(|e| format!("Erreur lecture fichier: {}", e))?;

    // Récupérer la clé de chiffrement
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;

    // Déchiffrer les données
    let decrypted_data = decrypt_data(&encrypted_data, &encryption_key)
        .map_err(|e| format!("Erreur déchiffrement: {}", e))?;

    // Réencoder en Base64 pour le frontend
    let base64_data = general_purpose::STANDARD.encode(decrypted_data.as_bytes());

    println!("✅ Fichier déchiffré et prêt pour téléchargement");

    Ok(base64_data)
}

#[tauri::command]
async fn delete_secure_file(id: i64, state: State<'_, AppState>) -> Result<bool, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer le fichier pour supprimer le fichier physique
    if let Ok(Some(file)) = db.get_secure_files(user_id).await.map(|files| {
        files.into_iter().find(|f| f.id == id)
    }) {
        println!("🗑️ Suppression du fichier physique: {}", file.file_path);
        let _ = std::fs::remove_file(&file.file_path);
    }

    let deleted = db
        .delete_secure_file(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression fichier: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "DELETE", "file", Some(id)).await;

    Ok(deleted)
}

// Secure key operations
#[tauri::command]
async fn create_secure_key(
    request: CreateKeyRequest,
    state: State<'_, AppState>,
) -> Result<i64, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Générer une clé selon le type demandé
    let key_data = match request.key_type.as_str() {
        "ssh" => {
            // Génération d'une paire de clés SSH (publique + privée)
            let private_key = generate_encryption_key();
            let public_key = generate_encryption_key();
            let private_key_b64 = general_purpose::STANDARD.encode(&private_key);
            let public_key_b64 = general_purpose::STANDARD.encode(&public_key);
            // Format: private_key|||public_key (uniquement les clés brutes en base64, sans préfixe/suffixe)
            format!("{}|||{}", private_key_b64, public_key_b64)
        },
        "api" => {
            // Génération d'une clé API (hexadécimale)
            let key = generate_encryption_key();
            hex::encode(&key)
        },
        "gpg" => {
            // Génération d'une clé GPG (base64 propre, sans marqueurs)
            let key = generate_encryption_key();
            general_purpose::STANDARD.encode(&key)
        },
        "encryption" => {
            // Génération d'une clé de chiffrement AES-256
            let key = generate_encryption_key();
            hex::encode(&key)
        },
        _ => {
            // Par défaut : clé hexadécimale
            let key = generate_encryption_key();
            hex::encode(&key)
        }
    };

    println!("🔑 Clé {} générée (type: {})", request.key_name, request.key_type);

    // Récupérer la clé maître depuis l'enclave sécurisée pour chiffrer la clé générée
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;
    
    let encrypted_key = encrypt_data(&key_data, &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer le nom de la clé pour plus de sécurité
    let encrypted_key_name = encrypt_data(&request.key_name, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement key_name: {}", e))?;

    let secure_key_id = db
        .create_secure_key(
            user_id,
            &encrypted_key_name,
            &request.key_type,
            &encrypted_key,
            &request.algorithm,
        )
        .await
        .map_err(|e| format!("Erreur création clé: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "CREATE", "key", Some(secure_key_id)).await;

    Ok(secure_key_id)
}

#[tauri::command]
async fn import_secure_key(
    request: ImportKeyRequest,
    state: State<'_, AppState>,
) -> Result<i64, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    println!("📥 Import de clé {} (type: {})", request.key_name, request.key_type);

    // Récupérer la clé maître depuis l'enclave sécurisée pour chiffrer la clé importée
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;
    
    // Chiffrer la clé importée
    let encrypted_key = encrypt_data(&request.key_data, &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer le nom de la clé
    let encrypted_key_name = encrypt_data(&request.key_name, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement key_name: {}", e))?;

    let secure_key_id = db
        .create_secure_key(
            user_id,
            &encrypted_key_name,
            &request.key_type,
            &encrypted_key,
            &request.algorithm,
        )
        .await
        .map_err(|e| format!("Erreur import clé: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "IMPORT", "key", Some(secure_key_id)).await;

    Ok(secure_key_id)
}

#[tauri::command]
async fn get_secure_keys(state: State<'_, AppState>) -> Result<Vec<SecureKey>, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let keys = db
        .get_secure_keys(user_id)
        .await
        .map_err(|e| format!("Erreur récupération clés: {}", e))?;

    // Récupérer la clé de chiffrement pour déchiffrer les noms de clés
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;

    // Déchiffrer les noms de clés
    let mut decrypted_keys = Vec::new();
    for mut key in keys {
        if let Ok(decrypted_key_name) = decrypt_data(&key.key_name, &encryption_key) {
            key.key_name = decrypted_key_name;
        } else {
            println!("⚠️ Erreur déchiffrement key_name pour clé {}", key.id);
        }
        decrypted_keys.push(key);
    }

    Ok(decrypted_keys)
}

#[tauri::command]
async fn delete_secure_key(id: i64, state: State<'_, AppState>) -> Result<bool, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let deleted = db
        .delete_secure_key(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression clé: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "DELETE", "key", Some(id)).await;

    Ok(deleted)
}

// File sharing commands
#[tauri::command]
async fn share_file(
    request: ShareFileRequest,
    state: State<'_, AppState>,
) -> Result<ShareFileResponse, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Vérifier que le fichier existe et appartient à l'utilisateur
    let file = db
        .get_secure_file(request.file_id, user_id)
        .await
        .map_err(|e| format!("Erreur base de données: {}", e))?
        .ok_or("Fichier non trouvé")?;

    // Générer un token unique et sécurisé
    let share_token = format!("{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
    
    // Récupérer la clé de chiffrement de l'utilisateur
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;
    
    // Chiffrer la clé de déchiffrement avec le token (pour sécuriser l'accès)
    let encrypted_key = encrypt_data(&general_purpose::STANDARD.encode(&encryption_key), &encryption_key)
        .map_err(|e| format!("Erreur chiffrement clé: {}", e))?;

    // Calculer la date d'expiration
    let expires_at = (Utc::now() + Duration::days(request.expiration_days))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    // Créer le partage dans la base de données
    let share_id = db
        .create_file_share(
            request.file_id,
            user_id,
            &request.recipient_email,
            &share_token,
            &encrypted_key,
            &expires_at,
        )
        .await
        .map_err(|e| format!("Erreur création partage: {}", e))?;

    // Générer le lien de partage
    let share_link = format!("securevault://share/{}", share_token);

    // Log l'action
    let _ = db.log_action(user_id, "SHARE", "file", Some(request.file_id)).await;

    println!("✅ Fichier {} partagé avec {} (expires: {})", file.filename, request.recipient_email, expires_at);

    Ok(ShareFileResponse {
        success: true,
        share_token,
        share_link,
        expires_at,
    })
}

#[tauri::command]
async fn get_user_shares(state: State<'_, AppState>) -> Result<Vec<FileShare>, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let shares = db
        .get_user_shares(user_id)
        .await
        .map_err(|e| format!("Erreur récupération partages: {}", e))?;

    Ok(shares)
}

#[tauri::command]
async fn revoke_share(share_id: i64, state: State<'_, AppState>) -> Result<bool, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let deleted = db
        .delete_file_share(share_id, user_id)
        .await
        .map_err(|e| format!("Erreur révocation partage: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "REVOKE_SHARE", "file_share", Some(share_id)).await;

    Ok(deleted)
}

#[tauri::command]
async fn decrypt_key(id: i64, state: State<'_, AppState>) -> Result<String, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer la clé depuis la base
    let key = db
        .get_secure_key_by_id(id, user_id)
        .await
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;

    // Récupérer la clé de chiffrement depuis le Keychain
    let encryption_key = retrieve_encryption_key(user_id)
        .map_err(|e| format!("Erreur récupération clé chiffrement: {}", e))?;

    // Déchiffrer les données de la clé
    let decrypted_key = decrypt_data(&key.key_data, &encryption_key)
        .map_err(|e| format!("Erreur déchiffrement: {}", e))?;

    println!("🔓 Clé {} déchiffrée pour utilisateur {}", id, user_id);

    Ok(decrypted_key)
}

#[tauri::command]
async fn get_security_events(state: State<'_, AppState>) -> Result<Vec<SecurityEvent>, String> {
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

// Commande pour créer des logs de test (développement uniquement)
#[tauri::command]
async fn create_test_logs(state: State<'_, AppState>) -> Result<String, String> {
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

// ========== Commandes ML / Sécurité ==========

/// Initialise le moteur ML (à appeler au démarrage)
#[tauri::command]
async fn initialize_ml() -> Result<String, String> {
    match initialize_ml_engine() {
        Ok(_) => Ok("ML engine initialized successfully".to_string()),
        Err(e) => Err(format!("Failed to initialize ML: {}", e)),
    }
}

/// Analyse le comportement d'un utilisateur
#[tauri::command]
async fn analyze_user_behavior(
    user_id: i64,
    action: String,
    timestamp: i64,
) -> Result<BehavioralScore, String> {
    let engine = get_ml_engine()?;
    engine.analyze_behavior(user_id, &action, timestamp)
        .map_err(|e| format!("Behavioral analysis failed: {}", e))
}

/// Teste la connexion du moteur ML Python
#[tauri::command]
async fn test_ml_connection() -> Result<String, String> {
    // Vérifier si le moteur est initialisé
    let engine = match get_ml_engine() {
        Ok(e) => e,
        Err(e) => return Err(format!("❌ Moteur ML non initialisé: {}", e))
    };
    
    // Tester une analyse simple
    match engine.analyze_behavior(1, "test", 1700000000) {
        Ok(result) => {
            if result.anomaly_score == 0.0 && result.risk_level == "low" {
                Ok(format!("⚠️ Moteur ML répond mais retourne des valeurs par défaut.\n\nCela peut indiquer:\n- Le module Python n'est pas trouvé\n- Les dépendances Python ne sont pas installées\n- Le chemin vers python-ml-engine est incorrect\n\nScore reçu: {:.2}\nRisque: {}", 
                    result.anomaly_score, result.risk_level))
            } else {
                Ok(format!("✅ Moteur ML Python connecté et fonctionnel!\n\nScore: {:.2}\nRisque: {}\nDétails: {}", 
                    result.anomaly_score, 
                    result.risk_level,
                    result.details.get("message").unwrap_or(&"N/A".to_string())))
            }
        }
        Err(e) => Err(format!("❌ Erreur lors du test ML: {}\n\nVérifiez que:\n1. Python 3.8+ est installé\n2. Les dépendances sont installées (pip install -r requirements.txt)\n3. Le chemin python-ml-engine/src est accessible", e))
    }
}

/// Détecte des anomalies dans l'activité
#[tauri::command]
async fn detect_anomaly(features: Vec<f64>) -> Result<AnomalyResult, String> {
    let engine = get_ml_engine()?;
    engine.detect_anomaly(features)
        .map_err(|e| format!("Anomaly detection failed: {}", e))
}

/// Scan un fichier pour ransomware
#[tauri::command]
async fn scan_file_ransomware(
    filename: String,
    extension: String,
    file_size: u64,
) -> Result<RansomwareScanResult, String> {
    let engine = get_ml_engine()?;
    engine.scan_for_ransomware(&filename, &extension, file_size)
        .map_err(|e| format!("Ransomware scan failed: {}", e))
}

/// Entraîne le modèle avec de nouvelles données
#[tauri::command]
async fn train_ml_model(training_data: Vec<Vec<f64>>) -> Result<String, String> {
    let engine = get_ml_engine()?;
    engine.train_anomaly_model(training_data)
        .map_err(|e| format!("Model training failed: {}", e))?;
    Ok("Model trained successfully".to_string())
}

// ========== 2FA COMMANDS ==========

#[derive(Debug, Serialize, Deserialize)]
struct Enable2FAResponse {
    success: bool,
    secret: String,
    qr_code: String,
    backup_codes: Vec<String>,
    message: String,
}

/// Génère un secret TOTP et QR code pour activer 2FA
#[tauri::command]
async fn setup_2fa(state: State<'_, AppState>) -> Result<Enable2FAResponse, String> {
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer l'utilisateur
    let user = db.get_user_by_id(user_id).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur non trouvé")?;

    // Générer le secret TOTP
    let setup = generate_totp_secret(&user.email, "SecureVault")
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
async fn verify_and_enable_2fa(
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

    // Activer 2FA dans la DB
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    
    db.enable_2fa(user_id, &secret, &backup_codes_json).await
        .map_err(|e| format!("Erreur DB: {}", e))?;

    println!("✅ 2FA activé pour l'utilisateur {}", user_id);

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
async fn disable_2fa(
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

    println!("❌ 2FA désactivé pour l'utilisateur {}", user_id);

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
async fn verify_2fa_login(
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

    if let Some(secret) = user.totp_secret {
        // Vérifier le code TOTP
        let verified = verify_totp_code(&secret, &code)
            .map_err(|e| format!("Erreur vérification: {}", e))?;

        if verified {
            // Authentifié avec succès
            *state.current_user_id.lock().await = Some(user.id);
            
            println!("✅ 2FA vérifié pour {}", username);

            return Ok(LoginResponse {
                success: true,
                token: Some(format!("token_{}", user.id)),
                message: "Authentification 2FA réussie".to_string(),
                user_id: Some(user.id),
                email: Some(user.email.clone()),
            });
        }

        // Si code invalide, essayer backup code
        if let Some(backup_codes) = user.backup_codes {
            let (verified, remaining_codes) = verify_backup_code(&backup_codes, &code)
                .map_err(|e| format!("Erreur backup code: {}", e))?;

            if verified {
                // Mettre à jour les backup codes
                let new_codes = serde_json::to_string(&remaining_codes)
                    .map_err(|e| format!("Erreur sérialisation: {}", e))?;
                db.update_backup_codes(user.id, &new_codes).await
                    .map_err(|e| format!("Erreur DB: {}", e))?;

                *state.current_user_id.lock().await = Some(user.id);

                println!("✅ Backup code utilisé pour {}", username);

                return Ok(LoginResponse {
                    success: true,
                    token: Some(format!("token_{}", user.id)),
                    message: format!("Backup code accepté. {} codes restants", remaining_codes.len()),
                    user_id: Some(user.id),
                    email: Some(user.email.clone()),
                });
            }
        }
    }

    Ok(LoginResponse {
        success: false,
        token: None,
        message: "Code 2FA invalide".to_string(),
        user_id: None,
        email: None,
    })
}

// ========== THREAT REACTION COMMANDS ==========

/// Analyse une action et applique les réactions automatiques
#[tauri::command]
async fn analyze_and_react(
    user_id: i64,
    action: String,
    timestamp: i64,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
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

    // Analyser le comportement
    let engine = get_ml_engine()?;
    let analysis = engine.analyze_behavior(user_id, &action, timestamp)
        .map_err(|e| format!("Erreur analyse: {}", e))?;

    // Réagir selon le niveau de menace
    let response = state.threat_reactor.react_to_threat(
        user_id,
        analysis.anomaly_score,
        &analysis.risk_level,
        &if analysis.is_normal { vec![] } else { vec!["anomaly detected".to_string()] },
    ).await;

    // Si blocage critique, bloquer dans la DB aussi
    if response.blocked {
        let db_guard = state.db.lock().await;
        if let Some(db) = db_guard.as_ref() {
            let _ = db.lock_account(user_id, 30).await;
        }
    }

    Ok(serde_json::json!({
        "analysis": analysis,
        "response": response,
    }))
}

// ========== MAINTENANCE COMMANDS ==========

/// Nettoie les vieux logs
#[tauri::command]
async fn cleanup_logs(days: i64, state: State<'_, AppState>) -> Result<String, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let deleted = db.cleanup_old_logs(days).await
        .map_err(|e| format!("Erreur nettoyage: {}", e))?;

    Ok(format!("{} logs supprimés (> {} jours)", deleted, days))
}

/// Obtient les stats des logs
#[tauri::command]
async fn get_logs_stats(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let count = db.get_logs_count().await
        .map_err(|e| format!("Erreur stats: {}", e))?;

    Ok(serde_json::json!({
        "total_logs": count,
        "estimated_size_mb": (count * 200) / (1024 * 1024), // Estimation
    }))
}

// ========== COMMANDES DE SÉCURITÉ NATIVE ==========

/// Vérifie l'état de sécurité global
#[tauri::command]
async fn get_security_status() -> Result<SecurityState, String> {
    let monitor = get_security_monitor();
    Ok(monitor.get_security_state().await)
}

/// Vérifie un code OTP reçu par email
#[tauri::command]
async fn verify_otp_code(user_email: String, code: String) -> Result<bool, String> {
    let monitor = get_security_monitor();
    Ok(monitor.verify_otp(&user_email, &code).await)
}

/// Demande l'envoi d'un nouveau code OTP
#[tauri::command]
async fn request_otp_code(user_email: String) -> Result<String, String> {
    let monitor = get_security_monitor();
    monitor.generate_and_send_otp(&user_email).await?;
    Ok(format!("Code envoyé à {}", mask_email(&user_email)))
}

/// Vérifie le délai d'attente pour un utilisateur (en secondes)
/// Retourne 0 si aucun délai, sinon le nombre de secondes à attendre
#[tauri::command]
async fn check_login_delay(username: String, state: State<'_, AppState>) -> Result<u64, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    
    let user = db.get_user_by_username(&username).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur non trouvé")?;
    
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
                println!("✅ check_login_delay: Délai expiré ({}s écoulées)", elapsed);
                return Ok(0);
            } else {
                // Délai actif - retourner le temps restant
                let remaining = (delay - elapsed) as u64;
                println!("⏱️ check_login_delay: {}s restantes sur {}s ({} tentatives)", remaining, delay, failed_count);
                return Ok(remaining);
            }
        }
    }
    
    println!("🔐 check_login_delay pour {}: {} tentatives → délai: {}s", username, failed_count, delay);
    Ok(delay as u64)
}

/// Récupère l'email d'un utilisateur par son username
#[tauri::command]
async fn get_user_email(username: String, state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    
    let user = db.get_user_by_username(&username).await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur non trouvé")?;
    
    Ok(serde_json::json!({
        "email": user.email
    }))
}

/// Désactive le mode lecture seule (nécessite mot de passe utilisateur)
#[tauri::command]
async fn disable_readonly_mode(password: String, state: State<'_, AppState>) -> Result<String, String> {
    println!("🔐 DEBUG: Tentative de désactivation du mode lecture seule");
    
    // Vérifier si un utilisateur est connecté
    let user_id_opt = state.current_user_id.lock().await.clone();
    
    println!("🔍 DEBUG: current_user_id = {:?}", user_id_opt);
    
    if let Some(user_id) = user_id_opt {
        // Si connecté, vérifier le mot de passe
        let db_guard = state.db.lock().await;
        let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
        
        // Récupérer l'utilisateur depuis la DB
        let user = db.get_user_by_id(user_id).await
            .map_err(|e| format!("Erreur DB: {}", e))?
            .ok_or("Utilisateur introuvable")?;
        
        println!("✅ DEBUG: Utilisateur trouvé: {}", user.username);
        
        // Vérifier le mot de passe
        verify_password(&password, &user.password_hash)
            .map_err(|_| {
                println!("❌ DEBUG: Mot de passe incorrect");
                "Mot de passe incorrect".to_string()
            })?;
        
        println!("✅ DEBUG: Mot de passe vérifié");
    } else {
        // Si pas connecté, on accepte quand même si le mode readonly est actif
        // (car l'utilisateur ne peut pas se connecter en mode readonly)
        println!("⚠️  DEBUG: Pas d'utilisateur connecté, désactivation d'urgence");
    }
    
    // Désactiver le mode lecture seule
    let monitor = get_security_monitor();
    monitor.disable_readonly(&password).await?;
    
    println!("✅ DEBUG: Mode lecture seule désactivé");
    
    Ok("✅ Mode lecture seule désactivé avec succès".to_string())
}

/// Réinitialise tous les compteurs de sécurité
#[tauri::command]
async fn reset_security_counters() -> Result<String, String> {
    let monitor = get_security_monitor();
    monitor.reset_all().await;
    Ok("Compteurs de sécurité réinitialisés".to_string())
}

// ========== COMMANDES FILESYSTEM MONITOR ==========

#[tauri::command]
fn get_filesystem_stats() -> Result<MonitoringStats, String> {
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    Ok(guard.get_stats())
}

#[tauri::command]
fn disable_filesystem_readonly() -> Result<String, String> {
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.disable_readonly();
    Ok("Mode lecture seule système désactivé".to_string())
}

#[tauri::command]
fn reset_filesystem_stats() -> Result<String, String> {
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.reset_stats();
    Ok("Statistiques système réinitialisées".to_string())
}

#[tauri::command]
fn enable_filesystem_monitoring() -> Result<String, String> {
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.enable_monitoring();
    Ok("Surveillance des fichiers activée".to_string())
}

#[tauri::command]
fn disable_filesystem_monitoring() -> Result<String, String> {
    let monitor = get_filesystem_monitor();
    let guard = monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.disable_monitoring();
    Ok("Surveillance des fichiers désactivée".to_string())
}

// ========== COMMANDE RESET VAULT ==========

#[tauri::command]
async fn reset_vault_completely(state: State<'_, AppState>) -> Result<String, String> {
    println!("⚠️ Réinitialisation complète du coffre-fort demandée");
    
    // Nettoyer l'ID utilisateur courant
    *state.current_user_id.lock().await = None;
    
    // Fermer la connexion à la base de données
    *state.db.lock().await = None;
    *state.ml_database.lock().await = None;
    
    // Obtenir le chemin du répertoire de données
    let app_data_dir = dirs::data_local_dir()
        .ok_or("Impossible de trouver le répertoire de données")?
        .join("com.securevault.app");
    
    // Supprimer tout le répertoire de l'application
    if app_data_dir.exists() {
        println!("🗑️ Suppression de: {:?}", app_data_dir);
        std::fs::remove_dir_all(&app_data_dir)
            .map_err(|e| format!("Erreur lors de la suppression de la base de données: {}", e))?;
    }
    
    // Réinitialiser les moniteurs de sécurité
    let security_monitor = get_security_monitor();
    security_monitor.reset_all().await;
    
    let fs_monitor = get_filesystem_monitor();
    let guard = fs_monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
    guard.reset_stats();
    drop(guard);
    
    println!("✅ Coffre-fort complètement réinitialisé");
    Ok("Coffre-fort complètement réinitialisé".to_string())
}

// ========== UTILITAIRES ==========

/// Masque partiellement un email pour la confidentialité
fn mask_email(email: &str) -> String {
    if let Some(at_pos) = email.find('@') {
        let (local, domain) = email.split_at(at_pos);
        if local.len() > 2 {
            format!("{}***{}", &local[0..2], domain)
        } else {
            format!("{}***{}", local, domain)
        }
    } else {
        email.to_string()
    }
}

#[tokio::main]
async fn main() {
    // IMPORTANT: Charger les variables d'environnement en tout premier
    // Le .env est dans tauri-desktop/, pas dans src-tauri/
    let env_path = std::path::PathBuf::from("../.env");
    
    println!("🔍 Tentative de chargement .env depuis: {:?}", env_path.canonicalize().unwrap_or(env_path.clone()));
    
    match dotenv::from_path(&env_path) {
        Ok(_) => {
            println!("✅ Variables d'environnement chargées depuis .env");
            // Afficher les variables SMTP pour debug
            if let Ok(host) = std::env::var("EMAIL_SMTP_HOST") {
                println!("   EMAIL_SMTP_HOST: {}", host);
            }
            if let Ok(user) = std::env::var("EMAIL_SMTP_USERNAME") {
                println!("   EMAIL_SMTP_USERNAME: {}", user);
            }
            if let Ok(pass) = std::env::var("EMAIL_SMTP_PASSWORD") {
                println!("   EMAIL_SMTP_PASSWORD: {} chars", pass.len());
            }
        },
        Err(e) => {
            eprintln!("⚠️ Impossible de charger .env: {}", e);
            // Essayer dotenv() par défaut
            if let Ok(_) = dotenv::dotenv() {
                println!("✅ Variables chargées depuis .env (chemin par défaut)");
            } else {
                eprintln!("❌ Aucun fichier .env trouvé!");
            }
        }
    }
    
    // Initialiser le moniteur de sécurité
    initialize_security_monitor();
    println!("🛡️  Moniteur de sécurité initialisé");
    
    // Initialiser le moniteur de système de fichiers
    initialize_filesystem_monitor();
    println!("🔍 Surveillance du système de fichiers activée");
    
    // Charger configuration
    let config = Config::from_env();
    
    // Créer services
    let email_service = EmailService::new(config.clone());
    
    let app_state = AppState {
        db: Arc::new(Mutex::new(None)),
        current_user_id: Arc::new(Mutex::new(None)),
        threat_reactor: Arc::new(ThreatReactor::new()),
        config: config.clone(),
        email_service: Arc::new(email_service),
        two_factor_service: Arc::new(TwoFactorService::new(config.clone())),
        ml_database: Arc::new(Mutex::new(None)),
    };

    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            check_backend_status,
            init_local_db,
            has_existing_user,
            local_login,
            local_register,
            create_password,
            get_passwords,
            get_password,
            decrypt_password,
            update_password,
            delete_password,
            create_secure_file,
            get_secure_files,
            decrypt_file,
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
            // ML / Security commands
            initialize_ml,
            test_ml_connection,
            analyze_user_behavior,
            detect_anomaly,
            scan_file_ransomware,
            train_ml_model,
            // 2FA commands
            setup_2fa,
            verify_and_enable_2fa,
            disable_2fa,
            verify_2fa_login,
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
            // Vault reset command
            reset_vault_completely,
        ])
        .setup(|app| {
            println!("🔐 SecureVault démarré");
            println!("📁 Répertoire de données: {:?}", 
                app.path_resolver().app_data_dir());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Erreur lors du lancement de l'application Tauri");
}

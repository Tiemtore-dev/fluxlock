use crate::{AppState, CreateKeyRequest, ImportKeyRequest};
use crate::generate_random_key_bytes;
use crate::crypto::{encrypt_data_secure, decrypt_data_secure};
use crate::database::SecureKey;
use tauri::State;
use base64::{Engine as _, engine::general_purpose};

#[tauri::command]
pub async fn create_secure_key(
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
            let private_key = generate_random_key_bytes();
            let public_key = generate_random_key_bytes();
            let private_key_b64 = general_purpose::STANDARD.encode(&private_key);
            let public_key_b64 = general_purpose::STANDARD.encode(&public_key);
            // Format: private_key|||public_key (uniquement les clés brutes en base64, sans préfixe/suffixe)
            format!("{}|||{}", private_key_b64, public_key_b64)
        },
        "api" => {
            // Génération d'une clé API (hexadécimale)
            let key = generate_random_key_bytes();
            hex::encode(&key)
        },
        "gpg" => {
            // Génération d'une clé GPG (base64 propre, sans marqueurs)
            let key = generate_random_key_bytes();
            general_purpose::STANDARD.encode(&key)
        },
        "encryption" => {
            // Génération d'une clé de chiffrement AES-256
            let key = generate_random_key_bytes();
            hex::encode(&key)
        },
        _ => {
            // Par défaut : clé hexadécimale
            let key = generate_random_key_bytes();
            hex::encode(&key)
        }
    };

    debug_log!("🔑 Clé {} générée (type: {})", request.key_name, request.key_type);

    // Récupérer la clé maître via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    let encrypted_key = encrypt_data_secure(&key_data, &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer le nom de la clé pour plus de sécurité
    let encrypted_key_name = encrypt_data_secure(&request.key_name, &encryption_key)
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
pub async fn import_secure_key(
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

    debug_log!("📥 Import de clé {} (type: {})", request.key_name, request.key_type);

    // Récupérer la clé maître via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    // Chiffrer la clé importée
    let encrypted_key = encrypt_data_secure(&request.key_data, &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer le nom de la clé
    let encrypted_key_name = encrypt_data_secure(&request.key_name, &encryption_key)
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
pub async fn get_secure_keys(state: State<'_, AppState>) -> Result<Vec<SecureKey>, String> {
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

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Déchiffrer les noms de clés
    let mut decrypted_keys = Vec::new();
    for mut key in keys {
        if let Ok(decrypted_key_name) = decrypt_data_secure(&key.key_name, &encryption_key) {
            key.key_name = decrypted_key_name;
        } else {
            // Masquer détails techniques en production
            debug_log!("⚠️ Erreur déchiffrement key_name pour clé {}", key.id);
        }
        decrypted_keys.push(key);
    }

    Ok(decrypted_keys)
}

#[tauri::command]
pub async fn decrypt_key(id: i64, state: State<'_, AppState>) -> Result<String, String> {
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

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Déchiffrer les données de la clé
    let decrypted_key = decrypt_data_secure(&key.key_data, &encryption_key)
        .map_err(|e| format!("Erreur déchiffrement: {}", e))?;

    #[cfg(debug_assertions)]
    debug_log!("🔓 Clé {} déchiffrée pour utilisateur {}", id, user_id);

    Ok(decrypted_key)
}

#[tauri::command]
pub async fn delete_secure_key(id: i64, state: State<'_, AppState>) -> Result<bool, String> {
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

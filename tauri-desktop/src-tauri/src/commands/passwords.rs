use crate::{AppState, CreatePasswordRequest, UpdatePasswordRequest};
use crate::crypto::{encrypt_data_secure, decrypt_data_secure};
use crate::security_monitor::get_security_monitor;
use crate::database::Password;
use tauri::State;

#[tauri::command]
pub async fn create_password(
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

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    // Chiffrer le mot de passe
    let encrypted_password = encrypt_data_secure(&request.password, &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer TOUS les champs sensibles (titre, username, url, notes, catégorie)
    let encrypted_title = encrypt_data_secure(&request.title, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement titre: {}", e))?;

    let encrypted_username = request.username.as_ref()
        .map(|u| encrypt_data_secure(u, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement username: {}", e))?;
    
    let encrypted_url = request.url.as_ref()
        .map(|u| encrypt_data_secure(u, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement URL: {}", e))?;
    
    let encrypted_notes = request.notes.as_ref()
        .map(|n| encrypt_data_secure(n, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement notes: {}", e))?;

    let encrypted_category = request.category.as_ref()
        .map(|c| encrypt_data_secure(c, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement catégorie: {}", e))?;

    let password_id = db
        .create_password(
            user_id,
            &encrypted_title,
            encrypted_username.as_deref(),
            &encrypted_password,
            encrypted_url.as_deref(),
            encrypted_notes.as_deref(),
            encrypted_category.as_deref(),
        )
        .await
        .map_err(|e| format!("Erreur création mot de passe: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "CREATE", "password", Some(password_id)).await;

    Ok(password_id)
}

#[tauri::command]
pub async fn get_passwords(state: State<'_, AppState>) -> Result<Vec<Password>, String> {
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

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Migration automatique v1→v2 : re-chiffrer en ChaCha20-Poly1305 les entrées AES-256-GCM legacy
    for pw in &passwords {
        let needs_migration = !pw.password.starts_with("v2:");
        if needs_migration {
            // Déchiffrer avec v1 (AES-256-GCM) puis re-chiffrer en v2 (ChaCha20-Poly1305)
            if let Ok(plaintext_pw) = decrypt_data_secure(&pw.password, &encryption_key) {
                if let Ok(v2_pw) = encrypt_data_secure(&plaintext_pw, &encryption_key) {
                    // Re-chiffrer title, username, url, notes, category en v2
                    let v2_title = encrypt_data_secure(&pw.title, &encryption_key).unwrap_or_else(|_| pw.title.clone());
                    let v2_username = pw.username.as_ref().map(|u| encrypt_data_secure(u, &encryption_key).unwrap_or_else(|_| u.clone()));
                    let v2_url = pw.url.as_ref().map(|u| encrypt_data_secure(u, &encryption_key).unwrap_or_else(|_| u.clone()));
                    let v2_notes = pw.notes.as_ref().map(|n| encrypt_data_secure(n, &encryption_key).unwrap_or_else(|_| n.clone()));
                    let v2_category = pw.category.as_ref().map(|c| encrypt_data_secure(c, &encryption_key).unwrap_or_else(|_| c.clone()));
                    let _ = db.update_password(
                        pw.id, user_id,
                        &v2_title,
                        v2_username.as_deref(),
                        &v2_pw,
                        v2_url.as_deref(),
                        v2_notes.as_deref(),
                        v2_category.as_deref(),
                    ).await;
                    if cfg!(debug_assertions) {
                        eprintln!("🔄 Migration v1→v2 effectuée pour le mot de passe {}", pw.id);
                    }
                }
            }
        }
    }

    // Re-lire les mots de passe après migration éventuelle
    let passwords = if passwords.iter().any(|pw| !pw.password.starts_with("v2:")) {
        db.get_passwords(user_id).await
            .map_err(|e| format!("Erreur récupération mots de passe: {}", e))?
    } else {
        passwords
    };

    // Déchiffrer tous les mots de passe et leurs champs sensibles avant de les renvoyer
    let mut decrypted_passwords = Vec::new();
    for mut password in passwords {
        // Déchiffrer le mot de passe
        match decrypt_data_secure(&password.password, &encryption_key) {
            Ok(decrypted) => {
                password.password = decrypted;
            }
            Err(_e) => {
                if cfg!(debug_assertions) {
                    eprintln!("⚠️ Erreur déchiffrement mot de passe {} (debug): {}", password.id, _e);
                } else {
                    eprintln!("⚠️ Erreur déchiffrement mot de passe {}", password.id);
                }
            }
        }
        
        // Déchiffrer le titre (chiffré depuis V-02)
        if let Ok(decrypted) = decrypt_data_secure(&password.title, &encryption_key) {
            password.title = decrypted;
        }

        // Déchiffrer username si présent
        if let Some(ref username) = password.username {
            if let Ok(decrypted) = decrypt_data_secure(username, &encryption_key) {
                password.username = Some(decrypted);
            }
        }
        
        // Déchiffrer URL si présente
        if let Some(ref url) = password.url {
            if let Ok(decrypted) = decrypt_data_secure(url, &encryption_key) {
                password.url = Some(decrypted);
            }
        }
        
        // Déchiffrer notes si présentes
        if let Some(ref notes) = password.notes {
            if let Ok(decrypted) = decrypt_data_secure(notes, &encryption_key) {
                password.notes = Some(decrypted);
            }
        }

        // Déchiffrer catégorie si présente
        if let Some(ref category) = password.category {
            if let Ok(decrypted) = decrypt_data_secure(category, &encryption_key) {
                password.category = Some(decrypted);
            }
        }
        
        decrypted_passwords.push(password);
    }

    Ok(decrypted_passwords)
}

#[tauri::command]
pub async fn get_password(id: i64, state: State<'_, AppState>) -> Result<Option<Password>, String> {
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
pub async fn decrypt_password(encrypted: String, state: State<'_, AppState>) -> Result<String, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;
    
    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    let decrypted = decrypt_data_secure(&encrypted, &encryption_key)
        .map_err(|e| format!("Erreur de déchiffrement: {}", e))?;

    Ok(decrypted)
}

#[tauri::command]
pub async fn update_password(
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

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    // Chiffrer le mot de passe
    let encrypted_password = encrypt_data_secure(&request.password, &encryption_key)
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer TOUS les champs sensibles (titre, username, url, notes, catégorie)
    let encrypted_title = encrypt_data_secure(&request.title, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement titre: {}", e))?;

    let encrypted_username = request.username.as_ref()
        .map(|u| encrypt_data_secure(u, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement username: {}", e))?;
    
    let encrypted_url = request.url.as_ref()
        .map(|u| encrypt_data_secure(u, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement URL: {}", e))?;
    
    let encrypted_notes = request.notes.as_ref()
        .map(|n| encrypt_data_secure(n, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement notes: {}", e))?;

    let encrypted_category = request.category.as_ref()
        .map(|c| encrypt_data_secure(c, &encryption_key))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement catégorie: {}", e))?;

    let updated = db
        .update_password(
            request.id,
            user_id,
            &encrypted_title,
            encrypted_username.as_deref(),
            &encrypted_password,
            encrypted_url.as_deref(),
            encrypted_notes.as_deref(),
            encrypted_category.as_deref(),
        )
        .await
        .map_err(|e| format!("Erreur mise à jour mot de passe: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "UPDATE", "password", Some(request.id)).await;

    Ok(updated)
}

#[tauri::command]
pub async fn delete_password(id: i64, state: State<'_, AppState>) -> Result<bool, String> {
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

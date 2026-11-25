use crate::{AppState, CreatePasswordRequest, UpdatePasswordRequest};
use crate::crypto::{encrypt_field_secure, decrypt_field_secure, V2_AAD_PREFIX};
use crate::security_monitor::get_security_monitor;
use crate::database::Password;
use tauri::State;
use zeroize::Zeroizing;

const TABLE_PASSWORDS: &str = "passwords";

#[tauri::command]
pub async fn create_password(
    request: CreatePasswordRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
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
    
    // Chiffrer chaque champ avec son AAD contextuelle (user_id + table + colonne) — RFC 8439
    let encrypted_password = encrypt_field_secure(&request.password, &encryption_key, user_id, TABLE_PASSWORDS, "password")
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    let encrypted_title = encrypt_field_secure(&request.title, &encryption_key, user_id, TABLE_PASSWORDS, "title")
        .map_err(|e| format!("Erreur chiffrement titre: {}", e))?;

    let encrypted_username = request.username.as_ref()
        .map(|u| encrypt_field_secure(u, &encryption_key, user_id, TABLE_PASSWORDS, "username"))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement username: {}", e))?;
    
    let encrypted_url = request.url.as_ref()
        .map(|u| encrypt_field_secure(u, &encryption_key, user_id, TABLE_PASSWORDS, "url"))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement URL: {}", e))?;
    
    let encrypted_notes = request.notes.as_ref()
        .map(|n| encrypt_field_secure(n, &encryption_key, user_id, TABLE_PASSWORDS, "notes"))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement notes: {}", e))?;

    let encrypted_category = request.category.as_ref()
        .map(|c| encrypt_field_secure(c, &encryption_key, user_id, TABLE_PASSWORDS, "category"))
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

    if let Some(ref totp_raw) = request.totp_secret {
        let trimmed = totp_raw.trim();
        if !trimmed.is_empty() {
            secure_vault_crypto::TotpConfig::parse(trimmed)
                .map_err(|e| format!("Secret TOTP invalide (RFC 6238): {}", e))?;
            let encrypted_totp = encrypt_field_secure(trimmed, &encryption_key, user_id, TABLE_PASSWORDS, "totp_secret")
                .map_err(|e| format!("Erreur chiffrement TOTP: {}", e))?;
            db.set_password_totp_secret(password_id, user_id, Some(&encrypted_totp))
                .await
                .map_err(|e| format!("Erreur enregistrement TOTP: {}", e))?;
        }
    }

    // Log l'action
    let _ = db.log_action(user_id, "CREATE", "password", Some(password_id)).await;

    Ok(password_id)
}

#[tauri::command]
pub async fn get_passwords(state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Vec<Password>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
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

    // Migration automatique v1 / v2 sans AAD → v2:aad: (ChaCha20-Poly1305 avec liaison AAD par colonne)
    let mut migrated_any = false;
    for pw in &passwords {
        let needs_migration = !pw.password.starts_with(V2_AAD_PREFIX);
        if needs_migration {
            if let Ok(plaintext_pw) = decrypt_field_secure(&pw.password, &encryption_key, user_id, TABLE_PASSWORDS, "password") {
                let plaintext_pw = Zeroizing::new(plaintext_pw);
                if let Ok(v2_pw) = encrypt_field_secure(&plaintext_pw, &encryption_key, user_id, TABLE_PASSWORDS, "password") {
                    let plain_title = decrypt_field_secure(&pw.title, &encryption_key, user_id, TABLE_PASSWORDS, "title")
                        .unwrap_or_else(|_| pw.title.clone());
                    let v2_title = encrypt_field_secure(&plain_title, &encryption_key, user_id, TABLE_PASSWORDS, "title")
                        .unwrap_or_else(|_| pw.title.clone());

                    let v2_username = pw.username.as_ref().map(|u| {
                        let plain = decrypt_field_secure(u, &encryption_key, user_id, TABLE_PASSWORDS, "username")
                            .unwrap_or_else(|_| u.clone());
                        encrypt_field_secure(&plain, &encryption_key, user_id, TABLE_PASSWORDS, "username")
                            .unwrap_or_else(|_| u.clone())
                    });
                    let v2_url = pw.url.as_ref().map(|u| {
                        let plain = decrypt_field_secure(u, &encryption_key, user_id, TABLE_PASSWORDS, "url")
                            .unwrap_or_else(|_| u.clone());
                        encrypt_field_secure(&plain, &encryption_key, user_id, TABLE_PASSWORDS, "url")
                            .unwrap_or_else(|_| u.clone())
                    });
                    let v2_notes = pw.notes.as_ref().map(|n| {
                        let plain = decrypt_field_secure(n, &encryption_key, user_id, TABLE_PASSWORDS, "notes")
                            .unwrap_or_else(|_| n.clone());
                        encrypt_field_secure(&plain, &encryption_key, user_id, TABLE_PASSWORDS, "notes")
                            .unwrap_or_else(|_| n.clone())
                    });
                    let v2_category = pw.category.as_ref().map(|c| {
                        let plain = decrypt_field_secure(c, &encryption_key, user_id, TABLE_PASSWORDS, "category")
                            .unwrap_or_else(|_| c.clone());
                        encrypt_field_secure(&plain, &encryption_key, user_id, TABLE_PASSWORDS, "category")
                            .unwrap_or_else(|_| c.clone())
                    });
                    let _ = db.update_password(
                        pw.id, user_id,
                        &v2_title,
                        v2_username.as_deref(),
                        &v2_pw,
                        v2_url.as_deref(),
                        v2_notes.as_deref(),
                        v2_category.as_deref(),
                    ).await;
                    migrated_any = true;
                }
            }
        }
    }

    // Re-lire les mots de passe après migration éventuelle
    let passwords = if migrated_any {
        db.get_passwords(user_id).await
            .map_err(|e| format!("Erreur récupération mots de passe: {}", e))?
    } else {
        passwords
    };

    // LAZY DECRYPTION : Déchiffrer uniquement les métadonnées d'affichage/recherche (titre, username, url, notes, catégorie).
    // Le secret `password.password` reste chiffré (`v2:aad:...`) et n'est déchiffré unitairement
    // via `decrypt_password` que lorsque l'utilisateur demande explicitement à le copier, le révéler ou l'éditer.
    let mut decrypted_passwords = Vec::with_capacity(passwords.len());
    for mut password in passwords {
        if let Ok(decrypted) = decrypt_field_secure(&password.title, &encryption_key, user_id, TABLE_PASSWORDS, "title") {
            password.title = decrypted;
        }

        if let Some(ref username) = password.username {
            if let Ok(decrypted) = decrypt_field_secure(username, &encryption_key, user_id, TABLE_PASSWORDS, "username") {
                password.username = Some(decrypted);
            }
        }
        
        if let Some(ref url) = password.url {
            if let Ok(decrypted) = decrypt_field_secure(url, &encryption_key, user_id, TABLE_PASSWORDS, "url") {
                password.url = Some(decrypted);
            }
        }
        
        if let Some(ref notes) = password.notes {
            if let Ok(decrypted) = decrypt_field_secure(notes, &encryption_key, user_id, TABLE_PASSWORDS, "notes") {
                password.notes = Some(decrypted);
            }
        }

        if let Some(ref category) = password.category {
            if let Ok(decrypted) = decrypt_field_secure(category, &encryption_key, user_id, TABLE_PASSWORDS, "category") {
                password.category = Some(decrypted);
            }
        }

        // Ne jamais exposer la graine TOTP au frontend : indiquer uniquement `has_totp = true`
        password.has_totp = password
            .totp_secret
            .as_ref()
            .is_some_and(|s| !s.trim().is_empty());
        password.totp_secret = None;
        
        decrypted_passwords.push(password);
    }

    Ok(decrypted_passwords)
}

#[tauri::command]
pub async fn get_password(id: i64, state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Option<Password>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
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
pub async fn decrypt_password(encrypted: String, state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;
    
    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    let decrypted = decrypt_field_secure(&encrypted, &encryption_key, user_id, TABLE_PASSWORDS, "password")
        .map_err(|e| format!("Erreur de déchiffrement: {}", e))?;

    Ok(decrypted)
}

#[tauri::command]
pub async fn update_password(
    request: UpdatePasswordRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<bool, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
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
    
    // Chiffrer TOUS les champs sensibles avec leur AAD contextuelle
    let encrypted_password = encrypt_field_secure(&request.password, &encryption_key, user_id, TABLE_PASSWORDS, "password")
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    let encrypted_title = encrypt_field_secure(&request.title, &encryption_key, user_id, TABLE_PASSWORDS, "title")
        .map_err(|e| format!("Erreur chiffrement titre: {}", e))?;

    let encrypted_username = request.username.as_ref()
        .map(|u| encrypt_field_secure(u, &encryption_key, user_id, TABLE_PASSWORDS, "username"))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement username: {}", e))?;
    
    let encrypted_url = request.url.as_ref()
        .map(|u| encrypt_field_secure(u, &encryption_key, user_id, TABLE_PASSWORDS, "url"))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement URL: {}", e))?;
    
    let encrypted_notes = request.notes.as_ref()
        .map(|n| encrypt_field_secure(n, &encryption_key, user_id, TABLE_PASSWORDS, "notes"))
        .transpose()
        .map_err(|e| format!("Erreur chiffrement notes: {}", e))?;

    let encrypted_category = request.category.as_ref()
        .map(|c| encrypt_field_secure(c, &encryption_key, user_id, TABLE_PASSWORDS, "category"))
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

    if let Some(ref totp_raw) = request.totp_secret {
        let trimmed = totp_raw.trim();
        if trimmed.is_empty() {
            db.set_password_totp_secret(request.id, user_id, None)
                .await
                .map_err(|e| format!("Erreur suppression TOTP: {}", e))?;
        } else if !trimmed.starts_with(V2_AAD_PREFIX) {
            secure_vault_crypto::TotpConfig::parse(trimmed)
                .map_err(|e| format!("Secret TOTP invalide (RFC 6238): {}", e))?;
            let encrypted_totp = encrypt_field_secure(trimmed, &encryption_key, user_id, TABLE_PASSWORDS, "totp_secret")
                .map_err(|e| format!("Erreur chiffrement TOTP: {}", e))?;
            db.set_password_totp_secret(request.id, user_id, Some(&encrypted_totp))
                .await
                .map_err(|e| format!("Erreur mise à jour TOTP: {}", e))?;
        }
    }

    // Log l'action
    let _ = db.log_action(user_id, "UPDATE", "password", Some(request.id)).await;

    Ok(updated)
}

/// Génère un code TOTP à 6 ou 8 chiffres (RFC 6238) côté Rust à partir de la graine chiffrée
/// associée à une entrée du coffre, sans jamais exposer la graine Base32 au frontend.
#[tauri::command]
pub async fn generate_password_totp(
    id: i64,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<secure_vault_crypto::TotpOutput, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let pw = db
        .get_password(id, user_id)
        .await
        .map_err(|e| format!("Erreur récupération entrée: {}", e))?
        .ok_or("Entrée introuvable")?;

    let encrypted_totp = pw
        .totp_secret
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .ok_or("Aucun secret TOTP configuré pour cet identifiant")?;

    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    let decrypted_secret = Zeroizing::new(
        decrypt_field_secure(encrypted_totp, &encryption_key, user_id, TABLE_PASSWORDS, "totp_secret")
            .map_err(|e| format!("Erreur déchiffrement TOTP: {}", e))?,
    );

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Horloge système invalide: {}", e))?
        .as_secs();

    secure_vault_crypto::generate_totp(&decrypted_secret, now_unix)
        .map_err(|e| format!("Erreur génération TOTP RFC 6238: {}", e))
}

#[tauri::command]
pub async fn delete_password(id: i64, state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<bool, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
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

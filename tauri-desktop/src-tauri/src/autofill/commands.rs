use super::*;
use tauri::{State, WebviewWindow};

#[derive(Serialize)]
pub struct BridgeStatus {
    pub enabled: bool,
    pub listening: bool,
    pub native_host_installed: bool,
    pub extension_id: String,
    pub profiles: Vec<identity::Profile>,
}
#[tauri::command]
pub async fn autofill_settings(
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<BridgeStatus, String> {
    let _life = crate::vault::access(&state, &context).await?;
    let identity = state.autofill.identity.lock().await;
    let enabled = identity.is_some();
    let mut host_status = super::host_relay::current_status();
    if enabled && !host_status.installed {
        if let Ok(installed) = super::host_relay::ensure_installed(None) {
            host_status = installed;
        }
    }
    Ok(BridgeStatus {
        enabled,
        listening: state.autofill.listening.load(Ordering::SeqCst),
        native_host_installed: host_status.installed,
        extension_id: host_status.extension_id,
        profiles: identity.as_ref().map_or_else(Vec::new, |i| {
            i.profiles
                .iter()
                .filter(|p| p.vault_id == context.vault_id)
                .cloned()
                .collect()
        }),
    })
}
#[tauri::command]
pub async fn autofill_enable(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
    extension_id: Option<String>,
) -> Result<(), String> {
    let _life = crate::vault::access(&state, &context).await?;
    let mut guard = state.autofill.identity.lock().await;
    if guard.is_none() {
        *guard = identity::load(true).await?;
    }
    drop(guard);
    let _ = super::host_relay::ensure_installed(extension_id.as_deref())?;
    ipc::start_listener(app).await
}
#[tauri::command]
pub async fn autofill_start_pairing(
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<(), String> {
    let _life = crate::vault::access(&state, &context).await?;
    if state.autofill.identity.lock().await.is_none() {
        return Err("Activez la passerelle navigateur".into());
    }
    *state.autofill.pairing.lock().await =
        Some((context.vault_id, Instant::now() + Duration::from_secs(60)));
    Ok(())
}
#[tauri::command]
pub async fn autofill_revoke(
    public: String,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<(), String> {
    let _life = state.auth_lifecycle.write().await;
    crate::vault::check_context(&state, &context, true).await?;
    crate::validate_session(&state).await?;
    let mut guard = state.autofill.identity.lock().await;
    let mut next = guard.as_ref().ok_or("Passerelle inactive")?.clone();
    next.profiles
        .retain(|p| !(p.public == public && p.vault_id == context.vault_id));
    identity::save(next.clone()).await?;
    *guard = Some(next);
    drop(guard);
    state.autofill.cancel().await;
    Ok(())
}
fn check_window(p: &Pending, id: &str, window: &WebviewWindow) -> Result<(), String> {
    if p.id != id || p.window != window.label() || Instant::now() >= p.expires {
        return Err("Fenêtre ou demande expirée".into());
    }
    Ok(())
}
#[tauri::command]
pub async fn autofill_prompt(
    request_id: String,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let _life = state.auth_lifecycle.read().await;
    let guard = state.autofill.pending.lock().await;
    let p = guard.as_ref().ok_or("Demande expirée")?;
    check_window(p, &request_id, &window)?;
    let kind = if p.target.is_none() {
        "pair"
    } else if p.save_payload.is_some() {
        "save"
    } else if p.passkey_request.is_some() {
        "passkey"
    } else if p.card_mode {
        "fill_card"
    } else {
        "fill"
    };
    let save_username = p
        .save_payload
        .as_ref()
        .map(|(u, _)| u.as_str())
        .or_else(|| p.passkey_request.as_ref().map(|r| r.username.as_str()));
    Ok(
        serde_json::json!({"kind":kind,"origin":p.target.as_ref().map(|t|&t.origin),"username":save_username,"fingerprint":p.fingerprint,"browser_confirmed":p.browser_confirmed}),
    )
}
#[tauri::command]
pub async fn autofill_confirm_pair(
    request_id: String,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let _life = state.auth_lifecycle.write().await;
    let vault = selected(&state).await?;
    crate::validate_session(&state).await?;
    let mut guard = state.autofill.pending.lock().await;
    let p = guard.as_mut().ok_or("Demande absente")?;
    check_window(p, &request_id, &window)?;
    if p.target.is_some() || p.vault_id != vault {
        return Err("Appairage refusé".into());
    }
    p.native_confirmed = true;
    drop(guard);
    state.autofill.finish_pair().await?;
    let _ = window.close();
    Ok(())
}
#[tauri::command]
pub async fn autofill_cancel_native(
    request_id: String,
    window: WebviewWindow,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let _life = state.auth_lifecycle.write().await;
    let mut guard = state.autofill.pending.lock().await;
    let p = guard.as_ref().ok_or("Demande absente")?;
    check_window(p, &request_id, &window)?;
    guard.take();
    state.autofill.busy.store(false, Ordering::SeqCst);
    let _ = window.close();
    Ok(())
}
#[tauri::command]
pub async fn autofill_authenticate(
    request_id: String,
    password: Option<String>,
    window: WebviewWindow,
    app: tauri::AppHandle,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let password = password.map(Zeroizing::new);
    let (user, dir, expected_vault) = {
        let _life = state.auth_lifecycle.write().await;
        let vault = selected(&state).await?;
        let mut guard = state.autofill.pending.lock().await;
        let p = guard.as_mut().ok_or("Demande absente")?;
        check_window(p, &request_id, &window)?;
        if p.target.is_none() || p.vault_id != vault || p.authenticated || p.verifying {
            return Err("Authentification refusée".into());
        }
        p.accepted = true;
        p.verifying = true;
        state.autofill.busy.store(true, Ordering::SeqCst);
        crate::commands::session::lock_vault_data(&state).await;
        let db_guard = state.db.lock().await;
        let db = db_guard.as_ref().ok_or("Base indisponible")?;
        let user = db
            .get_vault_owner()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Compte absent")?;
        let dir = state.data_dir.lock().await.clone().ok_or("Coffre absent")?;
        (user, dir, vault)
    };
    let _ = app.emit("autofill-vault-locked", ());
    // No lifecycle or coordinator mutex is held while the OS waits for the user.
    let verification = async {
        if let Some(password) = password.as_ref() {
            // Bind the verifier's DB reads/writes to the original vault too,
            // not only the eventual key admission after verification.
            let _life = state.auth_lifecycle.read().await;
            if selected(&state).await? != expected_vault {
                return Err("Le coffre a changé".into());
            }
            {
                let pending = state.autofill.pending.lock().await;
                let p = pending.as_ref().ok_or("Demande annulée")?;
                check_window(p, &request_id, &window)?;
                if !p.verifying || p.vault_id != expected_vault {
                    return Err("Demande annulée".into());
                }
            }
            let guard = state.db.lock().await;
            let db = guard.as_ref().ok_or("Base indisponible")?;
            crate::commands::auth::verify_vault_password(db, &user, password).await
        } else {
            {
                let _life = state.auth_lifecycle.read().await;
                if selected(&state).await? != expected_vault {
                    return Err("Le coffre a changé".into());
                }
                {
                    let pending = state.autofill.pending.lock().await;
                    let p = pending.as_ref().ok_or("Demande annulée")?;
                    check_window(p, &request_id, &window)?;
                    if !p.verifying || p.vault_id != expected_vault {
                        return Err("Demande annulée".into());
                    }
                }
                let guard = state.db.lock().await;
                let db = guard.as_ref().ok_or("Base indisponible")?;
                if db
                    .check_account_locked(user.id)
                    .await
                    .map_err(|e| e.to_string())?
                    || crate::commands::auth::login_delay(db, &user).await? > 0
                {
                    return Err("Compte temporairement bloqué".into());
                }
            }
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                let account = user.clone();
                tokio::time::timeout(
                    Duration::from_secs(30),
                    tokio::task::spawn_blocking(move || {
                        let (id, _, bytes) =
                            crate::biometric::biometric_login(&dir, &account.username, account.id)?;
                        let key = SecureKey::new(bytes);
                        crate::commands::biometric_cmds::validate_enrolled_key(&account, id, &key)?;
                        Ok::<_, String>(key)
                    }),
                )
                .await
                .map_err(|_| "Dialogue biométrique expiré")?
                .map_err(|_| "Dialogue biométrique interrompu")?
            }
            #[cfg(any(target_os = "android", target_os = "ios"))]
            {
                let _ = dir;
                Err("L’extension nécessite une authentification de bureau".into())
            }
        }
    }
    .await;
    let _life = state.auth_lifecycle.write().await;
    let vault = selected(&state).await?;
    let mut guard = state.autofill.pending.lock().await;
    let p = guard.as_mut().ok_or("Demande annulée")?;
    check_window(p, &request_id, &window)?;
    if p.vault_id != vault || !p.verifying {
        return Err("Demande annulée".into());
    }
    p.verifying = false;
    let key = verification?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base indisponible")?;
    let target_origin = p.target.as_ref().ok_or("Site absent")?.origin.clone();

    if let Some((save_username, save_password)) = p.save_payload.take() {
        // Capture & Save : enregistre ou met à jour l'identifiant capturé depuis le navigateur
        // avec chiffrement ChaCha20-Poly1305 lié par AAD (v2:aad:), puis verrouille immédiatement le coffre.
        let enc_pw = crate::crypto::encrypt_field_secure(
            &save_password,
            &key,
            user.id,
            "passwords",
            "password",
        )?;
        let title_str = target_origin
            .strip_prefix("https://")
            .unwrap_or(&target_origin)
            .to_string();
        let enc_title = crate::crypto::encrypt_field_secure(
            &title_str,
            &key,
            user.id,
            "passwords",
            "title",
        )?;
        let enc_user = if save_username.is_empty() {
            None
        } else {
            Some(crate::crypto::encrypt_field_secure(
                &save_username,
                &key,
                user.id,
                "passwords",
                "username",
            )?)
        };
        let enc_url = crate::crypto::encrypt_field_secure(
            &target_origin,
            &key,
            user.id,
            "passwords",
            "url",
        )?;
        let enc_cat = crate::crypto::encrypt_field_secure(
            "Web",
            &key,
            user.id,
            "passwords",
            "category",
        )?;

        // Vérifier s'il existe déjà une entrée pour cette origine et ce même username
        let existing_rows = db.get_passwords(user.id).await.map_err(|e| e.to_string())?;
        let mut updated_existing = false;
        for row in existing_rows {
            let Some(ref u_enc) = row.url else { continue };
            let Ok(u_plain) = crate::crypto::decrypt_field_secure(u_enc, &key, user.id, "passwords", "url") else { continue };
            if super::origin::canonical(&u_plain).ok().as_deref() != Some(target_origin.as_str()) {
                continue;
            }
            let row_user = row
                .username
                .as_ref()
                .and_then(|usr| crate::crypto::decrypt_field_secure(usr, &key, user.id, "passwords", "username").ok())
                .unwrap_or_default();
            if row_user == save_username {
                db.update_password(
                    row.id,
                    user.id,
                    &row.title,
                    enc_user.as_deref(),
                    &enc_pw,
                    Some(&enc_url),
                    row.notes.as_deref(),
                    row.category.as_deref(),
                )
                .await
                .map_err(|e| e.to_string())?;
                let _ = db.log_action(user.id, "UPDATE", "password", Some(row.id)).await;
                updated_existing = true;
                break;
            }
        }

        if !updated_existing {
            let new_id = db
                .create_password(
                    user.id,
                    &enc_title,
                    enc_user.as_deref(),
                    &enc_pw,
                    Some(&enc_url),
                    None,
                    Some(&enc_cat),
                )
                .await
                .map_err(|e| e.to_string())?;
            let _ = db.log_action(user.id, "CREATE", "password", Some(new_id)).await;
        }

        check_window(p, &request_id, &window)?;
        p.saved_done = true;
        p.authenticated = true;
        p.key = None; // Zeroize la clé immédiatement après écriture SQLite
        p.expires = Instant::now() + Duration::from_secs(30);
        drop(db_guard);
        drop(guard);
        crate::commands::session::lock_vault_data(&state).await;
        let _ = app.emit("autofill-vault-locked", ());
        let _ = window.close();
        return Ok(());
    }

    if let Some(pk_req) = p.passkey_request.take() {
        // Cérémonie Passkey WebAuthn Level 3 Zéro-Friction :
        // 1. Si une Passkey existe déjà pour ce rp_id (et ce compte), signe immédiatement une assertion webauthn.get.
        // 2. Sinon, génère une nouvelle Passkey résidente COSE EdDSA (-8) webauthn.create, chiffre la clé privée (v2:aad:)
        //    et retourne uniquement la clé publique et l'attestation.
        let existing_pks = db.get_passkeys(user.id).await.map_err(|e| e.to_string())?;
        let mut matched_pk = None;
        for row in existing_pks {
            if row.rp_id.eq_ignore_ascii_case(&pk_req.rp_id) {
                let row_user = crate::crypto::decrypt_field_secure(
                    &row.user_name,
                    &key,
                    user.id,
                    "passkeys",
                    "user_name",
                )
                .unwrap_or_default();
                if pk_req.username.is_empty() || row_user.eq_ignore_ascii_case(&pk_req.username) {
                    matched_pk = Some((row, row_user));
                    break;
                }
            }
        }

        let passkey_json = if let Some((pk_row, row_user)) = matched_pk {
            let priv_b64 = Zeroizing::new(crate::crypto::decrypt_field_secure(
                &pk_row.private_key,
                &key,
                user.id,
                "passkeys",
                "private_key",
            )?);
            let user_handle = crate::crypto::decrypt_field_secure(
                &pk_row.user_handle,
                &key,
                user.id,
                "passkeys",
                "user_handle",
            )
            .ok();
            let assertion = secure_vault_crypto::authenticate_passkey_assertion(
                &pk_row.rp_id,
                &pk_row.credential_id,
                &priv_b64,
                pk_row.sign_count as u32,
                &pk_req.challenge_b64url,
                &target_origin,
                user_handle.as_deref(),
            )
            .map_err(|e| format!("Erreur signature Passkey: {}", e))?;
            db.update_passkey_sign_count(pk_row.id, user.id, assertion.new_sign_count as i64)
                .await
                .map_err(|e| e.to_string())?;
            let _ = db.log_action(user.id, "AUTHENTICATE", "passkey", Some(pk_row.id)).await;
            serde_json::json!({
                "state": "passkey_once",
                "mode": "get",
                "request_id": p.id,
                "credential_id_b64url": assertion.credential_id_b64url,
                "rp_id": assertion.rp_id,
                "user_name": row_user,
                "user_handle_b64url": assertion.user_handle_b64url,
                "authenticator_data_b64url": assertion.authenticator_data_b64url,
                "client_data_json_b64url": assertion.client_data_json_b64url,
                "signature_b64url": assertion.signature_b64url,
                "new_sign_count": assertion.new_sign_count,
            })
        } else {
            let effective_user = if pk_req.username.is_empty() {
                user.email.clone()
            } else {
                pk_req.username.clone()
            };
            let user_handle_raw = format!("fluxlock-user-{}-{}", user.id, effective_user);
            let created = secure_vault_crypto::create_passkey_credential(
                &pk_req.rp_id,
                &pk_req.rp_name,
                user_handle_raw.as_bytes(),
                &effective_user,
                &effective_user,
                &pk_req.challenge_b64url,
                &target_origin,
            )
            .map_err(|e| format!("Erreur création Passkey: {}", e))?;

            let enc_handle = crate::crypto::encrypt_field_secure(
                &created.user_handle_b64url,
                &key,
                user.id,
                "passkeys",
                "user_handle",
            )?;
            let enc_uname = crate::crypto::encrypt_field_secure(
                &created.user_name,
                &key,
                user.id,
                "passkeys",
                "user_name",
            )?;
            let enc_dname = crate::crypto::encrypt_field_secure(
                &created.user_display_name,
                &key,
                user.id,
                "passkeys",
                "user_display_name",
            )?;
            let enc_priv = crate::crypto::encrypt_field_secure(
                &created.private_key_b64url,
                &key,
                user.id,
                "passkeys",
                "private_key",
            )?;

            let pk_id = db
                .create_passkey(
                    user.id,
                    &created.credential_id_b64url,
                    &created.rp_id,
                    &created.rp_name,
                    &enc_handle,
                    &enc_uname,
                    &enc_dname,
                    created.cose_algorithm as i64,
                    &created.public_key_b64url,
                    &enc_priv,
                )
                .await
                .map_err(|e| e.to_string())?;
            let _ = db.log_action(user.id, "CREATE", "passkey", Some(pk_id)).await;
            serde_json::json!({
                "state": "passkey_once",
                "mode": "create",
                "request_id": p.id,
                "credential_id_b64url": created.credential_id_b64url,
                "rp_id": created.rp_id,
                "user_name": created.user_name,
                "user_handle_b64url": created.user_handle_b64url,
                "public_key_b64url": created.public_key_b64url,
                "cose_public_key_b64url": created.cose_public_key_b64url,
                "authenticator_data_b64url": created.authenticator_data_b64url,
                "client_data_json_b64url": created.client_data_json_b64url,
            })
        };

        check_window(p, &request_id, &window)?;
        p.passkey_result = Some(passkey_json);
        p.authenticated = true;
        p.key = None; // Zeroize la clé maître immédiatement après signature/création
        p.expires = Instant::now() + Duration::from_secs(30);
        drop(db_guard);
        drop(guard);
        crate::commands::session::lock_vault_data(&state).await;
        let _ = app.emit("autofill-vault-locked", ());
        let _ = window.close();
        return Ok(());
    }

    if p.card_mode {
        let found_cards = super::card_candidates(db, &key, user.id).await?;
        check_window(p, &request_id, &window)?;
        p.card_candidates = found_cards;
    } else {
        let found = candidates(db, &key, user.id, &target_origin).await?;
        check_window(p, &request_id, &window)?;
        p.candidates = found;
    }
    p.user = user.id;
    p.key = Some(key);
    p.authenticated = true;
    p.expires = Instant::now() + Duration::from_secs(30);
    drop(db_guard);
    drop(guard);
    let _ = window.close();
    Ok(())
}

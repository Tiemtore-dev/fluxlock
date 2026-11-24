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
    Ok(
        serde_json::json!({"kind":if p.target.is_some(){"fill"}else{"pair"},"origin":p.target.as_ref().map(|t|&t.origin),"fingerprint":p.fingerprint,"browser_confirmed":p.browser_confirmed}),
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
    let found = candidates(
        db,
        &key,
        user.id,
        &p.target.as_ref().ok_or("Site absent")?.origin,
    )
    .await?;
    check_window(p, &request_id, &window)?;
    p.candidates = found;
    p.user = user.id;
    p.key = Some(key);
    p.authenticated = true;
    p.expires = Instant::now() + Duration::from_secs(30);
    drop(db_guard);
    drop(guard);
    let _ = window.close();
    Ok(())
}

//! Commandes Tauri pour l'authentificateur logiciel Passkeys (W3C WebAuthn Level 3 / FIDO2 CTAP2)
//!
//! - Génération de clés résidentes (Discoverable Credentials) COSE `EdDSA` (`alg = -8`, Ed25519)
//! - Flags `UP | UV | BE | BS` conformes aux Passkeys multi-appareils synchronisées
//! - Chiffrement ChaCha20-Poly1305 avec liaison AAD (`user_id`, `"passkeys"`, `"private_key"`)
//! - Signature d'assertions `webauthn.get` avec incrémentation atomique du compteur `sign_count`

use crate::crypto::{decrypt_field_secure, encrypt_field_secure};
use crate::database::PasskeyEntry;
use crate::security_monitor::get_security_monitor;
use crate::AppState;
use secure_vault_crypto::{
    authenticate_passkey_assertion, create_passkey_credential, CreatedPasskey, PasskeyAssertion,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

pub const TABLE_PASSKEYS: &str = "passkeys";

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePasskeyRequest {
    pub rp_id: String,
    pub rp_name: String,
    pub user_name: String,
    pub user_display_name: String,
    pub challenge_b64url: Option<String>,
    pub origin: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatePasskeyRequest {
    pub id: i64,
    pub challenge_b64url: String,
    pub origin: Option<String>,
}

#[tauri::command]
pub async fn create_passkey_entry(
    request: CreatePasskeyRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<CreatedPasskey, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".into());
    }

    let rp_id = request.rp_id.trim().to_ascii_lowercase();
    if rp_id.is_empty() || request.user_name.trim().is_empty() {
        return Err("Le domaine Relying Party (rp_id) et l'identifiant utilisateur sont requis".into());
    }

    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let challenge = request
        .challenge_b64url
        .unwrap_or_else(|| "Zmx1eGxvY2std2ViYXV0aG4tY3JlYXRl".to_string());
    let origin = request
        .origin
        .unwrap_or_else(|| format!("https://{}", rp_id));
    let user_handle = format!("fluxlock-user-{}-{}", user_id, request.user_name.trim());

    let mut created = create_passkey_credential(
        &rp_id,
        request.rp_name.trim(),
        user_handle.as_bytes(),
        request.user_name.trim(),
        request.user_display_name.trim(),
        &challenge,
        &origin,
    )
    .map_err(|e| format!("Erreur création Passkey WebAuthn: {}", e))?;

    let enc_user_handle = encrypt_field_secure(
        &created.user_handle_b64url,
        &key,
        user_id,
        TABLE_PASSKEYS,
        "user_handle",
    )?;
    let enc_user_name = encrypt_field_secure(
        &created.user_name,
        &key,
        user_id,
        TABLE_PASSKEYS,
        "user_name",
    )?;
    let enc_display_name = encrypt_field_secure(
        &created.user_display_name,
        &key,
        user_id,
        TABLE_PASSKEYS,
        "user_display_name",
    )?;
    let enc_private_key = encrypt_field_secure(
        &created.private_key_b64url,
        &key,
        user_id,
        TABLE_PASSKEYS,
        "private_key",
    )?;

    let passkey_id = db
        .create_passkey(
            user_id,
            &created.credential_id_b64url,
            &created.rp_id,
            &created.rp_name,
            &enc_user_handle,
            &enc_user_name,
            &enc_display_name,
            created.cose_algorithm as i64,
            &created.public_key_b64url,
            &enc_private_key,
        )
        .await
        .map_err(|e| format!("Erreur stockage Passkey: {}", e))?;

    // Ne jamais retourner la clé privée au frontend
    created.private_key_b64url = String::new();

    let _ = db.log_action(user_id, "CREATE", "passkey", Some(passkey_id)).await;
    Ok(created)
}

#[tauri::command]
pub async fn get_passkeys_list(
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Vec<PasskeyEntry>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let rows = db
        .get_passkeys(user_id)
        .await
        .map_err(|e| format!("Erreur récupération Passkeys: {}", e))?;

    let mut out = Vec::with_capacity(rows.len());
    for mut pk in rows {
        if let Ok(v) = decrypt_field_secure(&pk.user_handle, &key, user_id, TABLE_PASSKEYS, "user_handle") {
            pk.user_handle = v;
        }
        if let Ok(v) = decrypt_field_secure(&pk.user_name, &key, user_id, TABLE_PASSKEYS, "user_name") {
            pk.user_name = v;
        }
        if let Ok(v) = decrypt_field_secure(&pk.user_display_name, &key, user_id, TABLE_PASSKEYS, "user_display_name") {
            pk.user_display_name = v;
        }
        // La clé privée d'une Passkey ne quitte jamais le backend Rust
        pk.private_key = String::new();
        out.push(pk);
    }
    Ok(out)
}

#[tauri::command]
pub async fn authenticate_passkey_entry(
    request: AuthenticatePasskeyRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<PasskeyAssertion, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let pk = db
        .get_passkey(request.id, user_id)
        .await
        .map_err(|e| format!("Erreur lecture Passkey: {}", e))?
        .ok_or("Passkey introuvable")?;

    let priv_b64 = Zeroizing::new(decrypt_field_secure(
        &pk.private_key,
        &key,
        user_id,
        TABLE_PASSKEYS,
        "private_key",
    )?);
    let user_handle = decrypt_field_secure(
        &pk.user_handle,
        &key,
        user_id,
        TABLE_PASSKEYS,
        "user_handle",
    )
    .ok();

    let origin = request
        .origin
        .unwrap_or_else(|| format!("https://{}", pk.rp_id));

    let assertion = authenticate_passkey_assertion(
        &pk.rp_id,
        &pk.credential_id,
        &priv_b64,
        pk.sign_count as u32,
        &request.challenge_b64url,
        &origin,
        user_handle.as_deref(),
    )
    .map_err(|e| format!("Erreur signature assertion WebAuthn: {}", e))?;

    db.update_passkey_sign_count(pk.id, user_id, assertion.new_sign_count as i64)
        .await
        .map_err(|e| format!("Erreur mise à jour compteur Passkey: {}", e))?;

    let _ = db.log_action(user_id, "AUTHENTICATE", "passkey", Some(pk.id)).await;
    Ok(assertion)
}

#[tauri::command]
pub async fn delete_passkey_entry(
    id: i64,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<bool, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".into());
    }
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let deleted = db
        .delete_passkey(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression Passkey: {}", e))?;

    let _ = db.log_action(user_id, "DELETE", "passkey", Some(id)).await;
    Ok(deleted)
}

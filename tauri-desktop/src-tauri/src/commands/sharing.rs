use crate::{AppState, ShareFileRequest, ShareFileResponse};
use crate::crypto::{encrypt_field_secure, decrypt_data_secure};
use crate::security_monitor::get_security_monitor;
use crate::database::FileShare;
use tauri::State;
use chrono::{Utc, Duration};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use zeroize::Zeroizing;

/// Dérive une clé éphémère de partage dédiée (CEK) par HKDF-SHA-256 (RFC 5869)
/// à partir d'un secret aléatoire de 256 bits indépendant de la clé maître du coffre.
///
/// La clé maître du coffre n'est JAMAIS encodée ni partagée (NIST SP 800-57 §5.2).
pub(crate) fn generate_ephemeral_share_keys(
    file_id: i64,
    recipient_email: &str,
) -> Result<(String, Zeroizing<String>, Zeroizing<String>), String> {
    let mut token_bytes = [0u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut token_bytes)
        .map_err(|e| format!("CSPRNG error (share_token): {e}"))?;
    let share_token = hex::encode(token_bytes);

    let mut ephemeral_secret = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(&mut *ephemeral_secret)
        .map_err(|e| format!("CSPRNG error (ephemeral_secret): {e}"))?;

    let info = format!("fluxlock/share-v2/file:{file_id}/recipient:{recipient_email}/token:{share_token}");
    let derived_cek = secure_vault_crypto::derive_key_hkdf(
        &*ephemeral_secret,
        Some(&token_bytes),
        info.as_bytes(),
        32,
    )
    .map_err(|e| format!("HKDF share key derivation error: {e}"))?;

    let cek_b64 = Zeroizing::new(general_purpose::STANDARD.encode(derived_cek.expose_secret()));
    let fragment_key_b64url = Zeroizing::new(general_purpose::URL_SAFE_NO_PAD.encode(&*ephemeral_secret));

    Ok((share_token, cek_b64, fragment_key_b64url))
}

#[tauri::command]
pub async fn share_file(
    request: ShareFileRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<ShareFileResponse, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    if get_security_monitor().is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".to_string());
    }

    let recipient = request.recipient_email.trim();
    if recipient.is_empty() || recipient.len() > 320 || !recipient.contains('@') {
        return Err("Adresse email du destinataire invalide".into());
    }
    if !(1..=365).contains(&request.expiration_days) {
        return Err("La durée d'expiration doit être comprise entre 1 et 365 jours".into());
    }

    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Vérifier que le fichier existe et appartient à l'utilisateur
    let _file = db
        .get_secure_file(request.file_id, user_id)
        .await
        .map_err(|e| format!("Erreur base de données: {}", e))?
        .ok_or("Fichier non trouvé")?;

    // Récupérer la clé du coffre uniquement pour sceller la CEK éphémère en base locale
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Générer un token et une clé éphémère dédiée au partage (HKDF-SHA-256, RFC 5869)
    let (share_token, cek_b64, fragment_key_b64url) =
        generate_ephemeral_share_keys(request.file_id, recipient)?;

    // Sceller uniquement la CEK éphémère (JAMAIS la clé maître du coffre) avec liaison AAD
    let encrypted_key = encrypt_field_secure(
        &cek_b64,
        &encryption_key,
        user_id,
        "file_shares",
        "encrypted_key",
    )
    .map_err(|e| format!("Erreur chiffrement clé de partage: {}", e))?;

    // Calculer la date d'expiration
    let expires_at = (Utc::now() + Duration::days(request.expiration_days))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    // Créer le partage dans la base de données
    let _share_id = db
        .create_file_share(
            request.file_id,
            user_id,
            recipient,
            &share_token,
            &encrypted_key,
            &expires_at,
        )
        .await
        .map_err(|e| format!("Erreur création partage: {}", e))?;

    // Générer le lien de partage à capacité zero-knowledge (fragment #key= non transmis au serveur)
    let share_link = format!("securevault://share/{}#key={}", share_token, &*fragment_key_b64url);

    // Log l'action
    let _ = db.log_action(user_id, "SHARE", "file", Some(request.file_id)).await;

    debug_log!("✅ Fichier id={} partagé (expires: {})", request.file_id, expires_at);

    Ok(ShareFileResponse {
        success: true,
        share_token,
        share_link,
        expires_at,
    })
}

#[tauri::command]
pub async fn get_user_shares(state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Vec<FileShare>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let mut shares = db
        .get_user_shares(user_id)
        .await
        .map_err(|e| format!("Erreur récupération partages: {}", e))?;

    // Résoudre le nom de fichier déchiffré et expurger encrypted_key avant envoi au WebView
    for share in &mut shares {
        share.encrypted_key = String::new();
        if share.filename.is_none() {
            if let Ok(Some(file)) = db.get_secure_file(share.file_id, user_id).await {
                let name = decrypt_data_secure(&file.filename, &encryption_key)
                    .unwrap_or(file.filename);
                share.filename = Some(name);
            }
        }
    }

    Ok(shares)
}

#[tauri::command]
pub async fn revoke_share(share_id: i64, state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<bool, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    if get_security_monitor().is_readonly().await {
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
        .delete_file_share(share_id, user_id)
        .await
        .map_err(|e| format!("Erreur révocation partage: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "REVOKE_SHARE", "file_share", Some(share_id)).await;

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_share_keys_are_unique_and_independent_of_vault_master_key() {
        let fake_master_key_b64 = general_purpose::STANDARD.encode([0x42u8; 32]);
        let (tok1, cek1, frag1) = generate_ephemeral_share_keys(10, "alice@example.org").unwrap();
        let (tok2, cek2, frag2) = generate_ephemeral_share_keys(10, "alice@example.org").unwrap();

        assert_eq!(tok1.len(), 32);
        assert_ne!(tok1, tok2);
        assert_ne!(&*cek1, &*cek2);
        assert_ne!(&*frag1, &*frag2);
        assert_ne!(&*cek1, &fake_master_key_b64);
    }
}

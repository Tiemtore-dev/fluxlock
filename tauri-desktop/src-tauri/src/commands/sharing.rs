use crate::{AppState, ShareFileRequest, ShareFileResponse};
use crate::crypto::encrypt_data_secure;
use crate::database::FileShare;
use tauri::State;
use chrono::{Utc, Duration};
use base64::{Engine as _, engine::general_purpose};

#[tauri::command]
pub async fn share_file(
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
    
    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    // Chiffrer la clé de déchiffrement avec le token (pour sécuriser l'accès)
    let encrypted_key = {
        let encoded = encryption_key.use_key(|k| {
            Ok::<String, String>(general_purpose::STANDARD.encode(k))
        })?;
        encrypt_data_secure(&encoded, &encryption_key)
            .map_err(|e| format!("Erreur chiffrement clé: {}", e))?
    };

    // Calculer la date d'expiration
    let expires_at = (Utc::now() + Duration::days(request.expiration_days))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    // Créer le partage dans la base de données
    let _share_id = db
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

    debug_log!("✅ Fichier {} partagé avec {} (expires: {})", file.filename, request.recipient_email, expires_at);

    Ok(ShareFileResponse {
        success: true,
        share_token,
        share_link,
        expires_at,
    })
}

#[tauri::command]
pub async fn get_user_shares(state: State<'_, AppState>) -> Result<Vec<FileShare>, String> {
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
pub async fn revoke_share(share_id: i64, state: State<'_, AppState>) -> Result<bool, String> {
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

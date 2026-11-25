//! Commandes Tauri pour les Documents d'Identité Structurés & IETF SD-JWT (EUDI Wallet / eIDAS 2.0)
//!
//! - Chiffrement ChaCha20-Poly1305 avec liaison AAD contextuelle (`user_id`, `"identity_documents"`, `<colonne>`)
//! - Lazy Decryption sur `document_number`
//! - Émission à la demande d'un justificatif IETF SD-JWT à divulgation sélective (`generate_identity_sd_jwt`)

use crate::crypto::{decrypt_field_secure, encrypt_field_secure};
use crate::database::IdentityDocument;
use crate::security_monitor::get_security_monitor;
use crate::AppState;
use secure_vault_crypto::{issue_sd_jwt, IssuedSdJwt, SdJwtClaim};
use serde::{Deserialize, Serialize};
use tauri::State;

pub const TABLE_IDENTITY_DOCUMENTS: &str = "identity_documents";

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateIdentityDocumentRequest {
    pub doc_type: String,
    pub title: String,
    pub full_name: String,
    pub document_number: String,
    pub issuing_authority: Option<String>,
    pub issue_date: Option<String>,
    pub expiry_date: Option<String>,
    pub nationality: Option<String>,
    pub birth_date: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateIdentityDocumentRequest {
    pub id: i64,
    pub doc_type: String,
    pub title: String,
    pub full_name: String,
    pub document_number: String,
    pub issuing_authority: Option<String>,
    pub issue_date: Option<String>,
    pub expiry_date: Option<String>,
    pub nationality: Option<String>,
    pub birth_date: Option<String>,
    pub notes: Option<String>,
}

#[tauri::command]
pub async fn create_identity_document(
    request: CreateIdentityDocumentRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".into());
    }
    if request.title.trim().is_empty()
        || request.full_name.trim().is_empty()
        || request.document_number.trim().is_empty()
    {
        return Err("Le titre, le nom complet et le numéro du document sont obligatoires".into());
    }

    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let enc_type = encrypt_field_secure(request.doc_type.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "doc_type")?;
    let enc_title = encrypt_field_secure(request.title.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "title")?;
    let enc_name = encrypt_field_secure(request.full_name.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "full_name")?;
    let enc_number = encrypt_field_secure(request.document_number.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "document_number")?;
    let enc_auth = request
        .issuing_authority
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| encrypt_field_secure(s.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "issuing_authority"))
        .transpose()?;
    let enc_issue = request
        .issue_date
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| encrypt_field_secure(s.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "issue_date"))
        .transpose()?;
    let enc_expiry = request
        .expiry_date
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| encrypt_field_secure(s.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "expiry_date"))
        .transpose()?;
    let enc_nat = request
        .nationality
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| encrypt_field_secure(s.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "nationality"))
        .transpose()?;
    let enc_birth = request
        .birth_date
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| encrypt_field_secure(s.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "birth_date"))
        .transpose()?;
    let enc_notes = request
        .notes
        .as_ref()
        .filter(|s| !s.trim().is_empty())
        .map(|s| encrypt_field_secure(s.trim(), &key, user_id, TABLE_IDENTITY_DOCUMENTS, "notes"))
        .transpose()?;

    let doc_id = db
        .create_identity_document(
            user_id,
            &enc_type,
            &enc_title,
            &enc_name,
            &enc_number,
            enc_auth.as_deref(),
            enc_issue.as_deref(),
            enc_expiry.as_deref(),
            enc_nat.as_deref(),
            enc_birth.as_deref(),
            enc_notes.as_deref(),
            None,
        )
        .await
        .map_err(|e| format!("Erreur création document d'identité: {}", e))?;

    let _ = db.log_action(user_id, "CREATE", "identity_document", Some(doc_id)).await;
    Ok(doc_id)
}

#[tauri::command]
pub async fn get_identity_documents(
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Vec<IdentityDocument>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let rows = db
        .get_identity_documents(user_id)
        .await
        .map_err(|e| format!("Erreur récupération documents d'identité: {}", e))?;

    // Lazy Decryption : `document_number` reste chiffré (`v2:aad:...`) dans la liste
    let mut out = Vec::with_capacity(rows.len());
    for mut doc in rows {
        if let Ok(v) = decrypt_field_secure(&doc.doc_type, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "doc_type") {
            doc.doc_type = v;
        }
        if let Ok(v) = decrypt_field_secure(&doc.title, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "title") {
            doc.title = v;
        }
        if let Ok(v) = decrypt_field_secure(&doc.full_name, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "full_name") {
            doc.full_name = v;
        }
        if let Some(ref v) = doc.issuing_authority {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "issuing_authority") {
                doc.issuing_authority = Some(d);
            }
        }
        if let Some(ref v) = doc.issue_date {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "issue_date") {
                doc.issue_date = Some(d);
            }
        }
        if let Some(ref v) = doc.expiry_date {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "expiry_date") {
                doc.expiry_date = Some(d);
            }
        }
        if let Some(ref v) = doc.nationality {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "nationality") {
                doc.nationality = Some(d);
            }
        }
        if let Some(ref v) = doc.birth_date {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "birth_date") {
                doc.birth_date = Some(d);
            }
        }
        if let Some(ref v) = doc.notes {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "notes") {
                doc.notes = Some(d);
            }
        }
        doc.sd_jwt_credential = None;
        out.push(doc);
    }
    Ok(out)
}

#[tauri::command]
pub async fn decrypt_identity_document_number(
    id: i64,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let doc = db
        .get_identity_document(id, user_id)
        .await
        .map_err(|e| format!("Erreur lecture document: {}", e))?
        .ok_or("Document d'identité introuvable")?;

    Ok(decrypt_field_secure(&doc.document_number, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "document_number")?)
}

/// Génère un justificatif vérifiable IETF SD-JWT (`draft-ietf-oauth-selective-disclosure-jwt`)
/// ne divulguant que les attributs sélectionnés par l'utilisateur (`selected_claims`).
#[tauri::command]
pub async fn generate_identity_sd_jwt(
    id: i64,
    selected_claims: Vec<String>,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<IssuedSdJwt, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let doc = db
        .get_identity_document(id, user_id)
        .await
        .map_err(|e| format!("Erreur lecture document: {}", e))?
        .ok_or("Document d'identité introuvable")?;

    let doc_type = decrypt_field_secure(&doc.doc_type, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "doc_type")?;
    let full_name = decrypt_field_secure(&doc.full_name, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "full_name")?;
    let doc_num = decrypt_field_secure(&doc.document_number, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "document_number")?;

    let mut claims = Vec::new();
    let include_all = selected_claims.is_empty();
    let wants = |k: &str| include_all || selected_claims.iter().any(|s| s == k);

    if wants("full_name") {
        claims.push(SdJwtClaim {
            name: "full_name".into(),
            value: full_name,
        });
    }
    if wants("document_number") {
        claims.push(SdJwtClaim {
            name: "document_number".into(),
            value: doc_num,
        });
    }
    if wants("nationality") {
        if let Some(ref v) = doc.nationality {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "nationality") {
                claims.push(SdJwtClaim {
                    name: "nationality".into(),
                    value: d,
                });
            }
        }
    }
    if wants("birth_date") {
        if let Some(ref v) = doc.birth_date {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "birth_date") {
                claims.push(SdJwtClaim {
                    name: "birth_date".into(),
                    value: d,
                });
            }
        }
    }
    if wants("expiry_date") {
        if let Some(ref v) = doc.expiry_date {
            if let Ok(d) = decrypt_field_secure(v, &key, user_id, TABLE_IDENTITY_DOCUMENTS, "expiry_date") {
                claims.push(SdJwtClaim {
                    name: "expiry_date".into(),
                    value: d,
                });
            }
        }
    }

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();

    issue_sd_jwt(
        &format!("urn:eudi:pid:{}", doc_type),
        &format!("did:fluxlock:user:{}", user_id),
        &claims,
        now_unix,
    )
    .map_err(|e| format!("Erreur émission SD-JWT: {}", e))
}

#[tauri::command]
pub async fn delete_identity_document(
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
        .delete_identity_document(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression document d'identité: {}", e))?;

    let _ = db.log_action(user_id, "DELETE", "identity_document", Some(id)).await;
    Ok(deleted)
}

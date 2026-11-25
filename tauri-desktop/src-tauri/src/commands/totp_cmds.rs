//! Commandes Tauri pour l'onglet dédié Authentificateur TOTP 2FA (RFC 6238 / RFC 4226)
//!
//! - Permet d'ajouter une graine TOTP via une clé secrète Base32 (RFC 4648) ou une URI `otpauth://totp/...`
//! - Chiffre la graine avec ChaCha20-Poly1305 et AAD contextuelle (`user_id`, `"totp_entries"`, `"secret_uri"`)
//! - Génère les codes à 6 ou 8 chiffres directement en Rust sans jamais exposer la graine Base32 au frontend
//! - Agrège à la fois les entrées dédiées de la table `totp_entries` et les identifiants de `passwords` ayant un secret TOTP.

use crate::crypto::{decrypt_field_secure, encrypt_field_secure};
use crate::security_monitor::get_security_monitor;
use crate::AppState;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use secure_vault_crypto::{
    base32_encode, decode_qr_image_bytes, generate_totp, parse_totp_migration_input,
    TotpAlgorithm, TotpConfig,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

/// Décode en mémoire vive (100% pur Rust multiplateforme : macOS, Windows, Linux, Android)
/// une image de QR Code (PNG, JPEG, WebP, BMP, GIF) et retourne les URIs `otpauth://` ou `otpauth-migration://` extraites.
pub fn decode_qr_image_in_memory(image_bytes: &[u8]) -> Result<Zeroizing<String>, String> {
    decode_qr_image_bytes(image_bytes).map_err(|e| e.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportTotpMigrationRequest {
    /// Texte brut contenant une ou plusieurs URIs `otpauth-migration://offline?data=...`, `otpauth://totp/...` ou clés Base32
    pub raw_input: Option<String>,
    /// Image de QR Code encodée en Base64 (capture d'écran Google Authenticator ou QR code de site web)
    pub qr_image_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportTotpMigrationResponse {
    pub imported_count: usize,
    pub accounts: Vec<String>,
}

pub const TABLE_TOTP_ENTRIES: &str = "totp_entries";

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTotpEntryRequest {
    /// Nom du service / émetteur (ex: "GitHub", "Google", "AWS") — optionnel si `secret_or_uri` est une URI `otpauth://`
    pub issuer: Option<String>,
    /// Identifiant du compte (ex: "alice@example.com") — optionnel si `secret_or_uri` est une URI `otpauth://`
    pub account: Option<String>,
    /// Soit une clé Base32 brute (ex: "JBSWY3DPEHPK3PXP"), soit une URI complète `otpauth://totp/...`
    pub secret_or_uri: String,
    /// Algorithme HMAC optionnel ("SHA1", "SHA256", "SHA512" — défaut "SHA1")
    pub algorithm: Option<String>,
    /// Nombre de chiffres optionnel (6 ou 8 — défaut 6)
    pub digits: Option<u8>,
    /// Période en secondes (défaut 30)
    pub period: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpLiveItem {
    pub id: i64,
    /// `"standalone"` (table `totp_entries`) ou `"password"` (table `passwords`)
    pub source: String,
    pub issuer: String,
    pub account: String,
    pub code: String,
    pub period: u64,
    pub remaining_seconds: u64,
    pub digits: u8,
    pub algorithm: String,
}

#[tauri::command]
pub async fn create_totp_authenticator(
    request: CreateTotpEntryRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".into());
    }

    let raw = request.secret_or_uri.trim();
    if raw.is_empty() {
        return Err("La clé secrète Base32 ou l'URI otpauth:// est obligatoire".into());
    }

    let parsed = TotpConfig::parse(raw)
        .map_err(|e| format!("Graine TOTP invalide (RFC 6238 / Base32): {}", e))?;

    let issuer = request
        .issuer
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(parsed.issuer.clone())
        .unwrap_or_else(|| "Service 2FA".to_string());

    let account = request
        .account
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(parsed.account.clone())
        .unwrap_or_default();

    let algorithm = if let Some(ref alg_str) = request.algorithm {
        if !alg_str.trim().is_empty() && !raw.starts_with("otpauth://") {
            TotpAlgorithm::from_str_ignore_case(alg_str)
                .map_err(|e| format!("Algorithme TOTP invalide: {}", e))?
        } else {
            parsed.algorithm
        }
    } else {
        parsed.algorithm
    };

    let digits = if !raw.starts_with("otpauth://") {
        request.digits.unwrap_or(parsed.digits)
    } else {
        parsed.digits
    };
    if !(6..=8).contains(&digits) {
        return Err("Le nombre de chiffres TOTP doit être 6, 7 ou 8".into());
    }

    let period = if !raw.starts_with("otpauth://") {
        request.period.unwrap_or(parsed.period)
    } else {
        parsed.period
    };
    if period == 0 || period > 300 {
        return Err("La période TOTP doit être comprise entre 1 et 300 secondes".into());
    }

    let b32_secret = Zeroizing::new(base32_encode(&parsed.secret));
    let canonical_uri = Zeroizing::new(format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
        issuer.replace(':', " "),
        account.replace(':', " "),
        b32_secret.as_str(),
        issuer,
        algorithm.as_str(),
        digits,
        period
    ));

    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let enc_issuer = encrypt_field_secure(&issuer, &key, user_id, TABLE_TOTP_ENTRIES, "issuer")?;
    let enc_account = encrypt_field_secure(&account, &key, user_id, TABLE_TOTP_ENTRIES, "account")?;
    let enc_uri = encrypt_field_secure(&canonical_uri, &key, user_id, TABLE_TOTP_ENTRIES, "secret_uri")?;

    let id = db
        .create_totp_entry(
            user_id,
            &enc_issuer,
            &enc_account,
            &enc_uri,
            algorithm.as_str(),
            digits as i64,
            period as i64,
        )
        .await
        .map_err(|e| format!("Erreur enregistrement TOTP: {}", e))?;

    let _ = db.log_action(user_id, "CREATE", "totp_entry", Some(id)).await;
    Ok(id)
}

#[tauri::command]
pub async fn get_totp_authenticators(
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Vec<TotpLiveItem>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Horloge système invalide: {}", e))?
        .as_secs();

    let mut items = Vec::new();

    // 1. Entrées dédiées de la table totp_entries
    let rows = db
        .get_totp_entries(user_id)
        .await
        .map_err(|e| format!("Erreur lecture TOTP: {}", e))?;

    for row in rows {
        let issuer = decrypt_field_secure(&row.issuer, &key, user_id, TABLE_TOTP_ENTRIES, "issuer")
            .unwrap_or_else(|_| "Service 2FA".into());
        let account = decrypt_field_secure(&row.account, &key, user_id, TABLE_TOTP_ENTRIES, "account")
            .unwrap_or_default();
        let Ok(secret_plain) = decrypt_field_secure(&row.secret_uri, &key, user_id, TABLE_TOTP_ENTRIES, "secret_uri") else {
            continue;
        };
        let secret_plain = Zeroizing::new(secret_plain);
        if let Ok(out) = generate_totp(&secret_plain, now_unix) {
            items.push(TotpLiveItem {
                id: row.id,
                source: "standalone".into(),
                issuer,
                account,
                code: out.code,
                period: out.period,
                remaining_seconds: out.remaining_seconds,
                digits: out.digits,
                algorithm: out.algorithm,
            });
        }
    }

    // 2. Identifiants de la table passwords possédant également un secret TOTP
    let pw_rows = db
        .get_passwords(user_id)
        .await
        .map_err(|e| format!("Erreur lecture mots de passe TOTP: {}", e))?;

    for pw in pw_rows {
        let Some(ref enc_totp) = pw.totp_secret else { continue };
        if enc_totp.trim().is_empty() {
            continue;
        }
        let Ok(secret_plain) = decrypt_field_secure(enc_totp, &key, user_id, "passwords", "totp_secret") else {
            continue;
        };
        let secret_plain = Zeroizing::new(secret_plain);
        let title = decrypt_field_secure(&pw.title, &key, user_id, "passwords", "title")
            .unwrap_or_else(|_| pw.title.clone());
        let username = pw
            .username
            .as_ref()
            .and_then(|u| decrypt_field_secure(u, &key, user_id, "passwords", "username").ok())
            .unwrap_or_default();

        if let Ok(out) = generate_totp(&secret_plain, now_unix) {
            items.push(TotpLiveItem {
                id: pw.id,
                source: "password".into(),
                issuer: out.issuer.unwrap_or(title),
                account: if !username.is_empty() {
                    username
                } else {
                    out.account.unwrap_or_default()
                },
                code: out.code,
                period: out.period,
                remaining_seconds: out.remaining_seconds,
                digits: out.digits,
                algorithm: out.algorithm,
            });
        }
    }

    Ok(items)
}

#[tauri::command]
pub async fn delete_totp_authenticator(
    id: i64,
    source: String,
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

    let deleted = if source == "password" {
        db.set_password_totp_secret(id, user_id, None)
            .await
            .map_err(|e| format!("Erreur suppression TOTP lié: {}", e))?
    } else {
        db.delete_totp_entry(id, user_id)
            .await
            .map_err(|e| format!("Erreur suppression entrée TOTP: {}", e))?
    };

    let _ = db.log_action(user_id, "DELETE", "totp_entry", Some(id)).await;
    Ok(deleted)
}

/// Importe et chiffre un lot de comptes 2FA TOTP depuis :
/// - Une capture d'écran / image de QR Code (`qr_image_base64` décodée 100% en RAM via CoreImage)
/// - Un lot d'export Google Authenticator (`otpauth-migration://offline?data=...` Protobuf)
/// - Une liste multi-lignes d'URIs `otpauth://totp/...` (2FAS, Aegis, Raivo, Bitwarden, Proton Pass)
#[tauri::command]
pub async fn import_totp_migration_batch(
    request: ImportTotpMigrationRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<ImportTotpMigrationResponse, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".into());
    }

    let mut combined_payload = Zeroizing::new(String::new());

    if let Some(ref b64_img) = request.qr_image_base64 {
        let clean = b64_img
            .trim()
            .split_once(',')
            .map(|(_, data)| data)
            .unwrap_or(b64_img.trim());
        if !clean.is_empty() {
            let img_bytes = Zeroizing::new(
                STANDARD
                    .decode(clean)
                    .map_err(|e| format!("Image Base64 invalide: {}", e))?,
            );
            let decoded_qr = decode_qr_image_in_memory(&img_bytes)?;
            combined_payload.push_str(&decoded_qr);
            combined_payload.push('\n');
        }
    }

    if let Some(ref text) = request.raw_input {
        if !text.trim().is_empty() {
            combined_payload.push_str(text.trim());
            combined_payload.push('\n');
        }
    }

    let configs = parse_totp_migration_input(&combined_payload)
        .map_err(|e| format!("Erreur d'analyse de migration TOTP: {}", e))?;

    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let mut imported_accounts = Vec::with_capacity(configs.len());
    for (idx, cfg) in configs.iter().enumerate() {
        let issuer = cfg
            .issuer
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| format!("Compte Migré #{}", idx + 1));
        let account = cfg.account.clone().unwrap_or_default();
        let canonical_uri = cfg.to_otpauth_uri(&issuer);

        let enc_issuer = encrypt_field_secure(&issuer, &key, user_id, TABLE_TOTP_ENTRIES, "issuer")?;
        let enc_account = encrypt_field_secure(&account, &key, user_id, TABLE_TOTP_ENTRIES, "account")?;
        let enc_uri = encrypt_field_secure(&canonical_uri, &key, user_id, TABLE_TOTP_ENTRIES, "secret_uri")?;

        let id = db
            .create_totp_entry(
                user_id,
                &enc_issuer,
                &enc_account,
                &enc_uri,
                cfg.algorithm.as_str(),
                cfg.digits as i64,
                cfg.period as i64,
            )
            .await
            .map_err(|e| format!("Erreur stockage TOTP migré: {}", e))?;

        let _ = db.log_action(user_id, "IMPORT_MIGRATION", "totp_entry", Some(id)).await;
        if account.is_empty() {
            imported_accounts.push(issuer);
        } else {
            imported_accounts.push(format!("{} ({})", issuer, account));
        }
    }

    Ok(ImportTotpMigrationResponse {
        imported_count: imported_accounts.len(),
        accounts: imported_accounts,
    })
}

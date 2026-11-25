//! Commandes Tauri pour la gestion des cartes bancaires (Payment Cards)
//!
//! - Validation algorithmique ISO/IEC 7812-1 (Luhn) + détection automatique du réseau
//! - Chiffrement ChaCha20-Poly1305 avec liaison AAD contextuelle (`user_id`, `"payment_cards"`, `<colonne>`)
//! - Lazy Decryption : `get_payment_cards` conserve `card_number` et `cvv` chiffrés (`v2:aad:...`)
//!   et n'expose que `brand`, `last4`, `cardholder_name`, `exp_month`, `exp_year`.

use crate::crypto::{decrypt_field_secure, encrypt_field_secure};
use crate::database::PaymentCard;
use crate::security_monitor::get_security_monitor;
use crate::AppState;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

pub const TABLE_PAYMENT_CARDS: &str = "payment_cards";

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePaymentCardRequest {
    pub title: String,
    pub cardholder_name: String,
    pub card_number: String,
    pub exp_month: String,
    pub exp_year: String,
    pub cvv: String,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdatePaymentCardRequest {
    pub id: i64,
    pub title: String,
    pub cardholder_name: String,
    pub card_number: String,
    pub exp_month: String,
    pub exp_year: String,
    pub cvv: String,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptedCardSecret {
    pub card_number: String,
    pub cvv: String,
}

fn validate_expiry(exp_month: &str, exp_year: &str) -> Result<(String, String), String> {
    let m: u8 = exp_month
        .trim()
        .parse()
        .map_err(|_| "Mois d'expiration invalide (01-12)".to_string())?;
    if !(1..=12).contains(&m) {
        return Err("Le mois d'expiration doit être compris entre 01 et 12".into());
    }
    let y_trim = exp_year.trim();
    let y_num: u16 = y_trim
        .parse()
        .map_err(|_| "Année d'expiration invalide".to_string())?;
    let full_year = if y_num < 100 { 2000 + y_num } else { y_num };
    if !(2020..=2100).contains(&full_year) {
        return Err("Année d'expiration hors plage valide".into());
    }
    Ok((format!("{:02}", m), format!("{:04}", full_year)))
}

#[tauri::command]
pub async fn create_payment_card(
    request: CreatePaymentCardRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let monitor = get_security_monitor();
    if monitor.is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".into());
    }

    let sanitized_pan = secure_vault_crypto::sanitize_card_pan(&request.card_number);
    if !secure_vault_crypto::validate_luhn(&sanitized_pan) {
        return Err("Numéro de carte invalide (échec du contrôle Luhn ISO/IEC 7812-1)".into());
    }
    let (norm_month, norm_year) = validate_expiry(&request.exp_month, &request.exp_year)?;
    let cvv_trim = request.cvv.trim();
    if !(3..=4).contains(&cvv_trim.len()) || !cvv_trim.chars().all(|c| c.is_ascii_digit()) {
        return Err("Code CVV/CVC invalide (3 ou 4 chiffres requis)".into());
    }

    let brand = secure_vault_crypto::detect_card_brand(&sanitized_pan);
    let last4 = secure_vault_crypto::extract_card_last4(&sanitized_pan);

    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let enc_title = encrypt_field_secure(request.title.trim(), &key, user_id, TABLE_PAYMENT_CARDS, "title")?;
    let enc_holder = encrypt_field_secure(request.cardholder_name.trim(), &key, user_id, TABLE_PAYMENT_CARDS, "cardholder_name")?;
    let enc_pan = encrypt_field_secure(&sanitized_pan, &key, user_id, TABLE_PAYMENT_CARDS, "card_number")?;
    let enc_brand = encrypt_field_secure(brand, &key, user_id, TABLE_PAYMENT_CARDS, "brand")?;
    let enc_last4 = encrypt_field_secure(&last4, &key, user_id, TABLE_PAYMENT_CARDS, "last4")?;
    let enc_month = encrypt_field_secure(&norm_month, &key, user_id, TABLE_PAYMENT_CARDS, "exp_month")?;
    let enc_year = encrypt_field_secure(&norm_year, &key, user_id, TABLE_PAYMENT_CARDS, "exp_year")?;
    let enc_cvv = encrypt_field_secure(cvv_trim, &key, user_id, TABLE_PAYMENT_CARDS, "cvv")?;
    let enc_notes = request
        .notes
        .as_ref()
        .filter(|n| !n.trim().is_empty())
        .map(|n| encrypt_field_secure(n.trim(), &key, user_id, TABLE_PAYMENT_CARDS, "notes"))
        .transpose()?;

    let card_id = db
        .create_payment_card(
            user_id,
            &enc_title,
            &enc_holder,
            &enc_pan,
            &enc_brand,
            &enc_last4,
            &enc_month,
            &enc_year,
            &enc_cvv,
            enc_notes.as_deref(),
        )
        .await
        .map_err(|e| format!("Erreur création carte bancaire: {}", e))?;

    let _ = db.log_action(user_id, "CREATE", "payment_card", Some(card_id)).await;
    Ok(card_id)
}

#[tauri::command]
pub async fn get_payment_cards(
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Vec<PaymentCard>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let rows = db
        .get_payment_cards(user_id)
        .await
        .map_err(|e| format!("Erreur récupération cartes bancaires: {}", e))?;

    // Lazy Decryption : on déchiffre uniquement les métadonnées d'affichage.
    // `card_number` et `cvv` restent sous forme `v2:aad:...` en mémoire JS.
    let mut out = Vec::with_capacity(rows.len());
    for mut card in rows {
        if let Ok(v) = decrypt_field_secure(&card.title, &key, user_id, TABLE_PAYMENT_CARDS, "title") {
            card.title = v;
        }
        if let Ok(v) = decrypt_field_secure(&card.cardholder_name, &key, user_id, TABLE_PAYMENT_CARDS, "cardholder_name") {
            card.cardholder_name = v;
        }
        if let Ok(v) = decrypt_field_secure(&card.brand, &key, user_id, TABLE_PAYMENT_CARDS, "brand") {
            card.brand = v;
        }
        if let Ok(v) = decrypt_field_secure(&card.last4, &key, user_id, TABLE_PAYMENT_CARDS, "last4") {
            card.last4 = v;
        }
        if let Ok(v) = decrypt_field_secure(&card.exp_month, &key, user_id, TABLE_PAYMENT_CARDS, "exp_month") {
            card.exp_month = v;
        }
        if let Ok(v) = decrypt_field_secure(&card.exp_year, &key, user_id, TABLE_PAYMENT_CARDS, "exp_year") {
            card.exp_year = v;
        }
        if let Some(ref notes) = card.notes {
            if let Ok(v) = decrypt_field_secure(notes, &key, user_id, TABLE_PAYMENT_CARDS, "notes") {
                card.notes = Some(v);
            }
        }
        out.push(card);
    }
    Ok(out)
}

#[tauri::command]
pub async fn decrypt_payment_card_secret(
    id: i64,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<DecryptedCardSecret, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let card = db
        .get_payment_card(id, user_id)
        .await
        .map_err(|e| format!("Erreur lecture carte: {}", e))?
        .ok_or("Carte bancaire introuvable")?;

    let pan = decrypt_field_secure(&card.card_number, &key, user_id, TABLE_PAYMENT_CARDS, "card_number")
        .map_err(|e| format!("Erreur déchiffrement PAN: {}", e))?;
    let cvv = decrypt_field_secure(&card.cvv, &key, user_id, TABLE_PAYMENT_CARDS, "cvv")
        .map_err(|e| format!("Erreur déchiffrement CVV: {}", e))?;

    Ok(DecryptedCardSecret {
        card_number: pan,
        cvv,
    })
}

#[tauri::command]
pub async fn update_payment_card(
    request: UpdatePaymentCardRequest,
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
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    let existing = db
        .get_payment_card(request.id, user_id)
        .await
        .map_err(|e| format!("Erreur lecture carte: {}", e))?
        .ok_or("Carte bancaire introuvable")?;

    let pan_plain = Zeroizing::new(if request.card_number.starts_with("v2:") {
        decrypt_field_secure(&existing.card_number, &key, user_id, TABLE_PAYMENT_CARDS, "card_number")?
    } else {
        let s = secure_vault_crypto::sanitize_card_pan(&request.card_number);
        if !secure_vault_crypto::validate_luhn(&s) {
            return Err("Numéro de carte invalide (échec du contrôle Luhn ISO/IEC 7812-1)".into());
        }
        s.as_str().to_string()
    });

    let cvv_plain = Zeroizing::new(if request.cvv.starts_with("v2:") {
        decrypt_field_secure(&existing.cvv, &key, user_id, TABLE_PAYMENT_CARDS, "cvv")?
    } else {
        let c = request.cvv.trim();
        if !(3..=4).contains(&c.len()) || !c.chars().all(|ch| ch.is_ascii_digit()) {
            return Err("Code CVV/CVC invalide (3 ou 4 chiffres requis)".into());
        }
        c.to_string()
    });

    let (norm_month, norm_year) = validate_expiry(&request.exp_month, &request.exp_year)?;
    let brand = secure_vault_crypto::detect_card_brand(&pan_plain);
    let last4 = secure_vault_crypto::extract_card_last4(&pan_plain);

    let enc_title = encrypt_field_secure(request.title.trim(), &key, user_id, TABLE_PAYMENT_CARDS, "title")?;
    let enc_holder = encrypt_field_secure(request.cardholder_name.trim(), &key, user_id, TABLE_PAYMENT_CARDS, "cardholder_name")?;
    let enc_pan = encrypt_field_secure(&pan_plain, &key, user_id, TABLE_PAYMENT_CARDS, "card_number")?;
    let enc_brand = encrypt_field_secure(brand, &key, user_id, TABLE_PAYMENT_CARDS, "brand")?;
    let enc_last4 = encrypt_field_secure(&last4, &key, user_id, TABLE_PAYMENT_CARDS, "last4")?;
    let enc_month = encrypt_field_secure(&norm_month, &key, user_id, TABLE_PAYMENT_CARDS, "exp_month")?;
    let enc_year = encrypt_field_secure(&norm_year, &key, user_id, TABLE_PAYMENT_CARDS, "exp_year")?;
    let enc_cvv = encrypt_field_secure(&cvv_plain, &key, user_id, TABLE_PAYMENT_CARDS, "cvv")?;
    let enc_notes = request
        .notes
        .as_ref()
        .filter(|n| !n.trim().is_empty())
        .map(|n| encrypt_field_secure(n.trim(), &key, user_id, TABLE_PAYMENT_CARDS, "notes"))
        .transpose()?;

    let updated = db
        .update_payment_card(
            request.id,
            user_id,
            &enc_title,
            &enc_holder,
            &enc_pan,
            &enc_brand,
            &enc_last4,
            &enc_month,
            &enc_year,
            &enc_cvv,
            enc_notes.as_deref(),
        )
        .await
        .map_err(|e| format!("Erreur mise à jour carte bancaire: {}", e))?;

    let _ = db.log_action(user_id, "UPDATE", "payment_card", Some(request.id)).await;
    Ok(updated)
}

#[tauri::command]
pub async fn delete_payment_card(
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
        .delete_payment_card(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression carte bancaire: {}", e))?;

    let _ = db.log_action(user_id, "DELETE", "payment_card", Some(id)).await;
    Ok(deleted)
}

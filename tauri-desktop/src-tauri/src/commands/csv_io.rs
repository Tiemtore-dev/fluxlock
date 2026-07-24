// ═══════════════════════════════════════════════════════════════════════════
// csv_io.rs — Import/Export CSV de mots de passe
//
// Sécurité :
//   - Ré-authentification obligatoire (mot de passe maître OU biométrie)
//   - Zeroize de tous les buffers sensibles (CSV brut, mots de passe)
//   - Pas d'écriture disque côté backend (le frontend gère le save dialog)
//   - Protection ransomware (is_readonly check) pour l'import
//   - Audit trail pour chaque opération
//   - Validation des longueurs max (FIELD_MAX_LENGTHS) contre les injections
// ═══════════════════════════════════════════════════════════════════════════

use crate::{AppState};
use crate::crypto::{encrypt_data_secure, decrypt_data_secure, verify_password};
use crate::security_monitor::get_security_monitor;
use crate::database::Password;
use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroize;
use std::collections::HashMap;

// ── Max lengths from vault-service (VULN-020) ──
const MAX_TITLE: usize = 256;
const MAX_USERNAME: usize = 256;
const MAX_PASSWORD: usize = 4096;
const MAX_URL: usize = 2048;
const MAX_NOTES: usize = 10000;
const MAX_CATEGORY: usize = 128;
/// Safety limit: refuse CSV files larger than 10MB to prevent DoS
const MAX_CSV_SIZE: usize = 10 * 1024 * 1024;

// ════════════════════════════ Types ════════════════════════════

#[derive(Debug, Clone, PartialEq)]
enum CsvFormat {
    Chrome,
    Bitwarden,
    LastPass,
    OnePassword,
    FluXlock,
    Generic,
}

/// Request for import (preview or execute)
#[derive(Deserialize)]
pub struct ImportCsvRequest {
    /// Master password for re-authentication. None if using biometric or passkey.
    pub master_password: Option<String>,
    /// Authentication method: "passkey" to use passkey, null for password/biometric.
    pub auth_method: Option<String>,
    /// Raw CSV content read by the frontend
    pub csv_content: String,
    /// Source format hint: "chrome", "bitwarden", "lastpass", "1password", "fluxlock", "auto"
    pub source_format: Option<String>,
    /// "preview" = parse + detect duplicates, "import" = execute import
    pub mode: String,
    /// Actions for each entry (required when mode == "import")
    /// Maps entry index → action ("import", "skip", "overwrite")
    pub entry_actions: Option<Vec<EntryAction>>,
}

/// Per-entry user decision for conflict resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryAction {
    pub index: usize,
    /// "import" (new entry), "skip", "overwrite"
    pub action: String,
    /// ID of the existing password to overwrite (required if action == "overwrite")
    pub overwrite_id: Option<i64>,
}

/// A parsed CSV row mapped to FluXlock fields
#[derive(Debug, Clone, Serialize)]
pub struct ParsedCsvEntry {
    pub index: usize,
    pub title: String,
    pub username: Option<String>,
    /// Password masked as "••••••" in preview, actual value in import
    pub password_preview: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: Option<String>,
    pub is_duplicate: bool,
    pub existing_match: Option<DuplicateMatch>,
    pub parse_error: Option<String>,
}

/// Info about an existing password that matches a CSV entry
#[derive(Debug, Clone, Serialize)]
pub struct DuplicateMatch {
    pub id: i64,
    pub title: String,
    pub username: Option<String>,
    pub url: Option<String>,
}

/// Response from import_passwords_csv
#[derive(Debug, Serialize)]
pub struct ImportCsvResponse {
    pub success: bool,
    pub mode: String,
    /// Available in both modes
    pub detected_format: String,
    pub total_parsed: usize,
    pub duplicate_count: usize,
    pub new_count: usize,
    pub error_count: usize,
    /// Preview: parsed entries with duplicate info. Import: None
    pub entries: Option<Vec<ParsedCsvEntry>>,
    /// Import mode: counts
    pub imported_count: usize,
    pub skipped_count: usize,
    pub overwritten_count: usize,
    /// Errors for individual entries
    pub errors: Vec<String>,
    pub message: String,
}

/// Request for export
#[derive(Deserialize)]
pub struct ExportCsvRequest {
    /// Master password for re-authentication. None if using biometric or passkey.
    pub master_password: Option<String>,
    /// Authentication method: "passkey" to use passkey, null for password/biometric.
    pub auth_method: Option<String>,
}

/// Response from export_passwords_csv
#[derive(Serialize)]
pub struct ExportCsvResponse {
    pub success: bool,
    /// CSV content in memory (never written to disk by backend)
    pub csv_content: String,
    pub count: usize,
    pub message: String,
}

// ═══════════════════════ Internal Helpers ═══════════════════════

/// Unified re-authentication for CSV operations.
/// Accepts a master password, biometric auth, OR passkey auth.
/// Returns (user_id, vault_key) on success.
async fn authenticate_for_csv_op(
    master_password: &Option<String>,
    auth_method: &Option<String>,
    state: &State<'_, AppState>,
) -> Result<(i64, crate::secure_key::SecureKey), String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié — session requise")?;

    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;
    let user = db
        .get_user_by_id(user_id)
        .await
        .map_err(|e| format!("Erreur DB: {}", e))?
        .ok_or("Utilisateur introuvable")?;

    // ── Passkey authentication path ──
    if auth_method.as_deref() == Some("passkey") {
        let (pk_uid, _pk_name, key_bytes) =
            crate::passkey::authenticate_passkey(&user.username, None)
                .map_err(|e| format!("Échec de l'authentification passkey: {}", e))?;

        if pk_uid != user_id {
            return Err(
                "Incohérence d'identité — le compte passkey ne correspond pas à la session"
                    .to_string(),
            );
        }

        let key = crate::secure_key::SecureKey::from_slice(&key_bytes);
        return Ok((user_id, key));
    }

    match master_password {
        Some(ref password) if !password.is_empty() => {
            // ── Password authentication path ──
            verify_password(password, &user.password_hash)
                .map_err(|_| "❌ Mot de passe incorrect".to_string())?;
            let key = crate::get_or_fetch_vault_key(state, user_id).await?;
            Ok((user_id, key))
        }
        _ => {
            // ── Biometric authentication path ──
            // This triggers the OS-level biometric prompt (Touch ID / Face ID / Windows Hello)
            let (bio_uid, _bio_name, key_bytes) =
                crate::biometric::biometric_login(&user.username)
                    .map_err(|e| format!("Échec de l'authentification biométrique: {}", e))?;

            // Verify biometric identity matches current session
            if bio_uid != user_id {
                return Err(
                    "Incohérence d'identité — le compte biométrique ne correspond pas à la session"
                        .to_string(),
                );
            }

            let key = crate::secure_key::SecureKey::from_slice(&key_bytes);
            Ok((user_id, key))
        }
    }
}

/// Detect the CSV format from header names
fn detect_csv_format(headers: &csv::StringRecord, hint: &Option<String>) -> CsvFormat {
    // If a hint is provided and valid, use it
    if let Some(ref fmt) = hint {
        match fmt.to_lowercase().as_str() {
            "chrome" => return CsvFormat::Chrome,
            "bitwarden" => return CsvFormat::Bitwarden,
            "lastpass" => return CsvFormat::LastPass,
            "1password" | "onepassword" => return CsvFormat::OnePassword,
            "fluxlock" => return CsvFormat::FluXlock,
            _ => {} // "auto" or unknown → fall through to detection
        }
    }

    let h: Vec<String> = headers
        .iter()
        .map(|s| s.to_lowercase().trim().to_string())
        .collect();

    // Bitwarden: has login_uri or login_username (most specific)
    if h.iter().any(|c| c == "login_uri" || c == "login_username") {
        return CsvFormat::Bitwarden;
    }

    // LastPass: has both "extra" and "grouping"
    if h.iter().any(|c| c == "extra") && h.iter().any(|c| c == "grouping") {
        return CsvFormat::LastPass;
    }

    // FluXlock: has "title" and "category"
    if h.iter().any(|c| c == "title") && h.iter().any(|c| c == "category") {
        return CsvFormat::FluXlock;
    }

    // Chrome: has "name", "url", "username", "password" (no login_uri)
    if h.iter().any(|c| c == "name")
        && h.iter().any(|c| c == "url")
        && h.iter().any(|c| c == "username")
        && h.iter().any(|c| c == "password")
    {
        return CsvFormat::Chrome;
    }

    // 1Password: has "title" or "Title" + "password" or "Password"
    if h.iter().any(|c| c == "title") && h.iter().any(|c| c == "password") {
        return CsvFormat::OnePassword;
    }

    CsvFormat::Generic
}

fn format_name(f: &CsvFormat) -> String {
    match f {
        CsvFormat::Chrome => "Chrome".to_string(),
        CsvFormat::Bitwarden => "Bitwarden".to_string(),
        CsvFormat::LastPass => "LastPass".to_string(),
        CsvFormat::OnePassword => "1Password".to_string(),
        CsvFormat::FluXlock => "FluXlock".to_string(),
        CsvFormat::Generic => "Générique".to_string(),
    }
}

/// Truncate a string to max length without panicking on non-UTF8 boundaries
fn safe_truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Find the nearest char boundary before max_len
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// Map a CSV record to FluXlock fields using header-based column lookup.
/// Returns (title, username, password, url, notes, category)
fn map_record_to_fields(
    record: &csv::StringRecord,
    header_map: &HashMap<String, usize>,
    format: &CsvFormat,
) -> Result<(String, Option<String>, String, Option<String>, Option<String>, Option<String>), String> {
    // Helper: get a field by header name (case-insensitive)
    let get = |name: &str| -> Option<String> {
        header_map
            .get(&name.to_lowercase())
            .and_then(|&idx| record.get(idx))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };

    let (title, username, password, url, notes, category) = match format {
        CsvFormat::Chrome => (
            get("name").unwrap_or_default(),
            get("username"),
            get("password").unwrap_or_default(),
            get("url"),
            get("note").or_else(|| get("notes")),
            None,
        ),
        CsvFormat::Bitwarden => (
            get("name").unwrap_or_default(),
            get("login_username"),
            get("login_password").unwrap_or_default(),
            get("login_uri"),
            get("notes"),
            get("folder"),
        ),
        CsvFormat::LastPass => (
            get("name").unwrap_or_default(),
            get("username"),
            get("password").unwrap_or_default(),
            get("url"),
            get("extra"),
            get("grouping"),
        ),
        CsvFormat::OnePassword => (
            get("title").unwrap_or_default(),
            get("username"),
            get("password").unwrap_or_default(),
            get("url"),
            get("notes").or_else(|| get("notesplain")),
            get("type").or_else(|| get("category")),
        ),
        CsvFormat::FluXlock => (
            get("title").unwrap_or_default(),
            get("username"),
            get("password").unwrap_or_default(),
            get("url"),
            get("notes"),
            get("category"),
        ),
        CsvFormat::Generic => {
            // Best-effort mapping: try common names
            let title = get("title")
                .or_else(|| get("name"))
                .or_else(|| get("service"))
                .or_else(|| get("site"))
                .unwrap_or_default();
            let username = get("username")
                .or_else(|| get("login"))
                .or_else(|| get("email"))
                .or_else(|| get("user"));
            let password = get("password")
                .or_else(|| get("pass"))
                .unwrap_or_default();
            let url = get("url")
                .or_else(|| get("uri"))
                .or_else(|| get("website"));
            let notes = get("notes")
                .or_else(|| get("note"))
                .or_else(|| get("comment"));
            let category = get("category")
                .or_else(|| get("folder"))
                .or_else(|| get("group"));
            (title, username, password, url, notes, category)
        }
    };

    // Validate required fields
    if title.is_empty() && password.is_empty() {
        return Err("Titre et mot de passe vides — ligne ignorée".to_string());
    }
    if password.is_empty() {
        return Err(format!("Mot de passe vide pour \"{}\" — ligne ignorée", title));
    }

    // Enforce max lengths (VULN-020)
    Ok((
        safe_truncate(&title, MAX_TITLE),
        username.map(|u| safe_truncate(&u, MAX_USERNAME)),
        safe_truncate(&password, MAX_PASSWORD),
        url.map(|u| safe_truncate(&u, MAX_URL)),
        notes.map(|n| safe_truncate(&n, MAX_NOTES)),
        category.map(|c| safe_truncate(&c, MAX_CATEGORY)),
    ))
}

/// Build a header name → column index map (case-insensitive)
fn build_header_map(headers: &csv::StringRecord) -> HashMap<String, usize> {
    headers
        .iter()
        .enumerate()
        .map(|(idx, name)| (name.to_lowercase().trim().to_string(), idx))
        .collect()
}

/// Check if a parsed CSV entry matches an existing password (duplicate detection)
fn is_duplicate(
    title: &str,
    username: &Option<String>,
    _url: &Option<String>,
    existing: &[Password],
) -> Option<DuplicateMatch> {
    let title_lower = title.to_lowercase();
    for pw in existing {
        let title_match = pw.title.to_lowercase() == title_lower;
        let username_match = match (username, &pw.username) {
            (Some(a), Some(b)) => a.to_lowercase() == b.to_lowercase(),
            (None, None) => true,
            _ => false,
        };
        // Title + Username match is sufficient for duplicate detection
        if title_match && username_match {
            return Some(DuplicateMatch {
                id: pw.id,
                title: pw.title.clone(),
                username: pw.username.clone(),
                url: pw.url.clone(),
            });
        }
    }
    None
}

/// Mask a password for preview display
fn mask_password(pw: &str) -> String {
    if pw.is_empty() {
        return String::new();
    }
    let len = pw.chars().count();
    if len <= 4 {
        "••••".to_string()
    } else {
        format!("{}••••{}", &pw[..1], &pw[pw.len()-1..])
    }
}

// ═══════════════════════ Tauri Commands ═══════════════════════

/// Import passwords from a CSV file.
///
/// Two modes:
/// - "preview": Parse CSV, detect format and duplicates, return entries for user review
/// - "import": Execute the actual import using the user's conflict resolution decisions
///
/// Re-authentication is mandatory (master password OR biometric).
#[tauri::command]
pub async fn import_passwords_csv(
    mut request: ImportCsvRequest,
    state: State<'_, AppState>,
) -> Result<ImportCsvResponse, String> {
    // ── Size limit check (DoS prevention) ──
    if request.csv_content.len() > MAX_CSV_SIZE {
        return Err(format!(
            "Le fichier CSV dépasse la limite de {}MB",
            MAX_CSV_SIZE / (1024 * 1024)
        ));
    }

    if request.csv_content.trim().is_empty() {
        return Err("Le contenu CSV est vide".to_string());
    }

    // ── Re-authenticate ──
    let (user_id, encryption_key) =
        authenticate_for_csv_op(&request.master_password, &request.auth_method, &state).await?;

    // ── Protection ransomware (import modifie les données) ──
    if request.mode == "import" {
        let monitor = get_security_monitor();
        if monitor.is_readonly().await {
            // Zeroize sensitive data before returning
            request.csv_content.zeroize();
            if let Some(ref mut pw) = request.master_password {
                pw.zeroize();
            }
            return Err(
                "🚨 Système en mode lecture seule (protection ransomware) — import impossible"
                    .to_string(),
            );
        }
    }

    // ── Parse CSV headers ──
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .trim(csv::Trim::All)
        .from_reader(request.csv_content.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| format!("Erreur lecture en-têtes CSV: {}", e))?
        .clone();

    if headers.is_empty() {
        request.csv_content.zeroize();
        return Err("Le CSV ne contient pas d'en-têtes valides".to_string());
    }

    let format = detect_csv_format(&headers, &request.source_format);
    let header_map = build_header_map(&headers);

    // ── Retrieve existing passwords for duplicate detection ──
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;
    let existing_passwords = db
        .get_passwords(user_id)
        .await
        .map_err(|e| format!("Erreur récupération mots de passe: {}", e))?;

    // Decrypt existing passwords for duplicate comparison
    let mut decrypted_existing: Vec<Password> = Vec::new();
    for mut pw in existing_passwords {
        if let Ok(d) = decrypt_data_secure(&pw.title, &encryption_key) {
            pw.title = d;
        }
        if let Some(ref u) = pw.username {
            if let Ok(d) = decrypt_data_secure(u, &encryption_key) {
                pw.username = Some(d);
            }
        }
        if let Some(ref u) = pw.url {
            if let Ok(d) = decrypt_data_secure(u, &encryption_key) {
                pw.url = Some(d);
            }
        }
        decrypted_existing.push(pw);
    }

    // ── Parse all records ──
    let mut parsed_entries: Vec<ParsedCsvEntry> = Vec::new();
    let mut raw_passwords: Vec<String> = Vec::new(); // Keep actual passwords separate for import
    let mut error_count: usize = 0;
    let mut duplicate_count: usize = 0;
    let mut new_count: usize = 0;

    for (idx, result) in reader.records().enumerate() {
        match result {
            Ok(record) => {
                match map_record_to_fields(&record, &header_map, &format) {
                    Ok((title, username, password, url, notes, category)) => {
                        let dup = is_duplicate(&title, &username, &url, &decrypted_existing);
                        let is_dup = dup.is_some();
                        if is_dup {
                            duplicate_count += 1;
                        } else {
                            new_count += 1;
                        }

                        parsed_entries.push(ParsedCsvEntry {
                            index: idx,
                            title,
                            username,
                            password_preview: mask_password(&password),
                            url,
                            notes,
                            category,
                            is_duplicate: is_dup,
                            existing_match: dup,
                            parse_error: None,
                        });
                        raw_passwords.push(password);
                    }
                    Err(err) => {
                        error_count += 1;
                        parsed_entries.push(ParsedCsvEntry {
                            index: idx,
                            title: String::new(),
                            username: None,
                            password_preview: String::new(),
                            url: None,
                            notes: None,
                            category: None,
                            is_duplicate: false,
                            existing_match: None,
                            parse_error: Some(err),
                        });
                        raw_passwords.push(String::new());
                    }
                }
            }
            Err(e) => {
                error_count += 1;
                parsed_entries.push(ParsedCsvEntry {
                    index: idx,
                    title: String::new(),
                    username: None,
                    password_preview: String::new(),
                    url: None,
                    notes: None,
                    category: None,
                    is_duplicate: false,
                    existing_match: None,
                    parse_error: Some(format!("Erreur de parsing ligne {}: {}", idx + 2, e)),
                });
                raw_passwords.push(String::new());
            }
        }
    }

    let total_parsed = parsed_entries.len();

    // ════════════════════ PREVIEW MODE ════════════════════
    if request.mode == "preview" {
        // Zeroize raw CSV content and passwords (not needed for preview)
        request.csv_content.zeroize();
        if let Some(ref mut pw) = request.master_password {
            pw.zeroize();
        }
        for pw in raw_passwords.iter_mut() {
            pw.zeroize();
        }

        return Ok(ImportCsvResponse {
            success: true,
            mode: "preview".to_string(),
            detected_format: format_name(&format),
            total_parsed,
            duplicate_count,
            new_count,
            error_count,
            entries: Some(parsed_entries),
            imported_count: 0,
            skipped_count: 0,
            overwritten_count: 0,
            errors: Vec::new(),
            message: format!(
                "{} entrées détectées (format {}): {} nouvelles, {} doublons, {} erreurs",
                total_parsed,
                format_name(&format),
                new_count,
                duplicate_count,
                error_count
            ),
        });
    }

    // ════════════════════ IMPORT MODE ════════════════════
    let actions = request.entry_actions.ok_or(
        "Les actions par entrée sont requises en mode import (entry_actions manquant)".to_string(),
    )?;

    // Build action lookup map: index → action
    let action_map: HashMap<usize, &EntryAction> = actions.iter().map(|a| (a.index, a)).collect();

    let mut imported_count: usize = 0;
    let mut skipped_count: usize = 0;
    let mut overwritten_count: usize = 0;
    let mut import_errors: Vec<String> = Vec::new();

    for (i, entry) in parsed_entries.iter().enumerate() {
        // Skip entries with parse errors
        if entry.parse_error.is_some() {
            skipped_count += 1;
            continue;
        }

        let action = action_map.get(&entry.index);
        let action_str = action.map(|a| a.action.as_str()).unwrap_or("skip");

        match action_str {
            "skip" => {
                skipped_count += 1;
            }
            "import" | "overwrite" => {
                let raw_password = &raw_passwords[i];
                if raw_password.is_empty() {
                    import_errors.push(format!(
                        "Ligne {}: mot de passe vide, ignoré",
                        entry.index + 2
                    ));
                    skipped_count += 1;
                    continue;
                }

                // Encrypt all fields
                let enc_title = encrypt_data_secure(&entry.title, &encryption_key)
                    .map_err(|e| format!("Chiffrement titre: {}", e))?;
                let enc_username = entry
                    .username
                    .as_ref()
                    .map(|u| encrypt_data_secure(u, &encryption_key))
                    .transpose()
                    .map_err(|e| format!("Chiffrement username: {}", e))?;
                let enc_password = encrypt_data_secure(raw_password, &encryption_key)
                    .map_err(|e| format!("Chiffrement password: {}", e))?;
                let enc_url = entry
                    .url
                    .as_ref()
                    .map(|u| encrypt_data_secure(u, &encryption_key))
                    .transpose()
                    .map_err(|e| format!("Chiffrement URL: {}", e))?;
                let enc_notes = entry
                    .notes
                    .as_ref()
                    .map(|n| encrypt_data_secure(n, &encryption_key))
                    .transpose()
                    .map_err(|e| format!("Chiffrement notes: {}", e))?;
                let enc_category = entry
                    .category
                    .as_ref()
                    .map(|c| encrypt_data_secure(c, &encryption_key))
                    .transpose()
                    .map_err(|e| format!("Chiffrement catégorie: {}", e))?;

                if action_str == "overwrite" {
                    // Update existing entry
                    let overwrite_id = action
                        .and_then(|a| a.overwrite_id)
                        .or_else(|| entry.existing_match.as_ref().map(|m| m.id))
                        .ok_or_else(|| {
                            format!(
                                "Ligne {}: ID d'écrasement manquant pour le doublon",
                                entry.index + 2
                            )
                        })?;

                    match db
                        .update_password(
                            overwrite_id,
                            user_id,
                            &enc_title,
                            enc_username.as_deref(),
                            &enc_password,
                            enc_url.as_deref(),
                            enc_notes.as_deref(),
                            enc_category.as_deref(),
                        )
                        .await
                    {
                        Ok(_) => {
                            overwritten_count += 1;
                            let _ = db
                                .log_action(user_id, "CSV_OVERWRITE", "password", Some(overwrite_id))
                                .await;
                        }
                        Err(e) => {
                            import_errors.push(format!(
                                "Ligne {}: erreur mise à jour \"{}\" — {}",
                                entry.index + 2,
                                entry.title,
                                e
                            ));
                        }
                    }
                } else {
                    // Create new entry
                    match db
                        .create_password(
                            user_id,
                            &enc_title,
                            enc_username.as_deref(),
                            &enc_password,
                            enc_url.as_deref(),
                            enc_notes.as_deref(),
                            enc_category.as_deref(),
                        )
                        .await
                    {
                        Ok(new_id) => {
                            imported_count += 1;
                            let _ = db
                                .log_action(user_id, "CSV_IMPORT", "password", Some(new_id))
                                .await;
                        }
                        Err(e) => {
                            import_errors.push(format!(
                                "Ligne {}: erreur création \"{}\" — {}",
                                entry.index + 2,
                                entry.title,
                                e
                            ));
                        }
                    }
                }
            }
            other => {
                import_errors.push(format!(
                    "Ligne {}: action inconnue \"{}\"",
                    entry.index + 2,
                    other
                ));
                skipped_count += 1;
            }
        }
    }

    // ── Audit log ──
    let _ = db
        .log_action(user_id, "CSV_IMPORT_BATCH", "password", None)
        .await;

    // ── Zeroize all sensitive data ──
    request.csv_content.zeroize();
    if let Some(ref mut pw) = request.master_password {
        pw.zeroize();
    }
    for pw in raw_passwords.iter_mut() {
        pw.zeroize();
    }

    Ok(ImportCsvResponse {
        success: import_errors.is_empty(),
        mode: "import".to_string(),
        detected_format: format_name(&format),
        total_parsed,
        duplicate_count,
        new_count,
        error_count,
        entries: None,
        imported_count,
        skipped_count,
        overwritten_count,
        errors: import_errors,
        message: format!(
            "Import terminé: {} importés, {} écrasés, {} ignorés",
            imported_count, overwritten_count, skipped_count
        ),
    })
}

/// Export all passwords as a CSV string.
///
/// The CSV content is generated in memory and returned to the frontend
/// which handles the file save dialog. No file is written to disk.
///
/// Re-authentication is mandatory (master password OR biometric).
#[tauri::command]
pub async fn export_passwords_csv(
    mut request: ExportCsvRequest,
    state: State<'_, AppState>,
) -> Result<ExportCsvResponse, String> {
    // ── Re-authenticate ──
    let (user_id, encryption_key) =
        authenticate_for_csv_op(&request.master_password, &request.auth_method, &state).await?;

    // Zeroize password immediately (we have the key now)
    if let Some(ref mut pw) = request.master_password {
        pw.zeroize();
    }

    // ── Retrieve and decrypt all passwords ──
    let db_guard = state.db.lock().await;
    let db = db_guard
        .as_ref()
        .ok_or("Base de données non initialisée")?;
    let passwords = db
        .get_passwords(user_id)
        .await
        .map_err(|e| format!("Erreur récupération mots de passe: {}", e))?;

    // ── Build CSV in memory ──
    let mut csv_writer = csv::Writer::from_writer(Vec::new());

    // Write FluXlock native format header
    csv_writer
        .write_record(["title", "username", "password", "url", "notes", "category"])
        .map_err(|e| format!("Erreur écriture en-têtes CSV: {}", e))?;

    let mut count: usize = 0;
    let mut decrypt_errors: Vec<String> = Vec::new();

    for pw in &passwords {
        // Decrypt all fields
        let title = decrypt_data_secure(&pw.title, &encryption_key)
            .unwrap_or_else(|_| pw.title.clone());
        let username = pw
            .username
            .as_ref()
            .map(|u| decrypt_data_secure(u, &encryption_key).unwrap_or_else(|_| u.clone()))
            .unwrap_or_default();
        let password = match decrypt_data_secure(&pw.password, &encryption_key) {
            Ok(d) => d,
            Err(e) => {
                decrypt_errors.push(format!(
                    "Impossible de déchiffrer le mot de passe ID={}: {}",
                    pw.id, e
                ));
                continue; // Skip entries we can't decrypt
            }
        };
        let url = pw
            .url
            .as_ref()
            .map(|u| decrypt_data_secure(u, &encryption_key).unwrap_or_else(|_| u.clone()))
            .unwrap_or_default();
        let notes = pw
            .notes
            .as_ref()
            .map(|n| decrypt_data_secure(n, &encryption_key).unwrap_or_else(|_| n.clone()))
            .unwrap_or_default();
        let category = pw
            .category
            .as_ref()
            .map(|c| decrypt_data_secure(c, &encryption_key).unwrap_or_else(|_| c.clone()))
            .unwrap_or_default();

        csv_writer
            .write_record([&title, &username, &password, &url, &notes, &category])
            .map_err(|e| format!("Erreur écriture CSV ligne: {}", e))?;
        count += 1;
    }

    csv_writer
        .flush()
        .map_err(|e| format!("Erreur flush CSV: {}", e))?;

    let csv_bytes = csv_writer
        .into_inner()
        .map_err(|e| format!("Erreur finalisation CSV: {}", e))?;

    let csv_content = String::from_utf8(csv_bytes)
        .map_err(|_| "Erreur encodage CSV UTF-8".to_string())?;

    // ── Audit log ──
    let _ = db
        .log_action(user_id, "CSV_EXPORT", "password", None)
        .await;

    let message = if decrypt_errors.is_empty() {
        format!("{} mots de passe exportés avec succès", count)
    } else {
        format!(
            "{} exportés, {} erreurs de déchiffrement",
            count,
            decrypt_errors.len()
        )
    };

    Ok(ExportCsvResponse {
        success: true,
        csv_content,
        count,
        message,
    })
}

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
use zeroize::{Zeroize, Zeroizing};
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
    Chromium,
    Firefox,
    Bitwarden,
    LastPass,
    OnePassword,
    FluXlock,
    Generic,
}

/// Request for import (preview or execute)
#[derive(Deserialize)]
pub struct ImportCsvRequest {
    /// Master password for re-authentication. None if using biometric.
    pub master_password: Option<String>,
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
    /// Fixed mask for the preview. The import response contains no password.
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
    /// Master password for re-authentication. None if using biometric.
    pub master_password: Option<String>,
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
/// Accepts a master password or biometric auth.
/// Returns (user_id, vault_key) on success.
async fn authenticate_for_csv_op(
    master_password: &Option<String>,
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

    match master_password {
        Some(ref password) if !password.is_empty() => {
            // ── Password authentication path ──
            verify_password(password, &user.password_hash)
                .map_err(|_| "❌ Mot de passe incorrect".to_string())?;
            let key = crate::get_or_fetch_vault_key(state, user_id).await?;
            Ok((user_id, key))
        }
        _ => {
            #[cfg(target_os = "android")]
            return Err("Saisissez le mot de passe maître pour cette opération.".into());

            #[cfg(not(target_os = "android"))]
            {
                // ── Biometric authentication path ──
                // This triggers the OS-level biometric prompt (Touch ID / Face ID / Windows Hello)
                let (bio_uid, _bio_name, key_bytes) = crate::biometric::biometric_login(
                    &super::biometric_cmds::biometric_dir(state).await?,
                    &user.username,
                    user_id,
                )
                .map_err(|e| format!("Échec de l'authentification biométrique: {}", e))?;

                // Verify biometric identity matches current session
                if bio_uid != user_id {
                    return Err(
                        "Incohérence d'identité — le compte biométrique ne correspond pas à la session"
                            .to_string(),
                    );
                }

                let key = crate::secure_key::SecureKey::new(key_bytes);
                Ok((user_id, key))
            }
        }
    }
}

/// Detect the CSV format from header names
fn detect_csv_format(headers: &csv::StringRecord, hint: Option<&str>) -> CsvFormat {
    // If a hint is provided and valid, use it
    if let Some(fmt) = hint {
        match fmt.to_lowercase().as_str() {
            "brave" | "chrome" | "chromium" => return CsvFormat::Chromium,
            "firefox" => return CsvFormat::Firefox,
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
        return CsvFormat::Chromium;
    }

    if ["url", "username", "password", "guid"].iter().all(|name| h.iter().any(|header| header == name))
        && h.iter().any(|header| header == "httprealm" || header == "formactionorigin")
    {
        return CsvFormat::Firefox;
    }

    // 1Password: has "title" or "Title" + "password" or "Password"
    if h.iter().any(|c| c == "title") && h.iter().any(|c| c == "password") {
        return CsvFormat::OnePassword;
    }

    CsvFormat::Generic
}

fn format_name(f: &CsvFormat) -> String {
    match f {
        CsvFormat::Chromium => "Brave / Chrome".to_string(),
        CsvFormat::Firefox => "Firefox".to_string(),
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
    let get = |name: &str| -> Option<String> {
        header_map.get(name).and_then(|&index| record.get(index))
            .filter(|value| !value.is_empty()).map(str::to_owned)
    };

    let (title, username, password, url, notes, category) = match format {
        CsvFormat::Chromium => (
            get("name").unwrap_or_default(),
            get("username"),
            get("password").unwrap_or_default(),
            get("url"),
            get("note").or_else(|| get("notes")),
            None,
        ),
        CsvFormat::Firefox => {
            let url = get("url");
            let title = match (url.as_deref(), get("httprealm")) {
                (Some(url), Some(realm)) => format!("{} ({realm})", title_from_url(url)),
                _ => String::new(),
            };
            (title, get("username"), get("password").unwrap_or_default(), url, None, None)
        }
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
            get("website").or_else(|| get("url")),
            get("notes").or_else(|| get("notesplain")),
            get("category").or_else(|| get("tags")).or_else(|| get("type")),
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

    let url = url.map(|value| value.trim().to_owned()).filter(|value| !value.is_empty());
    let title = if !title.trim().is_empty() {
        title.trim().to_owned()
    } else {
        url.as_deref().map(title_from_url).unwrap_or_else(|| "Identifiant sans titre".into())
    };
    if password.is_empty() {
        return Err("Mot de passe vide".into());
    }
    if password.len() > MAX_PASSWORD {
        return Err(format!("Mot de passe au-delà de la limite de {MAX_PASSWORD} octets"));
    }

    // Enforce max lengths (VULN-020)
    Ok((
        safe_truncate(&title, MAX_TITLE),
        username.map(|u| safe_truncate(&u, MAX_USERNAME)),
        password,
        url.map(|u| safe_truncate(&u, MAX_URL)),
        notes.map(|n| safe_truncate(&n, MAX_NOTES)),
        category.map(|c| safe_truncate(&c, MAX_CATEGORY)),
    ))
}

fn title_from_url(value: &str) -> String {
    tauri::Url::parse(value).ok().and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| value.to_owned())
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
    url: &Option<String>,
    existing: &[Password],
) -> Option<DuplicateMatch> {
    let title_lower = title.to_lowercase();
    for pw in existing {
        if pw.title.to_lowercase() == title_lower && &pw.username == username && &pw.url == url {
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

enum CsvOperation<'a> {
    Preview,
    Import(&'a [EntryAction]),
}

fn csv_operation<'a>(mode: &str, actions: Option<&'a [EntryAction]>) -> Result<CsvOperation<'a>, String> {
    match (mode, actions) {
        ("preview", _) => Ok(CsvOperation::Preview),
        ("import", Some(actions)) => Ok(CsvOperation::Import(actions)),
        ("import", None) => Err("Les actions par entrée sont requises pour importer.".into()),
        _ => Err("Mode d’import CSV invalide.".into()),
    }
}

#[tauri::command]
pub async fn import_passwords_csv(
    request: ImportCsvRequest,
    state: State<'_, AppState>,
) -> Result<ImportCsvResponse, String> {
    let csv_content = Zeroizing::new(request.csv_content);
    let master_password = Zeroizing::new(request.master_password);
    if csv_content.len() > MAX_CSV_SIZE {
        return Err("Le fichier CSV dépasse la limite de 10 Mio.".into());
    }
    if csv_content.trim().is_empty() {
        return Err("Le contenu CSV est vide.".into());
    }

    let operation = csv_operation(&request.mode, request.entry_actions.as_deref())?;
    let _lifecycle = state.auth_lifecycle.lock().await;
    crate::validate_session(&state).await?;
    let (user_id, key) = authenticate_for_csv_op(&master_password, &state).await?;
    if matches!(operation, CsvOperation::Import(_)) && get_security_monitor().is_readonly().await {
        return Err("Le coffre est en lecture seule. L’import est indisponible.".into());
    }

    let database = state.db.lock().await;
    let db = database.as_ref().ok_or("Base de données non initialisée")?;
    process_csv(db, user_id, &key, &csv_content, request.source_format.as_deref(), operation).await
}

async fn process_csv(
    db: &crate::database::Database,
    user_id: i64,
    encryption_key: &crate::secure_key::SecureKey,
    csv_content: &str,
    source_format: Option<&str>,
    operation: CsvOperation<'_>,
) -> Result<ImportCsvResponse, String> {
    // ── Parse CSV headers ──
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .trim(csv::Trim::Headers)
        .from_reader(csv_content.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| format!("Erreur lecture en-têtes CSV: {}", e))?
        .clone();

    let format = detect_csv_format(&headers, source_format);
    let header_map = build_header_map(&headers);
    let has_password_column = match format {
        CsvFormat::Bitwarden => header_map.contains_key("login_password"),
        CsvFormat::Generic => header_map.contains_key("password") || header_map.contains_key("pass"),
        _ => header_map.contains_key("password"),
    };
    if !has_password_column || header_map.len() != headers.len() {
        return Err("Colonnes CSV non reconnues ou en double. Vérifiez le format sélectionné.".into());
    }

    let existing_passwords = db
        .get_passwords(user_id)
        .await
        .map_err(|e| format!("Erreur récupération mots de passe: {}", e))?;

    // Decrypt existing passwords for duplicate comparison
    let mut decrypted_existing: Vec<Password> = Vec::new();
    for mut pw in existing_passwords {
        if let Ok(d) = decrypt_data_secure(&pw.title, encryption_key) {
            pw.title = d;
        }
        if let Some(ref u) = pw.username {
            if let Ok(d) = decrypt_data_secure(u, encryption_key) {
                pw.username = Some(d);
            }
        }
        if let Some(ref u) = pw.url {
            if let Ok(d) = decrypt_data_secure(u, encryption_key) {
                pw.url = Some(d);
            }
        }
        decrypted_existing.push(pw);
    }

    // ── Parse all records ──
    let mut parsed_entries: Vec<ParsedCsvEntry> = Vec::new();
    let mut raw_passwords = Zeroizing::new(Vec::<String>::new());
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
                            password_preview: "••••••••".to_string(),
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
    let CsvOperation::Import(actions) = operation else {
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
    };

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
                let enc_title = encrypt_data_secure(&entry.title, encryption_key)
                    .map_err(|e| format!("Chiffrement titre: {}", e))?;
                let enc_username = entry
                    .username
                    .as_ref()
                    .map(|u| encrypt_data_secure(u, encryption_key))
                    .transpose()
                    .map_err(|e| format!("Chiffrement username: {}", e))?;
                let enc_password = encrypt_data_secure(raw_password, encryption_key)
                    .map_err(|e| format!("Chiffrement password: {}", e))?;
                let enc_url = entry
                    .url
                    .as_ref()
                    .map(|u| encrypt_data_secure(u, encryption_key))
                    .transpose()
                    .map_err(|e| format!("Chiffrement URL: {}", e))?;
                let enc_notes = entry
                    .notes
                    .as_ref()
                    .map(|n| encrypt_data_secure(n, encryption_key))
                    .transpose()
                    .map_err(|e| format!("Chiffrement notes: {}", e))?;
                let enc_category = entry
                    .category
                    .as_ref()
                    .map(|c| encrypt_data_secure(c, encryption_key))
                    .transpose()
                    .map_err(|e| format!("Chiffrement catégorie: {}", e))?;

                if action_str == "overwrite" {
                    let matched_id = entry.existing_match.as_ref().map(|matched| matched.id);
                    let requested_id = action.and_then(|action| action.overwrite_id);
                    let Some(overwrite_id) = matched_id.filter(|id| requested_id.is_none_or(|requested| requested == *id)) else {
                        import_errors.push(format!("Ligne {} : la fiche à remplacer ne correspond plus au doublon.", entry.index + 2));
                        skipped_count += 1;
                        continue;
                    };

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
                        Ok(true) => {
                            overwritten_count += 1;
                            let _ = db
                                .log_action(user_id, "CSV_OVERWRITE", "password", Some(overwrite_id))
                                .await;
                        }
                        Ok(false) => {
                            import_errors.push(format!("Ligne {} : la fiche à remplacer est introuvable.", entry.index + 2));
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
        authenticate_for_csv_op(&request.master_password, &state).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{database::Database, secure_key::SecureKey};

    #[derive(Deserialize)]
    struct Fixture {
        id: String,
        label: String,
        csv: String,
        expected: Vec<serde_json::Value>,
    }

    async fn test_vault(dir: &std::path::Path) -> (Database, i64, SecureKey) {
        let db = Database::new(&dir.join("vault.db")).await.unwrap();
        db.initialize().await.unwrap();
        let user = db.create_user("fixture", "test@example.test", "hash", "salt").await.unwrap();
        (db, user, SecureKey::from_slice(&[19; 32]))
    }

    fn action(index: usize, action: &str, overwrite_id: Option<i64>) -> EntryAction {
        EntryAction { index, action: action.into(), overwrite_id }
    }

    fn decrypt_optional(value: Option<&str>, key: &SecureKey) -> Option<String> {
        value.map(|value| decrypt_data_secure(value, key).unwrap())
    }

    #[tokio::test]
    async fn csv_market_exports_round_trip_through_the_vault() {
        let cases: Vec<Fixture> = serde_json::from_str(include_str!("../../../tests/fixtures/password-imports.json")).unwrap();
        let mut reports = Vec::new();

        for fixture in cases {
            let dir = tempfile::tempdir().unwrap();
            let (db, user_id, key) = test_vault(dir.path()).await;
            let preview = process_csv(&db, user_id, &key, &fixture.csv, None, CsvOperation::Preview).await.unwrap();
            let entries = preview.entries.as_ref().unwrap();
            assert!(db.get_passwords(user_id).await.unwrap().is_empty());
            assert_eq!(preview.detected_format, fixture.label);
            assert_eq!(preview.new_count, fixture.expected.len());
            assert_eq!(preview.error_count, usize::from(fixture.id == "brave"));
            let actions: Vec<_> = entries.iter().filter(|entry| entry.parse_error.is_none())
                .map(|entry| action(entry.index, "import", None)).collect();

            for (entry, expected) in entries.iter().zip(&fixture.expected) {
                assert_eq!(entry.title, expected["title"]);
                assert_eq!(serde_json::json!(entry.username), expected["username"]);
                assert_eq!(serde_json::json!(entry.url), expected["url"]);
                assert_eq!(serde_json::json!(entry.category), expected["category"]);
                assert_eq!(serde_json::json!(entry.notes), expected["notes"]);
                assert_eq!(entry.password_preview, "••••••••");
                assert!(!serde_json::to_string(&preview).unwrap().contains(expected["password"].as_str().unwrap()));
            }

            let imported = process_csv(&db, user_id, &key, &fixture.csv, None, CsvOperation::Import(&actions)).await.unwrap();
            assert!(imported.success);
            assert_eq!(imported.imported_count, fixture.expected.len());
            assert_eq!(imported.skipped_count, preview.error_count);
            let mut passwords = db.get_passwords(user_id).await.unwrap();
            passwords.sort_by_key(|password| password.id);
            assert_eq!(passwords.len(), fixture.expected.len());
            let displayed: Vec<_> = passwords.into_iter().zip(&fixture.expected).map(|(mut stored, expected)| {
                assert!(stored.password.starts_with("v2:"));
                assert!(stored.title.starts_with("v2:"));
                assert_ne!(stored.password, expected["password"]);
                stored.title = decrypt_data_secure(&stored.title, &key).unwrap();
                stored.password = decrypt_data_secure(&stored.password, &key).unwrap();
                stored.username = decrypt_optional(stored.username.as_deref(), &key);
                stored.url = decrypt_optional(stored.url.as_deref(), &key);
                stored.notes = decrypt_optional(stored.notes.as_deref(), &key);
                stored.category = decrypt_optional(stored.category.as_deref(), &key);
                let value = serde_json::to_value(stored).unwrap();
                for field in ["title", "password", "username", "url", "notes", "category"] {
                    assert_eq!(value[field], expected[field], "{} field {field}", fixture.label);
                }
                value
            }).collect();

            let repeated = process_csv(&db, user_id, &key, &fixture.csv, None, CsvOperation::Preview).await.unwrap();
            assert_eq!(repeated.duplicate_count, fixture.expected.len());
            assert_eq!(repeated.new_count, 0);
            reports.push(serde_json::json!({
                "id": fixture.id,
                "label": fixture.label,
                "csv": fixture.csv,
                "preview": preview,
                "imported": imported,
                "repeated": repeated,
                "passwords": displayed,
            }));
        }

        // Used by browser tests to render actual backend responses with fictitious data.
        if let Some(path) = std::env::var_os("FLUXLOCK_CSV_TEST_RESULTS") {
            let report = std::fs::File::create(path).unwrap();
            serde_json::to_writer(report, &reports).unwrap();
        }
    }

    #[tokio::test]
    async fn csv_rejects_ambiguous_input_and_protects_the_overwrite_target() {
        let dir = tempfile::tempdir().unwrap();
        let (db, user_id, key) = test_vault(dir.path()).await;
        let initial = "name,url,username,password\nExemple,https://one.example.test/,fixture,initial";
        let other = "name,url,username,password\nExemple,https://two.example.test/,fixture,autre";
        let replacement = "name,url,username,password\nExemple,https://one.example.test/,fixture,nouveau";
        let add = [action(0, "import", None)];
        for csv in [initial, other] {
            let report = process_csv(&db, user_id, &key, csv, None, CsvOperation::Import(&add)).await.unwrap();
            assert_eq!(report.imported_count, 1);
            assert_eq!(report.duplicate_count, 0);
        }

        let preview = process_csv(&db, user_id, &key, replacement, Some("brave"), CsvOperation::Preview).await.unwrap();
        let expected_id = preview.entries.unwrap()[0].existing_match.as_ref().unwrap().id;
        let rows = db.get_passwords(user_id).await.unwrap();
        let other_id = rows.iter().find(|row| row.id != expected_id).unwrap().id;
        let wrong_action = [action(0, "overwrite", Some(other_id))];
        let report = process_csv(&db, user_id, &key, replacement, None, CsvOperation::Import(&wrong_action)).await.unwrap();
        assert!(!report.success);
        assert_eq!(report.overwritten_count, 0);
        assert_eq!(decrypt_data_secure(&db.get_password(other_id, user_id).await.unwrap().unwrap().password, &key).unwrap(), "autre");

        let overwrite = [action(0, "overwrite", Some(expected_id))];
        let report = process_csv(&db, user_id, &key, replacement, None, CsvOperation::Import(&overwrite)).await.unwrap();
        assert!(report.success);
        assert_eq!(report.overwritten_count, 1);
        assert_eq!(decrypt_data_secure(&db.get_password(expected_id, user_id).await.unwrap().unwrap().password, &key).unwrap(), "nouveau");

        assert!(csv_operation("unexpected", Some(&add)).is_err());
        assert!(csv_operation("import", None).is_err());
        for csv in ["title,site\nExemple,example.test", "title,password,Password\nExemple,un,deux"] {
            assert!(process_csv(&db, user_id, &key, csv, None, CsvOperation::Preview).await.is_err());
        }
        let long = format!("name,url,username,password\nExemple,,fixture,{}", "é".repeat(MAX_PASSWORD));
        let report = process_csv(&db, user_id, &key, &long, None, CsvOperation::Preview).await.unwrap();
        assert_eq!(report.error_count, 1);
        assert_eq!(db.get_passwords(user_id).await.unwrap().len(), 2);
    }
}

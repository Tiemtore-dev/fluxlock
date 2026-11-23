//! Secure notes. Callers hold the vault lifecycle guard and the database mutex.
//! Titles and bodies use independent HKDF contexts and authenticated record identities.
use crate::{database::Database, secure_key::SecureKey, AppState};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use tauri::State;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_NOTE_BYTES: usize = 1024 * 1024;
pub const MAX_ATTACHMENT_BYTES: usize = 32 * 1024 * 1024;
const MAX_BLOB_BYTES: usize = 48 * 1024 * 1024;
// JSON may expand a UTF-8 control byte into six ASCII bytes (e.g. \u0000).
const MAX_BODY_JSON_BYTES: usize = 6 * MAX_NOTE_BYTES + 8192;

pub(crate) async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS note_schema (version INTEGER NOT NULL)")
        .execute(&mut *tx)
        .await?;
    let version: Option<i64> = sqlx::query_scalar("SELECT version FROM note_schema")
        .fetch_optional(&mut *tx)
        .await?;
    if version.is_some_and(|v| v != 1) {
        return Err(sqlx::Error::Protocol(
            "Version du modèle Notes non prise en charge".into(),
        ));
    }
    if version.is_none() {
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS secure_files_owner ON secure_files(id, user_id)",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("CREATE TABLE secure_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            crypto_id TEXT NOT NULL UNIQUE, encrypted_title TEXT NOT NULL, encrypted_body TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK(revision > 0), format_version INTEGER NOT NULL CHECK(format_version = 1),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(id, user_id), FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )").execute(&mut *tx).await?;
        sqlx::query(
            "CREATE TABLE note_attachments (
            note_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, file_id INTEGER NOT NULL,
            FOREIGN KEY(note_id, user_id) REFERENCES secure_notes(id, user_id) ON DELETE CASCADE,
            FOREIGN KEY(file_id, user_id) REFERENCES secure_files(id, user_id) ON DELETE RESTRICT
        )",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query("CREATE INDEX note_attachment_file ON note_attachments(file_id, user_id)")
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO note_schema VALUES (1)")
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

#[derive(FromRow)]
struct StoredNote {
    id: i64,
    user_id: i64,
    crypto_id: String,
    encrypted_title: String,
    encrypted_body: String,
    revision: i64,
    format_version: i64,
    created_at: String,
    updated_at: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoteAttachment {
    pub id: i64,
    pub filename: String,
    pub file_size: i64,
    // This hash is inside the authenticated note body, never accepted from the webview.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub(crate) blob_hash: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    text: String,
    attachment: Option<NoteAttachment>,
}
impl Drop for Body {
    fn drop(&mut self) {
        self.text.zeroize();
        if let Some(file) = self.attachment.as_mut() {
            file.filename.zeroize();
        }
    }
}

#[derive(Serialize)]
pub struct NoteSummary {
    pub id: i64,
    pub title: String,
    pub revision: i64,
    pub has_attachment: bool,
    pub created_at: String,
    pub updated_at: String,
}
impl Drop for NoteSummary {
    fn drop(&mut self) {
        self.title.zeroize();
    }
}
#[derive(Serialize)]
pub struct NotePage {
    pub items: Vec<NoteSummary>,
    pub total: i64,
}
#[derive(Serialize)]
pub struct NoteDetail {
    pub id: i64,
    pub title: String,
    pub body: String,
    pub revision: i64,
    pub attachment: Option<NoteAttachment>,
}
impl Drop for NoteDetail {
    fn drop(&mut self) {
        self.title.zeroize();
        self.body.zeroize();
        if let Some(file) = self.attachment.as_mut() {
            file.filename.zeroize();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveNoteRequest {
    pub id: Option<i64>,
    pub revision: Option<i64>,
    pub title: String,
    pub body: String,
    pub attachment_file_id: Option<i64>,
    pub attachment_path: Option<String>,
    pub attachment_name: Option<String>,
    pub attachment_data: Option<String>,
}
impl Drop for SaveNoteRequest {
    fn drop(&mut self) {
        self.title.zeroize();
        self.body.zeroize();
        if let Some(data) = self.attachment_data.as_mut() {
            data.zeroize();
        }
    }
}

fn valid_text(title: &str, body: &str) -> Result<(), String> {
    if title.trim().is_empty() || title.chars().count() > 256 || title.chars().any(char::is_control)
    {
        return Err(
            "Le titre doit contenir de 1 à 256 caractères, sans caractères de contrôle".into(),
        );
    }
    if body.len() > MAX_NOTE_BYTES {
        return Err("La note dépasse la limite de 1 Mio de texte UTF-8".into());
    }
    Ok(())
}

fn crypt(
    key: &SecureKey,
    identity: &str,
    owner: i64,
    record_id: i64,
    revision: i64,
    field: &str,
    data: &[u8],
    encrypt: bool,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if uuid::Uuid::parse_str(identity).is_err() || revision < 1 || record_id < 1 {
        return Err("Identité de note invalide".into());
    }
    let aad = serde_json::to_vec(&(
        "fluxlock/notes/v1",
        identity,
        owner,
        record_id,
        revision,
        field,
    ))
    .map_err(|e| e.to_string())?;
    key.use_key(|master| {
        let derived = secure_vault_crypto::key_derivation::hkdf::derive_key_hkdf(
            master,
            Some(identity.as_bytes()),
            format!("fluxlock/notes/v1/{field}").as_bytes(),
            32,
        )
        .map_err(|_| "Dérivation de note impossible")?;
        let cipher = ChaCha20Poly1305::new_from_slice(derived.expose_secret())
            .map_err(|_| "Clé invalide")?;
        if encrypt {
            let mut nonce = [0u8; 12];
            rand::rngs::OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| "Source aléatoire indisponible")?;
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: data,
                        aad: &aad,
                    },
                )
                .map_err(|_| "Chiffrement de note impossible")?;
            let mut result = nonce.to_vec();
            result.extend(ciphertext);
            Ok(Zeroizing::new(result))
        } else {
            if data.len() < 28 {
                return Err("Note chiffrée invalide".into());
            }
            cipher
                .decrypt(
                    Nonce::from_slice(&data[..12]),
                    Payload {
                        msg: &data[12..],
                        aad: &aad,
                    },
                )
                .map(Zeroizing::new)
                .map_err(|_| "L’intégrité de la note ne peut pas être vérifiée".into())
        }
    })
}
fn seal(
    key: &SecureKey,
    identity: &str,
    owner: i64,
    record_id: i64,
    revision: i64,
    field: &str,
    data: &[u8],
) -> Result<String, String> {
    Ok(format!(
        "note1:{}",
        STANDARD.encode(&*crypt(
            key, identity, owner, record_id, revision, field, data, true
        )?)
    ))
}
fn open(
    key: &SecureKey,
    note: &StoredNote,
    field: &str,
    value: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    if note.format_version != 1 || value.len() > (MAX_BODY_JSON_BYTES + 28).div_ceil(3) * 4 + 6 {
        return Err("Format de note invalide".into());
    }
    let bytes = STANDARD
        .decode(
            value
                .strip_prefix("note1:")
                .ok_or("Format de note invalide")?,
        )
        .map_err(|_| "Note chiffrée invalide")?;
    crypt(
        key,
        &note.crypto_id,
        note.user_id,
        note.id,
        note.revision,
        field,
        &bytes,
        false,
    )
}

async fn stored(db: &Database, user: i64, id: i64) -> Result<StoredNote, String> {
    sqlx::query_as("SELECT * FROM secure_notes WHERE id = ? AND user_id = ?")
        .bind(id)
        .bind(user)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Note introuvable".into())
}
fn blob_hash(path: &Path) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_BLOB_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_BLOB_BYTES {
        return Err("Pièce jointe trop volumineuse".into());
    }
    Ok(hex::encode(secure_vault_crypto::blake3_hash(&bytes)))
}

pub(crate) async fn read_detail(
    state: &AppState,
    db: &Database,
    key: &SecureKey,
    user: i64,
    id: i64,
) -> Result<NoteDetail, String> {
    let note = stored(db, user, id).await?;
    let title = Zeroizing::new(
        String::from_utf8(open(key, &note, "title", &note.encrypted_title)?.to_vec())
            .map_err(|_| "Titre invalide")?,
    );
    let body: Body = serde_json::from_slice(&open(key, &note, "body", &note.encrypted_body)?)
        .map_err(|_| "Contenu de note invalide")?;
    let linked: Option<i64> = sqlx::query_scalar(
        "SELECT file_id FROM note_attachments WHERE note_id = ? AND user_id = ?",
    )
    .bind(id)
    .bind(user)
    .fetch_optional(&db.pool)
    .await
    .map_err(|e| e.to_string())?;
    if linked != body.attachment.as_ref().map(|f| f.id) {
        return Err("Le rattachement de la pièce jointe a été altéré".into());
    }
    if let Some(attachment) = body.attachment.as_ref() {
        let file = db
            .get_secure_file(attachment.id, user)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Pièce jointe absente")?;
        let path = super::files::encrypted_file_path(state, &file.file_path).await?;
        let actual = tokio::task::spawn_blocking(move || blob_hash(&path))
            .await
            .map_err(|e| e.to_string())??;
        if actual != attachment.blob_hash || file.file_size != attachment.file_size {
            return Err("L’intégrité de la pièce jointe ne peut pas être vérifiée".into());
        }
    }
    Ok(NoteDetail {
        id: note.id,
        title: title.to_string(),
        body: body.text.clone(),
        revision: note.revision,
        attachment: body.attachment.clone(),
    })
}

// Uncommitted encrypted blobs are removed on error/cancellation. Crash recovery only
// removes note-owned UUID blobs absent from secure_files, never arbitrary user files.
struct PreparedFile {
    path: PathBuf,
    filename: String,
    size: i64,
    committed: bool,
}
impl Drop for PreparedFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
fn prepare_file(
    dir: &Path,
    key: &SecureKey,
    filename: String,
    reader: &mut impl Read,
) -> Result<PreparedFile, String> {
    if !super::files::valid_export_name(&filename) {
        return Err("Nom de pièce jointe invalide".into());
    }
    let path = dir.join(format!("note-{}.senc", uuid::Uuid::new_v4()));
    // Do not claim ownership until publication succeeds: a UUID collision must
    // never remove a pre-existing file when persist_noclobber fails.
    let mut prepared = PreparedFile {
        path,
        filename,
        size: 0,
        committed: true,
    };
    let (size, _) = super::files::publish_new_file(&prepared.path, |output| {
        let mut limited = reader.take(MAX_ATTACHMENT_BYTES as u64 + 1);
        crate::crypto::encrypt_file_stream_with_hash(key, &mut limited, output, 0)
            .map_err(|e| e.to_string())
    })?;
    prepared.committed = false;
    if size > MAX_ATTACHMENT_BYTES as u64 {
        return Err("La pièce jointe dépasse 32 Mio".into());
    }
    prepared.size = size as i64;
    Ok(prepared)
}

pub(crate) async fn recover_files(db: &Database, dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    crate::vault::private_directory(dir)?;
    let used: Vec<String> = sqlx::query_scalar("SELECT file_path FROM secure_files")
        .fetch_all(&db.pool)
        .await
        .map_err(|e| e.to_string())?;
    let names: std::collections::HashSet<_> = used
        .iter()
        .filter_map(|p| Path::new(p).file_name())
        .collect();
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|n| n.strip_prefix("note-"))
            .and_then(|n| n.strip_suffix(".senc"))
        else {
            continue;
        };
        if uuid::Uuid::parse_str(id).is_ok()
            && entry.file_type().map_err(|e| e.to_string())?.is_file()
            && !names.contains(name.as_os_str())
        {
            std::fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub(crate) async fn save_inner(
    state: &AppState,
    db: &Database,
    key: &SecureKey,
    user: i64,
    request: &SaveNoteRequest,
) -> Result<i64, String> {
    save_with_file(state, db, key, user, request, None).await
}

async fn save_with_file(
    state: &AppState,
    db: &Database,
    key: &SecureKey,
    user: i64,
    request: &SaveNoteRequest,
    imported: Option<PreparedFile>,
) -> Result<i64, String> {
    valid_text(&request.title, &request.body)?;
    if crate::security_monitor::get_security_monitor()
        .is_readonly()
        .await
    {
        return Err("Le coffre est en lecture seule".into());
    }
    if request.id.is_none() {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secure_notes WHERE user_id = ?")
            .bind(user)
            .fetch_one(&db.pool)
            .await
            .map_err(|e| e.to_string())?;
        if count >= 10000 {
            return Err("Ce coffre contient déjà 10 000 notes".into());
        }
    }
    let (identity, revision) = match request.id {
        Some(id) => {
            let old = stored(db, user, id).await?;
            if request.revision != Some(old.revision) {
                return Err("La note a été modifiée. Rouvrez-la avant d’enregistrer.".into());
            }
            // Authenticate the previous binding before accepting new references.
            read_detail(state, db, key, user, id).await?;
            (
                old.crypto_id,
                old.revision
                    .checked_add(1)
                    .ok_or("Version de note invalide")?,
            )
        }
        None => {
            if request.revision.is_some() {
                return Err("Version de note invalide".into());
            }
            (uuid::Uuid::new_v4().to_string(), 1)
        }
    };
    let sources = request.attachment_file_id.is_some() as u8
        + request.attachment_path.is_some() as u8
        + request.attachment_data.is_some() as u8;
    if sources > 1 || (request.attachment_data.is_some() != request.attachment_name.is_some()) {
        return Err("Choisissez une seule pièce jointe".into());
    }
    let dir = super::files::files_dir(state).await?;
    let mut prepared = if imported.is_some() {
        if sources != 0 {
            return Err("Pièce jointe ambiguë".into());
        }
        imported
    } else if let Some(path) = request.attachment_path.as_ref() {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| "Pièce jointe inaccessible")?;
        if !metadata.is_file() || metadata.len() > MAX_ATTACHMENT_BYTES as u64 {
            return Err("Choisissez un fichier ordinaire de 32 Mio maximum".into());
        }
        let filename = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Nom de fichier invalide")?
            .to_owned();
        let path = path.clone();
        let key = SecureKey::from_slice(&key.to_vec());
        let dir = dir.clone();
        Some(
            tokio::task::spawn_blocking(move || {
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NOFOLLOW);
                }
                let mut source = options
                    .open(path)
                    .map_err(|_| "Pièce jointe inaccessible")?;
                if !source.metadata().map_err(|e| e.to_string())?.is_file() {
                    return Err("Fichier ordinaire requis".into());
                }
                prepare_file(&dir, &key, filename, &mut source)
            })
            .await
            .map_err(|e| e.to_string())??,
        )
    } else if let Some(data) = request.attachment_data.as_ref() {
        if data.len() > MAX_ATTACHMENT_BYTES.div_ceil(3) * 4 {
            return Err("La pièce jointe dépasse 32 Mio".into());
        }
        let bytes = Zeroizing::new(STANDARD.decode(data).map_err(|_| "Pièce jointe invalide")?);
        if bytes.len() > MAX_ATTACHMENT_BYTES {
            return Err("La pièce jointe dépasse 32 Mio".into());
        }
        let filename = request
            .attachment_name
            .clone()
            .ok_or("Nom de fichier requis")?;
        let key = SecureKey::from_slice(&key.to_vec());
        let dir = dir.clone();
        Some(
            tokio::task::spawn_blocking(move || {
                prepare_file(&dir, &key, filename, &mut std::io::Cursor::new(&*bytes))
            })
            .await
            .map_err(|e| e.to_string())??,
        )
    } else {
        None
    };
    let mut tx = db.pool.begin().await.map_err(|e| e.to_string())?;
    let attachment = if let Some(file) = prepared.as_ref() {
        let name =
            crate::crypto::encrypt_data_secure(&file.filename, key).map_err(|e| e.to_string())?;
        let result = sqlx::query(
            "INSERT INTO secure_files(user_id, filename, file_path, file_size) VALUES (?, ?, ?, ?)",
        )
        .bind(user)
        .bind(name)
        .bind(file.path.to_string_lossy().as_ref())
        .bind(file.size)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
        let path = file.path.clone();
        let hash = tokio::task::spawn_blocking(move || blob_hash(&path))
            .await
            .map_err(|e| e.to_string())??;
        Some(NoteAttachment {
            id: result.last_insert_rowid(),
            filename: file.filename.clone(),
            file_size: file.size,
            blob_hash: hash,
        })
    } else if let Some(id) = request.attachment_file_id {
        let file = db
            .get_secure_file(id, user)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Fichier introuvable dans ce coffre")?;
        if file.file_size < 0 || file.file_size > MAX_ATTACHMENT_BYTES as i64 {
            return Err("La pièce jointe dépasse 32 Mio".into());
        }
        let filename = crate::crypto::decrypt_data_secure(&file.filename, key)
            .map_err(|_| "Nom de fichier altéré")?;
        let path = super::files::encrypted_file_path(state, &file.file_path).await?;
        let hash = tokio::task::spawn_blocking(move || blob_hash(&path))
            .await
            .map_err(|e| e.to_string())??;
        Some(NoteAttachment {
            id,
            filename,
            file_size: file.file_size,
            blob_hash: hash,
        })
    } else {
        None
    };
    let body = Zeroizing::new(
        serde_json::to_vec(&Body {
            text: request.body.clone(),
            attachment: attachment.clone(),
        })
        .map_err(|e| e.to_string())?,
    );
    let id = if let Some(id) = request.id {
        id
    } else {
        // Reserve the primary key inside the transaction so it can be authenticated
        // as well as the UUID. Only empty placeholders exist before encryption.
        sqlx::query("INSERT INTO secure_notes(user_id, crypto_id, encrypted_title, encrypted_body, revision, format_version) VALUES (?, ?, '', '', 1, 1)")
            .bind(user).bind(&identity).execute(&mut *tx).await.map_err(|e| e.to_string())?.last_insert_rowid()
    };
    let encrypted_title = seal(
        key,
        &identity,
        user,
        id,
        revision,
        "title",
        request.title.trim().as_bytes(),
    )?;
    let encrypted_body = seal(key, &identity, user, id, revision, "body", &body)?;
    let result = sqlx::query("UPDATE secure_notes SET encrypted_title = ?, encrypted_body = ?, revision = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND revision = ?")
        .bind(encrypted_title).bind(encrypted_body).bind(revision).bind(id).bind(user).bind(request.revision.unwrap_or(1)).execute(&mut *tx).await.map_err(|e| e.to_string())?;
    if result.rows_affected() != 1 {
        return Err("Conflit de modification de la note".into());
    }
    sqlx::query("DELETE FROM note_attachments WHERE note_id = ? AND user_id = ?")
        .bind(id)
        .bind(user)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(file) = attachment {
        sqlx::query("INSERT INTO note_attachments(note_id, user_id, file_id) VALUES (?, ?, ?)")
            .bind(id)
            .bind(user)
            .bind(file.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
    }
    // Once COMMIT starts its outcome can be ambiguous if the future is cancelled.
    // Keep the blob in that case; startup recovery safely collects true orphans.
    if let Some(file) = prepared.as_mut() {
        file.committed = true;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    let _ = db.log_action(user, "SAVE", "note", Some(id)).await;
    Ok(id)
}

#[tauri::command]
pub async fn list_notes(
    search: Option<String>,
    offset: Option<i64>,
    limit: Option<i64>,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<NotePage, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user = crate::validate_session(&state).await?;
    let key = crate::get_or_fetch_vault_key(&state, user).await?;
    let guard = state.db.lock().await;
    let db = guard.as_ref().ok_or("Base indisponible")?;
    list_inner(
        db,
        &key,
        user,
        search.as_deref().unwrap_or(""),
        offset.unwrap_or(0),
        limit.unwrap_or(50),
    )
    .await
}
pub(crate) async fn list_inner(
    db: &Database,
    key: &SecureKey,
    user: i64,
    search: &str,
    offset: i64,
    limit: i64,
) -> Result<NotePage, String> {
    if offset < 0 || !(1..=100).contains(&limit) || search.chars().count() > 256 {
        return Err("Recherche ou pagination invalide".into());
    }
    let search = search.to_lowercase();
    // Never load encrypted bodies into a listing query.
    let rows: Vec<StoredNote> = sqlx::query_as("SELECT id, user_id, crypto_id, encrypted_title, '' AS encrypted_body, revision, format_version, created_at, updated_at FROM secure_notes WHERE user_id = ? ORDER BY updated_at DESC, id DESC LIMIT 10001")
        .bind(user).fetch_all(&db.pool).await.map_err(|e| e.to_string())?;
    if rows.len() > 10000 {
        return Err("Nombre de notes non pris en charge".into());
    }
    let mut total = 0;
    let mut items = Vec::new();
    for row in rows {
        let title = String::from_utf8(open(key, &row, "title", &row.encrypted_title)?.to_vec())
            .map_err(|_| "Titre invalide")?;
        if !title.to_lowercase().contains(&search) {
            continue;
        }
        total += 1;
        if total <= offset || items.len() >= limit as usize {
            continue;
        }
        let has_attachment: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM note_attachments WHERE note_id = ? AND user_id = ?)",
        )
        .bind(row.id)
        .bind(user)
        .fetch_one(&db.pool)
        .await
        .map_err(|e| e.to_string())?;
        items.push(NoteSummary {
            id: row.id,
            title,
            revision: row.revision,
            has_attachment,
            created_at: row.created_at,
            updated_at: row.updated_at,
        });
    }
    Ok(NotePage { items, total })
}
#[tauri::command]
pub async fn export_note_attachment(
    id: i64,
    revision: i64,
    output_path: Option<String>,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user = crate::validate_session(&state).await?;
    let key = crate::get_or_fetch_vault_key(&state, user).await?;
    let guard = state.db.lock().await;
    let detail = read_detail(
        &state,
        guard.as_ref().ok_or("Base indisponible")?,
        &key,
        user,
        id,
    )
    .await?;
    if detail.revision != revision {
        return Err("La note a changé. Rouvrez-la avant l’export.".into());
    }
    let file = detail
        .attachment
        .as_ref()
        .ok_or("Cette note n’a pas de pièce jointe")?;
    let (file_id, hash) = (file.id, file.blob_hash.clone());
    drop(guard);
    super::files::export_file_inner(file_id, output_path, &state, app_handle, Some(hash)).await
}
#[tauri::command]
pub async fn get_note(
    id: i64,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<NoteDetail, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user = crate::validate_session(&state).await?;
    let key = crate::get_or_fetch_vault_key(&state, user).await?;
    let guard = state.db.lock().await;
    read_detail(
        &state,
        guard.as_ref().ok_or("Base indisponible")?,
        &key,
        user,
        id,
    )
    .await
}
#[tauri::command]
pub async fn save_note(
    request: SaveNoteRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user = crate::validate_session(&state).await?;
    let key = crate::get_or_fetch_vault_key(&state, user).await?;
    let guard = state.db.lock().await;
    save_inner(
        &state,
        guard.as_ref().ok_or("Base indisponible")?,
        &key,
        user,
        &request,
    )
    .await
}
#[tauri::command]
pub async fn delete_note(
    id: i64,
    revision: i64,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<(), String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user = crate::validate_session(&state).await?;
    if crate::security_monitor::get_security_monitor()
        .is_readonly()
        .await
    {
        return Err("Le coffre est en lecture seule".into());
    }
    let guard = state.db.lock().await;
    let db = guard.as_ref().ok_or("Base indisponible")?;
    let result =
        sqlx::query("DELETE FROM secure_notes WHERE id = ? AND user_id = ? AND revision = ?")
            .bind(id)
            .bind(user)
            .bind(revision)
            .execute(&db.pool)
            .await
            .map_err(|e| e.to_string())?;
    if result.rows_affected() != 1 {
        return Err("Note absente ou modifiée. Actualisez la liste.".into());
    }
    let _ = db.log_action(user, "DELETE", "note", Some(id)).await;
    Ok(())
}

/// Validate all note bindings before publishing a restored database. `state` is
/// not used here because the restored paths already point to the final directory.
pub(crate) async fn validate_restored(
    db: &Database,
    key: &SecureKey,
    staged_files: &Path,
) -> Result<(), String> {
    let rows: Vec<StoredNote> = sqlx::query_as("SELECT * FROM secure_notes")
        .fetch_all(&db.pool)
        .await
        .map_err(|e| e.to_string())?;
    for row in rows {
        open(key, &row, "title", &row.encrypted_title)?;
        let body: Body = serde_json::from_slice(&open(key, &row, "body", &row.encrypted_body)?)
            .map_err(|_| "Note sauvegardée invalide")?;
        let linked: Option<i64> = sqlx::query_scalar(
            "SELECT file_id FROM note_attachments WHERE note_id = ? AND user_id = ?",
        )
        .bind(row.id)
        .bind(row.user_id)
        .fetch_optional(&db.pool)
        .await
        .map_err(|e| e.to_string())?;
        if linked != body.attachment.as_ref().map(|f| f.id) {
            return Err("Rattachement de note invalide dans la sauvegarde".into());
        }
        if let Some(attachment) = body.attachment.as_ref() {
            let file = db
                .get_secure_file(attachment.id, row.user_id)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("Pièce jointe absente")?;
            let name = file
                .file_path
                .rsplit(['/', '\\'])
                .next()
                .ok_or("Chemin invalide")?;
            if !super::files::valid_export_name(name)
                || blob_hash(&staged_files.join(name))? != attachment.blob_hash
                || file.file_size != attachment.file_size
            {
                return Err("Pièce jointe altérée dans la sauvegarde".into());
            }
        }
    }
    Ok(())
}

pub(crate) const NOTE_WIRE_MAGIC: &[u8; 8] = b"FLXNOTE1";
pub(crate) const MAX_NOTE_WIRE_BYTES: usize = MAX_ATTACHMENT_BYTES + MAX_BODY_JSON_BYTES + 12;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PortableNote {
    version: u8,
    title: String,
    body: String,
    attachment_name: Option<String>,
    attachment_size: usize,
}
impl Drop for PortableNote {
    fn drop(&mut self) {
        self.title.zeroize();
        self.body.zeroize();
        if let Some(name) = self.attachment_name.as_mut() {
            name.zeroize();
        }
    }
}

pub(crate) async fn pack_note(
    state: &AppState,
    db: &Database,
    key: &SecureKey,
    user: i64,
    id: i64,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let detail = read_detail(state, db, key, user, id).await?;
    let metadata = PortableNote {
        version: 1,
        title: detail.title.clone(),
        body: detail.body.clone(),
        attachment_name: detail.attachment.as_ref().map(|f| f.filename.clone()),
        attachment_size: detail
            .attachment
            .as_ref()
            .map_or(0, |f| f.file_size as usize),
    };
    let json = Zeroizing::new(serde_json::to_vec(&metadata).map_err(|e| e.to_string())?);
    let mut result = Zeroizing::new(Vec::with_capacity(
        12 + json.len() + metadata.attachment_size,
    ));
    result.extend_from_slice(NOTE_WIRE_MAGIC);
    result.extend_from_slice(&(json.len() as u32).to_le_bytes());
    result.extend_from_slice(&json);
    if let Some(attachment) = detail.attachment.as_ref() {
        let file = db
            .get_secure_file(attachment.id, user)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Pièce jointe absente")?;
        let path = super::files::encrypted_file_path(state, &file.file_path).await?;
        let hash = attachment.blob_hash.clone();
        let key = SecureKey::from_slice(&key.to_vec());
        result = tokio::task::spawn_blocking(move || {
            let mut output = NoteTransferWriter { bytes: result };
            super::files::decrypt_verified_into(&path, &key, &mut output, &hash)?;
            Ok::<_, String>(output.bytes)
        })
        .await
        .map_err(|e| e.to_string())??;
        if result.len() != 12 + json.len() + metadata.attachment_size {
            return Err("Taille de pièce jointe incohérente".into());
        }
    }
    Ok(result)
}
struct NoteTransferWriter {
    bytes: Zeroizing<Vec<u8>>,
}
impl std::io::Write for NoteTransferWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(data.len()) > MAX_NOTE_WIRE_BYTES {
            return Err(std::io::Error::other("Note trop volumineuse"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) async fn receive_note(
    state: &AppState,
    db: &Database,
    key: &SecureKey,
    user: i64,
    bytes: &[u8],
) -> Result<i64, String> {
    if bytes.len() < 12 || bytes.len() > MAX_NOTE_WIRE_BYTES || !bytes.starts_with(NOTE_WIRE_MAGIC)
    {
        return Err("Format de transfert Notes invalide".into());
    }
    let len = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| "En-tête invalide")?) as usize;
    if len > MAX_BODY_JSON_BYTES || len > bytes.len() - 12 {
        return Err("Métadonnées de note trop volumineuses ou tronquées".into());
    }
    let metadata: PortableNote = serde_json::from_slice(&bytes[12..12 + len])
        .map_err(|_| "Métadonnées de note invalides")?;
    valid_text(&metadata.title, &metadata.body)?;
    let attachment_bytes = &bytes[12 + len..];
    if metadata.version != 1
        || metadata.attachment_size > MAX_ATTACHMENT_BYTES
        || attachment_bytes.len() != metadata.attachment_size
        || (metadata.attachment_name.is_none() && !attachment_bytes.is_empty())
    {
        return Err("Pièce jointe de note incohérente".into());
    }
    let prepared = if let Some(name) = metadata.attachment_name.as_ref() {
        let dir = super::files::files_dir(state).await?;
        // Encrypt directly from the bounded receive buffer; no plaintext staging file.
        Some(prepare_file(
            &dir,
            key,
            name.clone(),
            &mut std::io::Cursor::new(attachment_bytes),
        )?)
    } else {
        None
    };
    let request = SaveNoteRequest {
        id: None,
        revision: None,
        title: metadata.title.clone(),
        body: metadata.body.clone(),
        attachment_file_id: None,
        attachment_path: None,
        attachment_name: None,
        attachment_data: None,
    };
    save_with_file(state, db, key, user, &request, prepared).await
}

#[cfg(test)]
mod tests;

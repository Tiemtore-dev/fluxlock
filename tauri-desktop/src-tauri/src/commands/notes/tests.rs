use super::*;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

struct Fixture {
    dir: tempfile::TempDir,
    state: AppState,
    key: SecureKey,
    user: i64,
    context: crate::vault::VaultContext,
}
async fn fixture(seed: u8) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("sv.db")).await.unwrap();
    db.initialize().await.unwrap();
    let user = db
        .create_user("fixture", "fixture@example.test", "test-hash", "test-salt")
        .await
        .unwrap();
    let token = Arc::new(Mutex::new(Some("test-session".into())));
    let id = uuid::Uuid::new_v4().to_string();
    let state = AppState {
        autofill: Arc::new(crate::autofill::Service::default()),
        auth_lifecycle: RwLock::new(()),
        vault_catalog: Mutex::new(None),
        selected_vault: Mutex::new(Some(crate::vault::Vault {
            descriptor: crate::vault::VaultDescriptor {
                id: id.clone(),
                name: "Fixture".into(),
                schema_version: 1,
                created_at: "fixture".into(),
            },
            directory: dir.path().to_owned(),
        })),
        vault_session: Mutex::new(Some(crate::vault::VaultSession {
            vault_id: id.clone(),
            user_id: user,
            key: SecureKey::from_slice(&[seed; 32]),
        })),
        db: Arc::new(Mutex::new(Some(db))),
        current_user_id: Arc::new(Mutex::new(Some(user))),
        session_token: token.clone(),
        session: token,
        last_activity: Arc::new(Mutex::new(std::time::Instant::now())),
        auto_lock_minutes: Arc::new(Mutex::new(15)),
        threat_reactor: Mutex::new(Arc::new(crate::threat_reactor::ThreatReactor::new())),
        transfer_manager: Arc::new(Mutex::new(None)),
        decrypted_temp_files: Arc::new(Mutex::new(Vec::new())),
        data_dir: Arc::new(Mutex::new(Some(dir.path().to_owned()))),
        signed_log_manager: Arc::new(Mutex::new(None)),
        logging_enabled: Arc::new(Mutex::new(false)),
        isolation_mode: Arc::new(Mutex::new(true)),
        vault_key_cache: Arc::new(Mutex::new(crate::vault_key_cache::VaultKeyCache::new())),
        cache_enabled: false,
    };
    Fixture {
        dir,
        state,
        key: SecureKey::from_slice(&[seed; 32]),
        user,
        context: crate::vault::VaultContext {
            vault_id: id,
            token: Some("test-session".into()),
        },
    }
}
fn request(title: &str, body: &str) -> SaveNoteRequest {
    SaveNoteRequest {
        id: None,
        revision: None,
        title: title.into(),
        body: body.into(),
        attachment_file_id: None,
        attachment_path: None,
        attachment_name: None,
        attachment_data: None,
    }
}
async fn save(f: &Fixture, request: &SaveNoteRequest) -> Result<i64, String> {
    let _guard = crate::vault::access(&f.state, &f.context).await?;
    let db = f.state.db.lock().await;
    save_inner(&f.state, db.as_ref().unwrap(), &f.key, f.user, request).await
}
async fn detail(f: &Fixture, id: i64) -> Result<NoteDetail, String> {
    let _guard = crate::vault::access(&f.state, &f.context).await?;
    let db = f.state.db.lock().await;
    read_detail(&f.state, db.as_ref().unwrap(), &f.key, f.user, id).await
}

#[tokio::test]
async fn notes_are_encrypted_on_disk_and_body_is_not_in_list_results() {
    let f = fixture(1).await;
    let title = "TITLE_SENTINEL_4ec9a2";
    let text = "TEXT_SENTINEL_7bc813 <script>alert('x')</script>\nfrançais 🔐";
    let id = save(&f, &request(title, text)).await.unwrap();
    let note = detail(&f, id).await.unwrap();
    assert_eq!(note.title, title);
    assert_eq!(note.body, text);
    let guard = f.state.db.lock().await;
    let db = guard.as_ref().unwrap();
    let page = list_inner(db, &f.key, f.user, "sentinel", 0, 50)
        .await
        .unwrap();
    let json = serde_json::to_string(&page).unwrap();
    assert!(json.contains(title));
    assert!(!json.contains("TEXT_SENTINEL"));
    let stored = stored(db, f.user, id).await.unwrap();
    assert!(stored.encrypted_title.starts_with("note1:"));
    assert!(stored.encrypted_body.starts_with("note1:"));
    sqlx::query("PRAGMA wal_checkpoint(FULL)")
        .execute(&db.pool)
        .await
        .unwrap();
    for name in ["sv.db", "sv.db-wal", "sv.db-shm"] {
        if let Ok(bytes) = std::fs::read(f.dir.path().join(name)) {
            for secret in [title.as_bytes(), text.as_bytes()] {
                assert!(!bytes.windows(secret.len()).any(|w| w == secret));
            }
        }
    }
}

#[tokio::test]
async fn aad_rejects_record_field_revision_owner_and_key_substitution() {
    let f = fixture(2).await;
    let first = save(&f, &request("Première", "corps un")).await.unwrap();
    let second = save(&f, &request("Deuxième", "corps deux")).await.unwrap();
    let guard = f.state.db.lock().await;
    let db = guard.as_ref().unwrap();
    let mut row = stored(db, f.user, first).await.unwrap();
    let other = stored(db, f.user, second).await.unwrap();
    assert!(open(&f.key, &row, "title", &other.encrypted_title).is_err());
    assert!(open(&f.key, &row, "body", &row.encrypted_title).is_err());
    assert!(open(
        &SecureKey::from_slice(&[42; 32]),
        &row,
        "title",
        &row.encrypted_title
    )
    .is_err());
    row.id = second;
    assert!(open(&f.key, &row, "title", &row.encrypted_title).is_err());
    row.id = first;
    row.revision += 1;
    assert!(open(&f.key, &row, "title", &row.encrypted_title).is_err());
    row.revision -= 1;
    row.user_id += 1;
    assert!(open(&f.key, &row, "title", &row.encrypted_title).is_err());
}

#[tokio::test]
async fn attachments_are_atomic_authenticated_and_protected_from_deletion() {
    let f = fixture(3).await;
    let mut input = request("Document", "Un document joint");
    input.attachment_name = Some("secret.txt".into());
    input.attachment_data = Some(STANDARD.encode(b"ATTACHMENT_SENTINEL_129e"));
    let id = save(&f, &input).await.unwrap();
    let note = detail(&f, id).await.unwrap();
    let attached = note.attachment.as_ref().unwrap();
    let guard = f.state.db.lock().await;
    let db = guard.as_ref().unwrap();
    let file = db
        .get_secure_file(attached.id, f.user)
        .await
        .unwrap()
        .unwrap();
    assert!(!std::fs::read(&file.file_path)
        .unwrap()
        .windows(19)
        .any(|w| w == b"ATTACHMENT_SENTINEL"));
    assert!(db.delete_secure_file(file.id, f.user).await.is_err());
    let mut output = Vec::new();
    super::super::files::decrypt_verified_into(
        Path::new(&file.file_path),
        &f.key,
        &mut output,
        &attached.blob_hash,
    )
    .unwrap();
    assert_eq!(output, b"ATTACHMENT_SENTINEL_129e");
    std::fs::write(&file.file_path, b"replacement").unwrap();
    assert!(read_detail(&f.state, db, &f.key, f.user, id).await.is_err());
    let destination = f.dir.path().join("export.txt");
    assert!(super::super::files::publish_new_file(&destination, |out| {
        super::super::files::decrypt_verified_into(
            Path::new(&file.file_path),
            &f.key,
            out,
            &attached.blob_hash,
        )
    })
    .is_err());
    assert!(!destination.exists());
}

#[tokio::test]
async fn invalid_or_failed_import_does_not_leave_a_note_or_committed_file() {
    let f = fixture(4).await;
    let mut input = request("Échec", "texte");
    input.attachment_name = Some("../bad.txt".into());
    input.attachment_data = Some(STANDARD.encode(b"bytes"));
    assert!(save(&f, &input).await.is_err());
    input.attachment_name = Some("file.txt".into());
    let guard = f.state.db.lock().await;
    let db = guard.as_ref().unwrap();
    sqlx::query("CREATE TRIGGER fail_note BEFORE INSERT ON secure_notes BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").execute(&db.pool).await.unwrap();
    assert!(save_inner(&f.state, db, &f.key, f.user, &input)
        .await
        .is_err());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secure_files")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(
        std::fs::read_dir(f.dir.path().join("files"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn revisions_detach_and_delete_preserve_shared_files() {
    let f = fixture(5).await;
    let mut input = request("Note", "version une");
    input.attachment_name = Some("empty.txt".into());
    input.attachment_data = Some(STANDARD.encode(b""));
    let id = save(&f, &input).await.unwrap();
    let old = detail(&f, id).await.unwrap();
    let file_id = old.attachment.as_ref().unwrap().id;
    let mut update = request("Note mise à jour", "version deux");
    update.id = Some(id);
    update.revision = Some(1);
    save(&f, &update).await.unwrap();
    assert!(save(&f, &update).await.is_err());
    let note = detail(&f, id).await.unwrap();
    assert_eq!(note.revision, 2);
    assert!(note.attachment.is_none());
    let guard = f.state.db.lock().await;
    let db = guard.as_ref().unwrap();
    assert!(db.get_secure_file(file_id, f.user).await.unwrap().is_some());
    sqlx::query("DELETE FROM secure_notes WHERE id = ? AND user_id = ? AND revision = 2")
        .bind(id)
        .bind(f.user)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(read_detail(&f.state, db, &f.key, f.user, id).await.is_err());
    assert!(db.get_secure_file(file_id, f.user).await.unwrap().is_some());
}

#[tokio::test]
async fn owners_and_stale_sessions_cannot_read_or_attach_other_content() {
    let f = fixture(6).await;
    let id = save(&f, &request("Privée", "secret")).await.unwrap();
    {
        let guard = f.state.db.lock().await;
        let db = guard.as_ref().unwrap();
        assert!(read_detail(&f.state, db, &f.key, f.user + 1, id)
            .await
            .is_err());
        let foreign = sqlx::query("INSERT INTO users(username,email,password_hash,crypto_salt) VALUES('other','other@test','x','y')").execute(&db.pool).await.unwrap().last_insert_rowid();
        let file = db
            .create_secure_file(f.user, "encrypted", "unused", 0, None, None)
            .await
            .unwrap();
        assert!(sqlx::query("INSERT INTO note_attachments VALUES (?, ?, ?)")
            .bind(id)
            .bind(foreign)
            .bind(file)
            .execute(&db.pool)
            .await
            .is_err());
    }
    {
        let _guard = f.state.auth_lifecycle.write().await;
        crate::commands::session::lock_session(&f.state).await;
    }
    assert!(detail(&f, id).await.is_err());
    assert!(save(&f, &request("No", "No")).await.is_err());
    *f.state.current_user_id.lock().await = Some(f.user);
    *f.state.session_token.lock().await = Some("new-session".into());
    assert!(crate::vault::access(&f.state, &f.context).await.is_err());
}

#[tokio::test]
async fn transfer_reencrypts_whole_note_and_attachment_without_partial_import() {
    let source = fixture(7).await;
    let target = fixture(8).await;
    let mut input = request("Note envoyée", "texte avec caractères\n🔐");
    input.attachment_name = Some("copie.txt".into());
    input.attachment_data = Some(STANDARD.encode(b"synthetic attachment"));
    let id = save(&source, &input).await.unwrap();
    let source_guard = source.state.db.lock().await;
    let source_db = source_guard.as_ref().unwrap();
    let wire = pack_note(&source.state, source_db, &source.key, source.user, id)
        .await
        .unwrap();
    let target_guard = target.state.db.lock().await;
    let target_db = target_guard.as_ref().unwrap();
    assert!(receive_note(
        &target.state,
        target_db,
        &target.key,
        target.user,
        &wire[..wire.len() - 1]
    )
    .await
    .is_err());
    let received = receive_note(&target.state, target_db, &target.key, target.user, &wire)
        .await
        .unwrap();
    let detail = read_detail(&target.state, target_db, &target.key, target.user, received)
        .await
        .unwrap();
    assert_eq!(detail.title, input.title);
    assert_eq!(detail.body, input.body);
    assert_eq!(detail.attachment.as_ref().unwrap().filename, "copie.txt");
    let row = stored(target_db, target.user, received).await.unwrap();
    assert!(open(&source.key, &row, "body", &row.encrypted_body).is_err());
    assert_ne!(
        row.encrypted_body,
        stored(source_db, source.user, id)
            .await
            .unwrap()
            .encrypted_body
    );
}

#[tokio::test]
async fn migration_is_idempotent_and_recovery_only_removes_unreferenced_owned_blobs() {
    let f = fixture(9).await;
    let mut input = request("Conservée", "texte");
    input.attachment_name = Some("doc.txt".into());
    input.attachment_data = Some(STANDARD.encode(b"content"));
    let id = save(&f, &input).await.unwrap();
    let guard = f.state.db.lock().await;
    let db = guard.as_ref().unwrap();
    migrate(&db.pool).await.unwrap();
    let orphan = f
        .dir
        .path()
        .join("files")
        .join(format!("note-{}.senc", uuid::Uuid::new_v4()));
    std::fs::write(&orphan, b"encrypted orphan").unwrap();
    let other = f.dir.path().join("files/keep.dat");
    std::fs::write(&other, b"keep").unwrap();
    recover_files(db, &f.dir.path().join("files"))
        .await
        .unwrap();
    assert!(!orphan.exists());
    assert!(other.exists());
    read_detail(&f.state, db, &f.key, f.user, id).await.unwrap();
    sqlx::query("UPDATE note_schema SET version = 99")
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(migrate(&db.pool).await.is_err());
}

#[tokio::test]
async fn encrypted_backup_restores_note_under_a_different_vault_directory() {
    let mut f = fixture(10).await;
    let password = "synthetic master password for notes";
    let salt = crate::crypto::generate_salt();
    f.key = crate::crypto::derive_encryption_key_from_password_secure(password, &salt).unwrap();
    {
        let guard = f.state.db.lock().await;
        let db = guard.as_ref().unwrap();
        sqlx::query("UPDATE users SET password_hash = ?, crypto_salt = ? WHERE id = ?")
            .bind(crate::crypto::hash_password(password).unwrap())
            .bind(STANDARD.encode(salt))
            .bind(f.user)
            .execute(&db.pool)
            .await
            .unwrap();
    }
    let mut input = request("Sauvegardée", "RESTORE_NOTE_SENTINEL");
    input.attachment_name = Some("restored.txt".into());
    input.attachment_data = Some(STANDARD.encode(b"restored attachment"));
    let id = save(&f, &input).await.unwrap();
    let guard = f.state.db.lock().await;
    let db = guard.as_ref().unwrap();
    let backup = crate::backup_manager::create_backup(
        db,
        &f.dir.path().join("files"),
        password,
        "fixture",
        &f.dir.path().join("backups"),
    )
    .await
    .unwrap();
    let destination = tempfile::tempdir().unwrap();
    crate::backup_manager::restore_backup(
        &backup,
        password,
        &destination.path().join("sv.db"),
        &destination.path().join("files"),
    )
    .await
    .unwrap();
    let restored = Database::new(&destination.path().join("sv.db"))
        .await
        .unwrap();
    restored.initialize().await.unwrap();
    let mut target = fixture(11).await;
    *target.state.data_dir.lock().await = Some(destination.path().to_owned());
    target.key = SecureKey::from_slice(&f.key.to_vec());
    let note = read_detail(&target.state, &restored, &target.key, f.user, id)
        .await
        .unwrap();
    assert_eq!(note.title, input.title);
    assert_eq!(note.body, input.body);
    assert!(note.attachment.is_some());
    let file = restored
        .get_secure_file(note.attachment.as_ref().unwrap().id, f.user)
        .await
        .unwrap()
        .unwrap();
    assert!(file
        .file_path
        .starts_with(destination.path().to_str().unwrap()));
}

#[test]
fn text_and_aead_bounds_reject_invalid_inputs_without_truncation() {
    assert!(valid_text("", "body").is_err());
    assert!(valid_text(&"a".repeat(257), "body").is_err());
    assert!(valid_text("titre", &"x".repeat(MAX_NOTE_BYTES + 1)).is_err());
    assert!(valid_text("titre", &"x".repeat(MAX_NOTE_BYTES)).is_ok());
    let key = SecureKey::from_slice(&[1; 32]);
    assert!(crypt(&key, "invalid", 1, 1, 1, "body", b"text", true).is_err());
}

use super::*;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

pub(crate) fn state() -> AppState {
    let token = Arc::new(Mutex::new(None));
    AppState {
        autofill: Arc::new(crate::autofill::Service::default()),
        auth_lifecycle: RwLock::new(()),
        vault_catalog: Mutex::new(None),
        selected_vault: Mutex::new(None),
        vault_session: Mutex::new(None),
        db: Arc::new(Mutex::new(None)),
        current_user_id: Arc::new(Mutex::new(None)),
        session_token: token.clone(),
        session: token,
        last_activity: Arc::new(Mutex::new(std::time::Instant::now())),
        auto_lock_minutes: Arc::new(Mutex::new(15)),
        threat_reactor: Mutex::new(Arc::new(crate::threat_reactor::ThreatReactor::new())),
        transfer_manager: Arc::new(Mutex::new(None)),
        decrypted_temp_files: Arc::new(Mutex::new(Vec::new())),
        data_dir: Arc::new(Mutex::new(None)),
        signed_log_manager: Arc::new(Mutex::new(None)),
        logging_enabled: Arc::new(Mutex::new(false)),
        isolation_mode: Arc::new(Mutex::new(true)),
        vault_key_cache: Arc::new(Mutex::new(crate::vault_key_cache::VaultKeyCache::new())),
        cache_enabled: false,
    }
}

fn request(name: &str, password: &str) -> CreateVaultRequest {
    CreateVaultRequest {
        name: name.into(),
        username: "same-user".into(),
        email: "fixture@example.org".into(),
        password: password.into(),
    }
}
fn context(vault: &CreatedVault) -> VaultContext {
    VaultContext {
        vault_id: vault.vault.id.clone(),
        token: vault.auth.token.clone(),
    }
}
async fn lock(state: &AppState) {
    let _guard = state.auth_lifecycle.write().await;
    crate::commands::session::lock_session(state).await;
}
async fn add_password(state: &AppState, context: &VaultContext, title: &str) {
    let _guard = access(state, context).await.unwrap();
    let id = crate::validate_session(state).await.unwrap();
    let key = crate::get_or_fetch_vault_key(state, id).await.unwrap();
    let encrypted = crate::crypto::encrypt_data_secure("synthetic password", &key).unwrap();
    state
        .db
        .lock()
        .await
        .as_ref()
        .unwrap()
        .create_password(id, title, None, &encrypted, None, None, None)
        .await
        .unwrap();
}

#[test]
fn names_and_ids_are_validated_without_turning_names_into_paths() {
    assert_eq!(
        validated_name("  Personnel / 家族  ").unwrap(),
        "Personnel / 家族"
    );
    for name in ["", "   ", "Bad\nName", "A\u{202e}B", &"a".repeat(81)] {
        assert!(validated_name(name).is_err());
    }
    for id in ["../other", "/tmp", "LEGACY", "", "vaults/../legacy"] {
        assert!(!valid_id(id));
    }
    assert!(valid_id(LEGACY_VAULT_ID));
    assert!(valid_id(&uuid::Uuid::new_v4().to_string()));
}

#[test]
fn process_lock_and_catalog_corruption_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let catalog = VaultCatalog::load(dir.path()).unwrap();
    assert!(VaultCatalog::load(dir.path()).is_err());
    drop(catalog);
    let catalog = VaultCatalog::load(dir.path()).unwrap();
    drop(catalog);
    fs::write(dir.path().join("vaults.json"), b"truncated").unwrap();
    assert!(VaultCatalog::load(dir.path()).is_err());
    assert_eq!(
        fs::read(dir.path().join("vaults.json")).unwrap(),
        b"truncated"
    );
}

#[test]
fn malformed_catalog_cannot_select_arbitrary_filesystem_paths() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("vaults.json"), r#"{"version":1,"vaults":[{"id":"../escape","name":"test","schema_version":1,"created_at":"fixture"}]}"#).unwrap();
    assert!(VaultCatalog::load(dir.path()).is_err());
}

#[cfg(unix)]
#[test]
fn catalog_and_storage_reject_symlinks_and_keep_private_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    let catalog = VaultCatalog::load(&root).unwrap();
    assert_eq!(
        fs::metadata(&root).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("vaults.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(catalog);
    fs::remove_file(root.join("vaults.json")).unwrap();
    fs::write(dir.path().join("external"), "preserve").unwrap();
    symlink(dir.path().join("external"), root.join("vaults.json")).unwrap();
    assert!(VaultCatalog::load(&root).is_err());
    assert_eq!(
        fs::read_to_string(dir.path().join("external")).unwrap(),
        "preserve"
    );
}

#[test]
fn resetting_legacy_storage_preserves_the_catalog_other_vaults_and_backups() {
    let dir = tempfile::tempdir().unwrap();
    for file in ["vaults.json", "vaults.lock", "sv.db"] {
        fs::write(dir.path().join(file), "fixture").unwrap();
    }
    for folder in ["vaults/other", "backups", "files", "signed_logs"] {
        fs::create_dir_all(dir.path().join(folder)).unwrap();
        fs::write(dir.path().join(folder).join("fixture"), "keep").unwrap();
    }
    crate::commands::backup::reset_storage(dir.path()).unwrap();
    assert!(dir.path().join("vaults.json").is_file());
    assert!(dir.path().join("vaults.lock").is_file());
    assert!(dir.path().join("vaults/other/fixture").is_file());
    assert!(dir.path().join("backups/fixture").is_file());
    assert!(!dir.path().join("sv.db").exists());
    assert!(!dir.path().join("files").exists());
}

#[tokio::test]
async fn adopting_legacy_vault_keeps_database_and_file_locations() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::new(&dir.path().join("sv.db")).await.unwrap();
    db.initialize().await.unwrap();
    let id = db
        .create_user(
            "legacy-owner",
            "legacy@example.org",
            "fixture-hash",
            "fixture-salt",
        )
        .await
        .unwrap();
    fs::create_dir(dir.path().join("files")).unwrap();
    fs::write(dir.path().join("files/document.enc"), b"encrypted fixture").unwrap();
    db.pool.close().await;
    let state = state();
    initialize(&state, dir.path()).await.unwrap();
    let selected = state.selected_vault.lock().await.clone().unwrap();
    assert_eq!(selected.descriptor.id, LEGACY_VAULT_ID);
    assert_eq!(selected.directory, dir.path());
    assert_eq!(
        state
            .db
            .lock()
            .await
            .as_ref()
            .unwrap()
            .get_vault_owner()
            .await
            .unwrap()
            .unwrap()
            .id,
        id
    );
    assert_eq!(
        fs::read(dir.path().join("files/document.enc")).unwrap(),
        b"encrypted fixture"
    );
    assert!(state.vault_session.lock().await.is_none());
}

#[tokio::test]
async fn vaults_with_identical_local_user_ids_have_independent_keys_data_and_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let state = state();
    initialize(&state, dir.path()).await.unwrap();
    let a = create(&state, request("Personnel", "fixture password A"))
        .await
        .unwrap();
    let ca = context(&a);
    let key_a = crate::get_or_fetch_vault_key(&state, a.auth.user_id.unwrap())
        .await
        .unwrap();
    add_password(&state, &ca, "Only A").await;
    assert!(select(&state, &a.vault.id).await.is_err());
    assert!(create(&state, request("Forbidden", "fixture password C"))
        .await
        .is_err());
    let unlocked = VaultContext {
        vault_id: a.vault.id.clone(),
        token: None,
    };
    assert!(crate::commands::auth::unlock(
        &state,
        &unlocked,
        crate::LoginRequest {
            password: "fixture password A".into()
        }
    )
    .await
    .is_err());
    let temp = dir.path().join("temporary plaintext");
    fs::write(&temp, "synthetic only").unwrap();
    state
        .decrypted_temp_files
        .lock()
        .await
        .push(temp.to_string_lossy().into());
    lock(&state).await;
    assert!(!temp.exists());
    assert!(state.vault_session.lock().await.is_none());
    assert!(access(&state, &ca).await.is_err());
    let b = create(&state, request("Travail", "fixture password B"))
        .await
        .unwrap();
    let cb = context(&b);
    assert_eq!(a.auth.user_id, b.auth.user_id); // IDs overlap by design across isolated databases.
    let key_b = crate::get_or_fetch_vault_key(&state, b.auth.user_id.unwrap())
        .await
        .unwrap();
    let cipher = crate::crypto::encrypt_data_secure("synthetic", &key_a).unwrap();
    assert!(crate::crypto::decrypt_data_secure(&cipher, &key_b).is_err());
    assert!(access(&state, &ca).await.is_err());
    assert!(state
        .db
        .lock()
        .await
        .as_ref()
        .unwrap()
        .get_passwords(b.auth.user_id.unwrap())
        .await
        .unwrap()
        .is_empty());
    add_password(&state, &cb, "Only B").await;
    lock(&state).await;
    select(&state, &a.vault.id).await.unwrap();
    let unlock_context = VaultContext {
        vault_id: a.vault.id.clone(),
        token: None,
    };
    let wrong = crate::commands::auth::unlock(
        &state,
        &unlock_context,
        crate::LoginRequest {
            password: "fixture password B".into(),
        },
    )
    .await
    .unwrap();
    assert!(!wrong.success);
    assert!(state.vault_session.lock().await.is_none());
    let login = crate::commands::auth::unlock(
        &state,
        &unlock_context,
        crate::LoginRequest {
            password: "fixture password A".into(),
        },
    )
    .await
    .unwrap();
    assert!(login.success);
    assert_ne!(login.token, ca.token);
    assert!(crate::commands::session::lock_context(&state, ca.clone())
        .await
        .is_err());
    assert!(crate::commands::session::lock_context(
        &state,
        VaultContext {
            vault_id: a.vault.id.clone(),
            token: None
        }
    )
    .await
    .is_err());
    assert!(state.vault_session.lock().await.is_some());
    assert!(access(&state, &ca).await.is_err()); // Same vault, previous unlock.
    let current = VaultContext {
        vault_id: a.vault.id.clone(),
        token: login.token,
    };
    let _access = access(&state, &current).await.unwrap();
    let entries = state
        .db
        .lock()
        .await
        .as_ref()
        .unwrap()
        .get_passwords(a.auth.user_id.unwrap())
        .await
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].title, "Only A");
}

#[tokio::test]
async fn failed_creation_rolls_back_and_rename_survives_restart_without_rekeying() {
    let dir = tempfile::tempdir().unwrap();
    let state = state();
    initialize(&state, dir.path()).await.unwrap();
    assert!(create(&state, request("Invalid", "short")).await.is_err());
    assert!(state
        .vault_catalog
        .lock()
        .await
        .as_ref()
        .unwrap()
        .data
        .vaults
        .is_empty());
    assert!(state.vault_session.lock().await.is_none());
    let a = create(&state, request("Old name", "fixture password A"))
        .await
        .unwrap();
    let ca = context(&a);
    let path = state.data_dir.lock().await.clone().unwrap();
    add_password(&state, &ca, "Preserved").await;
    let renamed = rename(&state, &ca, "  Nouveau nom  ").await.unwrap();
    assert_eq!(renamed.id, a.vault.id);
    assert_eq!(renamed.name, "Nouveau nom");
    assert_eq!(state.data_dir.lock().await.as_ref(), Some(&path));
    assert!(access(&state, &ca).await.is_ok());
    assert!(rename(
        &state,
        &VaultContext {
            vault_id: a.vault.id.clone(),
            token: None
        },
        "Denied"
    )
    .await
    .is_err());
    lock(&state).await;
    if let Some(db) = state.db.lock().await.take() {
        db.pool.close().await;
    }
    drop(state);
    let restarted = super::tests::state();
    initialize(&restarted, dir.path()).await.unwrap();
    assert_eq!(
        restarted
            .selected_vault
            .lock()
            .await
            .as_ref()
            .unwrap()
            .descriptor
            .name,
        "Nouveau nom"
    );
    assert!(restarted.vault_session.lock().await.is_none());
}

#[tokio::test]
async fn exclusive_transition_waits_for_in_flight_operations_and_rejects_stale_work() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(state());
    initialize(&state, dir.path()).await.unwrap();
    let a = create(&state, request("A", "fixture password A"))
        .await
        .unwrap();
    let ca = context(&a);
    lock(&state).await;
    let b = create(&state, request("B", "fixture password B"))
        .await
        .unwrap();
    let cb = context(&b);
    let operation = access(&state, &cb).await.unwrap();
    let next_state = state.clone();
    let id = a.vault.id.clone();
    let mut switch = tokio::spawn(async move {
        let _exclusive = next_state.auth_lifecycle.write().await;
        crate::commands::session::lock_session(&next_state).await;
        select(&next_state, &id).await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut switch)
            .await
            .is_err()
    );
    assert_eq!(
        state
            .selected_vault
            .lock()
            .await
            .as_ref()
            .unwrap()
            .descriptor
            .id,
        b.vault.id
    );
    drop(operation);
    tokio::time::timeout(std::time::Duration::from_secs(5), switch)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(access(&state, &cb).await.is_err());
    assert!(access(&state, &ca).await.is_err());
    assert!(state.vault_session.lock().await.is_none());
}

#[tokio::test]
async fn vault_backup_authenticates_identity_and_restores_only_its_destination() {
    let dir = tempfile::tempdir().unwrap();
    let state = state();
    initialize(&state, dir.path()).await.unwrap();
    let a = create(&state, request("Archive A", "fixture password A"))
        .await
        .unwrap();
    add_password(&state, &context(&a), "Saved from A").await;
    let a_dir = state.data_dir.lock().await.clone().unwrap();
    let archive = {
        let db = state.db.lock().await;
        crate::backup_manager::create_backup_for_vault(
            db.as_ref().unwrap(),
            &a_dir.join("files"),
            "fixture password A",
            "same-user",
            &dir.path().join("backups"),
            Some(&a.vault),
        )
        .await
        .unwrap()
    };
    let metadata = crate::backup_manager::read_backup_metadata(&archive).unwrap();
    assert_eq!(metadata.vault_id.as_deref(), Some(a.vault.id.as_str()));
    assert_eq!(metadata.vault_name.as_deref(), Some("Archive A"));
    lock(&state).await;
    let b = create(&state, request("Destination B", "fixture password B"))
        .await
        .unwrap();
    let b_dir = state.data_dir.lock().await.clone().unwrap();
    lock(&state).await;
    if let Some(db) = state.db.lock().await.take() {
        db.pool.close().await;
    }
    crate::backup_manager::restore_backup(
        &archive,
        "fixture password A",
        &b_dir.join("sv.db"),
        &b_dir.join("files"),
    )
    .await
    .unwrap();
    // Registry identity stays B even when its contents originate from A.
    select(&state, &b.vault.id).await.unwrap();
    assert_eq!(
        state
            .selected_vault
            .lock()
            .await
            .as_ref()
            .unwrap()
            .descriptor
            .name,
        "Destination B"
    );
    assert_eq!(
        state
            .db
            .lock()
            .await
            .as_ref()
            .unwrap()
            .get_passwords(1)
            .await
            .unwrap()[0]
            .title,
        "Saved from A"
    );
    let source = Database::new(&a_dir.join("sv.db")).await.unwrap();
    assert_eq!(
        source.get_passwords(1).await.unwrap()[0].title,
        "Saved from A"
    );
    source.pool.close().await;
}

#[tokio::test]
async fn missing_last_vault_does_not_recreate_data_or_block_other_vaults() {
    let dir = tempfile::tempdir().unwrap();
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let catalog = VaultCatalog::load(dir.path()).unwrap();
    catalog
        .save(&CatalogData {
            version: CATALOG_VERSION,
            selected_vault_id: Some(a.clone()),
            vaults: [&a, &b]
                .into_iter()
                .map(|id| VaultDescriptor {
                    id: id.clone(),
                    name: id.clone(),
                    schema_version: 1,
                    created_at: "fixture".into(),
                })
                .collect(),
        })
        .unwrap();
    drop(catalog);
    let b_dir = dir.path().join("vaults").join(&b);
    private_directory(&b_dir).unwrap();
    let db = Database::new(&b_dir.join("sv.db")).await.unwrap();
    db.initialize().await.unwrap();
    db.pool.close().await;
    let state = state();
    initialize(&state, dir.path()).await.unwrap();
    assert!(state.selected_vault.lock().await.is_none());
    assert!(!dir.path().join("vaults").join(&a).exists());
    assert!(select(&state, &a).await.is_err());
    assert_eq!(select(&state, &b).await.unwrap().id, b);
}

use super::*;
use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn channel() -> (snow::TransportState, snow::TransportState) {
    let mut a = fluxlock_autofill_protocol::handshake(&[1; 64], true).unwrap();
    let mut b = fluxlock_autofill_protocol::handshake(&[2; 64], false).unwrap();
    let mut out = [0; fluxlock_autofill_protocol::MAX_HANDSHAKE];
    let mut tmp = [0; fluxlock_autofill_protocol::MAX_HANDSHAKE];
    let n = a.write_message(&[], &mut out).unwrap();
    b.read_message(&out[..n], &mut tmp).unwrap();
    let n = b.write_message(&[], &mut out).unwrap();
    a.read_message(&out[..n], &mut tmp).unwrap();
    let n = a.write_message(&[], &mut out).unwrap();
    b.read_message(&out[..n], &mut tmp).unwrap();
    (
        a.into_transport_mode().unwrap(),
        b.into_transport_mode().unwrap(),
    )
}
const PASSWORD: &str = "synthetic master password 2379";

async fn wire_send(stream: &mut tokio::io::DuplexStream, packet: &[u8]) {
    let frame = serde_json::to_vec(&serde_json::json!({"version":2,"frame":base64::engine::general_purpose::STANDARD.encode(packet)})).unwrap();
    stream
        .write_all(&(frame.len() as u32).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&frame).await.unwrap();
}
async fn wire_read(stream: &mut tokio::io::DuplexStream) -> Result<Vec<u8>, ()> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(|_| ())?;
    let len = u32::from_be_bytes(header) as usize;
    assert!(len <= 65536);
    let mut frame = vec![0; len];
    stream.read_exact(&mut frame).await.map_err(|_| ())?;
    let frame: serde_json::Value = serde_json::from_slice(&frame).unwrap();
    assert_eq!(frame["version"], 2);
    Ok(base64::engine::general_purpose::STANDARD
        .decode(frame["frame"].as_str().unwrap())
        .unwrap())
}

#[tokio::test]
async fn real_pq_ipc_authenticates_the_profile_but_never_releases_accounts_before_vault_auth() {
    let f = fixture().await;
    let state = f.app.state::<AppState>();
    state.autofill.pending.lock().await.take();
    state.autofill.busy.store(false, Ordering::SeqCst);
    let identity = state.autofill.identity.lock().await;
    let expected =
        fluxlock_autofill_protocol::public_identity(&identity.as_ref().unwrap().key().unwrap());
    drop(identity);
    let (mut client_stream, server_stream) = tokio::io::duplex(65536);
    let server = ipc::connection(f.app.handle().clone(), server_stream);
    let client = async move {
        let mut client = fluxlock_autofill_protocol::handshake(&[1; 64], true).unwrap();
        let mut out = vec![0; fluxlock_autofill_protocol::MAX_HANDSHAKE];
        let n = client.write_message(&[], &mut out).unwrap();
        wire_send(&mut client_stream, &out[..n]).await;
        let second = wire_read(&mut client_stream).await.unwrap();
        client.read_message(&second, &mut []).unwrap();
        assert_eq!(client.remote_identity().unwrap(), expected);
        let n = client.write_message(&[], &mut out).unwrap();
        let fingerprint = fluxlock_autofill_protocol::fingerprint(client.get_handshake_hash());
        wire_send(&mut client_stream, &out[..n]).await;
        let mut channel = client.into_transport_mode().unwrap();
        let welcome = wire_read(&mut client_stream).await.unwrap();
        let plain = fluxlock_autofill_protocol::decrypt(&mut channel, &welcome).unwrap();
        let welcome: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(welcome["state"], "connected");
        assert_eq!(welcome["fingerprint"], fingerprint);
        let request =
            serde_json::to_vec(&serde_json::json!({"op":"begin_fill","target":f.target})).unwrap();
        let bytes = fluxlock_autofill_protocol::encrypt(&mut channel, &request).unwrap();
        wire_send(&mut client_stream, &bytes).await;
        let response = wire_read(&mut client_stream).await.unwrap();
        let response = fluxlock_autofill_protocol::decrypt(&mut channel, &response).unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(response["state"], "auth_required");
        let request=serde_json::to_vec(&serde_json::json!({"op":"list_candidates","request_id":response["request_id"],"offset":0})).unwrap();
        let bytes = fluxlock_autofill_protocol::encrypt(&mut channel, &request).unwrap();
        wire_send(&mut client_stream, &bytes).await;
        assert!(wire_read(&mut client_stream).await.is_err());
    };
    let (result, ()) = tokio::join!(server, client);
    assert!(result.is_err());
    assert!(state.autofill.pending.lock().await.is_none());
    assert!(!state.autofill.busy.load(Ordering::SeqCst));
}

#[tokio::test]
async fn same_x25519_key_with_an_unpaired_mldsa_identity_is_rejected_by_real_ipc() {
    let f = fixture().await;
    let state = f.app.state::<AppState>();
    state.autofill.pending.lock().await.take();
    state.autofill.busy.store(false, Ordering::SeqCst);
    let (mut client_stream, server_stream) = tokio::io::duplex(65536);
    let server = ipc::connection(f.app.handle().clone(), server_stream);
    let client = async move {
        let mut seed = [1; 64];
        seed[32..].fill(9);
        let mut client = fluxlock_autofill_protocol::handshake(&seed, true).unwrap();
        let mut out = vec![0; fluxlock_autofill_protocol::MAX_HANDSHAKE];
        let n = client.write_message(&[], &mut out).unwrap();
        wire_send(&mut client_stream, &out[..n]).await;
        let second = wire_read(&mut client_stream).await.unwrap();
        client.read_message(&second, &mut []).unwrap();
        let n = client.write_message(&[], &mut out).unwrap();
        wire_send(&mut client_stream, &out[..n]).await;
        assert!(wire_read(&mut client_stream).await.is_err());
    };
    let (result, ()) = tokio::join!(server, client);
    assert!(result.is_err());
    assert!(state.autofill.pending.lock().await.is_none());
}
struct Fixture {
    _dir: tempfile::TempDir,
    app: tauri::App<MockRuntime>,
    target: Target,
    peer: String,
    request: String,
}
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let state = crate::vault::tests::state();
    crate::vault::initialize(&state, dir.path()).await.unwrap();
    let created = crate::vault::create(
        &state,
        crate::vault::CreateVaultRequest {
            name: "Test".into(),
            username: "test-user".into(),
            email: "user@example.test".into(),
            password: PASSWORD.into(),
        },
    )
    .await
    .unwrap();
    let user = created.auth.user_id.unwrap();
    let key = crate::get_or_fetch_vault_key(&state, user).await.unwrap();
    let guard = state.db.lock().await;
    let db = guard.as_ref().unwrap();
    for (origin, name, password) in [
        (
            "https://example.com/login",
            "one@example.test",
            "SELECTED_SECRET_1976",
        ),
        (
            "https://example.com",
            "two@example.test",
            "OTHER_SECRET_2439",
        ),
        (
            "https://example.com.evil.test",
            "evil@example.test",
            "WRONG_SITE_SECRET",
        ),
    ] {
        let e = |s: &str| crate::crypto::encrypt_data_secure(s, &key).unwrap();
        db.create_password(
            user,
            &e("title"),
            Some(&e(name)),
            &e(password),
            Some(&e(origin)),
            None,
            None,
        )
        .await
        .unwrap();
    }
    let target = Target {
        origin: "https://example.com".into(),
        tab_id: 1,
        frame_id: 0,
        document_id: "document-one".into(),
        nonce: token(),
    };
    // Deliberately put the second account first. Listing is ordered by update
    // time, not insertion; crossing a second on a busy runner exposed tests
    // that selected entries[0] but asserted the first-created account's secret.
    sqlx::query("UPDATE passwords SET updated_at = CASE WHEN id = 1 THEN '2020-01-01 00:00:00' ELSE '2021-01-01 00:00:00' END")
        .execute(&db.pool).await.unwrap();
    let candidates = candidates(db, &key, user, &target.origin).await.unwrap();
    drop(guard);
    let peer = hex::encode(fluxlock_autofill_protocol::public_identity(&[1; 64]));
    let request = token();
    let mut identity = identity::Identity::fresh();
    identity.profiles.push(identity::Profile {
        public: peer.clone(),
        vault_id: created.vault.id.clone(),
        name: "test".into(),
    });
    *state.autofill.identity.lock().await = Some(identity);
    crate::commands::session::lock_vault_data(&state).await;
    *state.autofill.pending.lock().await = Some(Pending {
        id: request.clone(),
        connection: "connection".into(),
        peer: peer.clone(),
        vault_id: created.vault.id,
        window: "autofill-auth-test".into(),
        expires: Instant::now() + Duration::from_secs(30),
        target: Some(target.clone()),
        fingerprint: String::new(),
        browser_confirmed: false,
        native_confirmed: false,
        accepted: true,
        verifying: false,
        authenticated: true,
        key: Some(key),
        user,
        candidates,
    });
    state.autofill.busy.store(true, Ordering::SeqCst);
    let app = mock_builder()
        .manage(state)
        .build(mock_context(noop_assets()))
        .unwrap();
    Fixture {
        _dir: dir,
        app,
        target,
        peer,
        request,
    }
}
async fn call(
    f: &Fixture,
    request: serde_json::Value,
    client: &mut snow::TransportState,
    server: &mut snow::TransportState,
) -> Result<serde_json::Value, String> {
    let bytes = Zeroizing::new(serde_json::to_vec(&request).unwrap());
    let reply = process(f.app.handle(), "connection", &f.peer, server, &bytes).await?;
    let plain = fluxlock_autofill_protocol::decrypt(client, &reply.frame)?;
    serde_json::from_slice(&plain).map_err(|e| e.to_string())
}
fn account_handle<'a>(list: &'a serde_json::Value, username: &str) -> &'a str {
    list["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["username"] == username)
        .expect("expected exact-site test account")["handle"]
        .as_str()
        .unwrap()
}
#[tokio::test]
async fn exact_site_list_has_no_password_and_selection_consumes_all_handles_before_delivery() {
    let f = fixture().await;
    let (mut client, mut server) = channel();
    let list = call(
        &f,
        serde_json::json!({"op":"list_candidates","request_id":f.request,"offset":0}),
        &mut client,
        &mut server,
    )
    .await
    .unwrap();
    assert_eq!(list["total"], 2);
    let serialized = list.to_string();
    assert!(!serialized.contains("SECRET"));
    assert!(!serialized.contains("evil@example"));
    assert!(!serialized.contains("password"));
    let handle = account_handle(&list, "one@example.test");
    let other_handle = account_handle(&list, "two@example.test");
    assert_ne!(list["entries"][0]["handle"], handle);
    let reply=call(&f,serde_json::json!({"op":"select_and_fill","request_id":f.request,"handle":handle,"target":f.target}),&mut client,&mut server).await.unwrap();
    assert_eq!(reply["state"], "fill_once");
    assert_eq!(reply["username"], "one@example.test");
    assert_eq!(reply["password"], "SELECTED_SECRET_1976");
    assert!(!reply.to_string().contains("OTHER_SECRET"));
    let state = f.app.state::<AppState>();
    assert!(state.autofill.pending.lock().await.is_none());
    assert!(state.vault_session.lock().await.is_none());
    assert!(state.session_token.lock().await.is_none());
    assert!(!state.autofill.busy.load(Ordering::SeqCst));
    assert!(call(&f,serde_json::json!({"op":"select_and_fill","request_id":f.request,"handle":other_handle,"target":f.target}),&mut client,&mut server).await.is_err());
}
#[tokio::test]
async fn no_auth_no_list_and_different_document_cannot_consume() {
    let f = fixture().await;
    let (mut client, mut server) = channel();
    let state = f.app.state::<AppState>();
    {
        let mut guard = state.autofill.pending.lock().await;
        guard.as_mut().unwrap().authenticated = false;
    }
    assert!(call(
        &f,
        serde_json::json!({"op":"list_candidates","request_id":f.request,"offset":0}),
        &mut client,
        &mut server
    )
    .await
    .is_err());
    {
        let mut guard = state.autofill.pending.lock().await;
        guard.as_mut().unwrap().authenticated = true;
    }
    let list = call(
        &f,
        serde_json::json!({"op":"list_candidates","request_id":f.request,"offset":0}),
        &mut client,
        &mut server,
    )
    .await
    .unwrap();
    let mut different = f.target.clone();
    different.document_id = "new-document".into();
    assert!(call(&f,serde_json::json!({"op":"select_and_fill","request_id":f.request,"handle":list["entries"][0]["handle"],"target":different}),&mut client,&mut server).await.is_err());
    assert!(state
        .autofill
        .pending
        .lock()
        .await
        .as_ref()
        .unwrap()
        .key
        .is_some());
    crate::commands::session::lock_session(&state).await;
    assert!(state.autofill.pending.lock().await.is_none());
    assert!(!state.autofill.busy.load(Ordering::SeqCst));
}
#[tokio::test]
async fn changed_record_and_expired_handle_fail_closed() {
    let f = fixture().await;
    let (mut client, mut server) = channel();
    let list = call(
        &f,
        serde_json::json!({"op":"list_candidates","request_id":f.request,"offset":0}),
        &mut client,
        &mut server,
    )
    .await
    .unwrap();
    let state = f.app.state::<AppState>();
    let handle = account_handle(&list, "one@example.test");
    let row_id = state
        .autofill
        .pending
        .lock()
        .await
        .as_ref()
        .unwrap()
        .candidates
        .iter()
        .find(|candidate| candidate.handle == handle)
        .unwrap()
        .id;
    {
        let guard = state.db.lock().await;
        sqlx::query("UPDATE passwords SET password='changed' WHERE id=?")
            .bind(row_id)
            .execute(&guard.as_ref().unwrap().pool)
            .await
            .unwrap();
    }
    assert!(call(&f,serde_json::json!({"op":"select_and_fill","request_id":f.request,"handle":handle,"target":f.target}),&mut client,&mut server).await.is_err());
    assert!(state.autofill.pending.lock().await.is_none());
    assert!(!state.autofill.busy.load(Ordering::SeqCst));
    assert!(owned(&None, "connection", "id", "vault").is_err());
}
#[tokio::test]
async fn shared_password_verifier_never_creates_a_general_session() {
    let f = fixture().await;
    let state = f.app.state::<AppState>();
    let guard = state.db.lock().await;
    let db = guard.as_ref().unwrap();
    let owner = db.get_vault_owner().await.unwrap().unwrap();
    assert!(
        crate::commands::auth::verify_vault_password(db, &owner, "wrong")
            .await
            .is_err()
    );
    let key = crate::commands::auth::verify_vault_password(db, &owner, PASSWORD)
        .await
        .unwrap();
    assert!(state.session_token.lock().await.is_none());
    assert!(state.vault_session.lock().await.is_none());
    drop(key);
}
#[test]
fn native_window_can_only_use_its_dedicated_auth_routes() {
    for command in [
        "get_passwords",
        "decrypt_password",
        "save_note",
        "plugin:fs|read_file",
        "local_login",
        "select_vault",
    ] {
        assert!(!command_allowed("autofill-auth-random", command));
    }
    assert!(command_allowed(
        "autofill-auth-random",
        "autofill_authenticate"
    ));
    assert!(!command_allowed("main", "autofill_authenticate"));
    assert!(!command_allowed("untrusted", "autofill_authenticate"));
}

#[tokio::test]
async fn expiry_other_connection_and_account_lock_cannot_release_a_secret() {
    let f = fixture().await;
    let (mut client, mut server) = channel();
    let list = call(
        &f,
        serde_json::json!({"op":"list_candidates","request_id":f.request,"offset":0}),
        &mut client,
        &mut server,
    )
    .await
    .unwrap();
    let selection = serde_json::json!({"op":"select_and_fill","request_id":f.request,"handle":list["entries"][0]["handle"],"target":f.target});
    assert!(process(
        f.app.handle(),
        "other-connection",
        &f.peer,
        &mut server,
        &serde_json::to_vec(&selection).unwrap()
    )
    .await
    .is_err());
    let state = f.app.state::<AppState>();
    {
        let mut guard = state.autofill.pending.lock().await;
        guard.as_mut().unwrap().expires = Instant::now() - Duration::from_secs(1);
    }
    assert!(call(&f, selection.clone(), &mut client, &mut server)
        .await
        .is_err());
    {
        let mut guard = state.autofill.pending.lock().await;
        guard.as_mut().unwrap().expires = Instant::now() + Duration::from_secs(30);
    }
    {
        let guard = state.db.lock().await;
        sqlx::query("UPDATE users SET account_locked=1")
            .execute(&guard.as_ref().unwrap().pool)
            .await
            .unwrap();
    }
    assert!(call(&f, selection, &mut client, &mut server).await.is_err());
    assert!(state.autofill.pending.lock().await.is_none());
    assert!(state.session_token.lock().await.is_none());
}

#[tokio::test]
async fn inactivity_is_enforced_on_sensitive_reads_without_frontend_polling() {
    let state = crate::vault::tests::state();
    *state.current_user_id.lock().await = Some(1);
    *state.session_token.lock().await = Some("synthetic-session".into());
    *state.auto_lock_minutes.lock().await = 1;
    *state.last_activity.lock().await = Instant::now() - Duration::from_secs(61);
    assert!(crate::validate_session(&state).await.is_err());
    *state.auto_lock_minutes.lock().await = 0;
    assert_eq!(crate::validate_session(&state).await.unwrap(), 1);
}

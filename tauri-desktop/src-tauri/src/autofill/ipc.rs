use super::*;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u8,
    frame: String,
}
async fn read<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>, String> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| "Canal fermé")?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > fluxlock_autofill_protocol::MAX_FRAME {
        return Err("Trame trop volumineuse".into());
    }
    let mut bytes = vec![0; len];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "Canal fermé")?;
    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| "Enveloppe invalide")?;
    if envelope.version != fluxlock_autofill_protocol::VERSION || envelope.frame.len() > 60000 {
        return Err("Version ou taille refusée".into());
    }
    STANDARD
        .decode(envelope.frame)
        .map_err(|_| "Trame invalide".into())
}
async fn write<W: AsyncWrite + Unpin>(stream: &mut W, frame: &[u8]) -> Result<(), String> {
    let bytes = serde_json::to_vec(&Envelope {
        version: fluxlock_autofill_protocol::VERSION,
        frame: STANDARD.encode(frame),
    })
    .map_err(|_| "Enveloppe invalide")?;
    if bytes.len() > 65536 {
        return Err("Réponse trop volumineuse".into());
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await
        .map_err(|_| "Canal fermé")?;
    stream.write_all(&bytes).await.map_err(|_| "Canal fermé")?;
    stream.flush().await.map_err(|_| "Canal fermé".into())
}
async fn bounded_read<R: AsyncRead + Unpin>(s: &mut R, seconds: u64) -> Result<Vec<u8>, String> {
    tokio::time::timeout(Duration::from_secs(seconds), read(s))
        .await
        .map_err(|_| "Canal expiré")?
}
async fn bounded_write<W: AsyncWrite + Unpin>(s: &mut W, bytes: &[u8]) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(2), write(s, bytes))
        .await
        .map_err(|_| "Envoi expiré")?
}
pub(super) async fn connection<R: tauri::Runtime, S: AsyncRead + AsyncWrite + Unpin>(
    app: tauri::AppHandle<R>,
    mut stream: S,
) -> Result<(), String> {
    let state = app.state::<AppState>();
    let key = state
        .autofill
        .identity
        .lock()
        .await
        .as_ref()
        .ok_or("Passerelle inactive")?
        .key()?;
    let mut handshake = fluxlock_autofill_protocol::handshake(&key, false)?;
    drop(key);
    let mut scratch = vec![0; fluxlock_autofill_protocol::MAX_HANDSHAKE];
    let mut out = vec![0; fluxlock_autofill_protocol::MAX_HANDSHAKE];
    let first = bounded_read(&mut stream, 5).await?;
    if first.len() > fluxlock_autofill_protocol::MAX_HANDSHAKE {
        return Err("Handshake invalide".into());
    }
    handshake
        .read_message(&first, &mut scratch)
        .map_err(|_| "Handshake refusé")?;
    let n = handshake
        .write_message(&[], &mut out)
        .map_err(|_| "Handshake refusé")?;
    bounded_write(&mut stream, &out[..n]).await?;
    let third = bounded_read(&mut stream, 5).await?;
    if third.len() > fluxlock_autofill_protocol::MAX_HANDSHAKE {
        return Err("Handshake invalide".into());
    }
    handshake
        .read_message(&third, &mut scratch)
        .map_err(|_| "Handshake refusé")?;
    let peer = hex::encode(
        handshake
            .remote_identity()
            .ok_or("Identité du profil absente")?,
    );
    let fingerprint = fluxlock_autofill_protocol::fingerprint(handshake.get_handshake_hash());
    let mut channel = handshake
        .into_transport_mode()
        .map_err(|_| "Handshake incomplet")?;
    let connection_id = token();
    let result=async {
        let _life=state.auth_lifecycle.write().await;
        let vault=selected(&state).await?;
        let paired=state.autofill.is_paired(&peer,&vault).await;
        let mut request_id=None;
        if !paired{
            let pairing=state.autofill.pairing.lock().await;
            if !pairing.as_ref().is_some_and(|(v,until)|v==&vault&&Instant::now()<*until){return Err("Ouvrez l’appairage dans les paramètres FluXlock".into());}
            drop(pairing);
            let mut pending=state.autofill.pending.lock().await;
            if pending.is_some(){return Err("Une demande est déjà ouverte".into());}
            let id=token();let window=format!("autofill-auth-{}",&id[..16]);
            *pending=Some(Pending{id:id.clone(),connection:connection_id.clone(),peer:peer.clone(),vault_id:vault,window:window.clone(),expires:Instant::now()+Duration::from_secs(60),target:None,fingerprint:fingerprint.clone(),browser_confirmed:false,native_confirmed:false,accepted:false,verifying:false,authenticated:false,key:None,user:0,candidates:Vec::new()});
            request_id=Some(id.clone());drop(pending);show_prompt(&app,&window,&id)?;
        }
        let welcome=seal(&mut channel,serde_json::json!({"state":if paired{"connected"}else{"pairing"},"fingerprint":fingerprint,"request_id":request_id}),false)?;
        drop(_life);bounded_write(&mut stream,&welcome.frame).await?;
        let mut calls=0;
        let started=Instant::now();
        loop {
            if started.elapsed()>Duration::from_secs(150)||calls>=180{return Err("Session de transport expirée".into());}
            let frame=bounded_read(&mut stream,65).await?;calls+=1;
            let bytes=fluxlock_autofill_protocol::decrypt(&mut channel,&frame)?;
            let epoch=state.autofill.epoch.load(Ordering::SeqCst);
            let reply=process(&app,&connection_id,&peer,&mut channel,&bytes).await?;drop(bytes);
            {
                // A local write is bounded to two seconds. Serialize its start
                // against revoke/lock/selection so an already sealed reply cannot
                // slip through after an external transition.
                let _release=state.auth_lifecycle.read().await;
                if state.autofill.epoch.load(Ordering::SeqCst)!=epoch {return Err("Réponse annulée".into());}
                bounded_write(&mut stream,&reply.frame).await?;
            }
            if reply.close {break;}
            // Status polling cannot prolong an authentication lifetime.
            tokio::time::sleep(Duration::from_millis(80)).await;
        } Ok(())
    }.await;
    let _life = state.auth_lifecycle.write().await;
    let mut pending = state.autofill.pending.lock().await;
    if pending
        .as_ref()
        .is_some_and(|p| p.connection == connection_id)
    {
        pending.take();
        state.autofill.busy.store(false, Ordering::SeqCst);
    }
    result
}

pub async fn boot(app: tauri::AppHandle) {
    let state = app.state::<AppState>();
    if let Ok(Some(identity)) = identity::load(false).await {
        *state.autofill.identity.lock().await = Some(identity);
        let _ = super::host_relay::ensure_installed(None);
        let _ = start_listener(app.clone()).await;
    }
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let _life = state.auth_lifecycle.write().await;
        let mut pending = state.autofill.pending.lock().await;
        if pending
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.expires)
        {
            if let Some(p) = pending.take() {
                if let Some(w) = app.get_webview_window(&p.window) {
                    let _ = w.close();
                }
            }
            state.autofill.busy.store(false, Ordering::SeqCst);
        }
        drop(pending);
        if state.current_user_id.lock().await.is_some() {
            let minutes = *state.auto_lock_minutes.lock().await;
            if minutes > 0
                && state.last_activity.lock().await.elapsed()
                    >= Duration::from_secs(minutes.saturating_mul(60))
            {
                crate::commands::session::lock_session(&state).await;
                let _ = app.emit("autofill-vault-locked", ());
            }
        }
    }
}
pub async fn start_listener(app: tauri::AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    if state.autofill.listening.swap(true, Ordering::SeqCst) {
        return Ok(());
    }
    let result = start(app.clone()).await;
    if result.is_err() {
        state.autofill.listening.store(false, Ordering::SeqCst);
    }
    result
}
#[cfg(unix)]
async fn start(app: tauri::AppHandle) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let root = crate::hidden_storage::get_hidden_database_dir()?.join("browser-ipc");
    crate::vault::private_directory(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let path = root.join("channel.sock");
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        use std::os::unix::fs::FileTypeExt;
        if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
            return Err("Endpoint local invalide".into());
        }
        if tokio::net::UnixStream::connect(&path).await.is_ok() {
            return Err("Une passerelle utilise déjà cet endpoint".into());
        }
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    let listener = tokio::net::UnixListener::bind(&path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    tauri::async_runtime::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            if stream
                .peer_cred()
                .map_or(true, |c| c.uid() != unsafe { libc::geteuid() })
            {
                continue;
            }
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let _permit = permit;
                let _ = connection(app, stream).await;
            });
        }
    });
    Ok(())
}
#[cfg(windows)]
async fn start(app: tauri::AppHandle) -> Result<(), String> {
    use super::windows_pipe::create as pipe;
    let root = std::env::var("LOCALAPPDATA").map_err(|e| e.to_string())?;
    let name = if crate::hidden_storage::TEST_BUILD {
        "SecureVault Test"
    } else {
        "SecureVault"
    };
    let mut hash = 0xcbf29ce484222325u64;
    for b in format!("{root}/{name}").bytes() {
        hash = (hash ^ b as u64).wrapping_mul(0x100000001b3);
    }
    let path = format!(r"\\.\pipe\fluxlock-autofill-{hash:016x}");
    let mut server = pipe(&path, true)?;
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    tauri::async_runtime::spawn(async move {
        loop {
            if server.connect().await.is_err() {
                break;
            }
            let next = match pipe(&path, false) {
                Ok(p) => p,
                Err(_) => break,
            };
            let connected = std::mem::replace(&mut server, next);
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let _permit = permit;
                let _ = connection(app, connected).await;
            });
        }
    });
    Ok(())
}
#[cfg(not(any(unix, windows)))]
async fn start(_app: tauri::AppHandle) -> Result<(), String> {
    Err("Passerelle non prise en charge".into())
}

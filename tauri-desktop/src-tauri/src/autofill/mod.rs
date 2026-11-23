//! Browser clients never receive a general vault session or master key.
mod commands;
mod identity;
mod ipc;
#[cfg(windows)]
mod windows_pipe;
pub mod origin;
use crate::{database::Database, secure_key::SecureKey, AppState};
use base64::Engine;
pub use commands::*;
use fluxlock_autofill_protocol::snow;
pub use ipc::boot;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager};
use tokio::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

pub fn token() -> String {
    let mut b = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub origin: String,
    pub tab_id: i64,
    pub frame_id: i64,
    pub document_id: String,
    pub nonce: String,
}
impl Target {
    fn validate(&self) -> Result<(), String> {
        if origin::canonical(&self.origin)? != self.origin
            || self.tab_id < 0
            || self.frame_id != 0
            || self.document_id.is_empty()
            || self.document_id.len() > 128
            || self.document_id.chars().any(char::is_control)
            || self.nonce.len() != 64
            || !self.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("Contexte navigateur invalide".into());
        }
        Ok(())
    }
}
pub struct Candidate {
    handle: String,
    id: i64,
    stamp: String,
    username: String,
}
impl Drop for Candidate {
    fn drop(&mut self) {
        self.username.zeroize();
    }
}
pub struct Pending {
    id: String,
    connection: String,
    peer: String,
    vault_id: String,
    window: String,
    expires: Instant,
    target: Option<Target>,
    fingerprint: String,
    browser_confirmed: bool,
    native_confirmed: bool,
    accepted: bool,
    verifying: bool,
    authenticated: bool,
    key: Option<SecureKey>,
    user: i64,
    candidates: Vec<Candidate>,
}
#[derive(Default)]
pub struct Service {
    pub epoch: AtomicU64,
    pub busy: AtomicBool,
    pub listening: AtomicBool,
    pub pending: Mutex<Option<Pending>>,
    identity: Mutex<Option<identity::Identity>>,
    pairing: Mutex<Option<(String, Instant)>>,
}
impl Service {
    pub async fn cancel(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        self.pending.lock().await.take();
        self.busy.store(false, Ordering::SeqCst);
        self.pairing.lock().await.take();
    }
    pub async fn reset_vault(&self, vault: &str) -> Result<(), String> {
        let mut guard = self.identity.lock().await;
        if let Some(current) = guard.as_ref() {
            let mut next = current.clone();
            next.profiles.retain(|p| p.vault_id != vault);
            identity::save(next.clone()).await?;
            *guard = Some(next);
        }
        drop(guard);
        self.cancel().await;
        Ok(())
    }
    async fn is_paired(&self, peer: &str, vault: &str) -> bool {
        self.identity.lock().await.as_ref().is_some_and(|i| {
            i.profiles
                .iter()
                .any(|p| p.public == peer && p.vault_id == vault)
        })
    }
    async fn finish_pair(&self) -> Result<bool, String> {
        let mut pending = self.pending.lock().await;
        let Some(p) = pending.as_ref() else {
            return Ok(false);
        };
        if p.target.is_some()
            || !p.browser_confirmed
            || !p.native_confirmed
            || Instant::now() >= p.expires
        {
            return Ok(false);
        }
        let mut guard = self.identity.lock().await;
        let mut next = guard.as_ref().ok_or("Passerelle désactivée")?.clone();
        next.profiles.retain(|profile| profile.public != p.peer);
        if next.profiles.len() >= 4 {
            return Err("Quatre profils maximum. Révoquez un ancien profil.".into());
        }
        next.profiles.push(identity::Profile {
            public: p.peer.clone(),
            vault_id: p.vault_id.clone(),
            name: "Navigateur".into(),
        });
        identity::save(next.clone()).await?;
        *guard = Some(next);
        pending.take();
        self.pairing.lock().await.take();
        Ok(true)
    }
}
fn selected(state: &AppState) -> impl std::future::Future<Output = Result<String, String>> + '_ {
    async {
        Ok(state
            .selected_vault
            .lock()
            .await
            .as_ref()
            .ok_or("Sélectionnez le coffre dans FluXlock")?
            .descriptor
            .id
            .clone())
    }
}
fn stamp(row: &crate::database::Password) -> String {
    let mut hash = Sha256::new();
    for field in [
        &row.password,
        row.url.as_deref().unwrap_or(""),
        row.username.as_deref().unwrap_or(""),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hex::encode(hash.finalize())
}
async fn candidates(
    db: &Database,
    key: &SecureKey,
    user: i64,
    origin: &str,
) -> Result<Vec<Candidate>, String> {
    let rows = db.get_passwords(user).await.map_err(|e| e.to_string())?;
    if rows.len() > 10000 {
        return Err("Trop d’identifiants pour le remplissage".into());
    }
    let mut result = Vec::new();
    for row in rows {
        let Some(url) = row.url.as_ref() else {
            continue;
        };
        if url.len() > 16384 {
            continue;
        }
        let Ok(url) = crate::crypto::decrypt_data_secure(url, key) else {
            continue;
        };
        if origin::canonical(&url).ok().as_deref() != Some(origin) {
            continue;
        }
        let Some(username) = row.username.as_ref() else {
            continue;
        };
        let username =
            crate::crypto::decrypt_data_secure(username, key).map_err(|_| "Identifiant altéré")?;
        if username.is_empty() || username.len() > 1024 || username.chars().any(char::is_control) {
            continue;
        }
        result.push(Candidate {
            handle: token(),
            id: row.id,
            stamp: stamp(&row),
            username,
        });
        if result.len() > 128 {
            return Err("Trop de comptes sur ce site".into());
        }
    }
    Ok(result)
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    PairConfirm,
    BeginFill {
        target: Target,
    },
    Status {
        request_id: Option<String>,
    },
    ListCandidates {
        request_id: String,
        offset: usize,
    },
    SelectAndFill {
        request_id: String,
        handle: String,
        target: Target,
    },
    Cancel {
        request_id: String,
    },
}
struct Reply {
    frame: Vec<u8>,
    close: bool,
}
fn seal(
    channel: &mut snow::TransportState,
    value: serde_json::Value,
    close: bool,
) -> Result<Reply, String> {
    let bytes = Zeroizing::new(serde_json::to_vec(&value).map_err(|_| "Réponse invalide")?);
    Ok(Reply {
        frame: fluxlock_autofill_protocol::encrypt(channel, &bytes)?,
        close,
    })
}
async fn process<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    connection: &str,
    peer: &str,
    channel: &mut snow::TransportState,
    bytes: &[u8],
) -> Result<Reply, String> {
    let request: Request = serde_json::from_slice(bytes).map_err(|_| "Message refusé")?;
    let state = app.state::<AppState>();
    let service = &state.autofill;
    // All state transitions use the same order: lifecycle -> pending -> identity.
    let _lifecycle = state.auth_lifecycle.write().await;
    let vault = selected(&state).await?;
    let paired = service.is_paired(peer, &vault).await;
    if !paired {
        match request {
            Request::PairConfirm => {
                let mut guard = service.pending.lock().await;
                let p = guard.as_mut().ok_or("Appairage absent")?;
                if p.connection != connection
                    || p.peer != peer
                    || p.target.is_some()
                    || Instant::now() >= p.expires
                {
                    return Err("Appairage expiré".into());
                }
                p.browser_confirmed = true;
                drop(guard);
                service.finish_pair().await?;
                return seal(channel, serde_json::json!({"state":"pairing"}), false);
            }
            Request::Status { .. } => {
                service.finish_pair().await?;
                return seal(
                    channel,
                    serde_json::json!({"state":if service.is_paired(peer,&vault).await{"paired"}else{"pairing"}}),
                    false,
                );
            }
            _ => return Err("Profil non appairé".into()),
        }
    }
    match request {
        Request::BeginFill { target } => {
            target.validate()?;
            let mut guard = service.pending.lock().await;
            if guard.is_some() {
                return Err("Une demande est déjà ouverte".into());
            }
            let id = token();
            let window = format!("autofill-auth-{}", &id[..16]);
            *guard = Some(Pending {
                id: id.clone(),
                connection: connection.into(),
                peer: peer.into(),
                vault_id: vault,
                window: window.clone(),
                expires: Instant::now() + Duration::from_secs(60),
                target: Some(target),
                fingerprint: String::new(),
                browser_confirmed: false,
                native_confirmed: false,
                accepted: false,
                verifying: false,
                authenticated: false,
                key: None,
                user: 0,
                candidates: Vec::new(),
            });
            drop(guard);
            show_prompt(app, &window, &id)?;
            seal(
                channel,
                serde_json::json!({"state":"auth_required","request_id":id}),
                false,
            )
        }
        Request::Cancel { request_id } => {
            let mut guard = service.pending.lock().await;
            if guard
                .as_ref()
                .is_some_and(|p| p.connection == connection && p.id == request_id)
            {
                guard.take();
                service.busy.store(false, Ordering::SeqCst);
            }
            seal(channel, serde_json::json!({"state":"cancelled"}), true)
        }
        Request::Status { request_id } => {
            if request_id.is_none() {
                return seal(channel, serde_json::json!({"state":"paired"}), false);
            }
            let guard = service.pending.lock().await;
            let p = owned(
                &guard,
                connection,
                request_id.as_deref().unwrap_or(""),
                &vault,
            )?;
            seal(
                channel,
                serde_json::json!({"state":if p.authenticated{"ready"}else{"auth_required"},"request_id":p.id}),
                false,
            )
        }
        Request::ListCandidates { request_id, offset } => {
            let guard = service.pending.lock().await;
            let p = owned(&guard, connection, &request_id, &vault)?;
            if !p.authenticated || p.key.is_none() {
                return Err("Authentification native requise".into());
            }
            if offset > 128 {
                return Err("Pagination invalide".into());
            }
            let entries: Vec<_> = p
                .candidates
                .iter()
                .skip(offset)
                .take(10)
                .map(|c| serde_json::json!({"handle":c.handle,"username":c.username}))
                .collect();
            seal(
                channel,
                serde_json::json!({"state":"ready","entries":entries,"total":p.candidates.len()}),
                false,
            )
        }
        Request::SelectAndFill {
            request_id,
            handle,
            target,
        } => {
            target.validate()?;
            let mut guard = service.pending.lock().await;
            let p = owned(&guard, connection, &request_id, &vault)?;
            if !p.authenticated || p.target.as_ref() != Some(&target) {
                return Err("Contexte de remplissage refusé".into());
            }
            if !p.candidates.iter().any(|c| c.handle == handle) {
                return Err("Choix refusé".into());
            }
            // Taking the entire transaction atomically consumes every candidate.
            let p = guard.take().ok_or("Demande consommée")?;
            drop(guard);
            let result = async {
                let candidate = p
                    .candidates
                    .iter()
                    .find(|c| c.handle == handle)
                    .ok_or("Choix absent")?;
                let key = p.key.as_ref().ok_or("Authentification absente")?;
                let db_guard = state.db.lock().await;
                let db = db_guard.as_ref().ok_or("Base indisponible")?;
                if db
                    .check_account_locked(p.user)
                    .await
                    .map_err(|e| e.to_string())?
                {
                    return Err("Compte verrouillé".into());
                }
                let row = db
                    .get_password(candidate.id, p.user)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or("Compte supprimé")?;
                if stamp(&row) != candidate.stamp {
                    return Err("Le compte a changé. Recommencez.".into());
                }
                let url = Zeroizing::new(
                    crate::crypto::decrypt_data_secure(
                        row.url.as_deref().ok_or("URL absente")?,
                        key,
                    )
                    .map_err(|_| "URL altérée")?,
                );
                if origin::canonical(&url)? != target.origin {
                    return Err("Origine différente".into());
                }
                let password = Zeroizing::new(
                    crate::crypto::decrypt_data_secure(&row.password, key)
                        .map_err(|_| "Mot de passe altéré")?,
                );
                if password.len() > 16384 {
                    return Err("Mot de passe trop volumineux pour le remplissage".into());
                }
                // Serialize without putting the password into an unprotected Value.
                #[derive(Serialize)]
                struct SecretReply<'a> {
                    state: &'a str,
                    username: &'a str,
                    password: &'a str,
                    request_id: &'a str,
                }
                let bytes = Zeroizing::new(
                    serde_json::to_vec(&SecretReply {
                        state: "fill_once",
                        username: &candidate.username,
                        password: &password,
                        request_id: &p.id,
                    })
                    .map_err(|_| "Réponse invalide")?,
                );
                Ok(Reply {
                    frame: fluxlock_autofill_protocol::encrypt(channel, &bytes)?,
                    close: true,
                })
            }
            .await;
            drop(p); // Zeroizes the only transaction vault key before any return.
            crate::commands::session::lock_vault_data(&state).await;
            service.busy.store(false, Ordering::SeqCst);
            let _ = app.emit("autofill-vault-locked", ());
            result
        }
        _ => Err("Opération refusée".into()),
    }
}
fn owned<'a>(
    guard: &'a Option<Pending>,
    connection: &str,
    id: &str,
    vault: &str,
) -> Result<&'a Pending, String> {
    let p = guard.as_ref().ok_or("Demande absente")?;
    if p.connection != connection
        || p.id != id
        || p.vault_id != vault
        || Instant::now() >= p.expires
    {
        return Err("Demande expirée ou différente".into());
    }
    Ok(p)
}
fn show_prompt<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    label: &str,
    id: &str,
) -> Result<(), String> {
    let app2 = app.clone();
    let request_id = id.to_owned();
    let window_label = label.to_owned();
    tauri::WebviewWindowBuilder::new(
        app,
        label,
        tauri::WebviewUrl::App(format!("autofill-auth?request={id}").into()),
    )
    .use_https_scheme(true)
    .title("FluXlock — Autoriser le navigateur")
    .inner_size(450., 520.)
    .resizable(false)
    .on_navigation(|url| {
        let trusted = if cfg!(debug_assertions) {
            url.scheme() == "http"
                && matches!(url.host_str(), Some("localhost") | Some("127.0.0.1"))
                && url.port() == Some(5173)
        } else {
            (url.scheme() == "tauri" && url.host_str() == Some("localhost"))
                || (url.scheme() == "https"
                    && url.host_str() == Some("tauri.localhost")
                    && url.port().is_none())
        };
        trusted && matches!(url.path(), "/autofill-auth" | "/index.html")
    })
    .build()
    .map_err(|_| "Ouverture de la fenêtre FluXlock impossible")?
    .on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Destroyed) {
            let app = app2.clone();
            let id = request_id.clone();
            let label = window_label.clone();
            tauri::async_runtime::spawn(async move {
                let state = app.state::<AppState>();
                let _life = state.auth_lifecycle.write().await;
                let mut guard = state.autofill.pending.lock().await;
                if guard.as_ref().is_some_and(|p| {
                    p.id == id && p.window == label && !p.authenticated && !p.native_confirmed
                }) {
                    guard.take();
                    state.autofill.busy.store(false, Ordering::SeqCst);
                }
            });
        }
    });
    Ok(())
}
pub fn command_allowed(label: &str, command: &str) -> bool {
    if label == "main" {
        return !matches!(
            command,
            "autofill_prompt"
                | "autofill_authenticate"
                | "autofill_confirm_pair"
                | "autofill_cancel_native"
        );
    }
    label.starts_with("autofill-auth-")
        && matches!(
            command,
            "autofill_prompt"
                | "autofill_authenticate"
                | "autofill_confirm_pair"
                | "autofill_cancel_native"
        )
}

#[cfg(test)]
mod tests;

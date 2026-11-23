//! Application vault model. Descriptors are public; session keys never leave Rust.
//! The lifecycle lock covers every scoped IPC operation. Selection, creation,
//! restore and lock take its write side, so two vaults cannot be open together.
use crate::{database::Database, secure_key::SecureKey, AppState};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use tauri::State;
use tokio::sync::RwLockReadGuard;

const CATALOG_VERSION: u32 = 1;
pub const LEGACY_VAULT_ID: &str = "legacy";
const MAX_VAULTS: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultDescriptor {
    pub id: String,
    pub name: String,
    pub schema_version: u32,
    pub created_at: String,
}

/// Storage location is derived by Rust, never supplied by the webview/catalog.
#[derive(Clone)]
pub struct Vault {
    pub descriptor: VaultDescriptor,
    pub directory: PathBuf,
}

/// Exactly one live session, zeroized on drop on every platform.
pub struct VaultSession {
    pub vault_id: String,
    pub user_id: i64,
    pub key: SecureKey,
}

/// Binds queued requests to both a vault and a particular unlock of that vault.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultContext {
    pub vault_id: String,
    pub token: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogData {
    version: u32,
    vaults: Vec<VaultDescriptor>,
    #[serde(default)]
    selected_vault_id: Option<String>,
}

pub struct VaultCatalog {
    root: PathBuf,
    data: CatalogData,
    // Kept open for the lifetime of the application; OS releases it after a crash.
    _instance_lock: File,
}

pub(crate) fn private_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path).map_err(|e| e.to_string())?;
    }
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("Le stockage du coffre doit être un dossier ordinaire".into());
    }
    Ok(())
}

pub fn validated_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > 80
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return Err(
            "Choisissez un nom de coffre de 1 à 80 caractères, sans caractères de contrôle".into(),
        );
    }
    Ok(name.to_owned())
}

fn valid_id(id: &str) -> bool {
    id == LEGACY_VAULT_ID || uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id)
}

impl VaultCatalog {
    fn load(root: &Path) -> Result<Self, String> {
        private_directory(root)?;
        let lock_path = root.join("vaults.lock");
        if fs::symlink_metadata(&lock_path)
            .is_ok_and(|m| !m.is_file() || m.file_type().is_symlink())
        {
            return Err("Verrou de l’application invalide".into());
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let instance_lock = options.open(lock_path).map_err(|e| e.to_string())?;
        instance_lock
            .try_lock()
            .map_err(|_| "FluXlock utilise déjà ces coffres dans une autre instance".to_string())?;
        let path = root.join("vaults.json");
        let exists = path.try_exists().map_err(|e| e.to_string())?;
        let data = if exists {
            let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 256 * 1024 {
                return Err("Catalogue des coffres invalide".into());
            }
            let data: CatalogData =
                serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?).map_err(
                    |_| "Catalogue des coffres illisible. Vos coffres sont conservés.".to_string(),
                )?;
            if data.version != CATALOG_VERSION || data.vaults.len() > MAX_VAULTS {
                return Err("Version ou taille du catalogue non prise en charge".into());
            }
            let mut ids = std::collections::HashSet::new();
            for vault in &data.vaults {
                if !valid_id(&vault.id)
                    || vault.schema_version != 1
                    || !ids.insert(vault.id.clone())
                {
                    return Err("Identité de coffre invalide dans le catalogue".into());
                }
                validated_name(&vault.name)?;
            }
            if data
                .selected_vault_id
                .as_ref()
                .is_some_and(|id| !ids.contains(id))
            {
                return Err("Le coffre sélectionné est absent du catalogue".into());
            }
            data
        } else {
            // Adopt legacy storage in place. No database/file/key rewrite.
            let vaults = if root.join("sv.db").try_exists().map_err(|e| e.to_string())? {
                vec![VaultDescriptor {
                    id: LEGACY_VAULT_ID.into(),
                    name: "Personnel".into(),
                    schema_version: 1,
                    created_at: chrono::Utc::now().to_rfc3339(),
                }]
            } else {
                Vec::new()
            };
            CatalogData {
                version: CATALOG_VERSION,
                selected_vault_id: vaults.first().map(|v| v.id.clone()),
                vaults,
            }
        };
        let catalog = Self {
            root: root.to_owned(),
            data,
            _instance_lock: instance_lock,
        };
        if !exists {
            catalog.save(&catalog.data)?;
        }
        Ok(catalog)
    }

    fn save(&self, data: &CatalogData) -> Result<(), String> {
        let mut staged = tempfile::NamedTempFile::new_in(&self.root).map_err(|e| e.to_string())?;
        staged
            .write_all(&serde_json::to_vec_pretty(data).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        staged.as_file().sync_all().map_err(|e| e.to_string())?;
        staged
            .persist(self.root.join("vaults.json"))
            .map_err(|e| e.error.to_string())?;
        #[cfg(unix)]
        if let Err(error) = File::open(&self.root).and_then(|dir| dir.sync_all()) {
            debug_log!("Catalogue publié, synchronisation du dossier indisponible : {error}");
        }
        Ok(())
    }

    fn resolve(&self, id: &str) -> Result<Vault, String> {
        let descriptor = self
            .data
            .vaults
            .iter()
            .find(|v| v.id == id)
            .ok_or("Coffre introuvable")?
            .clone();
        let directory = if id == LEGACY_VAULT_ID {
            self.root.clone()
        } else {
            self.root.join("vaults").join(id)
        };
        Ok(Vault {
            descriptor,
            directory,
        })
    }
}

pub(crate) async fn initialize(state: &AppState, root: &Path) -> Result<(), String> {
    let catalog = VaultCatalog::load(root)?;
    let initial = catalog
        .data
        .selected_vault_id
        .as_deref()
        .or_else(|| catalog.data.vaults.first().map(|v| v.id.as_str()))
        .map(|id| catalog.resolve(id))
        .transpose()?;
    if let Some(vault) = initial {
        if vault.directory.join("sv.db").is_file() {
            if let Err(error) = mount(state, vault).await {
                debug_log!("Coffre précédent indisponible : {error}");
            }
        }
        // Keep the catalog usable so another vault can be selected for recovery.
        // Missing/corrupt storage is never replaced by an empty database.
    }
    *state.vault_catalog.lock().await = Some(catalog);
    Ok(())
}

pub(crate) async fn require_locked(state: &AppState) -> Result<(), String> {
    if state.autofill.busy.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("Une authentification navigateur est en cours".into());
    }
    if state.vault_session.lock().await.is_some()
        || state.current_user_id.lock().await.is_some()
        || state.session_token.lock().await.is_some()
    {
        return Err("Verrouillez le coffre ouvert avant de continuer".into());
    }
    Ok(())
}

/// Call under the lifecycle lock, before reading any selected vault resource.
pub(crate) async fn check_context(
    state: &AppState,
    context: &VaultContext,
    authenticated: bool,
) -> Result<(), String> {
    let selected = state.selected_vault.lock().await;
    if selected.as_ref().map(|v| v.descriptor.id.as_str()) != Some(context.vault_id.as_str()) {
        return Err(
            "Le coffre a changé. Relancez cette action depuis le coffre sélectionné.".into(),
        );
    }
    drop(selected);
    let token = state.session_token.lock().await;
    if authenticated {
        use subtle::ConstantTimeEq;
        if !matches!((token.as_deref(), context.token.as_deref()), (Some(a), Some(b))
            if bool::from(a.as_bytes().ct_eq(b.as_bytes())))
        {
            return Err("Cette action appartient à une session verrouillée".into());
        }
    } else if context.token.is_some() && *token != context.token {
        return Err("Cette action appartient à une ancienne session".into());
    }
    Ok(())
}

pub(crate) async fn access<'a>(
    state: &'a AppState,
    context: &VaultContext,
) -> Result<RwLockReadGuard<'a, ()>, String> {
    let guard = state.auth_lifecycle.read().await;
    if state.autofill.busy.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("Une authentification navigateur est en cours".into());
    }
    check_context(state, context, true).await?;
    crate::validate_session(state).await?;
    Ok(guard)
}

/// Mount only while locked and under an exclusive lifecycle guard.
pub(crate) async fn mount(state: &AppState, vault: Vault) -> Result<(), String> {
    require_locked(state).await?;
    if vault.descriptor.id != LEGACY_VAULT_ID {
        private_directory(
            vault
                .directory
                .parent()
                .ok_or("Stockage du coffre invalide")?,
        )?;
    }
    private_directory(&vault.directory)?;
    let path = vault.directory.join("sv.db");
    if fs::symlink_metadata(&path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
        return Err("Base du coffre invalide".into());
    }
    let db = Database::new(&path).await.map_err(|e| e.to_string())?;
    db.initialize().await.map_err(|e| e.to_string())?;
    crate::commands::notes::recover_files(&db, &vault.directory.join("files")).await?;
    // Retire a crash-surviving session cache from pre-multi-vault desktop versions.
    // This service is separate from persistent biometric credentials.
    #[cfg(all(not(test), not(any(target_os = "android", target_os = "ios"))))]
    if vault.descriptor.id == LEGACY_VAULT_ID {
        if let Some(owner) = db.get_vault_owner().await.map_err(|e| e.to_string())? {
            if let Err(error) = crate::secure_storage::delete_encryption_key(owner.id) {
                debug_log!("Ancienne clé de session indisponible pour suppression : {error}");
            }
        }
    }
    let directory = vault.directory.clone();
    let (transfer_manager, log_manager) = tokio::task::spawn_blocking(move || {
        let peer_name = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "FluXlock".into());
        // An unavailable optional subsystem must not prevent password access.
        // Failed managers stay absent; no transfer/log operation can use a fallback vault.
        let transfer = crate::transfer::commands::TransferManager::new(&directory, &peer_name)
            .map_err(|error| debug_log!("Transferts indisponibles pour ce coffre : {error}"))
            .ok();
        let logs = crate::signed_log::SignedLogManager::init(&directory)
            .map_err(|error| debug_log!("Journal signé indisponible pour ce coffre : {error}"))
            .ok();
        (transfer, logs)
    })
    .await
    .map_err(|e| e.to_string())?;
    crate::commands::session::lock_session(state).await;
    if let Some(old) = state.db.lock().await.take() {
        old.pool.close().await;
    }
    *state.transfer_manager.lock().await = None;
    *state.signed_log_manager.lock().await = None;
    *state.data_dir.lock().await = Some(vault.directory.clone());
    *state.selected_vault.lock().await = Some(vault.clone());
    *state.db.lock().await = Some(db);
    *state.auto_lock_minutes.lock().await = 15;
    *state.threat_reactor.lock().await = std::sync::Arc::new(
        crate::threat_reactor::ThreatReactor::with_persistence(vault.directory.clone()),
    );
    *state.transfer_manager.lock().await = transfer_manager;
    *state.signed_log_manager.lock().await = log_manager;
    Ok(())
}

#[derive(Serialize)]
pub struct VaultOverview {
    pub vaults: Vec<VaultDescriptor>,
    pub selected_vault_id: Option<String>,
    pub unlocked_vault_id: Option<String>,
}

#[tauri::command]
pub async fn list_vaults(state: State<'_, AppState>) -> Result<VaultOverview, String> {
    let _guard = state.auth_lifecycle.read().await;
    let catalog = state.vault_catalog.lock().await;
    let catalog = catalog.as_ref().ok_or("Coffres non initialisés")?;
    Ok(VaultOverview {
        vaults: catalog.data.vaults.clone(),
        selected_vault_id: state
            .selected_vault
            .lock()
            .await
            .as_ref()
            .map(|v| v.descriptor.id.clone()),
        unlocked_vault_id: state
            .vault_session
            .lock()
            .await
            .as_ref()
            .map(|s| s.vault_id.clone()),
    })
}

#[tauri::command]
pub async fn select_vault(
    vault_id: String,
    state: State<'_, AppState>,
) -> Result<VaultDescriptor, String> {
    let _guard = state.auth_lifecycle.write().await;
    select(&state, &vault_id).await
}

pub(crate) async fn select(state: &AppState, id: &str) -> Result<VaultDescriptor, String> {
    require_locked(state).await?;
    let vault = state
        .vault_catalog
        .lock()
        .await
        .as_ref()
        .ok_or("Coffres non initialisés")?
        .resolve(id)?;
    // Never silently create an empty replacement for a missing vault database.
    if !vault.directory.join("sv.db").is_file() {
        return Err("Le stockage de ce coffre est introuvable".into());
    }
    let descriptor = vault.descriptor.clone();
    let previous = state.selected_vault.lock().await.clone();
    mount(state, vault).await?;
    let result = {
        let mut guard = state.vault_catalog.lock().await;
        let catalog = guard.as_mut().ok_or("Coffres non initialisés")?;
        let mut next = catalog.data.clone();
        next.selected_vault_id = Some(id.to_owned());
        match catalog.save(&next) {
            Ok(()) => {
                catalog.data = next;
                Ok(())
            }
            Err(error) => Err(error),
        }
    };
    if let Err(error) = result {
        if let Some(previous) = previous {
            mount(state, previous).await?;
        }
        return Err(error);
    }
    Ok(descriptor)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateVaultRequest {
    pub name: String,
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct CreatedVault {
    pub vault: VaultDescriptor,
    pub auth: crate::LoginResponse,
}

#[tauri::command]
pub async fn create_vault(
    request: CreateVaultRequest,
    state: State<'_, AppState>,
) -> Result<CreatedVault, String> {
    let _guard = state.auth_lifecycle.write().await;
    create(&state, request).await
}

pub(crate) async fn create(
    state: &AppState,
    request: CreateVaultRequest,
) -> Result<CreatedVault, String> {
    require_locked(state).await?;
    let name = validated_name(&request.name)?;
    let (descriptor, directory, next) = {
        let guard = state.vault_catalog.lock().await;
        let catalog = guard.as_ref().ok_or("Coffres non initialisés")?;
        if catalog.data.vaults.len() >= MAX_VAULTS {
            return Err("Nombre maximal de coffres atteint".into());
        }
        let descriptor = VaultDescriptor {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            schema_version: 1,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let directory = catalog.root.join("vaults").join(&descriptor.id);
        private_directory(&catalog.root.join("vaults"))?;
        // Exclusive creation: never overwrite/reuse a different vault's directory.
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&directory).map_err(|e| e.to_string())?;
        let mut next = catalog.data.clone();
        next.vaults.push(descriptor.clone());
        next.selected_vault_id = Some(descriptor.id.clone());
        (descriptor, directory, next)
    };
    let previous = state.selected_vault.lock().await.clone();
    let result = async {
        mount(
            state,
            Vault {
                descriptor: descriptor.clone(),
                directory: directory.clone(),
            },
        )
        .await?;
        let auth = crate::commands::auth::register_account(
            crate::RegisterRequest {
                username: request.username,
                email: request.email,
                password: request.password,
            },
            state,
        )
        .await?;
        let mut guard = state.vault_catalog.lock().await;
        let catalog = guard.as_mut().ok_or("Coffres non initialisés")?;
        catalog.save(&next)?;
        catalog.data = next;
        Ok(CreatedVault {
            vault: descriptor,
            auth,
        })
    }
    .await;
    if result.is_err() {
        crate::commands::session::lock_session(state).await;
        if let Some(db) = state.db.lock().await.take() {
            db.pool.close().await;
        }
        *state.transfer_manager.lock().await = None;
        *state.signed_log_manager.lock().await = None;
        *state.selected_vault.lock().await = None;
        *state.data_dir.lock().await = None;
        // This path was created exclusively by this call and contains no prior data.
        let _ = fs::remove_dir_all(&directory);
        if let Some(previous) = previous {
            let _ = mount(state, previous).await;
        }
    }
    result
}

#[tauri::command]
pub async fn rename_vault(
    name: String,
    context: VaultContext,
    state: State<'_, AppState>,
) -> Result<VaultDescriptor, String> {
    let _guard = state.auth_lifecycle.write().await;
    rename(&state, &context, &name).await
}

pub(crate) async fn rename(
    state: &AppState,
    context: &VaultContext,
    name: &str,
) -> Result<VaultDescriptor, String> {
    check_context(state, context, true).await?;
    crate::validate_session(state).await?;
    let name = validated_name(name)?;
    let mut catalog_guard = state.vault_catalog.lock().await;
    let catalog = catalog_guard.as_mut().ok_or("Coffres non initialisés")?;
    let mut next = catalog.data.clone();
    let descriptor = next
        .vaults
        .iter_mut()
        .find(|v| v.id == context.vault_id)
        .ok_or("Coffre introuvable")?;
    descriptor.name = name;
    let descriptor = descriptor.clone();
    catalog.save(&next)?;
    catalog.data = next;
    if let Some(vault) = state.selected_vault.lock().await.as_mut() {
        vault.descriptor = descriptor.clone();
    }
    Ok(descriptor)
}

#[cfg(test)]
pub(crate) mod tests;

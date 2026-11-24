//! Built-in Native Messaging stdio relay and automatic manifest installer/updater.
//!
//! Security model:
//! - When launched by Chrome/Brave/Edge with `chrome-extension://<32-char-id>/`,
//!   the process acts strictly as a length-prefixed JSON envelope relay over stdio
//!   to the private local IPC endpoint (`channel.sock` / Named Pipe) without
//!   initializing Tauri, WebView, SQLite, or vault state.
//! - Automatic manifest registration validates executable ownership/permissions,
//!   rejects symlinks on every target directory and file, preserves valid custom
//!   `allowed_origins`, and writes atomically with `0600` permissions on Unix.

use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_RELAY_FRAME: usize = 65536;
pub const DEFAULT_EXTENSION_ID: &str = "oifhfkkohaimodaedcjbnfbamhgocndg";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NativeHostStatus {
    pub installed: bool,
    pub host_path: String,
    pub extension_id: String,
    pub allowed_origins: Vec<String>,
    pub manifests: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct NativeHostManifest {
    name: String,
    description: String,
    path: String,
    #[serde(rename = "type")]
    kind: String,
    allowed_origins: Vec<String>,
}

pub fn validate_extension_id(id: &str) -> Result<(), String> {
    if id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b)) {
        Ok(())
    } else {
        Err("L’identifiant d’extension Chromium doit contenir 32 lettres de a à p".into())
    }
}

pub fn parse_browser_origin(origin: &str) -> Option<&str> {
    let authority = origin.strip_prefix("chrome-extension://")?;
    let id = authority.strip_suffix('/').unwrap_or(authority);
    validate_extension_id(id).ok()?;
    Some(id)
}

pub fn detect_relay_invocation<I, S>(args: I) -> Option<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter();
    let _program = iter.next()?;
    let first = iter.next()?;
    let first_str = first.as_ref();
    if first_str == "--native-messaging-host" {
        let second = iter.next()?;
        return parse_browser_origin(second.as_ref()).map(str::to_owned);
    }
    parse_browser_origin(first_str).map(str::to_owned)
}

pub fn maybe_run_native_host_from_env() -> Option<i32> {
    let _extension_id = detect_relay_invocation(std::env::args())?;
    let code = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => match rt.block_on(run_stdio_relay()) {
            Ok(()) => 0,
            Err(_) => 1,
        },
        Err(_) => 1,
    };
    Some(code)
}

fn ipc_endpoint() -> io::Result<String> {
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").map_err(io::Error::other)?;
        let storage = if crate::hidden_storage::TEST_BUILD {
            "SecureVault Test"
        } else {
            "SecureVault"
        };
        let mut hash = 0xcbf29ce484222325u64;
        for b in format!("{local}/{storage}").bytes() {
            hash = (hash ^ b as u64).wrapping_mul(0x100000001b3);
        }
        Ok(format!(r"\\.\pipe\fluxlock-autofill-{hash:016x}"))
    }
    #[cfg(not(windows))]
    {
        let root = crate::hidden_storage::get_hidden_database_dir().map_err(io::Error::other)?;
        Ok(root
            .join("browser-ipc/channel.sock")
            .to_string_lossy()
            .into_owned())
    }
}

fn validate_envelope_bytes(data: &[u8]) -> io::Result<()> {
    let value: serde_json::Value = serde_json::from_slice(data).map_err(io::Error::other)?;
    let object = value
        .as_object()
        .ok_or_else(|| io::Error::other("Invalid envelope"))?;
    if object.len() != 2 || value["version"] != 2 || !value["frame"].is_string() {
        return Err(io::Error::other("Invalid envelope"));
    }
    Ok(())
}

pub fn relay_frame_sync<R: io::Read>(reader: &mut R, native: bool) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    let len = if native {
        u32::from_ne_bytes(header)
    } else {
        u32::from_be_bytes(header)
    } as usize;
    if len == 0 || len > MAX_RELAY_FRAME {
        return Err(io::Error::other("Invalid frame size"));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data)?;
    validate_envelope_bytes(&data)?;
    Ok(data)
}

pub fn relay_send_sync<W: io::Write>(writer: &mut W, data: &[u8], native: bool) -> io::Result<()> {
    let header = if native {
        (data.len() as u32).to_ne_bytes()
    } else {
        (data.len() as u32).to_be_bytes()
    };
    writer.write_all(&header)?;
    writer.write_all(data)?;
    writer.flush()
}

pub async fn relay_frame<R: AsyncRead + Unpin>(reader: &mut R, native: bool) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let len = if native {
        u32::from_ne_bytes(header)
    } else {
        u32::from_be_bytes(header)
    } as usize;
    if len == 0 || len > MAX_RELAY_FRAME {
        return Err(io::Error::other("Invalid frame size"));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    validate_envelope_bytes(&data)?;
    Ok(data)
}

pub async fn relay_send<W: AsyncWrite + Unpin>(
    writer: &mut W,
    data: &[u8],
    native: bool,
) -> io::Result<()> {
    let header = if native {
        (data.len() as u32).to_ne_bytes()
    } else {
        (data.len() as u32).to_be_bytes()
    };
    writer.write_all(&header).await?;
    writer.write_all(data).await?;
    writer.flush().await
}

async fn run_stdio_relay() -> io::Result<()> {
    let endpoint = ipc_endpoint()?;
    #[cfg(unix)]
    let stream = tokio::net::UnixStream::connect(endpoint).await?;
    #[cfg(windows)]
    let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint)?;
    let (mut read, mut write) = tokio::io::split(stream);
    let (tx, mut rx) = tokio::sync::mpsc::channel::< io::Result<Vec<u8>> >(4);
    std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        loop {
            let res = relay_frame_sync(&mut stdin, true);
            let is_err = res.is_err();
            if tx.blocking_send(res).is_err() || is_err {
                break;
            }
        }
    });
    let input = async {
        while let Some(res) = rx.recv().await {
            let data = res?;
            relay_send(&mut write, &data, false).await?;
        }
        Err::<(), io::Error>(io::Error::new(io::ErrorKind::UnexpectedEof, "stdin closed"))
    };
    let output = async {
        loop {
            let data = relay_frame(&mut read, false).await?;
            let mut stdout = io::stdout().lock();
            relay_send_sync(&mut stdout, &data, true)?;
        }
    };
    tokio::select! { r = input => r, r = output => r }
}

pub fn host_manifest_name() -> &'static str {
    if crate::hidden_storage::TEST_BUILD {
        "com.fluxlock.browser.test"
    } else {
        "com.fluxlock.browser"
    }
}

pub fn validate_executable_candidate(path: &Path) -> Result<PathBuf, String> {
    let sym = fs::symlink_metadata(path)
        .map_err(|e| format!("Binaire relais introuvable ({}): {e}", path.display()))?;
    if sym.file_type().is_symlink() || !sym.file_type().is_file() {
        return Err("Le binaire relais ne doit pas être un lien symbolique".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let uid = unsafe { libc::geteuid() };
        if sym.uid() != uid && sym.uid() != 0 {
            return Err("Propriétaire du binaire relais non approuvé".into());
        }
        let mode = sym.permissions().mode();
        if mode & 0o111 == 0 {
            return Err("Le binaire relais n’est pas exécutable".into());
        }
        if mode & 0o022 != 0 {
            return Err("Le binaire relais est modifiable par le groupe ou par d’autres utilisateurs".into());
        }
    }
    fs::canonicalize(path).map_err(|e| format!("Impossible de résoudre le chemin du relais: {e}"))
}

pub fn resolve_relay_binary_path() -> Result<PathBuf, String> {
    let current = std::env::current_exe().map_err(|e| e.to_string())?;
    let canonical_current = fs::canonicalize(&current).map_err(|e| e.to_string())?;
    if let Some(parent) = canonical_current.parent() {
        let sibling_name = if cfg!(windows) {
            "fluxlock-browser-host.exe"
        } else {
            "fluxlock-browser-host"
        };
        let sibling = parent.join(sibling_name);
        if let Ok(valid_sibling) = validate_executable_candidate(&sibling) {
            return Ok(valid_sibling);
        }
    }
    validate_executable_candidate(&canonical_current)
}

fn default_browser_manifest_dirs() -> Result<Vec<(&'static str, PathBuf)>, String> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").map_err(|e| e.to_string())?;
        let base = PathBuf::from(home).join("Library/Application Support");
        Ok(vec![
            ("chrome", base.join("Google/Chrome/NativeMessagingHosts")),
            (
                "brave",
                base.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            ),
            ("edge", base.join("Microsoft Edge/NativeMessagingHosts")),
            ("chromium", base.join("Chromium/NativeMessagingHosts")),
        ])
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let config_root = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map_err(|e| e.to_string())?;
        Ok(vec![
            (
                "chrome",
                config_root.join("google-chrome/NativeMessagingHosts"),
            ),
            (
                "brave",
                config_root.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            ),
            (
                "edge",
                config_root.join("microsoft-edge/NativeMessagingHosts"),
            ),
            ("chromium", config_root.join("chromium/NativeMessagingHosts")),
        ])
    }
    #[cfg(windows)]
    {
        let local = std::env::var("LOCALAPPDATA").map_err(|e| e.to_string())?;
        let base = PathBuf::from(local).join("FluXlock Browser Host");
        Ok(vec![
            ("chrome", base.join("chrome")),
            ("brave", base.join("brave")),
            ("edge", base.join("edge")),
        ])
    }
}

fn ensure_no_symlinks_in_ancestors(root_stop: &Path, target_dir: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in target_dir.components() {
        current.push(component);
        if !current.starts_with(root_stop) {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(&current) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Lien symbolique détecté dans le chemin du manifeste: {}",
                    current.display()
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let uid = unsafe { libc::geteuid() };
                if meta.uid() != uid {
                    return Err(format!(
                        "Propriétaire invalide pour le dossier {}",
                        current.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

fn collect_allowed_origins(
    existing_path: &Path,
    extra_extension_id: Option<&str>,
) -> Result<Vec<String>, String> {
    let mut origins = vec![format!("chrome-extension://{DEFAULT_EXTENSION_ID}/")];
    if let Some(extra) = extra_extension_id {
        let trimmed = extra.trim();
        if !trimmed.is_empty() {
            validate_extension_id(trimmed)?;
            let formatted = format!("chrome-extension://{trimmed}/");
            if !origins.contains(&formatted) {
                origins.push(formatted);
            }
        }
    }
    if let Ok(meta) = fs::symlink_metadata(existing_path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Le manifeste existant est un lien symbolique: {}",
                existing_path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { libc::geteuid() } {
                return Err("Propriétaire du manifeste existant invalide".into());
            }
        }
        if let Ok(raw) = fs::read_to_string(existing_path) {
            if let Ok(parsed) = serde_json::from_str::<NativeHostManifest>(&raw) {
                for origin in parsed.allowed_origins {
                    if let Some(id) = parse_browser_origin(&origin) {
                        let canonical = format!("chrome-extension://{id}/");
                        if !origins.contains(&canonical) && origins.len() < 8 {
                            origins.push(canonical);
                        }
                    }
                }
            }
        }
    }
    Ok(origins)
}

fn write_manifest_atomically(destination: &Path, content: &str) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or("Dossier parent du manifeste introuvable")?;
    if let Ok(meta) = fs::symlink_metadata(destination) {
        if meta.file_type().is_symlink() {
            return Err("Le manifeste existant est un lien symbolique".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.uid() != unsafe { libc::geteuid() } {
                return Err("Propriétaire du manifeste existant invalide".into());
            }
            if meta.permissions().mode() & 0o777 == 0o600 {
                if let Ok(existing) = fs::read_to_string(destination) {
                    if existing == content {
                        return Ok(());
                    }
                }
            }
        }
        #[cfg(not(unix))]
        if let Ok(existing) = fs::read_to_string(destination) {
            if existing == content {
                return Ok(());
            }
        }
    }

    let nonce = super::token();
    let temp_path = parent.join(format!(
        ".{}.tmp-{}",
        destination
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("manifest"),
        &nonce[..16]
    ));

    let write_res = (|| -> io::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&temp_path)?;
        io::Write::write_all(&mut file, content.as_bytes())?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&temp_path, destination)?;
        Ok(())
    })();

    if let Err(e) = write_res {
        let _ = fs::remove_file(&temp_path);
        return Err(format!(
            "Échec d’écriture atomique du manifeste {}: {e}",
            destination.display()
        ));
    }
    Ok(())
}

pub fn install_manifests_in_dirs(
    root_stop: &Path,
    dirs: &[(&'static str, PathBuf)],
    host_binary: &Path,
    host_name: &str,
    extra_extension_id: Option<&str>,
) -> Result<NativeHostStatus, String> {
    let valid_binary = validate_executable_candidate(host_binary)?;
    if let Some(extra) = extra_extension_id {
        if !extra.trim().is_empty() {
            validate_extension_id(extra.trim())?;
        }
    }

    let mut installed_manifests = Vec::new();
    let mut merged_origins = vec![format!("chrome-extension://{DEFAULT_EXTENSION_ID}/")];

    for (_browser, dir) in dirs {
        ensure_no_symlinks_in_ancestors(root_stop, dir)?;
        fs::create_dir_all(dir)
            .map_err(|e| format!("Création du dossier {} impossible: {e}", dir.display()))?;
        ensure_no_symlinks_in_ancestors(root_stop, dir)?;

        let destination = dir.join(format!("{host_name}.json"));
        let allowed_origins = collect_allowed_origins(&destination, extra_extension_id)?;
        for origin in &allowed_origins {
            if !merged_origins.contains(origin) {
                merged_origins.push(origin.clone());
            }
        }
        let manifest = NativeHostManifest {
            name: host_name.to_owned(),
            description: "FluXlock local encrypted browser relay".into(),
            path: valid_binary.to_string_lossy().into_owned(),
            kind: "stdio".into(),
            allowed_origins,
        };
        let serialized =
            serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())? + "\n";
        write_manifest_atomically(&destination, &serialized)?;
        #[cfg(windows)]
        register_windows_native_host(_browser, host_name, &destination)?;
        installed_manifests.push(destination.to_string_lossy().into_owned());
    }

    Ok(NativeHostStatus {
        installed: !installed_manifests.is_empty(),
        host_path: valid_binary.to_string_lossy().into_owned(),
        extension_id: DEFAULT_EXTENSION_ID.into(),
        allowed_origins: merged_origins,
        manifests: installed_manifests,
    })
}

#[cfg(windows)]
fn register_windows_native_host(
    browser: &str,
    host_name: &str,
    manifest_path: &Path,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    type Hkey = isize;
    const HKEY_CURRENT_USER: Hkey = -2147483647i32 as isize; // 0x80000001
    const KEY_WRITE: u32 = 0x20006;
    const REG_SZ: u32 = 1;
    extern "system" {
        fn RegCreateKeyExW(
            hkey: Hkey,
            lpsubkey: *const u16,
            reserved: u32,
            lpclass: *const u16,
            dwoptions: u32,
            samdesired: u32,
            lpsecurityattributes: *const core::ffi::c_void,
            phkresult: *mut Hkey,
            lpdwdisposition: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            hkey: Hkey,
            lpvaluename: *const u16,
            reserved: u32,
            dwtype: u32,
            lpdata: *const u8,
            cbdata: u32,
        ) -> i32;
        fn RegCloseKey(hkey: Hkey) -> i32;
    }

    let vendor = match browser {
        "chrome" => "Google\\Chrome",
        "brave" => "BraveSoftware\\Brave-Browser",
        "edge" => "Microsoft\\Edge",
        _ => return Ok(()),
    };
    let subkey = format!("Software\\{vendor}\\NativeMessagingHosts\\{host_name}");
    let subkey_w: Vec<u16> = std::ffi::OsStr::new(&subkey)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let value_w: Vec<u16> = manifest_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut key: Hkey = 0;
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        );
        if status != 0 {
            return Err(format!("Échec création clé registre Windows ({status})"));
        }
        let set_status = RegSetValueExW(
            key,
            std::ptr::null(),
            0,
            REG_SZ,
            value_w.as_ptr() as *const u8,
            (value_w.len() * 2) as u32,
        );
        RegCloseKey(key);
        if set_status != 0 {
            return Err(format!("Échec écriture registre Windows ({set_status})"));
        }
    }
    Ok(())
}

pub fn ensure_installed(extra_extension_id: Option<&str>) -> Result<NativeHostStatus, String> {
    let host_binary = resolve_relay_binary_path()?;
    let dirs = default_browser_manifest_dirs()?;
    let root_stop = dirs
        .first()
        .and_then(|(_, p)| p.ancestors().nth(3))
        .unwrap_or_else(|| Path::new("/"));
    install_manifests_in_dirs(
        root_stop,
        &dirs,
        &host_binary,
        host_manifest_name(),
        extra_extension_id,
    )
}

pub fn current_status() -> NativeHostStatus {
    let host_name = host_manifest_name();
    let expected_binary = resolve_relay_binary_path().ok();
    let dirs = default_browser_manifest_dirs().unwrap_or_default();
    let mut manifests = Vec::new();
    let mut allowed_origins = vec![format!("chrome-extension://{DEFAULT_EXTENSION_ID}/")];
    let mut all_up_to_date = !dirs.is_empty() && expected_binary.is_some();

    for (_browser, dir) in &dirs {
        let path = dir.join(format!("{host_name}.json"));
        let Ok(meta) = fs::symlink_metadata(&path) else {
            all_up_to_date = false;
            continue;
        };
        if meta.file_type().is_symlink() {
            all_up_to_date = false;
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            all_up_to_date = false;
            continue;
        };
        let Ok(parsed) = serde_json::from_str::<NativeHostManifest>(&raw) else {
            all_up_to_date = false;
            continue;
        };
        if let Some(ref bin) = expected_binary {
            if Path::new(&parsed.path) != bin.as_path() {
                all_up_to_date = false;
            }
        }
        for origin in parsed.allowed_origins {
            if !allowed_origins.contains(&origin) {
                allowed_origins.push(origin);
            }
        }
        manifests.push(path.to_string_lossy().into_owned());
    }

    NativeHostStatus {
        installed: all_up_to_date && !manifests.is_empty(),
        host_path: expected_binary
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        extension_id: DEFAULT_EXTENSION_ID.into(),
        allowed_origins,
        manifests,
    }
}

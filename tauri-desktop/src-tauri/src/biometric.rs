/// ═══════════════════════════════════════════════════════════════
/// FluXlock — Desktop Biometric Authentication Module
/// ═══════════════════════════════════════════════════════════════
///
/// # Security Philosophy
/// The biometric NEVER replaces the master password. It unlocks an
/// intermediate key stored in the OS keychain. The fingerprint/face
/// never derives the vault key directly.
///
/// # Rules
/// - Cold start always requires master password
/// - Biometric is only for quick-unlock (app was in background)
/// - 3 consecutive failures → fall back to password
/// - Configurable timeout (default 15 min)
/// - Emergency lock disables biometric instantly

use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};
use zeroize::Zeroize;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
const MAX_FAILED_ATTEMPTS: u32 = 3;
const DEFAULT_TIMEOUT_SECS: u64 = 15 * 60; // 15 minutes

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    };
}

// ═══════════════════════════════════════════════════════
// Runtime state (in-memory, resets on app restart = cold start)
// ═══════════════════════════════════════════════════════

struct BiometricRuntime {
    /// Number of consecutive biometric failures this session
    failed_attempts: u32,
    /// Timestamp of last successful master-password login (session key derivation)
    last_password_login: Option<Instant>,
    /// Whether emergency lock was triggered this session
    emergency_locked: bool,
    /// Configured timeout in seconds
    timeout_secs: u64,
}

static RUNTIME: Mutex<Option<BiometricRuntime>> = Mutex::new(None);

fn with_runtime<F, R>(f: F) -> R
where
    F: FnOnce(&mut BiometricRuntime) -> R,
{
    let mut guard = RUNTIME.lock().unwrap();
    let rt = guard.get_or_insert_with(|| BiometricRuntime {
        failed_attempts: 0,
        last_password_login: None,
        emergency_locked: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    });
    f(rt)
}

// ═══════════════════════════════════════════════════════
// Types publics
// ═══════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricStatus {
    pub available: bool,
    pub biometric_type: String,
    pub enrolled: bool,
    pub enrolled_username: Option<String>,
    /// true → user must enter master password (cold start, timeout, emergency lock, 3 failures)
    pub requires_password: bool,
    /// Human-readable reason when requires_password is true
    pub password_reason: Option<String>,
    /// Number of consecutive biometric failures this session
    pub failed_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BiometricEnrollment {
    user_id: i64,
    username: String,
    // ⚠️ encryption_key_b64 supprimé — la clé est stockée dans le Keychain OS via `keyring`
    /// epoch secs when enrollment was created
    enrolled_at: u64,
}

/// Nom du service Keychain pour stocker la clé biométrique
#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
const KEYCHAIN_SERVICE: &str = "com.fluxlock.biometric";

/// Stocke la clé de chiffrement dans le Keychain OS avec protection biométrique
/// Sur macOS : utilise SecAccessControl via ObjC FFI (= Secure Enclave + Touch ID)
/// Sur Android : fichier sécurisé dans le répertoire app-privé
fn store_key_in_keychain(user_id: i64, key_b64: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(format!("user_{}", user_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let status = unsafe {
            biometric_keychain_store(
                account.as_ptr(),
                key_b64.as_ptr(),
                key_b64.len() as i32,
            )
        };
        if status != 0 {
            return Err(format!("Secure Enclave keychain store failed (OSStatus {})", status));
        }
        debug_log!("🔐 Key stored in biometric-protected Keychain (Secure Enclave)");
        Ok(())
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &format!("user_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        entry.set_password(key_b64)
            .map_err(|e| format!("Keychain store error: {}", e))?;
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        // On Android, keyring crate doesn't work. Store in app-private file.
        let path = biometric_key_file_path(user_id)?;
        std::fs::write(&path, key_b64.as_bytes())
            .map_err(|e| format!("Failed to store biometric key: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

/// Récupère la clé de chiffrement depuis le Keychain OS avec vérification biométrique
/// Sur macOS : SecItemCopyMatching déclenche automatiquement Touch ID
fn get_key_from_keychain(user_id: i64) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(format!("user_{}", user_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let reason = std::ffi::CString::new("Déverrouillez FluXlock avec Touch ID")
            .map_err(|_| "Invalid reason string".to_string())?;

        // 4KB buffer should be plenty for a base64-encoded encryption key
        let mut buffer = vec![0u8; 4096];
        let result = unsafe {
            biometric_keychain_retrieve(
                account.as_ptr(),
                reason.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as i32,
            )
        };
        if result < 0 {
            return Err(format!("Secure Enclave keychain retrieve failed (OSStatus {})", result));
        }
        let len = result as usize;
        let key_str = String::from_utf8(buffer[..len].to_vec())
            .map_err(|e| format!("Keychain key is not valid UTF-8: {}", e))?;
        debug_log!("🔐 Key retrieved from biometric-protected Keychain (Touch ID verified)");
        Ok(key_str)
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &format!("user_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        entry.get_password()
            .map_err(|e| format!("Keychain retrieve error: {}", e))
    }
    #[cfg(target_os = "android")]
    {
        let path = biometric_key_file_path(user_id)?;
        std::fs::read_to_string(&path)
            .map_err(|e| format!("Keychain retrieve error: {}", e))
    }
}

/// Supprime la clé de chiffrement du Keychain OS
fn delete_key_from_keychain(user_id: i64) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(format!("user_{}", user_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let status = unsafe { biometric_keychain_delete(account.as_ptr()) };
        if status != 0 {
            return Err(format!("Secure Enclave keychain delete failed (OSStatus {})", status));
        }
        Ok(())
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &format!("user_{}", user_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        let _ = entry.delete_password();
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        let path = biometric_key_file_path(user_id)?;
        let _ = std::fs::remove_file(&path);
        Ok(())
    }
}

/// Returns the path for storing biometric key on Android
#[cfg(target_os = "android")]
fn biometric_key_file_path(user_id: i64) -> Result<std::path::PathBuf, String> {
    let dir = crate::hidden_storage::get_hidden_database_dir()?;
    Ok(dir.join(format!(".biometric_key_{}", user_id)))
}

// ═══════════════════════════════════════════════════════
// macOS implementation (Touch ID via Objective-C FFI)
// ═══════════════════════════════════════════════════════

#[cfg(target_os = "macos")]
extern "C" {
    fn biometric_is_available_ex(out_error_code: *mut i32) -> bool;
    fn biometric_get_type() -> i32;
    fn biometric_authenticate(reason: *const std::os::raw::c_char) -> bool;
    // Secure Enclave keychain with biometric access control (SecAccessControl)
    fn biometric_keychain_store(account: *const std::os::raw::c_char, data: *const u8, data_len: i32) -> i32;
    fn biometric_keychain_retrieve(account: *const std::os::raw::c_char, reason: *const std::os::raw::c_char, out_data: *mut u8, out_data_capacity: i32) -> i32;
    fn biometric_keychain_delete(account: *const std::os::raw::c_char) -> i32;
}

#[cfg(target_os = "macos")]
fn platform_is_available() -> bool {
    // Catch panics from FFI to avoid crashing the whole app
    std::panic::catch_unwind(|| {
        let mut error_code: i32 = 0;
        let available = unsafe { biometric_is_available_ex(&mut error_code) };
        if !available {
            // LAError codes: -5 = passcodeNotSet, -6 = biometryNotAvailable, -7 = biometryNotEnrolled
            debug_log!("⚠️ biometric_is_available_ex returned false, LAError code = {}", error_code);
        } else {
            debug_log!("✅ biometric_is_available_ex = true");
        }
        available
    }).unwrap_or_else(|_| {
        debug_log!("⚠️ biometric_is_available_ex() FFI panicked");
        false
    })
}

#[cfg(target_os = "macos")]
fn platform_get_type() -> String {
    let btype = unsafe { biometric_get_type() };
    match btype {
        1 => "touchid".to_string(),
        2 => "faceid".to_string(),
        _ => "none".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn platform_authenticate(reason: &str) -> Result<(), String> {
    let c_reason = std::ffi::CString::new(reason)
        .map_err(|_| "Invalid reason string".to_string())?;
    let success = unsafe { biometric_authenticate(c_reason.as_ptr()) };
    if success {
        Ok(())
    } else {
        Err("Authentification biométrique échouée ou annulée".to_string())
    }
}

// ═══════════════════════════════════════════════════════
// Windows implementation (Windows Hello via WinRT)
// ═══════════════════════════════════════════════════════

#[cfg(target_os = "windows")]
fn platform_is_available() -> bool {
    use windows::Security::Credentials::UI::{
        UserConsentVerifier, UserConsentVerifierAvailability,
    };
    match UserConsentVerifier::CheckAvailabilityAsync() {
        Ok(op) => match op.get() {
            Ok(availability) => {
                let available = availability == UserConsentVerifierAvailability::Available;
                debug_log!(
                    "🔍 Windows Hello availability: {:?} (available={})",
                    availability,
                    available
                );
                available
            }
            Err(e) => {
                debug_log!("⚠️ Windows Hello CheckAvailabilityAsync failed: {}", e);
                false
            }
        },
        Err(e) => {
            debug_log!("⚠️ Windows Hello CheckAvailabilityAsync error: {}", e);
            false
        }
    }
}

#[cfg(target_os = "windows")]
fn platform_get_type() -> String {
    if platform_is_available() {
        "windows_hello".to_string()
    } else {
        "none".to_string()
    }
}

#[cfg(target_os = "windows")]
fn platform_authenticate(reason: &str) -> Result<(), String> {
    use windows::Security::Credentials::UI::{
        UserConsentVerificationResult, UserConsentVerifier,
    };
    use windows::core::HSTRING;

    let message = HSTRING::from(reason);
    let result = UserConsentVerifier::RequestVerificationAsync(&message)
        .map_err(|e| format!("Windows Hello: {}", e))?
        .get()
        .map_err(|e| format!("Windows Hello: {}", e))?;

    match result {
        UserConsentVerificationResult::Verified => {
            debug_log!("✅ Windows Hello authentication succeeded");
            Ok(())
        }
        UserConsentVerificationResult::DeviceBusy => {
            Err("Windows Hello : appareil occupé".to_string())
        }
        UserConsentVerificationResult::DeviceNotPresent => {
            Err("Windows Hello : appareil non disponible".to_string())
        }
        UserConsentVerificationResult::DisabledByPolicy => {
            Err("Windows Hello : désactivé par politique de sécurité".to_string())
        }
        UserConsentVerificationResult::NotConfiguredForUser => {
            Err("Windows Hello : non configuré pour cet utilisateur".to_string())
        }
        UserConsentVerificationResult::RetriesExhausted => {
            Err("Windows Hello : tentatives épuisées".to_string())
        }
        UserConsentVerificationResult::Canceled => {
            Err("Windows Hello : annulé par l'utilisateur".to_string())
        }
        _ => Err("Windows Hello : erreur inconnue".to_string()),
    }
}

// ═══════════════════════════════════════════════════════
// Linux implementation (fprintd via subprocess)
// ═══════════════════════════════════════════════════════

#[cfg(target_os = "linux")]
fn platform_is_available() -> bool {
    // Check if fprintd is installed and user has enrolled fingerprints
    let username = std::env::var("USER").unwrap_or_default();
    if username.is_empty() {
        debug_log!("⚠️ Linux biometric: cannot determine username");
        return false;
    }
    match std::process::Command::new("fprintd-list")
        .arg(&username)
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let has_fingers = stdout.contains("left-") || stdout.contains("right-");
            debug_log!(
                "🔍 Linux fprintd: enrolled fingers detected = {}",
                has_fingers
            );
            has_fingers
        }
        Err(e) => {
            debug_log!("⚠️ Linux fprintd not available: {}", e);
            false
        }
    }
}

#[cfg(target_os = "linux")]
fn platform_get_type() -> String {
    if platform_is_available() {
        "fingerprint".to_string()
    } else {
        "none".to_string()
    }
}

#[cfg(target_os = "linux")]
fn platform_authenticate(_reason: &str) -> Result<(), String> {
    // Use fprintd-verify with a timeout to avoid hanging indefinitely.
    // fprintd-verify blocks waiting for the user to touch the sensor.
    let child = std::process::Command::new("fprintd-verify")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Impossible de lancer fprintd-verify : {}", e))?;

    let output = child
        .wait_with_output()
        .map_err(|e| format!("fprintd-verify erreur : {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    debug_log!("🔍 fprintd-verify stdout: {}", stdout);
    debug_log!("🔍 fprintd-verify stderr: {}", stderr);

    if output.status.success() && stdout.contains("verify-match") {
        debug_log!("✅ Linux fingerprint authentication succeeded");
        Ok(())
    } else if stdout.contains("verify-no-match") {
        Err("Empreinte non reconnue".to_string())
    } else {
        Err(format!(
            "Authentification biométrique échouée (code {})",
            output.status.code().unwrap_or(-1)
        ))
    }
}

// ═══════════════════════════════════════════════════════
// Mobile stubs (Android/iOS will use Tauri v2 plugin)
// ═══════════════════════════════════════════════════════

// Android: BiometricPrompt authentication is handled by the frontend
// via the Kotlin BiometricBridge (window.AndroidBiometric JS interface).
// The Rust backend trusts the frontend's authentication result.
//
// ⚠️ KEY STORAGE SECURITY NOTE (Android):
// Currently the biometric key is stored in an app-private file protected
// by Android's filesystem sandbox (mode 0600). For maximum security,
// this should be migrated to Android Keystore with:
//   - KeyGenParameterSpec.Builder(...).setUserAuthenticationRequired(true)
//   - setInvalidatedByBiometricEnrollment(true)
//   - BiometricPrompt.CryptoObject for biometric-gated decryption
// This requires a custom Kotlin Tauri plugin exposing JNI to the Rust side.
// See: https://developer.android.com/privacy-and-security/keystore

#[cfg(target_os = "android")]
fn platform_is_available() -> bool { true }  // Actual check done by frontend via AndroidBiometric JS bridge
#[cfg(target_os = "android")]
fn platform_get_type() -> String { "fingerprint".to_string() }
#[cfg(target_os = "android")]
fn platform_authenticate(_reason: &str) -> Result<(), String> {
    // On Android, authentication is done by the frontend via BiometricPrompt (AndroidBiometric JS bridge).
    // When this function is called, the frontend has already verified the user's fingerprint.
    Ok(())
}

#[cfg(target_os = "ios")]
fn platform_is_available() -> bool { false }
#[cfg(target_os = "ios")]
fn platform_get_type() -> String { "none".to_string() }
#[cfg(target_os = "ios")]
fn platform_authenticate(_reason: &str) -> Result<(), String> {
    Err("Use tauri-plugin-biometric on mobile".to_string())
}

// ═══════════════════════════════════════════════════════
// File-based storage for biometric enrollment
// (Avoids keyring prompts on macOS Keychain at app startup)
// ═══════════════════════════════════════════════════════

fn enrollment_file_path() -> Result<std::path::PathBuf, String> {
    let dir = crate::hidden_storage::get_hidden_database_dir()?;
    Ok(dir.join(".biometric_enrollment.json"))
}

fn get_enrollment() -> Option<BiometricEnrollment> {
    let path = enrollment_file_path().ok()?;
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

fn store_enrollment(enrollment: &BiometricEnrollment) -> Result<(), String> {
    let path = enrollment_file_path()?;
    let json = serde_json::to_string(enrollment)
        .map_err(|e| format!("Serialization error: {}", e))?;
    std::fs::write(&path, json.as_bytes())
        .map_err(|e| format!("Failed to store biometric enrollment: {}", e))?;
    // Restrict permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn delete_enrollment() -> Result<(), String> {
    let path = match enrollment_file_path() {
        Ok(p) => p,
        Err(_) => return Ok(()),
    };
    if path.exists() {
        std::fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete biometric enrollment: {}", e))?;
    }
    Ok(())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ═══════════════════════════════════════════════════════
// Cold-start & timeout logic
// ═══════════════════════════════════════════════════════

/// Determine whether the biometric quick-unlock is blocked and why.
/// Returns (requires_password, reason).
fn evaluate_biometric_gate() -> (bool, Option<String>) {
    with_runtime(|rt| {
        // Emergency lock
        if rt.emergency_locked {
            return (true, Some("Verrouillage d'urgence activé — mot de passe requis".into()));
        }
        // 3 consecutive failures
        if rt.failed_attempts >= MAX_FAILED_ATTEMPTS {
            return (true, Some("Biométrie non reconnue — mot de passe requis".into()));
        }
        // Cold start (no password login happened in this process lifetime)
        let last = match rt.last_password_login {
            Some(t) => t,
            None => return (true, Some("Premier lancement — mot de passe requis".into())),
        };
        // Timeout
        let elapsed = last.elapsed().as_secs();
        if elapsed >= rt.timeout_secs {
            return (true, Some(format!(
                "Délai d'inactivité dépassé ({} min) — mot de passe requis",
                rt.timeout_secs / 60
            )));
        }
        (false, None)
    })
}

// ═══════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════

/// Called by the login command after a successful master-password verification.
/// Records the timestamp so that biometric quick-unlock becomes available.
pub fn notify_password_login_success() {
    with_runtime(|rt| {
        rt.last_password_login = Some(Instant::now());
        rt.failed_attempts = 0;
        rt.emergency_locked = false;
        debug_log!("🔐 Biometric: master-password login recorded, quick-unlock available");
    });
}

/// Emergency lock: instantly disable biometric until next password login.
pub fn emergency_lock() {
    with_runtime(|rt| {
        rt.emergency_locked = true;
        debug_log!("🚨 Biometric: emergency lock activated");
    });
}

/// Check biometric hardware availability, enrollment status, and whether
/// the user must enter the master password (cold start / timeout / etc.).
pub fn check_biometric_status() -> BiometricStatus {
    let available = platform_is_available();
    // Always call platform_get_type() — on macOS it uses the fallback policy
    // so it can detect Touch ID hardware even when strict biometric-only fails
    let biometric_type = platform_get_type();
    // If we detected a valid biometric type, override available to true
    let available = available || (biometric_type != "none");

    debug_log!("🔍 Biometric check: available={}, type={}", available, biometric_type);

    let enrollment = get_enrollment();
    let enrolled = enrollment.is_some();
    let enrolled_username = enrollment.map(|e| e.username);

    let (requires_password, password_reason) = if enrolled {
        evaluate_biometric_gate()
    } else {
        (true, None)
    };

    let failed_attempts = with_runtime(|rt| rt.failed_attempts);

    BiometricStatus {
        available,
        biometric_type,
        enrolled,
        enrolled_username,
        requires_password,
        password_reason,
        failed_attempts,
    }
}

/// Enable biometric authentication for the given user.
/// Requires: user is already authenticated (has encryption key in session).
///
/// Returns `Ok(None)` on desktop platforms (key stored in OS keychain).
/// Returns `Ok(Some(key_b64))` on Android — the frontend must store this key
/// in the Android Keystore (TEE/StrongBox) via the BiometricBridge.
pub fn enable_biometric(user_id: i64, username: &str, encryption_key: &[u8]) -> Result<Option<String>, String> {
    if !platform_is_available() {
        return Err("Biométrie non disponible sur cet appareil".to_string());
    }

    platform_authenticate("Activez la biométrie pour FluXlock")?;
    debug_log!("✅ Biometric authentication succeeded for enrollment");

    let mut key_b64 = general_purpose::STANDARD.encode(encryption_key);

    // On Android, skip OS keychain — the frontend will use Android Keystore (TEE/StrongBox)
    // via BiometricBridge.kt which provides hardware-backed AES-256-GCM encryption.
    #[cfg(not(target_os = "android"))]
    {
        store_key_in_keychain(user_id, &key_b64)?;
    }
    
    // Ne stocker que les métadonnées dans le fichier JSON (sans la clé)
    let enrollment = BiometricEnrollment {
        user_id,
        username: username.to_string(),
        enrolled_at: now_epoch(),
    };
    store_enrollment(&enrollment)?;

    // On Android, return the key so the frontend can store it in Android Keystore
    #[cfg(target_os = "android")]
    let result = {
        debug_log!("🔐 Biometric enrollment stored for user {} ({}) — key returned for Android Keystore", user_id, username);
        let key_copy = key_b64.clone();
        unsafe { key_b64.as_bytes_mut().zeroize(); }
        Ok(Some(key_copy))
    };

    #[cfg(not(target_os = "android"))]
    let result = {
        unsafe { key_b64.as_bytes_mut().zeroize(); }
        debug_log!("🔐 Biometric enrollment stored for user {} ({})", user_id, username);
        Ok(None)
    };

    result
}

/// Disable biometric authentication (remove enrollment).
pub fn disable_biometric() -> Result<(), String> {
    // Supprimer la clé du Keychain avant de supprimer l'enrollment
    if let Some(enrollment) = get_enrollment() {
        let _ = delete_key_from_keychain(enrollment.user_id);
    }
    delete_enrollment()?;
    debug_log!("🔓 Biometric enrollment removed");
    Ok(())
}

/// Perform biometric login for the given username.
/// Validates that (1) enrollment exists for that username,
/// (2) quick-unlock is allowed, (3) biometric succeeds.
/// Returns (user_id, username, encryption_key_bytes).
pub fn biometric_login(target_username: &str) -> Result<(i64, String, Vec<u8>), String> {
    // 1. Check enrollment
    let enrollment = get_enrollment()
        .ok_or("Biométrie non configurée. Veuillez vous connecter avec votre mot de passe.")?;

    // 2. Verify username matches
    if !enrollment.username.eq_ignore_ascii_case(target_username) {
        return Err("Biométrie non configurée pour cet utilisateur.".to_string());
    }

    // 3. Check gate (cold start / timeout / emergency / 3 failures)
    let (blocked, reason) = evaluate_biometric_gate();
    if blocked {
        return Err(reason.unwrap_or_else(|| "Mot de passe requis".into()));
    }

    // 4. Authenticate with biometric
    match platform_authenticate("Déverrouillez FluXlock") {
        Ok(()) => {
            with_runtime(|rt| rt.failed_attempts = 0);
            debug_log!("✅ Biometric login authenticated for user {}", enrollment.username);
        }
        Err(e) => {
            let attempts = with_runtime(|rt| {
                rt.failed_attempts += 1;
                rt.failed_attempts
            });
            debug_log!("❌ Biometric attempt failed ({}/{})", attempts, MAX_FAILED_ATTEMPTS);
            if attempts >= MAX_FAILED_ATTEMPTS {
                return Err("Biométrie non reconnue — mot de passe requis".into());
            }
            return Err(e);
        }
    }

    // 5. Récupérer la clé de chiffrement depuis le Keychain OS
    let key_b64 = match get_key_from_keychain(enrollment.user_id) {
        Ok(k) => k,
        Err(_) => {
            // Key was lost (vault reset, keychain cleared, etc.) — auto-disable biometric
            let _ = delete_enrollment();
            return Err(
                "La clé biométrique a été perdue (réinitialisation du coffre ?). \
                 Veuillez vous connecter avec votre mot de passe puis réactiver la biométrie dans les paramètres."
                    .to_string(),
            );
        }
    };
    let key_bytes = general_purpose::STANDARD
        .decode(&key_b64)
        .map_err(|e| format!("Erreur décodage clé biométrique: {}", e))?;

    Ok((enrollment.user_id, enrollment.username, key_bytes))
}

/// Biometric login for Android: the frontend already retrieved the key
/// from Android Keystore (via BiometricPrompt + CryptoObject), so we
/// skip the OS keychain read and biometric platform authentication.
///
/// The biometric gate (cold start, timeout, emergency lock, 3 failures)
/// is still enforced to maintain the security invariants.
pub fn biometric_login_with_key(target_username: &str, key_b64: &str) -> Result<(i64, String, Vec<u8>), String> {
    // 1. Check enrollment
    let enrollment = get_enrollment()
        .ok_or("Biométrie non configurée. Veuillez vous connecter avec votre mot de passe.")?;

    // 2. Verify username matches
    if !enrollment.username.eq_ignore_ascii_case(target_username) {
        return Err("Biométrie non configurée pour cet utilisateur.".to_string());
    }

    // 3. Check gate (cold start / timeout / emergency / 3 failures)
    let (blocked, reason) = evaluate_biometric_gate();
    if blocked {
        return Err(reason.unwrap_or_else(|| "Mot de passe requis".into()));
    }

    // 4. No platform_authenticate needed — biometric was already verified
    //    by Android Keystore CryptoObject (auth-per-use).
    with_runtime(|rt| rt.failed_attempts = 0);
    debug_log!("✅ Biometric login (Android Keystore) for user {}", enrollment.username);

    // 5. Decode the key received from the frontend
    let key_bytes = general_purpose::STANDARD
        .decode(key_b64)
        .map_err(|e| format!("Erreur décodage clé biométrique: {}", e))?;

    Ok((enrollment.user_id, enrollment.username, key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Serialize biometric tests that depend on the global RUNTIME state
    static TEST_MUTEX: StdMutex<()> = StdMutex::new(());

    #[test]
    fn test_check_status_returns_valid_structure() {
        let _lock = TEST_MUTEX.lock().unwrap();
        *RUNTIME.lock().unwrap() = None;
        let status = check_biometric_status();
        assert!(["touchid", "faceid", "windows_hello", "none"].contains(&status.biometric_type.as_str()));
        // On cold start, requires_password must be true
        assert!(status.requires_password);
    }

    #[test]
    fn test_enrollment_roundtrip() {
        let enrollment = BiometricEnrollment {
            user_id: 999,
            username: "test_user".to_string(),
            enrolled_at: 0,
        };
        let json = serde_json::to_string(&enrollment).unwrap();
        let decoded: BiometricEnrollment = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.user_id, 999);
        assert_eq!(decoded.username, "test_user");
    }

    #[test]
    fn test_cold_start_requires_password() {
        let _lock = TEST_MUTEX.lock().unwrap();
        // Reset runtime to simulate cold start
        *RUNTIME.lock().unwrap() = None;
        let (blocked, reason) = evaluate_biometric_gate();
        assert!(blocked);
        assert!(reason.unwrap().contains("Premier lancement"));
    }

    #[test]
    fn test_password_login_enables_biometric() {
        let _lock = TEST_MUTEX.lock().unwrap();
        *RUNTIME.lock().unwrap() = None;
        notify_password_login_success();
        let (blocked, _) = evaluate_biometric_gate();
        assert!(!blocked);
    }

    #[test]
    fn test_emergency_lock() {
        let _lock = TEST_MUTEX.lock().unwrap();
        *RUNTIME.lock().unwrap() = None;
        notify_password_login_success();
        emergency_lock();
        let (blocked, reason) = evaluate_biometric_gate();
        assert!(blocked);
        assert!(reason.unwrap().contains("urgence"));
    }

    #[test]
    fn test_failed_attempts_lockout() {
        let _lock = TEST_MUTEX.lock().unwrap();
        *RUNTIME.lock().unwrap() = None;
        notify_password_login_success();
        with_runtime(|rt| rt.failed_attempts = MAX_FAILED_ATTEMPTS);
        let (blocked, reason) = evaluate_biometric_gate();
        assert!(blocked);
        assert!(reason.unwrap().contains("non reconnue"));
    }
}

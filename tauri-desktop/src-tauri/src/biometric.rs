//! Unlocks a previously enrolled vault with the device's biometric authenticator.
//! A successful master-password check is required for enrollment.

use serde::{Serialize, Deserialize};
use base64::{Engine as _, engine::general_purpose};
use std::path::Path;
use std::sync::Mutex;
use zeroize::Zeroizing;
#[cfg(not(any(target_os = "macos", target_os = "android")))]
use std::time::Instant;

#[cfg(target_os = "macos")]
mod macos_compatibility;

const MAX_FAILED_ATTEMPTS: u32 = 3;
const NATIVE_KEYCHAIN_FORMAT: u8 = 1;
#[cfg(target_os = "macos")]
const COMPATIBILITY_KEYCHAIN_FORMAT: u8 = 2;

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    };
}

#[derive(Default)]
struct BiometricRuntime {
    failed_attempts: u32,
    #[cfg(not(any(target_os = "macos", target_os = "android")))]
    last_password_login: Option<Instant>,
}

static RUNTIME: once_cell::sync::Lazy<Mutex<std::collections::HashMap<std::path::PathBuf, BiometricRuntime>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(std::collections::HashMap::new()));

fn with_runtime<F, R>(dir: &Path, f: F) -> R
where F: FnOnce(&mut BiometricRuntime) -> R,
{
    let mut runtimes = RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    let runtime = runtimes.entry(dir.to_owned()).or_insert_with(|| BiometricRuntime {
        failed_attempts: 0,
        #[cfg(not(any(target_os = "macos", target_os = "android")))]
        last_password_login: None,
    });
    f(runtime)
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
    /// The authenticator is enrolled but the vault requires password verification.
    pub requires_password: bool,
    /// Human-readable reason when requires_password is true
    pub password_reason: Option<String>,
    pub unavailable_reason: Option<String>,
    pub compatibility_available: bool,
    pub compatibility_enrolled: bool,
    /// Number of consecutive biometric failures this session
    pub failed_attempts: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BiometricEnrollment {
    user_id: i64,
    username: String,
    /// Unique native credential per enrollment; old vaults retain their legacy account.
    #[serde(default)]
    credential_id: Option<uuid::Uuid>,
    /// Version of the native Keychain enrollment on macOS.
    #[serde(default)]
    keychain_format: u8,
    #[cfg(target_os = "macos")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compatibility_id: Option<uuid::Uuid>,
    #[serde(default)]
    restriction: Option<PasswordRestriction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum PasswordRestriction {
    Emergency,
    TooManyAttempts,
}

impl PasswordRestriction {
    fn message(self) -> &'static str {
        match self {
            Self::Emergency => "Verrouillage d’urgence. Saisissez votre mot de passe maître.",
            Self::TooManyAttempts => "Trop de tentatives biométriques. Saisissez votre mot de passe maître.",
        }
    }
}

/// Nom du service Keychain pour stocker la clé biométrique
#[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
const KEYCHAIN_SERVICE: &str = "com.fluxlock.biometric";

#[cfg(not(target_os = "android"))]
fn keychain_account(user_id: i64, test_build: bool) -> String {
    let prefix = if test_build { "test_user_" } else { "user_" };
    format!("{prefix}{user_id}")
}

#[cfg(all(test, not(target_os = "android")))]
#[test]
fn test_build_uses_separate_keychain_accounts() {
    assert_eq!(keychain_account(1, true), "test_user_1");
    assert_eq!(keychain_account(1, false), "user_1");
}

#[cfg(not(target_os = "android"))]
fn credential_account(user_id: i64, credential_id: Option<uuid::Uuid>) -> String {
    let legacy = keychain_account(user_id, crate::hidden_storage::TEST_BUILD);
    match credential_id { Some(id) => format!("{legacy}/vault/{id}"), None => legacy }
}

/// Stores the enrolled key in the platform credential store.
#[cfg(not(target_os = "android"))]
fn store_key_in_keychain(user_id: i64, credential_id: Option<uuid::Uuid>, key_b64: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(credential_account(user_id, credential_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let status = unsafe {
            biometric_keychain_store(
                account.as_ptr(),
                key_b64.as_ptr(),
                key_b64.len() as i32,
            )
        };
        if status != 0 {
            return Err(keychain_error(status));
        }
        debug_log!("Biometric key stored in the Data Protection Keychain");
        Ok(())
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &credential_account(user_id, credential_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        entry.set_password(key_b64)
            .map_err(|e| format!("Keychain store error: {}", e))?;
        Ok(())
    }

}

/// Récupère la clé de chiffrement depuis le Keychain OS avec vérification biométrique
/// Sur macOS : SecItemCopyMatching déclenche automatiquement Touch ID
#[cfg(not(target_os = "android"))]
fn get_key_from_keychain(user_id: i64, credential_id: Option<uuid::Uuid>) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(credential_account(user_id, credential_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let reason = std::ffi::CString::new("Déverrouillez FluXlock avec Touch ID")
            .map_err(|_| "Invalid reason string".to_string())?;

        // A base64-encoded 32-byte vault key occupies 44 bytes including padding.
        let mut buffer = Zeroizing::new(vec![0u8; 44]);
        let result = unsafe {
            biometric_keychain_retrieve(
                account.as_ptr(),
                reason.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as i32,
            )
        };
        if result < 0 {
            return Err(keychain_error(result));
        }
        let len = result as usize;
        let key_str = std::str::from_utf8(&buffer[..len]).map(str::to_owned)
            .map_err(|e| format!("Keychain key is not valid UTF-8: {}", e))?;
        debug_log!("🔐 Key retrieved from biometric-protected Keychain (Touch ID verified)");
        Ok(key_str)
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &credential_account(user_id, credential_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        entry.get_password()
            .map_err(|e| format!("Keychain retrieve error: {}", e))
    }

}

/// Supprime la clé de chiffrement du Keychain OS
#[cfg(not(target_os = "android"))]
fn delete_key_from_keychain(user_id: i64, credential_id: Option<uuid::Uuid>) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let account = std::ffi::CString::new(credential_account(user_id, credential_id))
            .map_err(|_| "Invalid account string".to_string())?;
        let status = unsafe { biometric_keychain_delete(account.as_ptr()) };
        if status != 0 && status != -25300 { // errSecItemNotFound is already deleted.
            return Err(format!("Secure Enclave keychain delete failed (OSStatus {})", status));
        }
        Ok(())
    }
    #[cfg(all(not(target_os = "macos"), not(target_os = "android")))]
    {
        let entry = keyring::Entry::new(KEYCHAIN_SERVICE, &credential_account(user_id, credential_id))
            .map_err(|e| format!("Keychain entry error: {}", e))?;
        match entry.delete_password() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(format!("Keychain delete error: {error}")),
        }
    }

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
    fn biometric_keychain_has_identity() -> bool;
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
#[cfg(target_os = "android")]
fn platform_is_available() -> bool { true }  // Verified by the Android Keystore bridge.
#[cfg(target_os = "android")]
fn platform_get_type() -> String { "fingerprint".to_string() }

#[cfg(target_os = "ios")]
fn platform_is_available() -> bool { false }
#[cfg(target_os = "ios")]
fn platform_get_type() -> String { "none".to_string() }
#[cfg(target_os = "ios")]
fn platform_authenticate(_reason: &str) -> Result<(), String> {
    Err("Use tauri-plugin-biometric on mobile".to_string())
}

#[cfg(target_os = "macos")]
const MACOS_SIGNATURE_REQUIRED: &str =
    "Cette version de FluXlock n’a pas la signature macOS requise pour Touch ID. Utilisez votre mot de passe maître.";

#[cfg(target_os = "macos")]
fn keychain_error(status: i32) -> String {
    match status {
        -34018 => MACOS_SIGNATURE_REQUIRED.into(),
        -128 => "Authentification biométrique annulée.".into(),
        -25291 => "Secure Enclave indisponible. Utilisez votre mot de passe maître.".into(),
        -25300 | -26275 => "Clé biométrique indisponible. Déverrouillez le coffre au mot de passe, puis réactivez la biométrie dans Paramètres.".into(),
        -25293 => "Touch ID a refusé l’authentification. Utilisez votre mot de passe maître si le capteur est verrouillé.".into(),
        _ => format!("Le trousseau macOS a refusé l’opération biométrique ({status})."),
    }
}

fn enrollment_path(dir: &Path) -> std::path::PathBuf {
    dir.join(".biometric_enrollment.json")
}

fn get_enrollment(dir: &Path) -> Option<BiometricEnrollment> {
    let data = std::fs::read(enrollment_path(dir)).ok()?;
    serde_json::from_slice(&data).ok()
}

fn store_enrollment(dir: &Path, enrollment: &BiometricEnrollment) -> Result<(), String> {
    use std::io::Write;
    let mut file = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, enrollment).map_err(|e| e.to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(enrollment_path(dir)).map_err(|e| e.to_string())?;
    Ok(())
}

fn is_current_enrollment(_enrollment: &BiometricEnrollment) -> bool {
    #[cfg(target_os = "macos")]
    return match (_enrollment.keychain_format, _enrollment.compatibility_id) {
        (NATIVE_KEYCHAIN_FORMAT, None) => true,
        (COMPATIBILITY_KEYCHAIN_FORMAT, Some(id)) => !id.is_nil(),
        _ => false,
    };
    #[cfg(not(target_os = "macos"))]
    true
}

#[cfg(target_os = "macos")]
fn macos_enrollment_format(compatibility: bool, native: bool, enclave: bool) -> Result<u8, String> {
    match (compatibility, native, enclave) {
        (false, true, _) => Ok(NATIVE_KEYCHAIN_FORMAT),
        (true, false, true) => Ok(COMPATIBILITY_KEYCHAIN_FORMAT),
        (true, true, _) => Err("Cette version de FluXlock peut utiliser le trousseau de protection des données.".into()),
        (true, false, false) => Err(keychain_error(-25291)),
        (false, false, true) => Err("Activez explicitement le mode compatibilité Touch ID dans Paramètres.".into()),
        (false, false, false) => Err(MACOS_SIGNATURE_REQUIRED.into()),
    }
}

#[cfg(not(target_os = "android"))]
fn delete_enrollment_key(enrollment: &BiometricEnrollment) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    if let Some(id) = enrollment.compatibility_id {
        return macos_compatibility::delete(enrollment.user_id, id);
    }
    delete_key_from_keychain(enrollment.user_id, enrollment.credential_id)
}

#[cfg(target_os = "macos")]
fn save_compatibility_enrollment(
    dir: &Path, enrollment: &BiometricEnrollment, id: uuid::Uuid, key: &[u8],
) -> Result<(), String> {
    let previous = get_enrollment(dir);
    macos_compatibility::store(enrollment.user_id, id, key)?;
    let saved = (|| {
        if dir.file_name().and_then(|name| name.to_str()).is_none_or(|name| uuid::Uuid::parse_str(name).is_err()) {
            macos_compatibility::delete_legacy(enrollment.user_id)?;
        }
        store_enrollment(dir, enrollment)
    })();
    if saved.is_err() {
        let _ = macos_compatibility::delete(enrollment.user_id, id);
    } else if let Some(previous) = previous {
        // Retire only this directory's previous credential, after publication.
        if let Err(error) = delete_enrollment_key(&previous) {
            debug_log!("Ancien credential biométrique conservé dans le trousseau : {error}");
        }
    }
    saved
}

fn password_requirement(dir: &Path, enrollment: &BiometricEnrollment) -> Option<&'static str> {
    if let Some(restriction) = enrollment.restriction {
        return Some(restriction.message());
    }
    with_runtime(dir, |runtime| {
        if runtime.failed_attempts >= MAX_FAILED_ATTEMPTS {
            return Some(PasswordRestriction::TooManyAttempts.message());
        }
        #[cfg(not(any(target_os = "macos", target_os = "android")))]
        if runtime.last_password_login.is_none_or(|instant| instant.elapsed().as_secs() >= 15 * 60) {
            return Some("Ouvrez le coffre au mot de passe maître pour réactiver la biométrie.");
        }
        None
    })
}

/// Clear a restriction only after the wallet password has been verified.
pub fn notify_password_login_success(dir: &Path) -> Result<(), String> {
    if let Some(mut enrollment) = get_enrollment(dir) {
        if enrollment.restriction.take().is_some() {
            store_enrollment(dir, &enrollment)?;
        }
    }
    with_runtime(dir, |runtime| {
        runtime.failed_attempts = 0;
        #[cfg(not(any(target_os = "macos", target_os = "android")))]
        { runtime.last_password_login = Some(Instant::now()); }
    });
    Ok(())
}

pub fn emergency_lock(dir: &Path) -> Result<(), String> {
    let mut enrollment = get_enrollment(dir).ok_or("Biométrie non configurée.")?;
    enrollment.restriction = Some(PasswordRestriction::Emergency);
    store_enrollment(dir, &enrollment)
}

pub fn check_biometric_status(dir: &Path) -> BiometricStatus {
    let hardware_available = platform_is_available();
    let raw_enrollment = get_enrollment(dir);
    let enrollment = raw_enrollment.as_ref().filter(|enrollment| is_current_enrollment(enrollment));
    let enrolled = enrollment.is_some();
    let legacy = raw_enrollment.is_some() && !enrolled;
    let reason = enrollment.and_then(|entry| password_requirement(dir, entry)).or(legacy.then_some(
        "Ouvrez le coffre au mot de passe maître, puis réactivez Touch ID pour cette version.",
    ));

    #[cfg(target_os = "macos")]
    let (available, unavailable_reason, compatibility_available, compatibility_enrolled) = {
        let native = hardware_available && unsafe { biometric_keychain_has_identity() };
        let enclave = hardware_available && macos_compatibility::is_available();
        let compatibility_available = enclave && !native;
        let compatibility_enrolled = enrollment.is_some_and(|entry|
            entry.keychain_format == COMPATIBILITY_KEYCHAIN_FORMAT);
        let available = match enrollment {
            Some(_) if compatibility_enrolled => enclave,
            Some(_) => native,
            None => native || compatibility_available,
        };
        let unavailable_reason = if hardware_available && !available {
            Some(if compatibility_enrolled { keychain_error(-25291) }
                 else { MACOS_SIGNATURE_REQUIRED.to_owned() })
        } else {
            None
        };
        (available, unavailable_reason, compatibility_available, compatibility_enrolled)
    };
    #[cfg(not(target_os = "macos"))]
    let (available, unavailable_reason, compatibility_available, compatibility_enrolled) =
        (hardware_available, None, false, false);

    BiometricStatus {
        available,
        biometric_type: platform_get_type(),
        enrolled,
        enrolled_username: enrollment.map(|entry| entry.username.clone()),
        requires_password: reason.is_some() || !enrolled || !available,
        password_reason: reason.map(str::to_owned),
        unavailable_reason,
        compatibility_available,
        compatibility_enrolled,
        failed_attempts: with_runtime(dir, |runtime| runtime.failed_attempts),
    }
}

pub fn enable_biometric(
    dir: &Path, user_id: i64, username: &str, encryption_key: &[u8], compatibility: bool,
) -> Result<Option<String>, String> {
    if !platform_is_available() {
        return Err("Biométrie indisponible sur cet appareil. Vérifiez son état dans les réglages système.".into());
    }

    #[cfg(target_os = "macos")]
    let keychain_format = macos_enrollment_format(compatibility,
        unsafe { biometric_keychain_has_identity() }, macos_compatibility::is_available())?;
    #[cfg(not(target_os = "macos"))]
    let keychain_format = {
        if compatibility {
            return Err("Le mode compatibilité Touch ID est réservé à macOS.".into());
        }
        NATIVE_KEYCHAIN_FORMAT
    };

    #[cfg(not(target_os = "android"))]
    let previous = get_enrollment(dir);
    let enrollment = BiometricEnrollment {
        user_id,
        username: username.to_string(),
        credential_id: Some(uuid::Uuid::new_v4()),
        keychain_format,
        #[cfg(target_os = "macos")]
        compatibility_id: (keychain_format == COMPATIBILITY_KEYCHAIN_FORMAT).then(uuid::Uuid::new_v4),
        restriction: None,
    };
    #[cfg(target_os = "macos")]
    if let Some(id) = enrollment.compatibility_id {
        save_compatibility_enrollment(dir, &enrollment, id, encryption_key)?;
        with_runtime(dir, |runtime| runtime.failed_attempts = 0);
        return Ok(None);
    }

    let key_b64 = Zeroizing::new(general_purpose::STANDARD.encode(encryption_key));
    #[cfg(not(target_os = "android"))]
    {
        platform_authenticate("Activez la biométrie pour FluXlock")?;
        store_key_in_keychain(user_id, enrollment.credential_id, &key_b64)?;
    }
    if let Err(error) = store_enrollment(dir, &enrollment) {
        #[cfg(not(target_os = "android"))]
        let _ = delete_enrollment_key(&enrollment);
        return Err(error);
    }
    #[cfg(not(target_os = "android"))]
    if let Some(previous) = previous {
        if let Err(error) = delete_enrollment_key(&previous) {
            debug_log!("Ancien credential biométrique conservé dans le trousseau : {error}");
        }
    }
    with_runtime(dir, |runtime| runtime.failed_attempts = 0);

    #[cfg(target_os = "android")]
    return Ok(Some(key_b64.to_string()));
    #[cfg(not(target_os = "android"))]
    Ok(None)
}

pub fn disable_biometric(dir: &Path) -> Result<(), String> {
    #[cfg(not(target_os = "android"))]
    if let Some(enrollment) = get_enrollment(dir) {
        delete_enrollment_key(&enrollment)?;
    }
    match std::fs::remove_file(enrollment_path(dir)) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
        _ => Ok(()),
    }
}

fn authorized_enrollment(dir: &Path, target_username: &str) -> Result<BiometricEnrollment, String> {
    let enrollment = get_enrollment(dir).filter(is_current_enrollment)
        .ok_or("Activez d’abord la biométrie avec votre mot de passe maître.")?;
    if !enrollment.username.eq_ignore_ascii_case(target_username) {
        return Err("Biométrie non configurée pour ce compte.".into());
    }
    if let Some(reason) = password_requirement(dir, &enrollment) {
        return Err(reason.into());
    }
    Ok(enrollment)
}

#[cfg(not(target_os = "android"))]
pub fn biometric_login(
    dir: &Path, target_username: &str, target_user_id: i64,
) -> Result<(i64, String, Vec<u8>), String> {
    let enrollment = authorized_enrollment(dir, target_username)?;
    if enrollment.user_id != target_user_id {
        return Err("Biométrie non configurée pour ce compte.".into());
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(id) = enrollment.compatibility_id {
            let key = macos_compatibility::retrieve(enrollment.user_id, id)?;
            with_runtime(dir, |runtime| runtime.failed_attempts = 0);
            return Ok((enrollment.user_id, enrollment.username, key.to_vec()));
        }
        if !unsafe { biometric_keychain_has_identity() } {
            return Err(MACOS_SIGNATURE_REQUIRED.into());
        }
    }

    // The macOS keychain prompts once when it releases the protected item.
    #[cfg(not(target_os = "macos"))]
    if let Err(error) = platform_authenticate("Déverrouillez FluXlock") {
        let attempts = with_runtime(dir, |runtime| {
            runtime.failed_attempts += 1;
            runtime.failed_attempts
        });
        if attempts >= MAX_FAILED_ATTEMPTS {
            let mut enrollment = enrollment;
            enrollment.restriction = Some(PasswordRestriction::TooManyAttempts);
            store_enrollment(dir, &enrollment)?;
            return Err(PasswordRestriction::TooManyAttempts.message().into());
        }
        return Err(error);
    }

    let key_b64 = Zeroizing::new(get_key_from_keychain(enrollment.user_id, enrollment.credential_id)?);
    let key = general_purpose::STANDARD.decode(key_b64.as_bytes())
        .map_err(|_| "Clé biométrique invalide.".to_string())?;
    with_runtime(dir, |runtime| runtime.failed_attempts = 0);
    Ok((enrollment.user_id, enrollment.username, key))
}

#[cfg(target_os = "android")]
pub fn biometric_login_with_key(dir: &Path, target_username: &str, key_b64: &str) -> Result<(i64, String, Vec<u8>), String> {
    let enrollment = authorized_enrollment(dir, target_username)?;
    let key = general_purpose::STANDARD.decode(key_b64)
        .map_err(|_| "Clé biométrique invalide.".to_string())?;
    Ok((enrollment.user_id, enrollment.username, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment() -> BiometricEnrollment {
        BiometricEnrollment {
            user_id: 1,
            username: "fixture".into(),
            credential_id: None,
            keychain_format: NATIVE_KEYCHAIN_FORMAT,
            #[cfg(target_os = "macos")]
            compatibility_id: None,
            restriction: None,
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn native_credentials_are_unique_even_when_local_user_ids_match() {
        let a = credential_account(1, Some(uuid::Uuid::new_v4()));
        let b = credential_account(1, Some(uuid::Uuid::new_v4()));
        assert_ne!(a, b);
        assert_ne!(a, credential_account(1, None));
    }

    #[test]
    fn biometric_retry_state_is_scoped_to_the_vault() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        with_runtime(a.path(), |runtime| runtime.failed_attempts = MAX_FAILED_ATTEMPTS);
        assert_eq!(with_runtime(b.path(), |runtime| runtime.failed_attempts), 0);
        assert_eq!(password_requirement(a.path(), &enrollment()), Some(PasswordRestriction::TooManyAttempts.message()));
    }

    #[test]
    fn enrollment_is_bound_to_the_vault_directory_and_account() {
        let vault = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        store_enrollment(vault.path(), &enrollment()).unwrap();
        notify_password_login_success(vault.path()).unwrap();
        assert!(authorized_enrollment(vault.path(), "fixture").is_ok());
        assert!(authorized_enrollment(vault.path(), "other").is_err());
        assert!(authorized_enrollment(other.path(), "fixture").is_err());
    }

    #[test]
    #[cfg(any(target_os = "macos", target_os = "android"))]
    fn enrolled_native_authenticator_is_ready_at_cold_start() {
        assert_eq!(password_requirement(Path::new("test-cold-start"), &enrollment()), None);
    }

    #[test]
    fn emergency_lock_persists_and_only_password_login_clears_it() {
        let vault = tempfile::tempdir().unwrap();
        store_enrollment(vault.path(), &enrollment()).unwrap();
        emergency_lock(vault.path()).unwrap();
        assert_eq!(get_enrollment(vault.path()).unwrap().restriction, Some(PasswordRestriction::Emergency));
        assert!(authorized_enrollment(vault.path(), "fixture").unwrap_err().contains("urgence"));
        notify_password_login_success(vault.path()).unwrap();
        assert!(authorized_enrollment(vault.path(), "fixture").is_ok());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn compatibility_requires_explicit_enrollment_and_a_secure_enclave() {
        assert_eq!(macos_enrollment_format(false, true, true).unwrap(), NATIVE_KEYCHAIN_FORMAT);
        assert_eq!(macos_enrollment_format(true, false, true).unwrap(), COMPATIBILITY_KEYCHAIN_FORMAT);
        assert!(macos_enrollment_format(false, false, true).is_err());
        assert!(macos_enrollment_format(true, false, false).is_err());
        assert!(macos_enrollment_format(true, true, true).is_err());

        let mut entry = enrollment();
        entry.keychain_format = COMPATIBILITY_KEYCHAIN_FORMAT;
        assert!(!is_current_enrollment(&entry));
        entry.compatibility_id = Some(uuid::Uuid::new_v4());
        assert!(is_current_enrollment(&entry));
        entry.keychain_format = NATIVE_KEYCHAIN_FORMAT;
        assert!(!is_current_enrollment(&entry));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_requires_reenrollment_for_old_keychain_entries() {
        let legacy: BiometricEnrollment = serde_json::from_str(r#"{"user_id":1,"username":"fixture","enrolled_at":0}"#).unwrap();
        assert!(!is_current_enrollment(&legacy));
        assert!(is_current_enrollment(&enrollment()));
        assert!(keychain_error(-34018).contains("signature"));
        assert!(keychain_error(-128).contains("annulée"));
    }
}

use base64::{engine::general_purpose::STANDARD, Engine as _};
use uuid::Uuid;
use zeroize::Zeroizing;

const COMPATIBILITY_SERVICE: &str = "com.fluxlock.biometric.compatibility";
const LEGACY_SERVICE: &str = "com.fluxlock.biometric.secureenclave";
const VAULT_KEY_LENGTH: usize = 32;
const MAX_ENVELOPE_LENGTH: usize = 4096;

extern "C" {
    fn fluxlock_compatibility_is_available() -> bool;
    fn fluxlock_compatibility_seal(
        key: *const u8,
        key_length: i32,
        account: *const u8,
        account_length: i32,
        output: *mut u8,
        capacity: i32,
    ) -> i32;
    fn fluxlock_compatibility_open(
        input: *const u8,
        input_length: i32,
        account: *const u8,
        account_length: i32,
        output: *mut u8,
        capacity: i32,
    ) -> i32;
}

pub(super) fn is_available() -> bool {
    unsafe { fluxlock_compatibility_is_available() }
}

fn account(user_id: i64, enrollment_id: Uuid) -> String {
    let account = super::keychain_account(user_id, crate::hidden_storage::TEST_BUILD);
    format!("{account}/{enrollment_id}")
}

pub(super) fn store(user_id: i64, id: Uuid, key: &[u8]) -> Result<(), String> {
    if key.len() != VAULT_KEY_LENGTH {
        return Err("Clé de coffre invalide.".into());
    }
    let account = account(user_id, id);
    let mut sealed = vec![0u8; MAX_ENVELOPE_LENGTH];
    let status = unsafe {
        fluxlock_compatibility_seal(
            key.as_ptr(),
            VAULT_KEY_LENGTH as i32,
            account.as_ptr(),
            account.len() as i32,
            sealed.as_mut_ptr(),
            MAX_ENVELOPE_LENGTH as i32,
        )
    };
    if status <= 0 {
        return Err(super::keychain_error(status));
    }
    let sealed = sealed
        .get(..status as usize)
        .ok_or("Clé chiffrée invalide.")?;
    // The traditional Keychain only receives an authenticated ciphertext and an
    // opaque Enclave reference. Their use still requires the native biometric ACL.
    keyring::Entry::new(COMPATIBILITY_SERVICE, &account)
        .and_then(|entry| entry.set_password(&STANDARD.encode(sealed)))
        .map_err(|_| {
            "Impossible d’enregistrer la clé chiffrée dans le trousseau de session.".into()
        })
}

pub(super) fn retrieve(
    user_id: i64,
    id: Uuid,
) -> Result<Zeroizing<[u8; VAULT_KEY_LENGTH]>, String> {
    let account = account(user_id, id);
    let encoded = keyring::Entry::new(COMPATIBILITY_SERVICE, &account)
        .and_then(|entry| entry.get_password())
        .map_err(|_| {
            "Clé Touch ID indisponible. Ouvrez le coffre au mot de passe, puis réactivez Touch ID."
                .to_string()
        })?;
    if encoded.len() > MAX_ENVELOPE_LENGTH.div_ceil(3) * 4 {
        return Err("Clé Touch ID endommagée.".into());
    }
    let sealed = STANDARD
        .decode(encoded)
        .map_err(|_| "Clé Touch ID endommagée.")?;
    if sealed.is_empty() || sealed.len() > MAX_ENVELOPE_LENGTH {
        return Err("Clé Touch ID endommagée.".into());
    }

    let mut key = Zeroizing::new([0u8; VAULT_KEY_LENGTH]);
    let status = unsafe {
        fluxlock_compatibility_open(
            sealed.as_ptr(),
            sealed.len() as i32,
            account.as_ptr(),
            account.len() as i32,
            key.as_mut_ptr(),
            VAULT_KEY_LENGTH as i32,
        )
    };
    if status < 0 {
        return Err(super::keychain_error(status));
    }
    if status as usize != VAULT_KEY_LENGTH {
        return Err("Clé de coffre invalide.".into());
    }
    Ok(key)
}

fn delete_entry(service: &str, account: &str) -> Result<(), String> {
    match keyring::Entry::new(service, account).and_then(|entry| entry.delete_password()) {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => {
            Err("Impossible de supprimer une entrée Touch ID du trousseau de session.".into())
        }
    }
}

pub(super) fn delete(user_id: i64, id: Uuid) -> Result<(), String> {
    delete_entry(COMPATIBILITY_SERVICE, &account(user_id, id))
}

pub(super) fn delete_legacy(user_id: i64) -> Result<(), String> {
    delete_entry(
        LEGACY_SERVICE,
        &super::keychain_account(user_id, crate::hidden_storage::TEST_BUILD),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_envelope_never_writes_a_key_to_the_ffi_output() {
        let invalid_envelopes: [&[u8]; 3] = [b"", b"{}", &[7; VAULT_KEY_LENGTH]];
        let account = account(1, Uuid::new_v4());

        for input in invalid_envelopes {
            let mut output = [0xAA; VAULT_KEY_LENGTH];
            let result = unsafe {
                fluxlock_compatibility_open(
                    input.as_ptr(),
                    input.len() as i32,
                    account.as_ptr(),
                    account.len() as i32,
                    output.as_mut_ptr(),
                    VAULT_KEY_LENGTH as i32,
                )
            };
            assert!(result < 0);
            assert_eq!(output, [0xAA; VAULT_KEY_LENGTH]);
        }
    }
}

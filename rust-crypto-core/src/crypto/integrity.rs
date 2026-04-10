//! Module d'intégrité du header vault via HMAC-SHA3-256.
//!
//! Protège le header du vault contre la falsification (tamper-evident).
//! Utilise HMAC avec SHA3-256 et comparaison constant-time.

use hmac::{Hmac, Mac};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;

use crate::errors::CryptoError;

/// Taille du MAC en bytes (256 bits)
pub const MAC_SIZE: usize = 32;

type HmacSha3_256 = Hmac<Sha3_256>;

/// Calcule un HMAC-SHA3-256 sur des données arbitraires.
///
/// # Arguments
/// * `key` - Clé HMAC de 32 bytes (dérivée de la clé maître).
/// * `data` - Données à authentifier (typiquement le header sérialisé du vault).
///
/// # Retour
/// MAC de 32 bytes.
pub fn compute_header_mac(key: &[u8; 32], data: &[u8]) -> Result<[u8; MAC_SIZE], CryptoError> {
    let mut mac = HmacSha3_256::new_from_slice(key)
        .map_err(|e| CryptoError::Generic(format!("HMAC init error: {}", e)))?;

    mac.update(data);

    let result = mac.finalize().into_bytes();
    let mut output = [0u8; MAC_SIZE];
    output.copy_from_slice(&result);
    Ok(output)
}

/// Vérifie un HMAC-SHA3-256 en temps constant.
///
/// # Sécurité
/// - La comparaison est **toujours constant-time** via `subtle::ConstantTimeEq`.
/// - Aucune information sur la position du mismatch n'est révélée par le timing.
pub fn verify_header_mac(
    key: &[u8; 32],
    data: &[u8],
    expected_mac: &[u8; MAC_SIZE],
) -> Result<(), CryptoError> {
    let computed = compute_header_mac(key, data)?;

    if computed.ct_eq(expected_mac).into() {
        Ok(())
    } else {
        Err(CryptoError::AuthenticationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    use rand::RngCore;

    #[test]
    fn test_mac_roundtrip() {
        let key = test_key();
        let data = b"vault header bytes here";
        let mac = compute_header_mac(&key, data).unwrap();
        assert!(verify_header_mac(&key, data, &mac).is_ok());
    }

    #[test]
    fn test_mac_deterministic() {
        let key = test_key();
        let data = b"same data";
        let mac1 = compute_header_mac(&key, data).unwrap();
        let mac2 = compute_header_mac(&key, data).unwrap();
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_tampered_header_fails() {
        let key = test_key();
        let data = b"original header";
        let mac = compute_header_mac(&key, data).unwrap();

        let tampered = b"modified header";
        assert!(verify_header_mac(&key, tampered, &mac).is_err());
    }

    #[test]
    fn test_tampered_mac_fails() {
        let key = test_key();
        let data = b"header data";
        let mut mac = compute_header_mac(&key, data).unwrap();
        mac[0] ^= 0xFF; // Flip one bit
        assert!(verify_header_mac(&key, data, &mac).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = test_key();
        let key2 = test_key();
        let data = b"header";
        let mac = compute_header_mac(&key1, data).unwrap();
        assert!(verify_header_mac(&key2, data, &mac).is_err());
    }

    #[test]
    fn test_empty_data() {
        let key = test_key();
        let mac = compute_header_mac(&key, b"").unwrap();
        assert!(verify_header_mac(&key, b"", &mac).is_ok());
    }

    #[test]
    fn test_constant_time_comparison() {
        // Verify that the function doesn't short-circuit:
        // both matching and non-matching should return in similar time.
        // (This is a logical test — actual timing tests require criterion.)
        let key = test_key();
        let data = b"test data for timing";
        let correct_mac = compute_header_mac(&key, data).unwrap();

        // Wrong MAC with first byte different
        let mut wrong_first = correct_mac;
        wrong_first[0] ^= 0xFF;
        assert!(verify_header_mac(&key, data, &wrong_first).is_err());

        // Wrong MAC with last byte different
        let mut wrong_last = correct_mac;
        wrong_last[31] ^= 0xFF;
        assert!(verify_header_mac(&key, data, &wrong_last).is_err());

        // Correct MAC
        assert!(verify_header_mac(&key, data, &correct_mac).is_ok());
    }
}

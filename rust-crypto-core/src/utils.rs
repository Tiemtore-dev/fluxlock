//! Utilitaires cryptographiques

use base64::{Engine as _, engine::general_purpose};
use crate::errors::Result;

/// Encode des bytes en Base64
pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Décode du Base64 en bytes
pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
    general_purpose::STANDARD.decode(data)
        .map_err(|e| crate::CryptoError::InvalidData(format!("Base64 decode error: {}", e)))
}

/// Encode en hexadécimal
pub fn encode_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Décode de l'hexadécimal
pub fn decode_hex(data: &str) -> Result<Vec<u8>> {
    hex::decode(data)
        .map_err(|e| crate::CryptoError::InvalidData(format!("Hex decode error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_roundtrip() {
        let data = b"test data";
        let encoded = encode_base64(data);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }

    #[test]
    fn test_hex_roundtrip() {
        let data = b"test";
        let encoded = encode_hex(data);
        let decoded = decode_hex(&encoded).unwrap();
        assert_eq!(data, decoded.as_slice());
    }
}

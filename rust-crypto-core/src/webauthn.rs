//! # Passkeys & W3C WebAuthn Level 3 / FIDO2 CTAP2 Software Authenticator
//!
//! Implémentation pure Rust d'un authentificateur logiciel conforme à :
//! - **W3C WebAuthn Level 3 §6.1 & §6.5** (`authenticatorData`, `attestedCredentialData`, `clientDataJSON`)
//! - **RFC 9052 / RFC 9053 (COSE)** : Clés publiques COSE_Key (`OKP` Ed25519 `alg = -8`)
//! - **FIDO2 CTAP2.1** : Flags `UP (0x01) | UV (0x04) | BE (0x08) | BS (0x10) | AT (0x40)`

use crate::errors::{CryptoError, Result};
use crate::signatures::ed25519::{
    sign_message, verify_signature_from_bytes, KeyPair as Ed25519KeyPair,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// AAGUID officiel de l'authentificateur logiciel FluXlock Post-Quantum Vault (16 octets)
pub const FLUXLOCK_PASSKEY_AAGUID: [u8; 16] = [
    0x46, 0x4c, 0x55, 0x58, 0x4c, 0x4f, 0x43, 0x4b, 0x50, 0x41, 0x53, 0x53, 0x4b, 0x45, 0x59, 0x03,
];

// Flags W3C WebAuthn §6.1
const FLAG_UP: u8 = 0x01; // User Present
const FLAG_UV: u8 = 0x04; // User Verified
const FLAG_BE: u8 = 0x08; // Backup Eligible (multi-device synced passkey)
const FLAG_BS: u8 = 0x10; // Backup State (backed up / synchronized)
const FLAG_AT: u8 = 0x40; // Attested credential data included

/// Résultat de la cérémonie `navigator.credentials.create` (WebAuthn Level 3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatedPasskey {
    /// Identifiant unique du credential (32 octets encodés en base64url)
    pub credential_id_b64url: String,
    /// Identifiant du Relying Party (ex: `github.com`)
    pub rp_id: String,
    /// Nom lisible du Relying Party
    pub rp_name: String,
    /// Identifiant utilisateur opaque côté RP (base64url)
    pub user_handle_b64url: String,
    /// Nom d'utilisateur (ex: `alice@example.com`)
    pub user_name: String,
    /// Nom d'affichage utilisateur
    pub user_display_name: String,
    /// Algorithme COSE (`-8` pour EdDSA / Ed25519)
    pub cose_algorithm: i32,
    /// Clé publique Ed25519 brute (32 octets, base64url)
    pub public_key_b64url: String,
    /// Clé publique encodée en CBOR COSE_Key (RFC 9052, base64url)
    pub cose_public_key_b64url: String,
    /// Clé privée Ed25519 (32 octets seed, base64url) — effacée au Drop, à chiffrer immédiatement avec `v2:aad:`
    pub private_key_b64url: String,
    /// `authenticatorData` initial avec `attestedCredentialData` (base64url)
    pub authenticator_data_b64url: String,
    /// `clientDataJSON` sérialisé (base64url)
    pub client_data_json_b64url: String,
}

impl Drop for CreatedPasskey {
    fn drop(&mut self) {
        self.private_key_b64url.zeroize();
    }
}

/// Résultat de la cérémonie `navigator.credentials.get` (Assertion WebAuthn Level 3)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAssertion {
    pub credential_id_b64url: String,
    pub rp_id: String,
    pub authenticator_data_b64url: String,
    pub client_data_json_b64url: String,
    pub signature_b64url: String,
    pub user_handle_b64url: Option<String>,
    pub new_sign_count: u32,
}

/// Encode une clé publique Ed25519 (32 octets) au format CBOR `COSE_Key` (RFC 9052 §7 / RFC 9053) :
/// `{ 1 (kty): 1 (OKP), 3 (alg): -8 (EdDSA), -1 (crv): 6 (Ed25519), -2 (x): h'...' }`
pub fn encode_cose_ed25519_public_key(public_key: &[u8; 32]) -> Vec<u8> {
    let mut cbor = Vec::with_capacity(42);
    cbor.push(0xA4); // Map(4)
    // 1: 1 (kty: OKP)
    cbor.push(0x01);
    cbor.push(0x01);
    // 3: -8 (alg: EdDSA -> CBOR negative integer -8 is 0x20 | 7 = 0x27)
    cbor.push(0x03);
    cbor.push(0x27);
    // -1: 6 (crv: Ed25519 -> CBOR -1 is 0x20, 6 is 0x06)
    cbor.push(0x20);
    cbor.push(0x06);
    // -2: bytes(32) (x -> CBOR -2 is 0x21, byte string len 32 is 0x58, 0x20)
    cbor.push(0x21);
    cbor.push(0x58);
    cbor.push(0x20);
    cbor.extend_from_slice(public_key);
    cbor
}

/// Génère une nouvelle Passkey résidente (Discoverable Credential / Passkey) conforme W3C WebAuthn Level 3.
pub fn create_passkey_credential(
    rp_id: &str,
    rp_name: &str,
    user_handle: &[u8],
    user_name: &str,
    user_display_name: &str,
    challenge_b64url: &str,
    origin: &str,
) -> Result<CreatedPasskey> {
    if rp_id.trim().is_empty() {
        return Err(CryptoError::InvalidData("rp_id WebAuthn vide".into()));
    }

    let mut credential_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut credential_id);
    let credential_id_b64url = URL_SAFE_NO_PAD.encode(credential_id);

    let keypair = Ed25519KeyPair::generate();
    let pub_bytes = keypair.public_key.to_bytes();
    let priv_bytes = Zeroizing::new(keypair.export_private_key());

    let cose_pub = encode_cose_ed25519_public_key(&pub_bytes);

    // Construction de authenticatorData (W3C WebAuthn §6.1) :
    // rpIdHash (32) || flags (1) || signCount (4) || AAGUID (16) || credIdLen (2) || credId (32) || credentialPublicKey
    let rp_id_hash = Sha256::digest(rp_id.trim().as_bytes());
    let flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS | FLAG_AT;
    let sign_count: u32 = 0;

    let mut auth_data = Vec::with_capacity(37 + 16 + 2 + 32 + cose_pub.len());
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    auth_data.extend_from_slice(&FLUXLOCK_PASSKEY_AAGUID);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(&credential_id);
    auth_data.extend_from_slice(&cose_pub);

    let client_data = serde_json::json!({
        "type": "webauthn.create",
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_bytes = serde_json::to_vec(&client_data)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

    Ok(CreatedPasskey {
        credential_id_b64url,
        rp_id: rp_id.trim().to_string(),
        rp_name: rp_name.trim().to_string(),
        user_handle_b64url: URL_SAFE_NO_PAD.encode(user_handle),
        user_name: user_name.trim().to_string(),
        user_display_name: user_display_name.trim().to_string(),
        cose_algorithm: -8,
        public_key_b64url: URL_SAFE_NO_PAD.encode(pub_bytes),
        cose_public_key_b64url: URL_SAFE_NO_PAD.encode(&cose_pub),
        private_key_b64url: URL_SAFE_NO_PAD.encode(*priv_bytes),
        authenticator_data_b64url: URL_SAFE_NO_PAD.encode(&auth_data),
        client_data_json_b64url: URL_SAFE_NO_PAD.encode(&client_data_bytes),
    })
}

/// Signe une assertion d'authentification WebAuthn Level 3 (`navigator.credentials.get`).
pub fn authenticate_passkey_assertion(
    rp_id: &str,
    credential_id_b64url: &str,
    private_key_b64url: &str,
    current_sign_count: u32,
    challenge_b64url: &str,
    origin: &str,
    user_handle_b64url: Option<&str>,
) -> Result<PasskeyAssertion> {
    let priv_vec = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(private_key_b64url.trim())
            .map_err(|e| CryptoError::InvalidData(format!("Clé privée Passkey base64url: {}", e)))?,
    );
    if priv_vec.len() != 32 {
        return Err(CryptoError::InvalidKeySize {
            expected: 32,
            actual: priv_vec.len(),
        });
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&priv_vec);
    let keypair = Ed25519KeyPair::from_bytes(&seed)?;

    let new_sign_count = current_sign_count.saturating_add(1);
    let rp_id_hash = Sha256::digest(rp_id.trim().as_bytes());
    let flags = FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS;

    let mut auth_data = [0u8; 37];
    auth_data[0..32].copy_from_slice(&rp_id_hash);
    auth_data[32] = flags;
    auth_data[33..37].copy_from_slice(&new_sign_count.to_be_bytes());

    let client_data = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": false,
    });
    let client_data_bytes = serde_json::to_vec(&client_data)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
    let client_data_hash = Sha256::digest(&client_data_bytes);

    // Message signé selon W3C WebAuthn §6.3.3 : authenticatorData || SHA-256(clientDataJSON)
    let mut signed_payload = [0u8; 37 + 32];
    signed_payload[0..37].copy_from_slice(&auth_data);
    signed_payload[37..69].copy_from_slice(&client_data_hash);

    let signature = sign_message(&signed_payload, &keypair);

    // Auto-vérification cryptographique avant émission
    let verified = verify_signature_from_bytes(
        &signed_payload,
        &signature,
        keypair.public_key.as_bytes(),
    );
    if !verified {
        return Err(CryptoError::SignatureVerificationFailed);
    }

    Ok(PasskeyAssertion {
        credential_id_b64url: credential_id_b64url.to_string(),
        rp_id: rp_id.trim().to_string(),
        authenticator_data_b64url: URL_SAFE_NO_PAD.encode(auth_data),
        client_data_json_b64url: URL_SAFE_NO_PAD.encode(&client_data_bytes),
        signature_b64url: URL_SAFE_NO_PAD.encode(&signature),
        user_handle_b64url: user_handle_b64url.map(ToOwned::to_owned),
        new_sign_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_passkey_create_and_assert_roundtrip() {
        let created = create_passkey_credential(
            "github.com",
            "GitHub",
            b"user-uuid-1234",
            "alice@example.com",
            "Alice",
            "dGVzdC1jaGFsbGVuZ2UtMTIz",
            "https://github.com",
        )
        .unwrap();

        assert_eq!(created.cose_algorithm, -8);
        assert!(!created.credential_id_b64url.is_empty());

        let assertion = authenticate_passkey_assertion(
            "github.com",
            &created.credential_id_b64url,
            &created.private_key_b64url,
            0,
            "YW5vdGhlci1jaGFsbGVuZ2U",
            "https://github.com",
            Some(&created.user_handle_b64url),
        )
        .unwrap();

        assert_eq!(assertion.new_sign_count, 1);

        // Vérifier que la signature WebAuthn est valide avec la clé publique du credential
        let auth_data = URL_SAFE_NO_PAD
            .decode(&assertion.authenticator_data_b64url)
            .unwrap();
        let client_json = URL_SAFE_NO_PAD
            .decode(&assertion.client_data_json_b64url)
            .unwrap();
        let client_hash = Sha256::digest(&client_json);
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&auth_data);
        signed_data.extend_from_slice(&client_hash);

        let sig = URL_SAFE_NO_PAD.decode(&assertion.signature_b64url).unwrap();
        let pub_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&created.public_key_b64url)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(verify_signature_from_bytes(&signed_data, &sig, &pub_key));
    }
}

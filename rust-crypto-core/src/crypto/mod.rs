//! Module principal de cryptographie — Vault PQC-native v2
//!
//! ## Architecture
//! - `cipher` : ChaCha20-Poly1305 (chiffrement symétrique AEAD)
//! - `kdf` : Argon2id (dérivation de clé depuis mot de passe)
//! - `kem` : ML-KEM-768 / FIPS 203 (encapsulation de clé post-quantique)
//! - `integrity` : HMAC-SHA3-256 (intégrité du header vault)
//! - `vault` : Format vault v2 structuré (header + payload + MAC)
//! - `aes_gcm` : AES-256-GCM (rétrocompatibilité vault v1)
//! - `chacha` : ChaCha20-Poly1305 façade legacy

// ═══ Modules PQC v2 ═══
pub mod kdf;
pub mod cipher;
pub mod stream_cipher;
pub mod kem;
pub mod integrity;
pub mod vault;

// ═══ Modules legacy (rétrocompatibilité v1) ═══
pub mod aes_gcm;
pub mod chacha;

// ═══ Exports publics v2 ═══
pub use vault::{encrypt_vault, decrypt_vault, decrypt_vault_checked, SealedVault, VaultData, VaultEntry, VaultMeta, CipherAlgo};
pub use kdf::{derive_master_key, MasterKey, KdfParams, generate_salt as generate_kdf_salt};
pub use cipher::{encrypt, decrypt, EncryptedBlob};
pub use stream_cipher::{encrypt_stream, decrypt_stream, is_senc_format, SENC_MAGIC, SENC_HEADER_SIZE, DEFAULT_STREAM_CHUNK_SIZE};
pub use integrity::{compute_header_mac, verify_header_mac};
pub use kem::{
    generate_recipient_keypair, encapsulate, decapsulate,
    KemPublicKey, KemPrivateKey, SharedSecret, KemCiphertext,
};

// ═══ Exports legacy v1 ═══
pub use aes_gcm::{AesGcmCipher, encrypt_aes_gcm, decrypt_aes_gcm};
pub use chacha::{ChaCha20Cipher, encrypt_chacha20, decrypt_chacha20};

//! Module de signatures numériques

pub mod ed25519;

pub use ed25519::{KeyPair, PublicKeyExport, sign_message, verify_signature};

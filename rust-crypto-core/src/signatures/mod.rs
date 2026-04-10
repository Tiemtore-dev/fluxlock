//! Module de signatures numériques

pub mod ed25519;
pub mod ml_dsa;

pub use ed25519::{KeyPair, PublicKeyExport, sign_message, verify_signature};
pub use ml_dsa::{MlDsaKeyPair, verify_ml_dsa};

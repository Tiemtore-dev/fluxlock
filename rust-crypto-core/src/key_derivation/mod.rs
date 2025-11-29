//! Module de dérivation de clés

pub mod argon2;
pub mod hkdf;

pub use argon2::{
    derive_key_from_password,
    derive_key_with_new_salt,
    generate_salt,
    verify_password,
    Argon2Config,
};
pub use hkdf::derive_key_hkdf;

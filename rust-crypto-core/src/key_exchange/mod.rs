//! Module d'échange de clés

pub mod x25519;

pub use x25519::{generate_keypair, compute_shared_secret};

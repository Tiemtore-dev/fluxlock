//! VAULT SECURE TRANSFER — Module racine
//!
//! Transfert P2P chiffré end-to-end avec crypto post-quantique.
//! Le plaintext ne touche jamais le disque.
//!
//! Architecture :
//! - `protocol`   — Types de messages sur le fil (MessagePack)
//! - `discovery`  — Découverte réseau (mDNS + IPv6 link-local)
//! - `handshake`  — SPAKE2 wormhole + ML-KEM-768 hybride
//! - `transport`  — Connexion directe IPv6 / relay TLS fallback
//! - `session`    — Session chiffrée ChaCha20-Poly1305
//! - `trust_store`— Confiance par empreinte de clé
//! - `reencrypt`  — Re-chiffrement vault-à-vault sans plaintext sur disque
//! - `commands`   — Commandes Tauri exposées au frontend

pub mod protocol;
pub mod discovery;
pub mod handshake;
pub mod transport;
pub mod session;
pub mod trust_store;
pub mod reencrypt;
pub mod commands;

use serde::{Serialize, Deserialize};

/// Méthode de connexion utilisée pour le transfert
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionMethod {
    /// Connexion directe IPv6 link-local
    DirectIPv6,
    /// Découverte mDNS sur réseau local
    MdnsLocal,
    /// Relay TLS (fallback)
    Relay,
}

impl std::fmt::Display for ConnectionMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirectIPv6 => write!(f, "IPv6 Direct"),
            Self::MdnsLocal => write!(f, "mDNS Local"),
            Self::Relay => write!(f, "Relay TLS"),
        }
    }
}

/// État du transfert, envoyé au frontend via événements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferState {
    WaitingForPeer,
    Handshaking,
    ConfirmingSafetyNumber,
    Transferring { progress_pct: u8, bytes_sent: u64, total_bytes: u64 },
    Completed,
    Failed { reason: String },
}

/// Info de transfert retournée au frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferInfo {
    pub transfer_id: String,
    pub state: TransferState,
    pub connection_method: ConnectionMethod,
    pub safety_number: Option<String>,
    pub peer_name: Option<String>,
    /// Timestamp de création (epoch seconds) — le code wormhole expire après WORMHOLE_TTL_SECS
    #[serde(default)]
    pub created_at: u64,
}

/// Durée de validité du code wormhole (5 minutes)
pub const WORMHOLE_TTL_SECS: u64 = 300;

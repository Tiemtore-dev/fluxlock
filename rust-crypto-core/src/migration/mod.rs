//! Migration des vaults v1 vers v2 (PQC-native).
//!
//! ## Processus de migration
//! 1. Détection de la version via heuristique (v1 = base64 AES-GCM, v2 = magic bytes).
//! 2. Déchiffrement du vault v1 avec l'ancien algorithme.
//! 3. Re-chiffrement immédiat en vault v2 (ChaCha20-Poly1305 + Argon2id).
//! 4. Écriture atomique (fichier temp → rename).
//! 5. Vérification post-migration (re-déchiffrement du v2).
//!
//! ## Garanties
//! - **Atomique** : écriture via fichier temporaire + `fs::rename()`.
//! - **Transactionnelle** : le vault original n'est jamais modifié.
//! - **Vérifiable** : re-déchiffrement de contrôle après migration.

pub mod migrate;

pub use migrate::{migrate_v1_to_v2, MigrationReport, MigrationError};

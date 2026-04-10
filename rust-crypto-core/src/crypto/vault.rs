//! Format vault v2 — structure binaire avec header versionné, HMAC, et PQC.
//!
//! ## Structure binaire du vault v2
//!
//! ```text
//! ┌──────────────┬──────────────────────────────────────┐
//! │ HEADER       │ magic: b"VAULT\x02" (6 bytes)        │
//! │              │ version: u8 = 2                       │
//! │              │ algo: u8 (CipherAlgo enum)            │
//! │              │ kdf_m_cost: u32 LE                    │
//! │              │ kdf_t_cost: u32 LE                    │
//! │              │ kdf_p_cost: u32 LE                    │
//! │              │ salt: [u8; 32]                        │
//! ├──────────────┼──────────────────────────────────────┤
//! │ PAYLOAD      │ nonce: [u8; 12]                      │
//! │              │ ciphertext_len: u32 LE               │
//! │              │ ciphertext: [u8; ciphertext_len]     │
//! ├──────────────┼──────────────────────────────────────┤
//! │ INTEGRITY    │ header_mac: [u8; 32]                  │
//! │              │ (HMAC-SHA3-256 sur header bytes)      │
//! └──────────────┴──────────────────────────────────────┘
//! ```

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::cipher::{self, EncryptedBlob, NONCE_SIZE};
use crate::crypto::integrity::{self, MAC_SIZE};
use crate::crypto::kdf::{self, KdfParams, SALT_SIZE};
use crate::errors::CryptoError;

/// Magic bytes identifiant un vault v2.
pub const VAULT_MAGIC: &[u8; 6] = b"VAULT\x02";

/// Version courante du format.
pub const VAULT_VERSION: u8 = 2;

/// Taille fixe du header (avant le payload).
/// 6 (magic) + 1 (version) + 1 (algo) + 4+4+4 (kdf params) + 32 (salt) = 52 bytes
pub const HEADER_SIZE: usize = 52;

/// Taille maximale autorisée pour le ciphertext (256 MiB).
/// Empêche un vault malformé de provoquer une allocation mémoire excessive (OOM DoS).
pub const MAX_CIPHERTEXT_SIZE: usize = 256 * 1024 * 1024;

/// Algorithme de chiffrement symétrique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CipherAlgo {
    /// AES-256-GCM (legacy v1, rétrocompatibilité)
    Aes256Gcm = 0,
    /// ChaCha20-Poly1305 (v2, recommandé)
    ChaCha20Poly1305 = 1,
}

impl CipherAlgo {
    pub fn from_u8(v: u8) -> Result<Self, CryptoError> {
        match v {
            0 => Ok(Self::Aes256Gcm),
            1 => Ok(Self::ChaCha20Poly1305),
            _ => Err(CryptoError::InvalidData(format!("Unknown cipher algo: {}", v))),
        }
    }
}

/// Header structuré du vault v2.
#[derive(Debug, Clone)]
pub struct VaultHeader {
    pub version: u8,
    pub algo: CipherAlgo,
    pub kdf_params: KdfParams,
    pub salt: [u8; SALT_SIZE],
}

impl VaultHeader {
    /// Sérialise le header en bytes (pour calcul du MAC).
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..6].copy_from_slice(VAULT_MAGIC);
        buf[6] = self.version;
        buf[7] = self.algo as u8;
        buf[8..12].copy_from_slice(&self.kdf_params.m_cost.to_le_bytes());
        buf[12..16].copy_from_slice(&self.kdf_params.t_cost.to_le_bytes());
        buf[16..20].copy_from_slice(&self.kdf_params.p_cost.to_le_bytes());
        buf[20..52].copy_from_slice(&self.salt);
        buf
    }

    /// Désérialise un header depuis des bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, CryptoError> {
        if buf.len() < HEADER_SIZE {
            return Err(CryptoError::InvalidData("Header too short".into()));
        }
        if &buf[0..6] != VAULT_MAGIC {
            return Err(CryptoError::InvalidData("Invalid vault magic bytes".into()));
        }
        let version = buf[6];
        if version != VAULT_VERSION {
            return Err(CryptoError::InvalidData(format!(
                "Unsupported vault version: {} (expected {})",
                version, VAULT_VERSION
            )));
        }
        let algo = CipherAlgo::from_u8(buf[7])?;
        let m_cost = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let t_cost = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        let p_cost = u32::from_le_bytes(buf[16..20].try_into().unwrap());
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&buf[20..52]);

        Ok(Self {
            version,
            algo,
            kdf_params: KdfParams {
                m_cost,
                t_cost,
                p_cost,
            },
            salt,
        })
    }
}

/// Données structurées du vault (sérialisées en MessagePack avant chiffrement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub entries: Vec<VaultEntry>,
    pub metadata: VaultMeta,
}

/// Entrée individuelle du vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Métadonnées du vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    pub created_at: i64,
    pub updated_at: i64,
    pub entry_count: usize,
    pub format_version: u8,
    /// Compteur monotone anti-rollback.
    /// Incrémenté à chaque écriture du vault. Permet de détecter la restauration
    /// d'une version antérieure (attaque par rollback). Défaut 0 pour rétrocompatibilité
    /// avec les vaults existants qui n'avaient pas ce champ.
    #[serde(default)]
    pub sequence: u64,
}

/// Vault complet sérialisé (pour écriture sur disque).
pub struct SealedVault {
    pub header: VaultHeader,
    pub encrypted_payload: EncryptedBlob,
    pub header_mac: [u8; MAC_SIZE],
}

impl SealedVault {
    /// Sérialise le vault complet en bytes pour écriture fichier.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let payload_bytes = self.encrypted_payload.to_bytes();

        let mut out = Vec::with_capacity(
            HEADER_SIZE + 4 + payload_bytes.len() + MAC_SIZE,
        );
        out.extend_from_slice(&header_bytes);
        // Payload: nonce is already in payload_bytes, just prepend length of ciphertext part
        let ct_len = self.encrypted_payload.ciphertext.len() as u32;
        out.extend_from_slice(&self.encrypted_payload.nonce);
        out.extend_from_slice(&ct_len.to_le_bytes());
        out.extend_from_slice(&self.encrypted_payload.ciphertext);
        out.extend_from_slice(&self.header_mac);
        out
    }

    /// Désérialise un vault complet depuis des bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() < HEADER_SIZE + NONCE_SIZE + 4 + MAC_SIZE {
            return Err(CryptoError::InvalidData("Vault file too short".into()));
        }

        let header = VaultHeader::from_bytes(&data[..HEADER_SIZE])?;

        let pos = HEADER_SIZE;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[pos..pos + NONCE_SIZE]);

        let ct_len_pos = pos + NONCE_SIZE;
        let ct_len = u32::from_le_bytes(
            data[ct_len_pos..ct_len_pos + 4]
                .try_into()
                .map_err(|_| CryptoError::InvalidData("Invalid ciphertext length".into()))?,
        ) as usize;

        // Protection OOM : rejeter les ciphertexts anormalement grands
        if ct_len > MAX_CIPHERTEXT_SIZE {
            return Err(CryptoError::InvalidData(format!(
                "Ciphertext too large: {} bytes (max {} bytes)",
                ct_len, MAX_CIPHERTEXT_SIZE
            )));
        }

        let ct_start = ct_len_pos + 4;
        let ct_end = ct_start + ct_len;

        if data.len() < ct_end + MAC_SIZE {
            return Err(CryptoError::InvalidData("Vault file truncated".into()));
        }

        let ciphertext = data[ct_start..ct_end].to_vec();

        let mut header_mac = [0u8; MAC_SIZE];
        header_mac.copy_from_slice(&data[ct_end..ct_end + MAC_SIZE]);

        Ok(Self {
            header,
            encrypted_payload: EncryptedBlob { nonce, ciphertext },
            header_mac,
        })
    }
}

/// Chiffre et scelle un vault v2 complet.
///
/// # Arguments
/// * `password` - Mot de passe utilisateur.
/// * `vault_data` - Données du vault à chiffrer.
///
/// # Retour
/// `SealedVault` prêt à écrire sur disque.
///
/// # Anti-rollback
/// Le champ `vault_data.metadata.sequence` est inclus dans le payload chiffré
/// (protégé par le tag Poly1305). L'appelant doit incrémenter `sequence` avant
/// chaque appel et persister le dernier `sequence` connu pour vérifier au déchiffrement
/// qu'aucune version antérieure n'a été restaurée.
pub fn encrypt_vault(password: &[u8], vault_data: &VaultData) -> Result<SealedVault, CryptoError> {
    // 1. Générer un sel unique
    let salt = kdf::generate_salt()?;

    // 2. Dériver la clé maître
    let master_key = kdf::derive_master_key(password, &salt)?;

    // 3. Sérialiser les données en MessagePack
    let plaintext = Zeroizing::new(
        rmp_serde::to_vec(vault_data)
            .map_err(|e| CryptoError::SerializationError(format!("MessagePack serialize: {}", e)))?,
    );

    // 4. Chiffrer avec ChaCha20-Poly1305
    let encrypted_payload = cipher::encrypt(master_key.as_bytes(), &plaintext)?;

    // 5. Construire le header
    let header = VaultHeader {
        version: VAULT_VERSION,
        algo: CipherAlgo::ChaCha20Poly1305,
        kdf_params: KdfParams::default(),
        salt,
    };

    // 6. Calculer le MAC du header
    let header_bytes = header.to_bytes();
    let header_mac = integrity::compute_header_mac(master_key.as_bytes(), &header_bytes)?;

    Ok(SealedVault {
        header,
        encrypted_payload,
        header_mac,
    })
}

/// Déchiffre et vérifie un vault v2 complet.
///
/// # Arguments
/// * `password` - Mot de passe utilisateur.
/// * `sealed` - Vault scellé lu depuis le disque.
///
/// # Sécurité
/// 1. Dérive la clé depuis le password + salt du header.
/// 2. Vérifie le MAC du header (tamper detection).
/// 3. Déchiffre le payload (vérifie le tag AEAD).
/// 4. Désérialise le MessagePack.
pub fn decrypt_vault(password: &[u8], sealed: &SealedVault) -> Result<VaultData, CryptoError> {
    // 1. Dériver la clé maître
    let master_key = kdf::derive_master_key_with_params(
        password,
        &sealed.header.salt,
        &sealed.header.kdf_params,
    )?;

    // 2. Vérifier le MAC du header (AVANT déchiffrement)
    let header_bytes = sealed.header.to_bytes();
    integrity::verify_header_mac(master_key.as_bytes(), &header_bytes, &sealed.header_mac)?;

    // 3. Déchiffrer le payload
    let plaintext = cipher::decrypt(master_key.as_bytes(), &sealed.encrypted_payload)?;

    // 4. Désérialiser
    let vault_data: VaultData = rmp_serde::from_slice(&plaintext)
        .map_err(|e| CryptoError::DeserializationError(format!("MessagePack deserialize: {}", e)))?;

    Ok(vault_data)
}

/// Déchiffre un vault v2 avec vérification anti-rollback.
///
/// Identique à [`decrypt_vault`], mais rejette le vault si son `sequence`
/// est strictement inférieur à `expected_min_sequence`. Cela empêche un
/// attaquant de restaurer une ancienne version du fichier vault.
///
/// # Arguments
/// * `password` - Mot de passe utilisateur.
/// * `sealed` - Vault scellé lu depuis le disque.
/// * `expected_min_sequence` - Dernière séquence connue (persistée côté appelant).
///
/// # Erreurs
/// Retourne `CryptoError::InvalidData` si `metadata.sequence < expected_min_sequence`.
pub fn decrypt_vault_checked(
    password: &[u8],
    sealed: &SealedVault,
    expected_min_sequence: u64,
) -> Result<VaultData, CryptoError> {
    let vault_data = decrypt_vault(password, sealed)?;

    if vault_data.metadata.sequence < expected_min_sequence {
        return Err(CryptoError::InvalidData(format!(
            "Rollback detected: vault sequence {} < expected minimum {}",
            vault_data.metadata.sequence, expected_min_sequence
        )));
    }

    Ok(vault_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vault_data() -> VaultData {
        VaultData {
            entries: vec![
                VaultEntry {
                    id: "entry-1".into(),
                    title: "GitHub".into(),
                    username: Some("user@example.com".into()),
                    password: Some("s3cret!P@ss".into()),
                    url: Some("https://github.com".into()),
                    notes: None,
                    category: "passwords".into(),
                    created_at: 1700000000,
                    updated_at: 1700000000,
                },
                VaultEntry {
                    id: "entry-2".into(),
                    title: "Note secrète".into(),
                    username: None,
                    password: None,
                    url: None,
                    notes: Some("Contenu confidentiel avec accents éàü".into()),
                    category: "notes".into(),
                    created_at: 1700000001,
                    updated_at: 1700000002,
                },
            ],
            metadata: VaultMeta {
                created_at: 1700000000,
                updated_at: 1700000002,
                entry_count: 2,
                format_version: 2,
                sequence: 0,
            },
        }
    }

    #[test]
    fn test_encrypt_decrypt_vault_roundtrip() {
        let password = b"correct horse battery staple";
        let data = sample_vault_data();
        let sealed = encrypt_vault(password, &data).unwrap();
        let decrypted = decrypt_vault(password, &sealed).unwrap();

        assert_eq!(decrypted.entries.len(), 2);
        assert_eq!(decrypted.entries[0].title, "GitHub");
        assert_eq!(decrypted.entries[0].password.as_deref(), Some("s3cret!P@ss"));
        assert_eq!(decrypted.entries[1].notes.as_deref(), Some("Contenu confidentiel avec accents éàü"));
        assert_eq!(decrypted.metadata.entry_count, 2);
        assert_eq!(decrypted.metadata.format_version, 2);
        assert_eq!(decrypted.metadata.sequence, 0);
    }

    #[test]
    fn test_wrong_password_fails() {
        let data = sample_vault_data();
        let sealed = encrypt_vault(b"correct_password", &data).unwrap();
        let result = decrypt_vault(b"wrong_password", &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_header_fails() {
        let password = b"my_password";
        let data = sample_vault_data();
        let mut sealed = encrypt_vault(password, &data).unwrap();
        // Tamper with the salt in the header
        sealed.header.salt[0] ^= 0xFF;
        let result = decrypt_vault(password, &sealed);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_serialization_roundtrip() {
        let password = b"test_serialization";
        let data = sample_vault_data();
        let sealed = encrypt_vault(password, &data).unwrap();

        // Serialize to bytes (as if writing to disk)
        let bytes = sealed.to_bytes();

        // Deserialize (as if reading from disk)
        let restored = SealedVault::from_bytes(&bytes).unwrap();

        // Decrypt the restored vault
        let decrypted = decrypt_vault(password, &restored).unwrap();
        assert_eq!(decrypted.entries.len(), 2);
        assert_eq!(decrypted.entries[0].title, "GitHub");
    }

    #[test]
    fn test_header_magic_and_version() {
        let password = b"header_test";
        let data = sample_vault_data();
        let sealed = encrypt_vault(password, &data).unwrap();
        let bytes = sealed.to_bytes();

        // Check magic bytes
        assert_eq!(&bytes[0..6], VAULT_MAGIC);
        // Check version
        assert_eq!(bytes[6], VAULT_VERSION);
        // Check algo (ChaCha20-Poly1305 = 1)
        assert_eq!(bytes[7], CipherAlgo::ChaCha20Poly1305 as u8);
    }

    #[test]
    fn test_empty_vault() {
        let password = b"empty_vault";
        let data = VaultData {
            entries: vec![],
            metadata: VaultMeta {
                created_at: 0,
                updated_at: 0,
                entry_count: 0,
                format_version: 2,
                sequence: 0,
            },
        };
        let sealed = encrypt_vault(password, &data).unwrap();
        let decrypted = decrypt_vault(password, &sealed).unwrap();
        assert!(decrypted.entries.is_empty());
    }

    #[test]
    fn test_sequence_anti_rollback_preserved() {
        let password = b"anti_rollback_test";

        // Simuler un vault à sequence 42
        let mut data = sample_vault_data();
        data.metadata.sequence = 42;

        let sealed = encrypt_vault(password, &data).unwrap();
        let decrypted = decrypt_vault(password, &sealed).unwrap();

        // Le sequence doit être fidèlement restitué
        assert_eq!(decrypted.metadata.sequence, 42);
    }

    #[test]
    fn test_rollback_detection_rejects_old_sequence() {
        let password = b"rollback_check";

        // Vault avec sequence 10 (ancienne version)
        let mut data = sample_vault_data();
        data.metadata.sequence = 10;
        let sealed_old = encrypt_vault(password, &data).unwrap();

        // L'appelant a vu sequence 20 — toute restauration ≤ 19 est rejetée
        let result = decrypt_vault_checked(password, &sealed_old, 20);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Rollback detected"));
    }

    #[test]
    fn test_rollback_check_accepts_current_or_newer() {
        let password = b"rollback_ok";

        let mut data = sample_vault_data();
        data.metadata.sequence = 25;
        let sealed = encrypt_vault(password, &data).unwrap();

        // Exact match OK
        assert!(decrypt_vault_checked(password, &sealed, 25).is_ok());
        // Older expectation OK
        assert!(decrypt_vault_checked(password, &sealed, 20).is_ok());
    }
}

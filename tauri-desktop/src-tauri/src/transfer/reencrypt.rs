//! Re-encrypt — Re-chiffrement vault-à-vault sans plaintext sur disque.
//!
//! Flux pour le transfert de données chiffrées :
//! 1. Le sender déchiffre en mémoire avec sa clé vault
//! 2. Les données plaintext sont immédiatement re-chiffrées avec la clé de session
//! 3. Le receiver déchiffre avec la clé de session
//! 4. Le receiver re-chiffre avec sa propre clé vault
//!
//! INVARIANT : Le plaintext ne touche JAMAIS le disque.
//! INVARIANT : Les buffers plaintext sont zéroïsés après usage via Zeroizing.

use zeroize::{Zeroize, Zeroizing};
use crate::secure_key::SecureKey;

/// Taille des chunks pour le transfert (64 KiB)
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Prépare les données d'un mot de passe pour le transfert.
/// Déchiffre avec la clé vault du sender, retourne le plaintext protégé.
///
/// Le plaintext est enveloppé dans `Zeroizing` : il sera automatiquement
/// effacé de la mémoire au drop, même en cas de panic.
pub fn prepare_password_for_transfer(
    encrypted_password: &str,
    vault_key: &SecureKey,
) -> Result<Zeroizing<Vec<u8>>, String> {
    use crate::crypto::decrypt_data_secure;

    let plaintext = decrypt_data_secure(encrypted_password, vault_key)
        .map_err(|e| format!("Déchiffrement mot de passe: {}", e))?;

    Ok(Zeroizing::new(plaintext.into_bytes()))
}

/// Importe un mot de passe reçu en le re-chiffrant avec la clé vault locale.
///
/// Le plaintext est zéroïsé IMMÉDIATEMENT après re-chiffrement.
pub fn import_received_password(
    plaintext: &mut Zeroizing<Vec<u8>>,
    vault_key: &SecureKey,
) -> Result<String, String> {
    use crate::crypto::encrypt_data_secure;

    let plain_str = std::str::from_utf8(plaintext)
        .map_err(|_| "Données mot de passe invalides".to_string())?;

    let encrypted = encrypt_data_secure(plain_str, vault_key)
        .map_err(|e| format!("Re-chiffrement mot de passe: {}", e))?;

    // Zéroïser le plaintext immédiatement (en plus du Zeroizing au drop)
    plaintext.zeroize();

    Ok(encrypted)
}

/// Prépare un fichier chiffré pour le transfert.
/// Lit le fichier chiffré et le retourne en chunks pour streaming.
pub fn prepare_file_chunks(
    file_path: &str,
) -> Result<FileChunkIterator, String> {
    let data = std::fs::read(file_path)
        .map_err(|e| format!("Lecture fichier: {}", e))?;

    Ok(FileChunkIterator {
        data,
        offset: 0,
        chunk_size: CHUNK_SIZE,
    })
}

/// Itérateur sur les chunks d'un fichier
///
/// Le buffer interne est zéroïsé au drop pour ne pas laisser de données
/// en mémoire après le transfert.
pub struct FileChunkIterator {
    data: Vec<u8>,
    offset: usize,
    chunk_size: usize,
}

impl Drop for FileChunkIterator {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl FileChunkIterator {
    pub fn total_size(&self) -> u64 {
        self.data.len() as u64
    }
}

impl Iterator for FileChunkIterator {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        let end = (self.offset + self.chunk_size).min(self.data.len());
        let chunk = self.data[self.offset..end].to_vec();
        self.offset = end;
        Some(chunk)
    }
}

/// Vérifie l'intégrité d'un fichier reçu via BLAKE3
pub fn verify_integrity(data: &[u8], expected_hash: &str) -> bool {
    let hash_bytes = secure_vault_crypto::blake3_hash(data);
    let actual_hex = hex::encode(&hash_bytes);
    // Comparaison constant-time
    use subtle::ConstantTimeEq;
    actual_hex.as_bytes().ct_eq(expected_hash.as_bytes()).into()
}

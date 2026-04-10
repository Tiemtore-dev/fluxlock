//! Chiffrement AEAD par flux (streaming) — ChaCha20-Poly1305.
//!
//! Permet de chiffrer/déchiffrer des fichiers volumineux sans les charger
//! intégralement en mémoire. Chaque chunk est chiffré indépendamment avec
//! un nonce dérivé et un AAD anti-réordonnancement / anti-troncature.
//!
//! ## Format binaire SENC v1
//!
//! ```text
//! ┌──────────────┬──────────────────────────────────────┐
//! │ HEADER       │ magic: b"SENC\x01\x00" (6 bytes)     │
//! │              │ chunk_size: u32 LE (plaintext chunk)  │
//! │              │ base_nonce: [u8; 12]                  │
//! ├──────────────┼──────────────────────────────────────┤
//! │ CHUNK 0      │ flags: u8 (0x00=more, 0x01=final)    │
//! │              │ encrypted_len: u32 LE (ct + 16 tag)   │
//! │              │ encrypted_data: [u8; encrypted_len]   │
//! ├──────────────┼──────────────────────────────────────┤
//! │ CHUNK N      │ flags: 0x01 (final)                   │
//! │ (last)       │ encrypted_len: u32 LE                 │
//! │              │ encrypted_data: [u8; encrypted_len]   │
//! └──────────────┴──────────────────────────────────────┘
//! ```
//!
//! ## Sécurité
//!
//! - Nonce unique par chunk : `base_nonce XOR (counter in bytes 8..12)`.
//! - AAD par chunk : `"senc-v1:" || chunk_index (u64 BE) || flags (u8)`.
//! - Anti-troncature : le dernier chunk porte le flag `FINAL` dans son AAD ;
//!   un attaquant ne peut pas supprimer des chunks finaux sans casser l'AEAD.
//! - Anti-réordonnancement : le chunk_index dans l'AAD empêche de permuter.
//! - Chaque buffer plaintext est zéroïsé après chiffrement.
//! - Mémoire pic ≈ 2 × chunk_size (double buffer look-ahead).

use std::io::{Read, Write};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::errors::CryptoError;

// ═══════════════════════════════════════════════════════
// Constantes publiques
// ═══════════════════════════════════════════════════════

/// Magic bytes identifiant le format SENC v1.
pub const SENC_MAGIC: &[u8; 6] = b"SENC\x01\x00";

/// Taille du header SENC (6 magic + 4 chunk_size + 12 nonce = 22 bytes).
pub const SENC_HEADER_SIZE: usize = 22;

/// Taille par défaut d'un chunk plaintext (64 KiB).
pub const DEFAULT_STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Taille maximale autorisée pour un chunk plaintext (16 MiB).
pub const MAX_STREAM_CHUNK_SIZE: usize = 16 * 1024 * 1024;

// ═══════════════════════════════════════════════════════
// Constantes internes
// ═══════════════════════════════════════════════════════

const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const FLAG_CONTINUATION: u8 = 0x00;
const FLAG_FINAL: u8 = 0x01;
const MAX_CHUNK_COUNT: u32 = u32::MAX - 1;

// ═══════════════════════════════════════════════════════
// API publique
// ═══════════════════════════════════════════════════════

/// Chiffre un flux en streaming avec ChaCha20-Poly1305.
///
/// Lit `reader` par blocs de `chunk_size`, chiffre chaque bloc avec un nonce
/// unique dérivé, et écrit le résultat dans `writer` au format SENC v1.
///
/// Utilise un double-buffer look-ahead pour déterminer le dernier chunk
/// sans "peek" compliqué : on lit toujours un chunk d'avance.
///
/// # Arguments
/// * `key` — Clé de 256 bits (32 bytes).
/// * `reader` — Source de données en clair.
/// * `writer` — Destination du flux chiffré.
/// * `chunk_size` — Taille des blocs plaintext (0 = défaut 64 KiB).
///
/// # Retour
/// Nombre total d'octets plaintext traités.
pub fn encrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
    chunk_size: usize,
) -> Result<u64, CryptoError> {
    let chunk_size = if chunk_size == 0 { DEFAULT_STREAM_CHUNK_SIZE } else { chunk_size };

    if chunk_size > MAX_STREAM_CHUNK_SIZE {
        return Err(CryptoError::InvalidData(format!(
            "Chunk size {} exceeds maximum {}",
            chunk_size, MAX_STREAM_CHUNK_SIZE
        )));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::EncryptionError(format!("Invalid key: {}", e)))?;

    let mut base_nonce = [0u8; NONCE_SIZE];
    rand::rngs::OsRng
        .try_fill_bytes(&mut base_nonce)
        .map_err(|e| CryptoError::RandomGenerationError(format!("Nonce gen failed: {}", e)))?;

    write_header(writer, chunk_size as u32, &base_nonce)?;

    // Double-buffer look-ahead
    let mut buf_a = vec![0u8; chunk_size];
    let mut buf_b = vec![0u8; chunk_size];
    let mut chunk_index: u32 = 0;
    let mut total_plaintext: u64 = 0;

    let mut len_a = fill_buffer(reader, &mut buf_a)?;

    if len_a == 0 {
        // Flux vide → chunk final vide
        encrypt_and_write(&cipher, &base_nonce, 0, FLAG_FINAL, &[], writer)?;
        buf_a.zeroize();
        buf_b.zeroize();
        writer.flush().map_err(io_enc_err)?;
        return Ok(0);
    }

    loop {
        let len_b = fill_buffer(reader, &mut buf_b)?;
        let is_final = len_b == 0;
        let flags = if is_final { FLAG_FINAL } else { FLAG_CONTINUATION };

        if chunk_index > MAX_CHUNK_COUNT {
            buf_a.zeroize();
            buf_b.zeroize();
            return Err(CryptoError::EncryptionError("Max chunk count exceeded".into()));
        }

        encrypt_and_write(&cipher, &base_nonce, chunk_index, flags, &buf_a[..len_a], writer)?;
        buf_a[..len_a].zeroize();
        total_plaintext += len_a as u64;
        chunk_index += 1;

        if is_final {
            break;
        }

        // Swap buffers
        std::mem::swap(&mut buf_a, &mut buf_b);
        len_a = len_b;
    }

    buf_a.zeroize();
    buf_b.zeroize();
    writer.flush().map_err(io_enc_err)?;

    Ok(total_plaintext)
}

/// Déchiffre un flux SENC v1 en streaming avec ChaCha20-Poly1305.
///
/// Lit le header, puis déchiffre chaque chunk séquentiellement et écrit
/// le plaintext dans `writer`. Chaque chunk est authentifié avant écriture.
///
/// # Arguments
/// * `key` — Clé de 256 bits (32 bytes).
/// * `reader` — Source du flux chiffré (format SENC v1).
/// * `writer` — Destination des données déchiffrées.
///
/// # Retour
/// Nombre total d'octets plaintext récupérés.
pub fn decrypt_stream<R: Read, W: Write>(
    key: &[u8; 32],
    reader: &mut R,
    writer: &mut W,
) -> Result<u64, CryptoError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| CryptoError::DecryptionError(format!("Invalid key: {}", e)))?;

    let (chunk_size, base_nonce) = read_header(reader)?;

    if chunk_size == 0 || chunk_size as usize > MAX_STREAM_CHUNK_SIZE {
        return Err(CryptoError::InvalidData(format!(
            "Invalid chunk_size in header: {}", chunk_size
        )));
    }

    let max_ct_len = chunk_size as usize + TAG_SIZE;
    let mut chunk_index: u32 = 0;
    let mut total_plaintext: u64 = 0;

    loop {
        // Flag (1 byte)
        let mut flag_buf = [0u8; 1];
        if fill_buffer(reader, &mut flag_buf)? == 0 {
            return Err(CryptoError::InvalidData("Unexpected EOF: expected chunk flag".into()));
        }
        let flags = flag_buf[0];

        if flags != FLAG_CONTINUATION && flags != FLAG_FINAL {
            return Err(CryptoError::InvalidData(format!(
                "Invalid chunk flag: 0x{:02x}", flags
            )));
        }

        // Ciphertext length (4 bytes LE)
        let mut len_buf = [0u8; 4];
        read_exact(reader, &mut len_buf)?;
        let ct_len = u32::from_le_bytes(len_buf) as usize;

        if ct_len > max_ct_len {
            return Err(CryptoError::InvalidData(format!(
                "Chunk ciphertext too large: {} (max {})", ct_len, max_ct_len
            )));
        }

        // Ciphertext
        let mut ct_buf = vec![0u8; ct_len];
        read_exact(reader, &mut ct_buf)?;

        let nonce = derive_chunk_nonce(&base_nonce, chunk_index);
        let aad = build_aad(chunk_index, flags);

        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: &ct_buf, aad: &aad },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        ct_buf.zeroize();

        writer.write_all(&plaintext).map_err(io_dec_err)?;
        total_plaintext += plaintext.len() as u64;

        chunk_index += 1;

        if flags == FLAG_FINAL {
            break;
        }

        if chunk_index > MAX_CHUNK_COUNT {
            return Err(CryptoError::DecryptionError("Max chunk count exceeded".into()));
        }
    }

    writer.flush().map_err(io_dec_err)?;
    Ok(total_plaintext)
}

/// Vérifie si des bytes commencent par le magic SENC v1.
pub fn is_senc_format(header_bytes: &[u8]) -> bool {
    header_bytes.len() >= SENC_MAGIC.len() && &header_bytes[..SENC_MAGIC.len()] == SENC_MAGIC
}

// ═══════════════════════════════════════════════════════
// Fonctions internes
// ═══════════════════════════════════════════════════════

fn derive_chunk_nonce(base: &[u8; NONCE_SIZE], counter: u32) -> [u8; NONCE_SIZE] {
    let mut nonce = *base;
    let cb = counter.to_le_bytes();
    nonce[8] ^= cb[0];
    nonce[9] ^= cb[1];
    nonce[10] ^= cb[2];
    nonce[11] ^= cb[3];
    nonce
}

fn build_aad(chunk_index: u32, flags: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(17);
    aad.extend_from_slice(b"senc-v1:");
    aad.extend_from_slice(&(chunk_index as u64).to_be_bytes());
    aad.push(flags);
    aad
}

fn write_header<W: Write>(w: &mut W, chunk_size: u32, nonce: &[u8; NONCE_SIZE]) -> Result<(), CryptoError> {
    w.write_all(SENC_MAGIC).map_err(io_enc_err)?;
    w.write_all(&chunk_size.to_le_bytes()).map_err(io_enc_err)?;
    w.write_all(nonce).map_err(io_enc_err)?;
    Ok(())
}

fn read_header<R: Read>(r: &mut R) -> Result<(u32, [u8; NONCE_SIZE]), CryptoError> {
    let mut buf = [0u8; SENC_HEADER_SIZE];
    read_exact(r, &mut buf)?;
    if &buf[..6] != SENC_MAGIC {
        return Err(CryptoError::InvalidData("Invalid SENC magic — not a streaming encrypted file".into()));
    }
    let chunk_size = u32::from_le_bytes([buf[6], buf[7], buf[8], buf[9]]);
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&buf[10..22]);
    Ok((chunk_size, nonce))
}

fn encrypt_and_write<W: Write>(
    cipher: &ChaCha20Poly1305,
    base_nonce: &[u8; NONCE_SIZE],
    chunk_index: u32,
    flags: u8,
    plaintext: &[u8],
    writer: &mut W,
) -> Result<(), CryptoError> {
    let nonce = derive_chunk_nonce(base_nonce, chunk_index);
    let aad = build_aad(chunk_index, flags);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
        .map_err(|e| CryptoError::EncryptionError(format!("AEAD encrypt failed: {}", e)))?;
    writer.write_all(&[flags]).map_err(io_enc_err)?;
    writer.write_all(&(ct.len() as u32).to_le_bytes()).map_err(io_enc_err)?;
    writer.write_all(&ct).map_err(io_enc_err)?;
    Ok(())
}

fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<(), CryptoError> {
    r.read_exact(buf)
        .map_err(|e| CryptoError::InvalidData(format!("Read error / unexpected EOF: {}", e)))
}

/// Remplit `buf` autant que possible. Retourne le nombre de bytes lus (0 = EOF).
fn fill_buffer<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<usize, CryptoError> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CryptoError::EncryptionError(format!("Read error: {}", e))),
        }
    }
    Ok(total)
}

fn io_enc_err(e: std::io::Error) -> CryptoError {
    CryptoError::EncryptionError(format!("I/O error: {}", e))
}

fn io_dec_err(e: std::io::Error) -> CryptoError {
    CryptoError::DecryptionError(format!("I/O error: {}", e))
}

// ═══════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_round_trip_small() {
        let key = test_key();
        let plaintext = b"Hello, streaming encryption!";
        let mut enc = Vec::new();
        let written = encrypt_stream(&key, &mut &plaintext[..], &mut enc, 0).unwrap();
        assert_eq!(written, plaintext.len() as u64);
        let mut dec = Vec::new();
        let read = decrypt_stream(&key, &mut &enc[..], &mut dec).unwrap();
        assert_eq!(read, plaintext.len() as u64);
        assert_eq!(&dec, plaintext);
    }

    #[test]
    fn test_round_trip_empty() {
        let key = test_key();
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &[][..], &mut enc, 0).unwrap();
        let mut dec = Vec::new();
        let read = decrypt_stream(&key, &mut &enc[..], &mut dec).unwrap();
        assert_eq!(read, 0);
        assert!(dec.is_empty());
    }

    #[test]
    fn test_round_trip_exact_chunk_size() {
        let key = test_key();
        let cs = 256;
        let pt = vec![0xAB; cs];
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &pt[..], &mut enc, cs).unwrap();
        let mut dec = Vec::new();
        decrypt_stream(&key, &mut &enc[..], &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_round_trip_multi_chunk() {
        let key = test_key();
        let cs = 128;
        let pt = vec![0x42; 500]; // ~4 chunks
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &pt[..], &mut enc, cs).unwrap();
        let mut dec = Vec::new();
        decrypt_stream(&key, &mut &enc[..], &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_round_trip_large() {
        let key = test_key();
        let pt: Vec<u8> = (0..=255u8).cycle().take(1_000_000).collect();
        let mut enc = Vec::new();
        let written = encrypt_stream(&key, &mut &pt[..], &mut enc, DEFAULT_STREAM_CHUNK_SIZE).unwrap();
        assert_eq!(written, 1_000_000);
        let mut dec = Vec::new();
        let read = decrypt_stream(&key, &mut &enc[..], &mut dec).unwrap();
        assert_eq!(read, 1_000_000);
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_round_trip_one_byte() {
        let key = test_key();
        let pt = [0x42u8];
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &pt[..], &mut enc, 64).unwrap();
        let mut dec = Vec::new();
        decrypt_stream(&key, &mut &enc[..], &mut dec).unwrap();
        assert_eq!(dec, &pt);
    }

    #[test]
    fn test_round_trip_chunk_plus_one() {
        let key = test_key();
        let cs = 256;
        let pt = vec![0xCD; cs + 1]; // 1 full chunk + 1 byte
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &pt[..], &mut enc, cs).unwrap();
        let mut dec = Vec::new();
        decrypt_stream(&key, &mut &enc[..], &mut dec).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_wrong_key_fails() {
        let k1 = test_key();
        let k2 = test_key();
        let pt = b"Secret";
        let mut enc = Vec::new();
        encrypt_stream(&k1, &mut &pt[..], &mut enc, 0).unwrap();
        let result = decrypt_stream(&k2, &mut &enc[..], &mut Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let pt = b"Tamper test";
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &pt[..], &mut enc, 0).unwrap();
        let ct_start = SENC_HEADER_SIZE + 1 + 4;
        if enc.len() > ct_start + 5 {
            enc[ct_start + 5] ^= 0xFF;
        }
        assert!(decrypt_stream(&key, &mut &enc[..], &mut Vec::new()).is_err());
    }

    #[test]
    fn test_truncated_stream_fails() {
        let key = test_key();
        let pt = vec![0x42; 500];
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &pt[..], &mut enc, 128).unwrap();
        let trunc = &enc[..enc.len() / 2];
        assert!(decrypt_stream(&key, &mut &trunc[..], &mut Vec::new()).is_err());
    }

    #[test]
    fn test_is_senc_format() {
        assert!(is_senc_format(SENC_MAGIC));
        assert!(is_senc_format(b"SENC\x01\x00extra"));
        assert!(!is_senc_format(b"v2:abc"));
        assert!(!is_senc_format(b"SHORT"));
        assert!(!is_senc_format(b""));
    }

    #[test]
    fn test_nonce_uniqueness() {
        let base = [0u8; 12];
        let n0 = derive_chunk_nonce(&base, 0);
        let n1 = derive_chunk_nonce(&base, 1);
        let n2 = derive_chunk_nonce(&base, 2);
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_chunk_size_too_large() {
        let key = test_key();
        let result = encrypt_stream(&key, &mut &b"data"[..], &mut Vec::new(), MAX_STREAM_CHUNK_SIZE + 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_header_format() {
        let key = test_key();
        let cs = 1024;
        let mut enc = Vec::new();
        encrypt_stream(&key, &mut &b"test"[..], &mut enc, cs).unwrap();
        assert_eq!(&enc[..6], SENC_MAGIC);
        let stored = u32::from_le_bytes([enc[6], enc[7], enc[8], enc[9]]);
        assert_eq!(stored, cs as u32);
    }
}

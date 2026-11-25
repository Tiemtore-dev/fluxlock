//! # TOTP (RFC 6238 / RFC 4226), Validation Luhn (ISO/IEC 7812-1) & IETF SD-JWT
//!
//! Implémentation pure Rust des standards :
//! - **RFC 4226** : HOTP (HMAC-Based One-Time Password Algorithm)
//! - **RFC 6238** : TOTP (Time-Based One-Time Password Algorithm — SHA-1, SHA-256, SHA-512)
//! - **RFC 4648 §6** : Décodage/encodage Base32 sans fuite mémoire (`Zeroizing`)
//! - **ISO/IEC 7812-1** : Algorithme de Luhn et détection d'émetteur de carte bancaire
//! - **IETF SD-JWT** (`draft-ietf-oauth-selective-disclosure-jwt`) : Divulgation sélective
//!   de justificatifs d'identité signés par Ed25519 ou ML-DSA-65 (FIPS 204).

use crate::errors::{CryptoError, Result};
use crate::signatures::ed25519::{sign_message, verify_signature_from_bytes, KeyPair as Ed25519KeyPair};
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
    Engine as _,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Algorithmes HMAC supportés par RFC 6238.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    pub fn from_str_ignore_case(s: &str) -> Result<Self> {
        match s.trim().to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" => Ok(Self::Sha1),
            "SHA256" => Ok(Self::Sha256),
            "SHA512" => Ok(Self::Sha512),
            other => Err(CryptoError::InvalidData(format!(
                "Algorithme TOTP non supporté: {}",
                other
            ))),
        }
    }
}

/// Configuration TOTP extraite d'un secret Base32 brut ou d'une URI `otpauth://totp/...`
pub struct TotpConfig {
    pub secret: Zeroizing<Vec<u8>>,
    pub algorithm: TotpAlgorithm,
    pub digits: u8,
    pub period: u64,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Drop for TotpConfig {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Résultat d'une génération TOTP RFC 6238
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpOutput {
    pub code: String,
    pub period: u64,
    pub remaining_seconds: u64,
    pub digits: u8,
    pub algorithm: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// FIPS 180-4 SHA-1 & RFC 2104 HMAC-SHA1 (Pure Rust, requis par RFC 6238/4226)
// ═══════════════════════════════════════════════════════════════════════════

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn hmac_sha1(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 20]> {
    let mut k_block = Zeroizing::new([0u8; 64]);
    if key.len() > 64 {
        let hashed = sha1_digest(key);
        k_block[..20].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = Zeroizing::new(Vec::with_capacity(64 + message.len()));
    let mut opad = Zeroizing::new([0u8; 64 + 20]);
    for i in 0..64 {
        ipad.push(k_block[i] ^ 0x36);
        opad[i] = k_block[i] ^ 0x5c;
    }
    ipad.extend_from_slice(message);
    let inner = sha1_digest(&ipad);
    opad[64..84].copy_from_slice(&inner);
    Zeroizing::new(sha1_digest(opad.as_slice()))
}

// ═══════════════════════════════════════════════════════════════════════════
// RFC 4648 §6 Base32 Decode / Encode
// ═══════════════════════════════════════════════════════════════════════════

/// Décode une chaîne Base32 (RFC 4648) en octets protégés par `Zeroizing`.
/// Ignore les espaces, tirets et caractères de remplissage `=`.
pub fn base32_decode(input: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;
    let mut output = Zeroizing::new(Vec::with_capacity((input.len() * 5) / 8 + 1));

    for ch in input.chars() {
        if ch == '=' || ch.is_ascii_whitespace() || ch == '-' {
            continue;
        }
        let val: u32 = match ch.to_ascii_uppercase() {
            'A'..='Z' => (ch.to_ascii_uppercase() as u32) - ('A' as u32),
            '2'..='7' => (ch as u32) - ('2' as u32) + 26,
            _ => {
                return Err(CryptoError::InvalidData(format!(
                    "Caractère Base32 invalide: '{}'",
                    ch
                )))
            }
        };
        buffer = (buffer << 5) | val;
        bits_left += 5;
        if bits_left >= 8 {
            bits_left -= 8;
            output.push(((buffer >> bits_left) & 0xFF) as u8);
        }
    }

    if output.is_empty() {
        return Err(CryptoError::InvalidData(
            "Le secret TOTP Base32 est vide".to_string(),
        ));
    }
    Ok(output)
}

/// Encode des octets en Base32 (RFC 4648, sans padding `=`)
pub fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;

    for &byte in data {
        buffer = (buffer << 8) | (byte as u32);
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let idx = ((buffer >> bits_left) & 0x1F) as usize;
            result.push(ALPHABET[idx] as char);
        }
    }
    if bits_left > 0 {
        let idx = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        result.push(ALPHABET[idx] as char);
    }
    result
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl TotpConfig {
    /// Parse soit une URI standard `otpauth://totp/Label?secret=BASE32&issuer=...&algorithm=SHA1&digits=6&period=30`,
    /// soit directement une clé secrète Base32 brute.
    pub fn parse(secret_or_uri: &str) -> Result<Self> {
        let trimmed = secret_or_uri.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::InvalidData("Secret TOTP vide".to_string()));
        }

        if let Some(rest) = trimmed.strip_prefix("otpauth://") {
            let (kind_and_label, query) = rest.split_once('?').ok_or_else(|| {
                CryptoError::InvalidData("URI otpauth:// invalide (paramètres manquants)".into())
            })?;
            let (kind, raw_label) = kind_and_label.split_once('/').unwrap_or((kind_and_label, ""));
            if !kind.eq_ignore_ascii_case("totp") {
                return Err(CryptoError::InvalidData(format!(
                    "Type OTP non supporté (attendu totp, reçu {})",
                    kind
                )));
            }

            let decoded_label = percent_decode(raw_label);
            let (mut issuer, account) = if let Some((iss, acc)) = decoded_label.split_once(':') {
                (
                    Some(iss.trim().to_string()),
                    Some(acc.trim().to_string()),
                )
            } else if !decoded_label.trim().is_empty() {
                (None, Some(decoded_label.trim().to_string()))
            } else {
                (None, None)
            };

            let mut secret: Option<Zeroizing<Vec<u8>>> = None;
            let mut algorithm = TotpAlgorithm::Sha1;
            let mut digits: u8 = 6;
            let mut period: u64 = 30;

            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                let v_decoded = percent_decode(v);
                match k.to_ascii_lowercase().as_str() {
                    "secret" => {
                        secret = Some(base32_decode(&v_decoded)?);
                    }
                    "issuer" => {
                        if !v_decoded.trim().is_empty() {
                            issuer = Some(v_decoded.trim().to_string());
                        }
                    }
                    "algorithm" => {
                        algorithm = TotpAlgorithm::from_str_ignore_case(&v_decoded)?;
                    }
                    "digits" => {
                        digits = v_decoded.parse::<u8>().map_err(|_| {
                            CryptoError::InvalidData("Paramètre digits invalide".into())
                        })?;
                        if digits != 6 && digits != 7 && digits != 8 {
                            return Err(CryptoError::InvalidData(
                                "Le nombre de chiffres TOTP doit être 6, 7 ou 8".into(),
                            ));
                        }
                    }
                    "period" => {
                        period = v_decoded.parse::<u64>().map_err(|_| {
                            CryptoError::InvalidData("Paramètre period invalide".into())
                        })?;
                        if period == 0 || period > 300 {
                            return Err(CryptoError::InvalidData(
                                "La période TOTP doit être comprise entre 1 et 300 secondes".into(),
                            ));
                        }
                    }
                    _ => {}
                }
            }

            let secret = secret.ok_or_else(|| {
                CryptoError::InvalidData("Paramètre 'secret' absent de l'URI otpauth://".into())
            })?;

            Ok(Self {
                secret,
                algorithm,
                digits,
                period,
                issuer,
                account,
            })
        } else {
            let secret = base32_decode(trimmed)?;
            Ok(Self {
                secret,
                algorithm: TotpAlgorithm::Sha1,
                digits: 6,
                period: 30,
                issuer: None,
                account: None,
            })
        }
    }

    /// Convertit cette configuration en URI canonique `otpauth://totp/...`
    pub fn to_otpauth_uri(&self, fallback_issuer: &str) -> Zeroizing<String> {
        let issuer = self
            .issuer
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(fallback_issuer);
        let account = self.account.as_deref().unwrap_or("");
        let b32 = Zeroizing::new(base32_encode(&self.secret));
        Zeroizing::new(format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            issuer.replace(':', " "),
            account.replace(':', " "),
            b32.as_str(),
            issuer,
            self.algorithm.as_str(),
            self.digits,
            self.period
        ))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Décodeur Protobuf Pur-Rust pour Google Authenticator (`otpauth-migration://`)
// ═══════════════════════════════════════════════════════════════════════════

fn read_protobuf_varint(data: &[u8], pos: &mut usize) -> Result<u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    while *pos < data.len() {
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
        if shift >= 64 {
            return Err(CryptoError::InvalidData("Varint Protobuf hors limites".into()));
        }
    }
    Err(CryptoError::InvalidData("Fin inattendue de flux Protobuf".into()))
}

fn read_protobuf_length_delimited<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    let len = read_protobuf_varint(data, pos)? as usize;
    if *pos + len > data.len() {
        return Err(CryptoError::InvalidData(
            "Champ Protobuf length-delimited tronqué".into(),
        ));
    }
    let slice = &data[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

fn skip_protobuf_field(data: &[u8], pos: &mut usize, wire_type: u64) -> Result<()> {
    match wire_type {
        0 => {
            let _ = read_protobuf_varint(data, pos)?;
            Ok(())
        }
        1 => {
            if *pos + 8 > data.len() {
                return Err(CryptoError::InvalidData("Champ Protobuf 64-bit tronqué".into()));
            }
            *pos += 8;
            Ok(())
        }
        2 => {
            let _ = read_protobuf_length_delimited(data, pos)?;
            Ok(())
        }
        5 => {
            if *pos + 4 > data.len() {
                return Err(CryptoError::InvalidData("Champ Protobuf 32-bit tronqué".into()));
            }
            *pos += 4;
            Ok(())
        }
        _ => Err(CryptoError::InvalidData(format!(
            "Wire type Protobuf inconnu: {}",
            wire_type
        ))),
    }
}

fn parse_otp_parameters_proto(buf: &[u8]) -> Result<Option<TotpConfig>> {
    let mut pos = 0;
    let mut secret = Zeroizing::new(Vec::new());
    let mut name = String::new();
    let mut issuer = String::new();
    let mut alg_enum: u64 = 1; // 1 = SHA1
    let mut digits_enum: u64 = 1; // 1 = 6 digits
    let mut otp_type_enum: u64 = 2; // 2 = TOTP

    while pos < buf.len() {
        let tag = read_protobuf_varint(buf, &mut pos)?;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        match (field_number, wire_type) {
            (1, 2) => {
                // bytes secret = 1
                let bytes = read_protobuf_length_delimited(buf, &mut pos)?;
                *secret = bytes.to_vec();
            }
            (2, 2) => {
                // string name = 2
                let bytes = read_protobuf_length_delimited(buf, &mut pos)?;
                name = String::from_utf8_lossy(bytes).trim().to_string();
            }
            (3, 2) => {
                // string issuer = 3
                let bytes = read_protobuf_length_delimited(buf, &mut pos)?;
                issuer = String::from_utf8_lossy(bytes).trim().to_string();
            }
            (4, 0) => {
                // Algorithm algorithm = 4
                alg_enum = read_protobuf_varint(buf, &mut pos)?;
            }
            (5, 0) => {
                // DigitCount digits = 5
                digits_enum = read_protobuf_varint(buf, &mut pos)?;
            }
            (6, 0) => {
                // OtpType type = 6 (1 = HOTP, 2 = TOTP)
                otp_type_enum = read_protobuf_varint(buf, &mut pos)?;
            }
            _ => {
                skip_protobuf_field(buf, &mut pos, wire_type)?;
            }
        }
    }

    if secret.is_empty() {
        return Ok(None);
    }
    // Ignorer les compteurs HOTP purs si non-TOTP (2 = TOTP, 0 = non spécifié -> défaut TOTP)
    if otp_type_enum == 1 {
        return Ok(None);
    }

    let algorithm = match alg_enum {
        0 | 1 => TotpAlgorithm::Sha1,
        2 => TotpAlgorithm::Sha256,
        3 => TotpAlgorithm::Sha512,
        other => {
            return Err(CryptoError::InvalidData(format!(
                "Algorithme Google Authenticator Migration non supporté (code {})",
                other
            )))
        }
    };

    let digits = match digits_enum {
        0 | 1 => 6,
        2 => 8,
        _ => 6,
    };

    // Si name est de la forme "Issuer:Account" et que issuer est vide
    let (final_issuer, final_account) = if let Some((pref_iss, acc)) = name.split_once(':') {
        let iss = if !issuer.is_empty() {
            issuer
        } else {
            pref_iss.trim().to_string()
        };
        (
            if iss.is_empty() { None } else { Some(iss) },
            Some(acc.trim().to_string()),
        )
    } else {
        (
            if issuer.is_empty() { None } else { Some(issuer) },
            if name.is_empty() { None } else { Some(name) },
        )
    };

    Ok(Some(TotpConfig {
        secret,
        algorithm,
        digits,
        period: 30,
        issuer: final_issuer,
        account: final_account,
    }))
}

/// Décode une URI de migration par lot Google Authenticator :
/// `otpauth-migration://offline?data=<URL_Encoded_Base64_Protobuf>`
/// Retourne tous les comptes TOTP extraits du lot en mémoire sécurisée (`Zeroizing`).
pub fn parse_otpauth_migration_uri(uri: &str) -> Result<Vec<TotpConfig>> {
    let trimmed = uri.trim();
    let rest = trimmed
        .strip_prefix("otpauth-migration://offline?")
        .or_else(|| trimmed.strip_prefix("otpauth-migration://offline/?"))
        .ok_or_else(|| {
            CryptoError::InvalidData(
                "URI de migration invalide (attendu otpauth-migration://offline?data=...)".into(),
            )
        })?;

    let mut data_param: Option<String> = None;
    for pair in rest.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k.eq_ignore_ascii_case("data") {
            data_param = Some(percent_decode(v));
            break;
        }
    }

    let b64_str = data_param
        .ok_or_else(|| CryptoError::InvalidData("Paramètre 'data' manquant dans otpauth-migration://".into()))?;
    let clean_b64: String = b64_str.chars().filter(|c| !c.is_ascii_whitespace()).collect();

    let decoded = Zeroizing::new(
        STANDARD
            .decode(&clean_b64)
            .or_else(|_| STANDARD_NO_PAD.decode(clean_b64.trim_end_matches('=')))
            .or_else(|_| URL_SAFE.decode(&clean_b64))
            .or_else(|_| URL_SAFE_NO_PAD.decode(clean_b64.trim_end_matches('=')))
            .map_err(|e| CryptoError::InvalidData(format!("Base64 otpauth-migration invalide: {}", e)))?,
    );

    let mut pos = 0;
    let mut configs = Vec::new();
    while pos < decoded.len() {
        let tag = read_protobuf_varint(&decoded, &mut pos)?;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;
        if field_number == 1 && wire_type == 2 {
            let sub = read_protobuf_length_delimited(&decoded, &mut pos)?;
            if let Some(cfg) = parse_otp_parameters_proto(sub)? {
                configs.push(cfg);
            }
        } else {
            skip_protobuf_field(&decoded, &mut pos, wire_type)?;
        }
    }

    if configs.is_empty() {
        return Err(CryptoError::InvalidData(
            "Aucun compte TOTP valide trouvé dans le lot otpauth-migration://".into(),
        ));
    }
    Ok(configs)
}

/// Analyseur universel d'import et de migration TOTP :
/// Accepte un bloc de texte contenant une ou plusieurs lignes parmi :
/// - `otpauth-migration://offline?data=...` (Lot Google Authenticator Protobuf — jusqu'à 50 comptes d'un coup)
/// - `otpauth://totp/...` (Export multi-lignes 2FAS, Aegis, Raivo, Bitwarden, Proton Pass ou QR standard)
/// - Une clé secrète Base32 brute (`JBSWY3DPEHPK3PXP`)
pub fn parse_totp_migration_input(input: &str) -> Result<Vec<TotpConfig>> {
    let mut results = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("otpauth-migration://") {
            let mut batch = parse_otpauth_migration_uri(trimmed)?;
            results.append(&mut batch);
        } else {
            results.push(TotpConfig::parse(trimmed)?);
        }
    }
    if results.is_empty() {
        return Err(CryptoError::InvalidData(
            "Aucune URI otpauth://, otpauth-migration:// ou clé Base32 trouvée".into(),
        ));
    }
    Ok(results)
}

// ═══════════════════════════════════════════════════════════════════════════
// Analyseur d'image QR Code 100% Pur Rust Multiplateforme (macOS, Windows, Linux, Android)
// ═══════════════════════════════════════════════════════════════════════════

/// Décode en mémoire vive (100% pur Rust via `image` + `rqrr`, zéro dépendance C/OS,
/// compatible macOS, Windows, Linux et Android) un ou plusieurs QR Codes contenus
/// dans une image (PNG, JPEG, WebP, BMP, GIF).
pub fn decode_qr_image_bytes(image_bytes: &[u8]) -> Result<Zeroizing<String>> {
    if image_bytes.is_empty() || image_bytes.len() > 15 * 1024 * 1024 {
        return Err(CryptoError::InvalidData(
            "Taille d'image QR invalide (max 15 Mo)".into(),
        ));
    }

    let dyn_img = image::load_from_memory(image_bytes).map_err(|e| {
        CryptoError::InvalidData(format!(
            "Format d'image non reconnu (PNG, JPEG, WebP, BMP supportés): {}",
            e
        ))
    })?;

    let luma = dyn_img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(luma);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err(CryptoError::InvalidData(
            "Aucun QR Code détecté dans cette image. Vérifiez que le QR Code est net et bien cadré.".into(),
        ));
    }

    let mut payloads = Zeroizing::new(String::new());
    for grid in grids {
        let mut raw_bytes = Zeroizing::new(Vec::new());
        if grid.decode_to(&mut *raw_bytes).is_ok() {
            let content = String::from_utf8_lossy(&raw_bytes);
            if !content.trim().is_empty() {
                if !payloads.is_empty() {
                    payloads.push('\n');
                }
                payloads.push_str(content.trim());
            }
        }
    }

    if payloads.is_empty() {
        return Err(CryptoError::InvalidData(
            "Le QR Code a été détecté mais son contenu n'a pas pu être décodé.".into(),
        ));
    }

    Ok(payloads)
}

/// Calcule un code HOTP (RFC 4226 §5.3) par troncature dynamique (Dynamic Truncation)
pub fn generate_hotp_raw(
    secret: &[u8],
    counter: u64,
    algorithm: TotpAlgorithm,
    digits: u8,
) -> Result<String> {
    if !(6..=8).contains(&digits) {
        return Err(CryptoError::InvalidData(
            "Le nombre de chiffres HOTP/TOTP doit être entre 6 et 8".into(),
        ));
    }
    let counter_bytes = counter.to_be_bytes();

    let mac_bytes: Zeroizing<Vec<u8>> = match algorithm {
        TotpAlgorithm::Sha1 => {
            let digest = hmac_sha1(secret, &counter_bytes);
            Zeroizing::new(digest.to_vec())
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(secret)
                .map_err(|e| CryptoError::Generic(format!("HMAC-SHA256 init: {}", e)))?;
            mac.update(&counter_bytes);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(secret)
                .map_err(|e| CryptoError::Generic(format!("HMAC-SHA512 init: {}", e)))?;
            mac.update(&counter_bytes);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
    };

    // Dynamic Truncation — RFC 4226 §5.4
    let offset = (mac_bytes[mac_bytes.len() - 1] & 0x0f) as usize;
    let binary: u32 = (((mac_bytes[offset] & 0x7f) as u32) << 24)
        | ((mac_bytes[offset + 1] as u32) << 16)
        | ((mac_bytes[offset + 2] as u32) << 8)
        | (mac_bytes[offset + 3] as u32);

    let modulus = 10u32.pow(digits as u32);
    let otp = binary % modulus;
    Ok(format!("{:0width$}", otp, width = digits as usize))
}

/// Génère le code TOTP (RFC 6238) pour un timestamp UNIX (secondes) donné.
pub fn generate_totp(secret_or_uri: &str, unix_timestamp: u64) -> Result<TotpOutput> {
    let config = TotpConfig::parse(secret_or_uri)?;
    let counter = unix_timestamp / config.period;
    let remaining_seconds = config.period - (unix_timestamp % config.period);
    let code = generate_hotp_raw(&config.secret, counter, config.algorithm, config.digits)?;

    Ok(TotpOutput {
        code,
        period: config.period,
        remaining_seconds,
        digits: config.digits,
        algorithm: config.algorithm.as_str().to_string(),
        issuer: config.issuer.clone(),
        account: config.account.clone(),
    })
}

/// Vérifie un code TOTP en temps constant avec une fenêtre de tolérance RFC 6238 §5.2
/// (`skew_steps = 1` vérifie `[T - 1, T, T + 1]`, soit ±30s).
pub fn verify_totp_window(
    secret_or_uri: &str,
    candidate_code: &str,
    unix_timestamp: u64,
    skew_steps: u64,
) -> Result<bool> {
    let config = TotpConfig::parse(secret_or_uri)?;
    let normalized = candidate_code.trim();
    if normalized.len() != config.digits as usize {
        return Ok(false);
    }

    let current_step = unix_timestamp / config.period;
    let start_step = current_step.saturating_sub(skew_steps);
    let end_step = current_step.saturating_add(skew_steps);

    let mut matched = 0u8;
    for step in start_step..=end_step {
        let expected = generate_hotp_raw(&config.secret, step, config.algorithm, config.digits)?;
        let eq: bool = expected.as_bytes().ct_eq(normalized.as_bytes()).into();
        matched |= u8::from(eq);
    }

    Ok(matched == 1)
}

// ═══════════════════════════════════════════════════════════════════════════
// ISO/IEC 7812-1 — Validation de Luhn & Détection d'émetteur de carte bancaire
// ═══════════════════════════════════════════════════════════════════════════

/// Nettoie un numéro de carte (PAN) en ne conservant que les chiffres ASCII.
pub fn sanitize_card_pan(pan: &str) -> Zeroizing<String> {
    Zeroizing::new(pan.chars().filter(|c| c.is_ascii_digit()).collect())
}

/// Valide un numéro de carte bancaire selon l'algorithme de Luhn (ISO/IEC 7812-1).
pub fn validate_luhn(pan: &str) -> bool {
    let digits = sanitize_card_pan(pan);
    if digits.len() < 12 || digits.len() > 19 {
        return false;
    }

    let mut sum: u32 = 0;
    let mut double = false;
    for ch in digits.chars().rev() {
        let mut d = (ch as u8 - b'0') as u32;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum % 10 == 0
}

/// Détecte le réseau émetteur d'une carte bancaire à partir de son préfixe IIN/BIN.
pub fn detect_card_brand(pan: &str) -> &'static str {
    let digits = sanitize_card_pan(pan);
    let s = digits.as_str();
    if s.starts_with('4') {
        "Visa"
    } else if s.starts_with("34") || s.starts_with("37") {
        "American Express"
    } else if s.starts_with("51")
        || s.starts_with("52")
        || s.starts_with("53")
        || s.starts_with("54")
        || s.starts_with("55")
        || (s.len() >= 4
            && s[..4]
                .parse::<u16>()
                .is_ok_and(|p| (2221..=2720).contains(&p)))
    {
        "Mastercard"
    } else if s.starts_with("6011") || s.starts_with("65") {
        "Discover"
    } else if s.starts_with("35") {
        "JCB"
    } else if s.starts_with("62") {
        "UnionPay"
    } else {
        "Carte Bancaire"
    }
}

/// Retourne les 4 derniers chiffres non sensibles d'un PAN (pour affichage masqué).
pub fn extract_card_last4(pan: &str) -> String {
    let digits = sanitize_card_pan(pan);
    if digits.len() <= 4 {
        digits.as_str().to_string()
    } else {
        digits[digits.len() - 4..].to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// IETF SD-JWT (Selective Disclosure for JWTs) — EUDI Wallet / eIDAS 2.0 Ready
// ═══════════════════════════════════════════════════════════════════════════

/// Claim divulguable sélectivement (`[salt, claim_name, claim_value]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdJwtClaim {
    pub name: String,
    pub value: String,
}

/// Jeton SD-JWT émis avec ses disclosures sélectives et la clé publique du détenteur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedSdJwt {
    /// Format compact `<issuer_jwt>~<disclosure_1>~...~<disclosure_n>~`
    pub compact_sd_jwt: String,
    /// Clé publique Ed25519 (base64url) permettant de vérifier le justificatif
    pub issuer_public_key_b64url: String,
    /// Liste des digests SHA-256 (`_sd`) inclus dans le payload signé
    pub sd_digests: Vec<String>,
}

/// Émet un justificatif d'identité au format IETF SD-JWT (`draft-ietf-oauth-selective-disclosure-jwt`)
/// signé avec Ed25519. Chaque attribut d'identité est salé avec 128 bits d'entropie CSPRNG
/// et haché avec SHA-256 (`_sd_alg: "sha-256"`), permettant au citoyen de ne révéler
/// que les attributs strictement nécessaires.
pub fn issue_sd_jwt(
    doc_type: &str,
    subject_id: &str,
    claims: &[SdJwtClaim],
    issued_at_unix: u64,
) -> Result<IssuedSdJwt> {
    let keypair = Ed25519KeyPair::generate();
    let pub_b64 = URL_SAFE_NO_PAD.encode(keypair.public_key.as_bytes());

    let mut disclosures_b64 = Vec::with_capacity(claims.len());
    let mut sd_digests = Vec::with_capacity(claims.len());

    for claim in claims {
        let mut salt_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt_bytes);
        let salt_b64 = URL_SAFE_NO_PAD.encode(salt_bytes);

        let disclosure_json = serde_json::to_string(&(&salt_b64, &claim.name, &claim.value))
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        let disclosure_b64 = URL_SAFE_NO_PAD.encode(disclosure_json.as_bytes());

        let digest = Sha256::digest(disclosure_b64.as_bytes());
        let digest_b64 = URL_SAFE_NO_PAD.encode(digest);

        disclosures_b64.push(disclosure_b64);
        sd_digests.push(digest_b64);
    }

    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "vc+sd-jwt",
        "kid": &pub_b64,
    });
    let payload = serde_json::json!({
        "iss": "urn:fluxlock:self-sovereign-vault",
        "sub": subject_id,
        "vct": doc_type,
        "iat": issued_at_unix,
        "_sd_alg": "sha-256",
        "_sd": &sd_digests,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|e| CryptoError::SerializationError(e.to_string()))?,
    );
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload).map_err(|e| CryptoError::SerializationError(e.to_string()))?,
    );

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = sign_message(signing_input.as_bytes(), &keypair);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

    let mut compact = format!("{}.{}.{}", header_b64, payload_b64, sig_b64);
    for d in &disclosures_b64 {
        compact.push('~');
        compact.push_str(d);
    }
    compact.push('~');

    Ok(IssuedSdJwt {
        compact_sd_jwt: compact,
        issuer_public_key_b64url: pub_b64,
        sd_digests,
    })
}

/// Vérifie la signature EdDSA d'un SD-JWT et retourne les attributs divulgués dont
/// l'empreinte SHA-256 figure bien dans le tableau `_sd` signé.
pub fn verify_sd_jwt(
    compact_sd_jwt: &str,
    issuer_public_key_b64url: &str,
) -> Result<Vec<SdJwtClaim>> {
    let parts: Vec<&str> = compact_sd_jwt.split('~').collect();
    if parts.is_empty() {
        return Err(CryptoError::InvalidData("SD-JWT vide".into()));
    }

    let jwt_parts: Vec<&str> = parts[0].split('.').collect();
    if jwt_parts.len() != 3 {
        return Err(CryptoError::InvalidData("En-tête JWT malformé".into()));
    }

    let signing_input = format!("{}.{}", jwt_parts[0], jwt_parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[2])
        .map_err(|e| CryptoError::InvalidData(format!("Signature base64url: {}", e)))?;
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(issuer_public_key_b64url)
        .map_err(|e| CryptoError::InvalidData(format!("Clé publique base64url: {}", e)))?;
    let pub_arr: [u8; 32] = pub_bytes.try_into().map_err(|v: Vec<u8>| {
        CryptoError::InvalidKeySize {
            expected: 32,
            actual: v.len(),
        }
    })?;

    let valid = verify_signature_from_bytes(signing_input.as_bytes(), &sig_bytes, &pub_arr);
    if !valid {
        return Err(CryptoError::SignatureVerificationFailed);
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(jwt_parts[1])
        .map_err(|e| CryptoError::InvalidData(format!("Payload base64url: {}", e)))?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| CryptoError::DeserializationError(e.to_string()))?;

    let sd_array = payload
        .get("_sd")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CryptoError::InvalidData("Champ _sd absent du payload SD-JWT".into()))?;

    let mut verified_claims = Vec::new();
    for disclosure_b64 in &parts[1..] {
        if disclosure_b64.is_empty() {
            continue;
        }
        let digest = Sha256::digest(disclosure_b64.as_bytes());
        let digest_b64 = URL_SAFE_NO_PAD.encode(digest);

        let present = sd_array
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s == digest_b64));
        if !present {
            return Err(CryptoError::AuthenticationFailed);
        }

        let raw = URL_SAFE_NO_PAD
            .decode(disclosure_b64)
            .map_err(|e| CryptoError::InvalidData(format!("Disclosure base64url: {}", e)))?;
        let tuple: (String, String, String) = serde_json::from_slice(&raw)
            .map_err(|e| CryptoError::DeserializationError(e.to_string()))?;
        verified_claims.push(SdJwtClaim {
            name: tuple.1,
            value: tuple.2,
        });
    }

    Ok(verified_claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vecteurs officiels RFC 6238 Appendix B :
    /// Secret ASCII = "12345678901234567890" (Base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    #[test]
    fn test_rfc6238_appendix_b_official_vectors() {
        let secret_sha1 = b"12345678901234567890";
        let secret_sha256 = b"12345678901234567890123456789012";
        let secret_sha512 =
            b"1234567890123456789012345678901234567890123456789012345678901234";

        let vectors: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];

        for &(timestamp, expected_sha1, expected_sha256, expected_sha512) in vectors {
            let step = timestamp / 30;
            let got_sha1 =
                generate_hotp_raw(secret_sha1, step, TotpAlgorithm::Sha1, 8).unwrap();
            let got_sha256 =
                generate_hotp_raw(secret_sha256, step, TotpAlgorithm::Sha256, 8).unwrap();
            let got_sha512 =
                generate_hotp_raw(secret_sha512, step, TotpAlgorithm::Sha512, 8).unwrap();

            assert_eq!(got_sha1, expected_sha1, "RFC 6238 SHA-1 mismatch at T={}", timestamp);
            assert_eq!(
                got_sha256, expected_sha256,
                "RFC 6238 SHA-256 mismatch at T={}",
                timestamp
            );
            assert_eq!(
                got_sha512, expected_sha512,
                "RFC 6238 SHA-512 mismatch at T={}",
                timestamp
            );
        }
    }

    #[test]
    fn test_otpauth_uri_parsing_and_window_verification() {
        let uri = "otpauth://totp/GitHub:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
        let out = generate_totp(uri, 1_700_000_000).unwrap();
        assert_eq!(out.code.len(), 6);
        assert_eq!(out.issuer.as_deref(), Some("GitHub"));
        assert_eq!(out.account.as_deref(), Some("alice@example.com"));
        assert_eq!(out.period, 30);

        // Vérification dans la fenêtre ±1 pas (±30s)
        assert!(verify_totp_window(uri, &out.code, 1_700_000_000, 1).unwrap());
        assert!(verify_totp_window(uri, &out.code, 1_700_000_025, 1).unwrap());
        assert!(!verify_totp_window(uri, "000000", 1_700_000_000, 1).unwrap());
    }

    #[test]
    fn test_google_authenticator_otpauth_migration_protobuf_batch() {
        // Construction d'un MigrationPayload Protobuf contenant 2 comptes (GitHub + AWS)
        fn encode_entry(secret: &[u8], name: &str, issuer: &str, alg: u8, digits: u8) -> Vec<u8> {
            let mut sub = Vec::new();
            // field 1 (secret): tag = (1 << 3) | 2 = 0x0A
            sub.push(0x0A);
            sub.push(secret.len() as u8);
            sub.extend_from_slice(secret);
            // field 2 (name): tag = (2 << 3) | 2 = 0x12
            sub.push(0x12);
            sub.push(name.len() as u8);
            sub.extend_from_slice(name.as_bytes());
            // field 3 (issuer): tag = (3 << 3) | 2 = 0x1A
            sub.push(0x1A);
            sub.push(issuer.len() as u8);
            sub.extend_from_slice(issuer.as_bytes());
            // field 4 (algorithm): tag = (4 << 3) | 0 = 0x20
            sub.push(0x20);
            sub.push(alg);
            // field 5 (digits): tag = (5 << 3) | 0 = 0x28
            sub.push(0x28);
            sub.push(digits);
            // field 6 (type = 2 TOTP): tag = (6 << 3) | 0 = 0x30
            sub.push(0x30);
            sub.push(2);
            sub
        }

        let e1 = encode_entry(b"12345678901234567890", "GitHub:alice@example.com", "GitHub", 1, 1);
        let e2 = encode_entry(b"12345678901234567890123456789012", "aws-root", "AWS", 2, 2);

        let mut payload = Vec::new();
        payload.push(0x0A);
        payload.push(e1.len() as u8);
        payload.extend_from_slice(&e1);
        payload.push(0x0A);
        payload.push(e2.len() as u8);
        payload.extend_from_slice(&e2);
        // version = 1 (tag 0x10, val 1)
        payload.extend_from_slice(&[0x10, 0x01]);

        let b64 = STANDARD.encode(&payload);
        let uri = format!("otpauth-migration://offline?data={}", b64);

        let parsed = parse_totp_migration_input(&uri).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].issuer.as_deref(), Some("GitHub"));
        assert_eq!(parsed[0].account.as_deref(), Some("alice@example.com"));
        assert_eq!(parsed[0].algorithm, TotpAlgorithm::Sha1);
        assert_eq!(parsed[0].digits, 6);

        assert_eq!(parsed[1].issuer.as_deref(), Some("AWS"));
        assert_eq!(parsed[1].account.as_deref(), Some("aws-root"));
        assert_eq!(parsed[1].algorithm, TotpAlgorithm::Sha256);
        assert_eq!(parsed[1].digits, 8);
    }

    #[test]
    fn test_luhn_and_card_brand() {
        // Numéros de test standards conformes Luhn
        assert!(validate_luhn("4532 0151 1283 0366"));
        assert!(!validate_luhn("4532 0151 1283 0367"));
        assert_eq!(detect_card_brand("4532 0151 1283 0366"), "Visa");
        assert_eq!(detect_card_brand("5555 5555 5555 4444"), "Mastercard");
        assert_eq!(detect_card_brand("3782 822463 10005"), "American Express");
        assert_eq!(extract_card_last4("4532 0151 1283 0366"), "0366");
    }

    #[test]
    fn test_sd_jwt_selective_disclosure_roundtrip() {
        let claims = vec![
            SdJwtClaim {
                name: "given_name".into(),
                value: "Marie".into(),
            },
            SdJwtClaim {
                name: "document_number".into(),
                value: "24FR998877".into(),
            },
            SdJwtClaim {
                name: "age_over_18".into(),
                value: "true".into(),
            },
        ];
        let issued = issue_sd_jwt("eu.europa.ec.eudi.pid.1", "did:key:user1", &claims, 1700000000)
            .unwrap();
        let verified =
            verify_sd_jwt(&issued.compact_sd_jwt, &issued.issuer_public_key_b64url).unwrap();
        assert_eq!(verified.len(), 3);
        assert_eq!(verified[0].name, "given_name");
        assert_eq!(verified[0].value, "Marie");
    }
}

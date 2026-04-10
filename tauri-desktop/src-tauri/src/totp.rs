use totp_rs::{Algorithm, Secret, TOTP};
use qrcode::QrCode;
use image::Luma;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use base64::Engine;

#[derive(Debug, Serialize, Deserialize)]
pub struct TotpSetup {
    pub secret: String,
    pub qr_code_base64: String,
    pub backup_codes: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct TotpVerification {
    pub verified: bool,
    pub message: String,
}

/// Génère un secret TOTP et un QR code pour configuration
pub fn generate_totp_secret(username: &str, issuer: &str) -> Result<TotpSetup, String> {
    // Générer un secret aléatoire (32 bytes = 256 bits) avec OsRng
    let mut secret_bytes = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
    let secret = Secret::Raw(secret_bytes);
    let secret_base32 = secret.to_encoded().to_string();
    
    // Créer l'instance TOTP avec SHA-256 (SHA-1 est cryptographiquement cassé)
    let totp = TOTP::new(
        Algorithm::SHA256,
        6,  // 6 digits
        1,  // 1 step (tolérance)
        30, // 30 secondes de validité
        secret.to_bytes().unwrap(),
        Some(issuer.to_string()),
        username.to_string(),
    ).map_err(|e| format!("Erreur création TOTP: {}", e))?;
    
    // Générer l'URL otpauth pour le QR code
    let otpauth_url = totp.get_url();
    
    // Générer le QR code
    let qr = QrCode::new(otpauth_url.as_bytes())
        .map_err(|e| format!("Erreur génération QR: {}", e))?;
    
    // Convertir en image
    let image = qr.render::<Luma<u8>>().build();
    
    // Encoder en base64
    let mut buffer = Vec::new();
    image.write_to(&mut std::io::Cursor::new(&mut buffer), image::ImageFormat::Png)
        .map_err(|e| format!("Erreur encodage image: {}", e))?;
    let qr_code_base64 = base64::engine::general_purpose::STANDARD.encode(&buffer);
    
    // Générer 10 codes de backup
    let backup_codes = generate_backup_codes(10);
    
    Ok(TotpSetup {
        secret: secret_base32,
        qr_code_base64: format!("data:image/png;base64,{}", qr_code_base64),
        backup_codes,
    })
}

/// Vérifie un code TOTP
pub fn verify_totp_code(secret: &str, code: &str) -> Result<bool, String> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|e| format!("Secret invalide: {}", e))?;
    
    let totp = TOTP::new(
        Algorithm::SHA256,
        6,
        1,
        30,
        secret_bytes,
        None,
        "".to_string(),
    ).map_err(|e| format!("Erreur TOTP: {}", e))?;
    
    // Vérifier le code avec une tolérance de 1 step (±30s)
    Ok(totp.check_current(code).map_err(|e| format!("Erreur vérification: {}", e))?)
}

/// Génère des codes de backup aléatoires
fn generate_backup_codes(count: usize) -> Vec<String> {
    let mut codes = Vec::with_capacity(count);
    let chars = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Sans ambiguïtés (I, O, 0, 1)
    
    for _ in 0..count {
        let mut code_bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut code_bytes);
        
        let code: String = code_bytes.iter().enumerate()
            .map(|(i, b)| {
                let c = chars[(*b as usize) % chars.len()] as char;
                if i == 4 { format!("-{}", c) } else { c.to_string() }
            })
            .collect();
        codes.push(code);
    }
    
    codes
}

/// Vérifie un code de backup
pub fn verify_backup_code(backup_codes_json: &str, code: &str) -> Result<(bool, Vec<String>), String> {
    let mut codes: Vec<String> = serde_json::from_str(backup_codes_json)
        .map_err(|e| format!("Erreur parsing backup codes: {}", e))?;
    
    // Normaliser le code entré
    let code_upper = code.to_uppercase().replace("-", "");
    
    // Comparaison constant-time : toujours itérer sur TOUS les codes
    use subtle::ConstantTimeEq;
    let mut found_index: Option<usize> = None;
    for (i, c) in codes.iter().enumerate() {
        let stored = c.to_uppercase().replace("-", "");
        if stored.as_bytes().ct_eq(code_upper.as_bytes()).into() {
            found_index = Some(i);
        }
    }
    
    if let Some(pos) = found_index {
        codes.remove(pos);
        Ok((true, codes))
    } else {
        Ok((false, codes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        let setup = generate_totp_secret("test@example.com", "SecureVault").unwrap();
        assert!(!setup.secret.is_empty());
        assert!(setup.qr_code_base64.starts_with("data:image/png;base64,"));
        assert_eq!(setup.backup_codes.len(), 10);
    }

    #[test]
    fn test_totp_verification() {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = vec![0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = Secret::Raw(secret_bytes);
        let secret_base32 = secret.to_encoded().to_string();
        
        let totp = TOTP::new(
            Algorithm::SHA256, // VULN-018: align with production (was SHA1)
            6,
            1,
            30,
            secret.to_bytes().unwrap(),
            None,
            "".to_string(),
        ).unwrap();
        
        let code = totp.generate_current().unwrap();
        let result = verify_totp_code(&secret_base32, &code).unwrap();
        assert!(result);
    }

    #[test]
    fn test_backup_codes() {
        let codes = generate_backup_codes(10);
        assert_eq!(codes.len(), 10);
        
        let json = serde_json::to_string(&codes).unwrap();
        let (verified, remaining) = verify_backup_code(&json, &codes[0]).unwrap();
        assert!(verified);
        assert_eq!(remaining.len(), 9);
    }
}

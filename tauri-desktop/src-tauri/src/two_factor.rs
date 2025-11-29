// ============================================
// MODULE 2FA HYBRIDE (TOTP + EMAIL)
// ============================================

use crate::config::{Auth2FAMethod, Config};
use crate::email_service::{EmailService, EmailTemplate};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc, Duration as ChronoDuration};
use totp_rs::{Algorithm, Secret, TOTP};
use qrcode::QrCode;
use image::Luma;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TwoFactorMethod {
    Totp,  // Google Authenticator
    Email, // Code par email
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorSetup {
    pub method: TwoFactorMethod,
    pub totp_secret: Option<String>,
    pub qr_code_base64: Option<String>,
    pub backup_codes: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
struct EmailCode {
    code: String,
    created_at: DateTime<Utc>,
    attempts: i32,
}

pub struct TwoFactorService {
    config: Config,
    email_service: EmailService,
    email_codes: Arc<Mutex<HashMap<i32, EmailCode>>>, // user_id -> code
}

impl TwoFactorService {
    pub fn new(config: Config) -> Self {
        let email_service = EmailService::new(config.clone());
        
        TwoFactorService {
            config,
            email_service,
            email_codes: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Setup 2FA - L'utilisateur choisit la méthode
    pub fn setup_2fa(
        &self,
        user_id: i32,
        username: &str,
        email: &str,
        method: TwoFactorMethod,
    ) -> Result<TwoFactorSetup, String> {
        // Générer backup codes (communs aux 2 méthodes)
        let backup_codes = self.generate_backup_codes(10);
        
        match method {
            TwoFactorMethod::Totp => {
                // Générer TOTP secret + QR code
                let mut rng = rand::thread_rng();
                let secret_bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
                let secret = Secret::Raw(secret_bytes);
                let secret_base32 = secret.to_encoded().to_string();
                
                let totp = TOTP::new(
                    Algorithm::SHA1,
                    6,
                    1,
                    30,
                    secret.to_bytes().unwrap(),
                    Some("SecureVault".to_string()),
                    username.to_string(),
                ).map_err(|e| format!("Erreur TOTP: {}", e))?;
                
                let qr = QrCode::new(totp.get_url().as_bytes())
                    .map_err(|e| format!("Erreur QR: {}", e))?;
                
                let image = qr.render::<Luma<u8>>().build();
                let mut buffer = Vec::new();
                image.write_to(&mut std::io::Cursor::new(&mut buffer), image::ImageFormat::Png)
                    .map_err(|e| format!("Erreur image: {}", e))?;
                
                let qr_base64 = format!("data:image/png;base64,{}", base64::encode(&buffer));
                
                Ok(TwoFactorSetup {
                    method: TwoFactorMethod::Totp,
                    totp_secret: Some(secret_base32),
                    qr_code_base64: Some(qr_base64),
                    backup_codes: backup_codes.clone(),
                    message: "Scannez le QR code avec Google Authenticator".to_string(),
                })
            }
            
            TwoFactorMethod::Email => {
                // Pour Email, pas besoin de setup complexe
                Ok(TwoFactorSetup {
                    method: TwoFactorMethod::Email,
                    totp_secret: None,
                    qr_code_base64: None,
                    backup_codes: backup_codes.clone(),
                    message: format!("Codes de vérification seront envoyés à {}", email),
                })
            }
        }
    }
    
    /// Générer et envoyer un code 2FA par email
    pub fn send_email_code(
        &self,
        user_id: i32,
        email: &str,
    ) -> Result<(), String> {
        // Générer code 6 chiffres
        let mut rng = rand::thread_rng();
        let code = format!("{:06}", rng.gen_range(100000..999999));
        
        // Stocker le code
        let email_code = EmailCode {
            code: code.clone(),
            created_at: Utc::now(),
            attempts: 0,
        };
        
        {
            let mut codes = self.email_codes.lock().unwrap();
            codes.insert(user_id, email_code);
        }
        
        // Envoyer par email
        let template = EmailTemplate::TwoFactorCode {
            code: code.clone(),
            validity_minutes: self.config.auth_email_code_validity / 60,
        };
        
        self.email_service.send_email(
            email,
            "🔐 Code de vérification SecureVault",
            template,
        )?;
        
        println!("✅ Code 2FA envoyé à {} (User {})", email, user_id);
        
        Ok(())
    }
    
    /// Vérifier un code TOTP (Google Authenticator)
    pub fn verify_totp_code(&self, secret: &str, code: &str) -> Result<bool, String> {
        let secret_bytes = Secret::Encoded(secret.to_string())
            .to_bytes()
            .map_err(|e| format!("Secret invalide: {}", e))?;
        
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,  // Tolérance de ±30 secondes
            30,
            secret_bytes,
            None,
            String::new(),
        ).map_err(|e| format!("Erreur TOTP: {}", e))?;
        
        let valid = totp.check_current(code)
            .map_err(|e| format!("Erreur vérification: {}", e))?;
        
        Ok(valid)
    }
    
    /// Vérifier un code email
    pub fn verify_email_code(&self, user_id: i32, code: &str) -> Result<bool, String> {
        let mut codes = self.email_codes.lock().unwrap();
        
        let email_code = codes.get_mut(&user_id)
            .ok_or("Aucun code trouvé pour cet utilisateur".to_string())?;
        
        // Vérifier expiration
        let now = Utc::now();
        let age_seconds = (now - email_code.created_at).num_seconds();
        
        if age_seconds > self.config.auth_email_code_validity as i64 {
            codes.remove(&user_id);
            return Err("Code expiré".to_string());
        }
        
        // Vérifier nombre de tentatives
        if email_code.attempts >= self.config.auth_2fa_max_attempts {
            codes.remove(&user_id);
            return Err(format!(
                "Trop de tentatives. Compte verrouillé {} minutes.",
                self.config.auth_2fa_lockout_minutes
            ));
        }
        
        email_code.attempts += 1;
        
        // Vérifier le code
        if email_code.code == code {
            codes.remove(&user_id); // Code valide, on le supprime
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Vérifier un backup code
    pub fn verify_backup_code(
        &self,
        stored_codes: &str,
        provided_code: &str,
    ) -> Result<(bool, String), String> {
        let codes: Vec<String> = serde_json::from_str(stored_codes)
            .map_err(|e| format!("Erreur parsing backup codes: {}", e))?;
        
        if codes.contains(&provided_code.to_string()) {
            // Retirer le code utilisé
            let remaining: Vec<String> = codes
                .into_iter()
                .filter(|c| c != provided_code)
                .collect();
            
            let updated = serde_json::to_string(&remaining)
                .map_err(|e| format!("Erreur serialization: {}", e))?;
            
            Ok((true, updated))
        } else {
            Ok((false, stored_codes.to_string()))
        }
    }
    
    /// Générer des backup codes
    fn generate_backup_codes(&self, count: usize) -> Vec<String> {
        let mut rng = rand::thread_rng();
        (0..count)
            .map(|_| {
                format!(
                    "{:04}-{:04}-{:04}",
                    rng.gen_range(0..10000),
                    rng.gen_range(0..10000),
                    rng.gen_range(0..10000)
                )
            })
            .collect()
    }
    
    /// Nettoyer les codes email expirés
    pub fn cleanup_expired_codes(&self) {
        let mut codes = self.email_codes.lock().unwrap();
        let now = Utc::now();
        
        codes.retain(|user_id, email_code| {
            let age = (now - email_code.created_at).num_seconds();
            let keep = age <= self.config.auth_email_code_validity as i64;
            
            if !keep {
                println!("🧹 Code expiré nettoyé pour user {}", user_id);
            }
            
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_backup_code_generation() {
        let config = Config::default();
        let service = TwoFactorService::new(config);
        
        let codes = service.generate_backup_codes(10);
        
        assert_eq!(codes.len(), 10);
        for code in codes {
            assert!(code.contains('-'));
            assert_eq!(code.len(), 14); // XXXX-XXXX-XXXX
        }
    }
    
    #[test]
    fn test_backup_code_verification() {
        let config = Config::default();
        let service = TwoFactorService::new(config);
        
        let codes = vec![
            "1234-5678-9012".to_string(),
            "2345-6789-0123".to_string(),
        ];
        
        let stored = serde_json::to_string(&codes).unwrap();
        
        let (valid, updated) = service.verify_backup_code(&stored, "1234-5678-9012").unwrap();
        
        assert!(valid);
        
        let remaining: Vec<String> = serde_json::from_str(&updated).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], "2345-6789-0123");
    }
    
    #[test]
    fn test_email_code_expiry() {
        let config = Config::default();
        let service = TwoFactorService::new(config);
        
        // Insérer un code expiré
        let old_code = EmailCode {
            code: "123456".to_string(),
            created_at: Utc::now() - ChronoDuration::seconds(400),
            attempts: 0,
        };
        
        {
            let mut codes = service.email_codes.lock().unwrap();
            codes.insert(1, old_code);
        }
        
        // Tenter de vérifier
        let result = service.verify_email_code(1, "123456");
        
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expiré"));
    }
}

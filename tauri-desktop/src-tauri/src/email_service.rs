// ============================================
// MODULE EMAIL AVEC VÉRIFICATION INTERNET
// ============================================

use crate::config::Config;
use lettre::message::{header, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailService {
    config: Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmailTemplate {
    TwoFactorCode { code: String, validity_minutes: i32 },
    FileShared { filename: String, sender: String },
    FileAccessed { filename: String, accessor: String },
    SecurityAlert { message: String, severity: String },
    AccountLocked { duration_minutes: i32, reason: String },
    TwoFactorEnabled { backup_codes: Vec<String> },
}

impl EmailService {
    pub fn new(config: Config) -> Self {
        EmailService { config }
    }
    
    /// Vérifie si l'appareil est connecté à Internet
    pub fn check_internet_connection(&self) -> Result<bool, String> {
        if !self.config.email_check_internet {
            return Ok(true); // Skip si désactivé dans config
        }
        
        // Essayer de se connecter à plusieurs serveurs DNS publics
        let test_hosts = vec![
            ("8.8.8.8", 53),          // Google DNS
            ("1.1.1.1", 53),          // Cloudflare DNS
            ("208.67.222.222", 53),   // OpenDNS
        ];
        
        for (host, port) in test_hosts {
            match TcpStream::connect_timeout(
                &format!("{}:{}", host, port).parse().unwrap(),
                Duration::from_secs(2)
            ) {
                Ok(_) => {
                    println!("✅ Connexion Internet détectée via {}", host);
                    return Ok(true);
                }
                Err(_) => continue,
            }
        }
        
        Err("❌ Aucune connexion Internet détectée".to_string())
    }
    
    /// Envoie un email avec retry automatique
    pub fn send_email(
        &self,
        to: &str,
        subject: &str,
        template: EmailTemplate,
    ) -> Result<(), String> {
        if !self.config.email_enabled {
            println!("📧 Email désactivé dans la config, simulation envoi à {}", to);
            return Ok(());
        }
        
        // Vérifier la connexion Internet
        match self.check_internet_connection() {
            Ok(true) => {},
            Ok(false) => return Err("Pas de connexion Internet".to_string()),
            Err(e) => return Err(e),
        }
        
        // Générer le contenu HTML
        let (html_body, text_body) = self.generate_email_content(template);
        
        // Construire le message
        let email = Message::builder()
            .from(
                format!("{} <{}>", self.config.email_from_name, self.config.email_from_address)
                    .parse()
                    .map_err(|e| format!("Invalid from address: {}", e))?,
            )
            .to(to.parse().map_err(|e| format!("Invalid to address: {}", e))?)
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )
            .map_err(|e| format!("Failed to build email: {}", e))?;
        
        // Configurer SMTP
        let creds = Credentials::new(
            self.config.email_smtp_username.clone(),
            self.config.email_smtp_password.clone(),
        );
        
        let mailer = if self.config.email_smtp_use_tls {
            SmtpTransport::starttls_relay(&self.config.email_smtp_host)
                .map_err(|e| format!("SMTP connection error: {}", e))?
                .credentials(creds)
                .timeout(Some(Duration::from_secs(self.config.email_timeout_seconds)))
                .build()
        } else {
            SmtpTransport::builder_dangerous(&self.config.email_smtp_host)
                .credentials(creds)
                .timeout(Some(Duration::from_secs(self.config.email_timeout_seconds)))
                .build()
        };
        
        // Retry logic
        let mut attempts = 0;
        let mut last_error = String::new();
        
        while attempts < self.config.email_retry_attempts {
            attempts += 1;
            
            match mailer.send(&email) {
                Ok(_) => {
                    println!("✅ Email envoyé à {} (tentative {})", to, attempts);
                    return Ok(());
                }
                Err(e) => {
                    last_error = format!("{}", e);
                    println!("⚠️ Échec envoi email (tentative {}): {}", attempts, last_error);
                    
                    if attempts < self.config.email_retry_attempts {
                        std::thread::sleep(Duration::from_secs(2_u64.pow(attempts)));
                    }
                }
            }
        }
        
        Err(format!(
            "Échec après {} tentatives: {}",
            self.config.email_retry_attempts, last_error
        ))
    }
    
    /// Génère le contenu HTML et texte brut d'un email
    fn generate_email_content(&self, template: EmailTemplate) -> (String, String) {
        match template {
            EmailTemplate::TwoFactorCode { code, validity_minutes } => {
                let html = format!(
                    r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
        .container {{ background-color: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }}
        .code {{ font-size: 32px; font-weight: bold; color: #2563eb; text-align: center; padding: 20px; background-color: #eff6ff; border-radius: 5px; letter-spacing: 5px; }}
        .warning {{ color: #dc2626; margin-top: 20px; }}
        .footer {{ margin-top: 30px; font-size: 12px; color: #6b7280; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 style="color: #1f2937;">🔐 Code de vérification SecureVault</h1>
        <p>Votre code de double authentification est :</p>
        <div class="code">{}</div>
        <p class="warning">⏱️ Ce code expire dans {} minutes.</p>
        <p>Si vous n'avez pas demandé ce code, ignorez cet email et contactez l'administrateur.</p>
        <div class="footer">
            SecureVault Next-Gen • Sécurité de niveau militaire<br>
            Cet email a été généré automatiquement, ne pas répondre.
        </div>
    </div>
</body>
</html>
                    "#,
                    code, validity_minutes
                );
                
                let text = format!(
                    "SecureVault - Code de vérification\n\n\
                    Votre code : {}\n\
                    Expire dans {} minutes.\n\n\
                    Si vous n'avez pas demandé ce code, ignorez cet email.",
                    code, validity_minutes
                );
                
                (html, text)
            }
            
            EmailTemplate::FileShared { filename, sender } => {
                let html = format!(
                    r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
        .container {{ background-color: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }}
        .file {{ font-weight: bold; color: #2563eb; }}
        .sender {{ font-weight: bold; color: #059669; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 Nouveau fichier partagé</h1>
        <p><span class="sender">{}</span> a partagé le fichier <span class="file">{}</span> avec vous.</p>
        <p>Connectez-vous à SecureVault pour y accéder.</p>
    </div>
</body>
</html>
                    "#,
                    sender, filename
                );
                
                let text = format!(
                    "SecureVault - Nouveau fichier partagé\n\n\
                    {} a partagé '{}' avec vous.\n\
                    Connectez-vous pour y accéder.",
                    sender, filename
                );
                
                (html, text)
            }
            
            EmailTemplate::FileAccessed { filename, accessor } => {
                let html = format!(
                    r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
        .container {{ background-color: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }}
        .file {{ font-weight: bold; color: #2563eb; }}
        .accessor {{ font-weight: bold; color: #059669; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔔 Fichier accédé</h1>
        <p><span class="accessor">{}</span> a accédé à votre fichier <span class="file">{}</span>.</p>
        <p>Date : {}</p>
    </div>
</body>
</html>
                    "#,
                    accessor, filename, chrono::Local::now().format("%d/%m/%Y %H:%M")
                );
                
                let text = format!(
                    "SecureVault - Fichier accédé\n\n\
                    {} a accédé à '{}'.\n\
                    Date : {}",
                    accessor, filename, chrono::Local::now().format("%d/%m/%Y %H:%M")
                );
                
                (html, text)
            }
            
            EmailTemplate::SecurityAlert { message, severity } => {
                let color = match severity.as_str() {
                    "critical" => "#dc2626",
                    "high" => "#ea580c",
                    "medium" => "#f59e0b",
                    _ => "#6b7280",
                };
                
                let html = format!(
                    r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
        .container {{ background-color: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }}
        .alert {{ color: {}; font-weight: bold; font-size: 18px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 style="color: {};">⚠️ Alerte de sécurité</h1>
        <p class="alert">{}</p>
        <p>Vérifiez votre compte immédiatement.</p>
    </div>
</body>
</html>
                    "#,
                    color, color, message
                );
                
                let text = format!(
                    "SecureVault - Alerte de sécurité [{}]\n\n\
                    {}\n\n\
                    Vérifiez votre compte immédiatement.",
                    severity.to_uppercase(), message
                );
                
                (html, text)
            }
            
            EmailTemplate::AccountLocked { duration_minutes, reason } => {
                let html = format!(
                    r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
        .container {{ background-color: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }}
        .warning {{ color: #dc2626; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="warning">🚨 Compte verrouillé</h1>
        <p>Votre compte a été temporairement verrouillé pour {} minutes.</p>
        <p><strong>Raison :</strong> {}</p>
        <p>Si ce n'était pas vous, contactez immédiatement le support.</p>
    </div>
</body>
</html>
                    "#,
                    duration_minutes, reason
                );
                
                let text = format!(
                    "SecureVault - Compte verrouillé\n\n\
                    Votre compte est verrouillé pour {} minutes.\n\
                    Raison : {}\n\n\
                    Contactez le support si nécessaire.",
                    duration_minutes, reason
                );
                
                (html, text)
            }
            
            EmailTemplate::TwoFactorEnabled { backup_codes } => {
                let codes_html = backup_codes
                    .iter()
                    .map(|c| format!("<li style='font-family: monospace; font-size: 14px;'>{}</li>", c))
                    .collect::<Vec<_>>()
                    .join("");
                
                let html = format!(
                    r#"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }}
        .container {{ background-color: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }}
        .success {{ color: #059669; }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="success">✅ Double authentification activée</h1>
        <p>Votre compte est maintenant protégé par la double authentification.</p>
        <h3>Codes de secours</h3>
        <p>Conservez ces codes dans un endroit sûr. Chacun ne peut être utilisé qu'une seule fois :</p>
        <ul>{}</ul>
        <p style="color: #dc2626;"><strong>IMPORTANT :</strong> Ne partagez jamais ces codes avec quiconque.</p>
    </div>
</body>
</html>
                    "#,
                    codes_html
                );
                
                let text = format!(
                    "SecureVault - Double authentification activée\n\n\
                    Codes de secours (usage unique) :\n{}\n\n\
                    Conservez-les en sécurité.",
                    backup_codes.join("\n")
                );
                
                (html, text)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_internet_check() {
        let config = Config::default();
        let email_service = EmailService::new(config);
        
        // Ce test peut échouer en mode hors ligne
        match email_service.check_internet_connection() {
            Ok(connected) => println!("Internet: {}", connected),
            Err(e) => println!("Error: {}", e),
        }
    }
    
    #[test]
    fn test_email_generation() {
        let config = Config::default();
        let email_service = EmailService::new(config);
        
        let template = EmailTemplate::TwoFactorCode {
            code: "123456".to_string(),
            validity_minutes: 5,
        };
        
        let (html, text) = email_service.generate_email_content(template);
        
        assert!(html.contains("123456"));
        assert!(text.contains("123456"));
    }
}

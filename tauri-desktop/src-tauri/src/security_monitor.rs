//! Moniteur de sécurité natif Rust
//! 
//! Ce module implémente :
//! - Protection anti-brute force avec verrouillage progressif
//! - Détection d'activité ransomware en temps réel
//! - Mode lecture seule automatique en cas de menace
//! - Authentification renforcée par email OTP

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use lettre::message::{header::ContentType, MultiPart, SinglePart};

// ========== STRUCTURES ==========

/// Tentatives de connexion par utilisateur
#[derive(Debug, Clone)]
pub struct LoginAttempts {
    pub failed_count: u32,
    pub last_attempt: u64,
    pub lockout_until: Option<u64>,
}

/// Activité de fichier pour détection ransomware
#[derive(Debug, Clone)]
pub struct FileActivity {
    pub access_count: u32,
    pub last_access: u64,
    pub suspicious_extensions: Vec<String>,
}

/// État de sécurité global
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityState {
    pub is_locked: bool,
    pub is_readonly: bool,
    pub threat_level: ThreatLevel,
    pub active_threats: Vec<String>,
}

/// Niveau de menace
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatLevel {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

/// Code OTP temporaire
#[derive(Debug, Clone)]
pub struct OtpCode {
    pub code: String,
    pub expires_at: u64,
    pub user_email: String,
}

// ========== MONITEUR DE SÉCURITÉ ==========

pub struct SecurityMonitor {
    /// Tentatives de connexion par email utilisateur
    login_attempts: Arc<Mutex<HashMap<String, LoginAttempts>>>,
    
    /// Activité fichiers (détection ransomware)
    file_activity: Arc<Mutex<FileActivity>>,
    
    /// État de sécurité global
    security_state: Arc<Mutex<SecurityState>>,
    
    /// Codes OTP actifs
    active_otps: Arc<Mutex<HashMap<String, OtpCode>>>,
}

impl SecurityMonitor {
    /// Crée un nouveau moniteur de sécurité
    pub fn new() -> Self {
        SecurityMonitor {
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
            file_activity: Arc::new(Mutex::new(FileActivity {
                access_count: 0,
                last_access: 0,
                suspicious_extensions: Vec::new(),
            })),
            security_state: Arc::new(Mutex::new(SecurityState {
                is_locked: false,
                is_readonly: false,
                threat_level: ThreatLevel::None,
                active_threats: Vec::new(),
            })),
            active_otps: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ========== ANTI-BRUTE FORCE ==========

    /// Enregistre une tentative de connexion échouée
    pub async fn record_failed_login(&self, user_email: &str) -> BruteForceAction {
        let mut attempts = self.login_attempts.lock().await;
        let now = current_timestamp();
        
        let entry = attempts.entry(user_email.to_string()).or_insert(LoginAttempts {
            failed_count: 0,
            last_attempt: now,
            lockout_until: None,
        });

        // Vérifier si déjà verrouillé
        if let Some(lockout_until) = entry.lockout_until {
            if now < lockout_until {
                let remaining = lockout_until - now;
                return BruteForceAction::Locked { 
                    remaining_seconds: remaining,
                    requires_otp: entry.failed_count >= 5,
                };
            } else {
                // Le verrouillage a expiré, mais on garde le compteur pour progression
                entry.lockout_until = None;
                // Ne PAS réinitialiser failed_count ici !
            }
        }

        entry.failed_count += 1;
        entry.last_attempt = now;

        // Déterminer l'action selon le nombre de tentatives
        match entry.failed_count {
            1..=2 => BruteForceAction::Allow,
            3..=4 => {
                // Délai progressif: 30s (3e), 60s (4e)
                let lockout_duration = 30 * (entry.failed_count - 2) as u64;
                entry.lockout_until = Some(now + lockout_duration);
                BruteForceAction::Locked {
                    remaining_seconds: lockout_duration,
                    requires_otp: false,
                }
            }
            5..=9 => {
                // 5+ tentatives : verrouillage de 5 minutes + OTP requis
                let lockout_duration = 300; // 5 minutes
                entry.lockout_until = Some(now + lockout_duration);
                BruteForceAction::Locked {
                    remaining_seconds: lockout_duration,
                    requires_otp: true,
                }
            }
            _ => {
                // 10+ tentatives : verrouillage de 30 minutes + OTP obligatoire
                let lockout_duration = 1800; // 30 minutes
                entry.lockout_until = Some(now + lockout_duration);
                
                // Augmenter le niveau de menace
                let mut state = self.security_state.lock().await;
                state.threat_level = ThreatLevel::High;
                state.active_threats.push(format!("Tentative de brute force détectée sur {}", user_email));
                
                BruteForceAction::Locked {
                    remaining_seconds: lockout_duration,
                    requires_otp: true,
                }
            }
        }
    }

    /// Enregistre une connexion réussie (réinitialise le compteur)
    pub async fn record_successful_login(&self, user_email: &str) {
        let mut attempts = self.login_attempts.lock().await;
        attempts.remove(user_email);
    }

    /// Vérifie si un utilisateur est verrouillé
    pub async fn is_user_locked(&self, user_email: &str) -> Option<u64> {
        let attempts = self.login_attempts.lock().await;
        if let Some(entry) = attempts.get(user_email) {
            if let Some(lockout_until) = entry.lockout_until {
                let now = current_timestamp();
                if now < lockout_until {
                    return Some(lockout_until - now);
                }
            }
        }
        None
    }

    /// Vérifie si un utilisateur nécessite une validation OTP (5+ tentatives échouées)
    pub async fn requires_otp(&self, user_email: &str) -> bool {
        let attempts = self.login_attempts.lock().await;
        if let Some(entry) = attempts.get(user_email) {
            return entry.failed_count >= 5;
        }
        false
    }

    // ========== DÉTECTION RANSOMWARE ==========

    /// Surveille l'accès à un fichier
    pub async fn monitor_file_access(&self, filename: &str) -> RansomwareStatus {
        let mut activity = self.file_activity.lock().await;
        let now = current_timestamp();

        // Réinitialiser le compteur si > 10 secondes depuis le dernier accès
        if now - activity.last_access > 10 {
            activity.access_count = 0;
            activity.suspicious_extensions.clear();
        }

        activity.access_count += 1;
        activity.last_access = now;

        // Détecter extensions suspectes
        let suspicious_exts = [
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
            ".locky", ".cerber", ".wannacry", ".zepto", ".osiris",
            ".cryptolocker", ".cryptowall", ".zzzzz", ".micro",
        ];

        for ext in &suspicious_exts {
            if filename.ends_with(ext) {
                activity.suspicious_extensions.push(filename.to_string());
                
                // ALERTE IMMÉDIATE : extension ransomware détectée
                return self.trigger_ransomware_lockdown("Extension ransomware détectée").await;
            }
        }

        // Seuil de détection : > 20 accès fichiers en moins de 10 secondes
        if activity.access_count > 20 {
            return self.trigger_ransomware_lockdown(
                "Activité fichier anormalement élevée (possible ransomware)"
            ).await;
        }

        RansomwareStatus::Safe
    }

    /// Déclenche le mode verrouillage anti-ransomware
    async fn trigger_ransomware_lockdown(&self, reason: &str) -> RansomwareStatus {
        let mut state = self.security_state.lock().await;
        
        state.is_readonly = true;
        state.threat_level = ThreatLevel::Critical;
        state.active_threats.push(format!("🚨 RANSOMWARE: {}", reason));
        
        println!("🚨 ALERTE RANSOMWARE: {}", reason);
        println!("🔒 Coffre-fort passé en MODE LECTURE SEULE");
        
        RansomwareStatus::ThreatDetected {
            reason: reason.to_string(),
            is_readonly: true,
        }
    }

    /// Vérifie si le système est en lecture seule
    pub async fn is_readonly(&self) -> bool {
        let state = self.security_state.lock().await;
        state.is_readonly
    }

    /// Active le mode lecture seule (appelé par le filesystem_monitor)
    pub async fn activate_readonly_for_ransomware(&self, reason: &str) -> Result<(), String> {
        let mut state = self.security_state.lock().await;
        
        if !state.is_readonly {
            state.is_readonly = true;
            state.threat_level = ThreatLevel::Critical;
            
            let threat_msg = format!("🚨 RANSOMWARE: {}", reason);
            if !state.active_threats.contains(&threat_msg) {
                state.active_threats.push(threat_msg.clone());
            }
            
            println!("🔒 SecurityMonitor: Mode lecture seule activé");
            println!("   Raison: {}", reason);
        }
        
        Ok(())
    }

    /// Désactive le mode lecture seule (admin uniquement)
    pub async fn disable_readonly(&self, admin_password: &str) -> Result<(), String> {
        // TODO: Vérifier le mot de passe admin
        let mut state = self.security_state.lock().await;
        state.is_readonly = false;
        state.threat_level = ThreatLevel::None;
        state.active_threats.clear();
        
        // Réinitialiser l'activité fichiers
        let mut activity = self.file_activity.lock().await;
        activity.access_count = 0;
        activity.suspicious_extensions.clear();
        
        // SYNCHRONISER avec filesystem_monitor
        drop(state);
        drop(activity);
        
        use crate::filesystem_monitor::get_filesystem_monitor;
        let fs_monitor = get_filesystem_monitor();
        let guard = fs_monitor.lock().map_err(|e| format!("Lock error: {}", e))?;
        guard.disable_readonly();
        
        println!("✅ Mode lecture seule désactivé sur les deux moniteurs");
        
        Ok(())
    }

    // ========== AUTHENTIFICATION OTP EMAIL ==========

    /// Génère et envoie un code OTP par email
    pub async fn generate_and_send_otp(&self, user_email: &str) -> Result<String, String> {
        let code = generate_otp_code();
        let now = current_timestamp();
        let expires_at = now + 30; // 30 secondes

        // Stocker le code
        let mut otps = self.active_otps.lock().await;
        otps.insert(user_email.to_string(), OtpCode {
            code: code.clone(),
            expires_at,
            user_email: user_email.to_string(),
        });

        println!("📧 Code OTP pour {}: {} (expire dans 30s)", user_email, code);
        
        // Envoyer l'email via SMTP
        match self.send_otp_email(user_email, &code).await {
            Ok(_) => println!("✅ Email OTP envoyé avec succès à {}", user_email),
            Err(e) => {
                eprintln!("❌ Erreur envoi email OTP: {}", e);
                // On continue quand même pour permettre le test en développement
            }
        }
        
        Ok(code)
    }

    /// Envoie l'email OTP via SMTP
    async fn send_otp_email(&self, user_email: &str, code: &str) -> Result<(), String> {
        // Lire les variables d'environnement
        let smtp_host = std::env::var("EMAIL_SMTP_HOST")
            .unwrap_or_else(|_| "smtp.gmail.com".to_string());
        let smtp_port = std::env::var("EMAIL_SMTP_PORT")
            .unwrap_or_else(|_| "587".to_string())
            .parse::<u16>()
            .unwrap_or(587);
        let smtp_user = std::env::var("EMAIL_SMTP_USERNAME")
            .or_else(|_| std::env::var("EMAIL_SMTP_USER"))
            .map(|s| s.trim().to_string())  // Trim whitespace
            .map_err(|_| "EMAIL_SMTP_USERNAME/EMAIL_SMTP_USER non configuré".to_string())?;
        let smtp_password = std::env::var("EMAIL_SMTP_PASSWORD")
            .or_else(|_| std::env::var("SMTP_PASSWORD"))
            .map(|s| s.trim().to_string())  // Trim whitespace
            .map_err(|_| "EMAIL_SMTP_PASSWORD non configuré".to_string())?;
        
        println!("🔍 DEBUG SMTP Config:");
        println!("   Host: {}", smtp_host);
        println!("   Port: {}", smtp_port);
        println!("   User: {}", smtp_user);
        println!("   Password length: {} chars", smtp_password.len());
        println!("   Password starts with: {}...", &smtp_password.chars().take(4).collect::<String>());
        let from_name = std::env::var("EMAIL_FROM_NAME")
            .unwrap_or_else(|_| "SecureVault".to_string());

        // Créer le contenu HTML (design sobre et professionnel)
        let html_body = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }}
        .container {{ max-width: 500px; margin: 40px auto; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .header {{ background: #1f2937; color: white; padding: 24px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 20px; font-weight: 600; }}
        .content {{ padding: 32px 24px; }}
        .code-box {{ background: #f9fafb; border: 2px solid #e5e7eb; border-radius: 6px; padding: 24px; text-align: center; margin: 24px 0; }}
        .code {{ font-size: 32px; font-weight: 700; letter-spacing: 6px; color: #111827; font-family: 'Courier New', monospace; }}
        .expiry {{ color: #6b7280; font-size: 13px; margin-top: 8px; }}
        .warning {{ background: #fef3c7; border-left: 3px solid #f59e0b; padding: 12px 16px; margin: 20px 0; font-size: 14px; color: #92400e; }}
        .footer {{ text-align: center; color: #9ca3af; font-size: 12px; padding: 16px; background: #f9fafb; }}
        p {{ margin: 0 0 12px 0; color: #374151; line-height: 1.6; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Code de Vérification SecureVault</h1>
        </div>
        <div class="content">
            <p>Bonjour,</p>
            <p>Un code de vérification a été demandé pour votre compte.</p>
            
            <div class="code-box">
                <div class="code">{}</div>
                <p class="expiry">Expire dans 30 secondes</p>
            </div>

            <div class="warning">
                <strong>⚠️ Attention :</strong> Si vous n'êtes pas à l'origine de cette demande, quelqu'un tente peut-être d'accéder à votre compte.
            </div>
        </div>
        <div class="footer">
            <p>SecureVault - Gestion Sécurisée de Mots de Passe</p>
            <p>Cet email est généré automatiquement</p>
        </div>
    </div>
</body>
</html>"#,
            code
        );

        let text_body = format!(
            "SecureVault - Code de Vérification\n\n\
            Nous avons détecté plusieurs tentatives de connexion échouées.\n\n\
            Code de vérification : {}\n\
            Valide pendant 30 secondes\n\n\
            Si vous n'avez pas demandé ce code, changez immédiatement votre mot de passe.\n\n\
            SecureVault Security Team",
            code
        );

        // Construire l'email
        let email = Message::builder()
            .from(format!("{} <{}>", from_name, smtp_user).parse().map_err(|e| format!("Erreur parse FROM: {}", e))?)
            .to(user_email.parse().map_err(|e| format!("Erreur parse TO: {}", e))?)
            .subject("🔐 SecureVault - Code de Vérification (Anti-Brute Force)")
            .multipart(
                MultiPart::alternative()
                    .singlepart(SinglePart::plain(text_body))
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html_body)
                    )
            )
            .map_err(|e| format!("Erreur construction email: {}", e))?;

        // Configurer SMTP
        let creds = Credentials::new(smtp_user.clone(), smtp_password.clone());
        let mailer = SmtpTransport::starttls_relay(&smtp_host)
            .map_err(|e| format!("Erreur relay SMTP: {}", e))?
            .port(smtp_port)
            .credentials(creds)
            .build();

        // Envoyer
        mailer.send(&email)
            .map_err(|e| format!("Erreur envoi SMTP: {}", e))?;

        Ok(())
    }

    /// Vérifie un code OTP
    pub async fn verify_otp(&self, user_email: &str, code: &str) -> bool {
        let mut otps = self.active_otps.lock().await;
        
        if let Some(stored_otp) = otps.get(user_email) {
            let now = current_timestamp();
            
            // Vérifier expiration
            if now > stored_otp.expires_at {
                otps.remove(user_email);
                return false;
            }

            // Vérifier le code
            if stored_otp.code == code {
                otps.remove(user_email);
                return true;
            }
        }

        false
    }

    // ========== ÉTAT DE SÉCURITÉ ==========

    /// Récupère l'état de sécurité actuel
    pub async fn get_security_state(&self) -> SecurityState {
        self.security_state.lock().await.clone()
    }

    /// Réinitialise tous les compteurs (maintenance)
    pub async fn reset_all(&self) {
        let mut attempts = self.login_attempts.lock().await;
        attempts.clear();
        
        let mut activity = self.file_activity.lock().await;
        activity.access_count = 0;
        activity.suspicious_extensions.clear();
        
        let mut state = self.security_state.lock().await;
        state.is_locked = false;
        state.is_readonly = false;
        state.threat_level = ThreatLevel::None;
        state.active_threats.clear();
        
        let mut otps = self.active_otps.lock().await;
        otps.clear();
    }
}

// ========== TYPES DE RÉSULTATS ==========

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BruteForceAction {
    Allow,
    Locked {
        remaining_seconds: u64,
        requires_otp: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RansomwareStatus {
    Safe,
    ThreatDetected {
        reason: String,
        is_readonly: bool,
    },
}

// ========== UTILITAIRES ==========

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_otp_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1000000))
}

// ========== SINGLETON GLOBAL ==========

static mut SECURITY_MONITOR: Option<SecurityMonitor> = None;

pub fn initialize_security_monitor() {
    unsafe {
        if SECURITY_MONITOR.is_none() {
            SECURITY_MONITOR = Some(SecurityMonitor::new());
        }
    }
}

pub fn get_security_monitor() -> &'static SecurityMonitor {
    unsafe {
        SECURITY_MONITOR.as_ref().expect("Security monitor not initialized")
    }
}

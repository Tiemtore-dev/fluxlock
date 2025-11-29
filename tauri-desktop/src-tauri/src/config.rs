// ============================================
// MODULE DE CONFIGURATION
// ============================================
// Charge et expose toutes les variables d'environnement

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    // Machine Learning
    pub ml_training_retention_days: i32,
    pub ml_retraining_interval_hours: i32,
    pub ml_min_logs_for_training: i32,
    pub ml_contamination_threshold: f64,
    pub ml_n_estimators: usize,
    
    // Compression des logs
    pub log_compression_after_days: i32,
    pub log_compression_format: String,
    pub log_compression_level: i32,
    pub log_delete_after_compression: bool,
    
    // Authentification 2FA
    pub auth_2fa_method: Auth2FAMethod,
    pub auth_email_code_validity: i32,
    pub auth_2fa_max_attempts: i32,
    pub auth_2fa_lockout_minutes: i32,
    
    // Email / SMTP
    pub email_enabled: bool,
    pub email_check_internet: bool,
    pub email_smtp_host: String,
    pub email_smtp_port: u16,
    pub email_smtp_use_tls: bool,
    pub email_smtp_username: String,
    pub email_smtp_password: String,
    pub email_from_address: String,
    pub email_from_name: String,
    pub email_timeout_seconds: u64,
    pub email_retry_attempts: u32,
    
    // Réactions aux menaces
    pub threat_low_threshold: i32,
    pub threat_medium_threshold: i32,
    pub threat_high_threshold: i32,
    pub threat_critical_threshold: i32,
    pub threat_critical_block_minutes: i32,
    pub threat_medium_rate_limit: f64,
    pub threat_high_rate_limit: f64,
    
    // Notifications
    pub notification_enabled_types: Vec<String>,
    pub notification_send_email: bool,
    pub notification_send_inapp: bool,
    
    // Base de données
    pub database_path: String,
    pub database_wal_mode: bool,
    pub database_cache_size: i32,
    
    // Sécurité
    pub session_token_validity_hours: i32,
    pub share_default_expiry_days: i32,
    pub share_max_files_per_user: i32,
    
    // Performance
    pub max_file_size_mb: i32,
    pub ml_worker_threads: usize,
    pub ml_autosave_interval_seconds: u64,
    
    // Logs & Monitoring
    pub log_level: String,
    pub log_rotation: String,
    pub log_max_size_mb: i32,
    pub log_retention_count: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Auth2FAMethod {
    Totp,   // Google Authenticator uniquement
    Email,  // Code par email uniquement
    Both,   // L'utilisateur choisit
}

impl Default for Config {
    fn default() -> Self {
        Config {
            // ML defaults
            ml_training_retention_days: 30,
            ml_retraining_interval_hours: 24,
            ml_min_logs_for_training: 100,
            ml_contamination_threshold: 0.05,
            ml_n_estimators: 100,
            
            // Compression defaults
            log_compression_after_days: 90,
            log_compression_format: "gzip".to_string(),
            log_compression_level: 9,
            log_delete_after_compression: false,
            
            // Auth defaults
            auth_2fa_method: Auth2FAMethod::Both,
            auth_email_code_validity: 300,
            auth_2fa_max_attempts: 5,
            auth_2fa_lockout_minutes: 15,
            
            // Email defaults
            email_enabled: true,
            email_check_internet: true,
            email_smtp_host: "smtp.gmail.com".to_string(),
            email_smtp_port: 587,
            email_smtp_use_tls: true,
            email_smtp_username: String::new(),
            email_smtp_password: String::new(),
            email_from_address: "noreply@securevault.com".to_string(),
            email_from_name: "SecureVault Security".to_string(),
            email_timeout_seconds: 10,
            email_retry_attempts: 3,
            
            // Threat defaults
            threat_low_threshold: 0,
            threat_medium_threshold: 40,
            threat_high_threshold: 60,
            threat_critical_threshold: 80,
            threat_critical_block_minutes: 30,
            threat_medium_rate_limit: 0.2,
            threat_high_rate_limit: 0.1,
            
            // Notification defaults
            notification_enabled_types: vec![
                "file_shared".to_string(),
                "file_accessed".to_string(),
                "security_alert".to_string(),
                "account_locked".to_string(),
            ],
            notification_send_email: true,
            notification_send_inapp: true,
            
            // Database defaults
            database_path: "./database/secure_vault.db".to_string(),
            database_wal_mode: true,
            database_cache_size: 10000,
            
            // Security defaults
            session_token_validity_hours: 24,
            share_default_expiry_days: 7,
            share_max_files_per_user: 100,
            
            // Performance defaults
            max_file_size_mb: 100,
            ml_worker_threads: 4,
            ml_autosave_interval_seconds: 300,
            
            // Log defaults
            log_level: "info".to_string(),
            log_rotation: "daily".to_string(),
            log_max_size_mb: 50,
            log_retention_count: 10,
        }
    }
}

impl Config {
    /// Charge la configuration depuis les variables d'environnement
    pub fn from_env() -> Self {
        dotenv::dotenv().ok(); // Charge le fichier .env
        
        let mut config = Config::default();
        
        // ML
        if let Ok(val) = env::var("ML_TRAINING_RETENTION_DAYS") {
            config.ml_training_retention_days = val.parse().unwrap_or(30);
        }
        if let Ok(val) = env::var("ML_RETRAINING_INTERVAL_HOURS") {
            config.ml_retraining_interval_hours = val.parse().unwrap_or(24);
        }
        if let Ok(val) = env::var("ML_MIN_LOGS_FOR_TRAINING") {
            config.ml_min_logs_for_training = val.parse().unwrap_or(100);
        }
        if let Ok(val) = env::var("ML_CONTAMINATION_THRESHOLD") {
            config.ml_contamination_threshold = val.parse().unwrap_or(0.05);
        }
        if let Ok(val) = env::var("ML_N_ESTIMATORS") {
            config.ml_n_estimators = val.parse().unwrap_or(100);
        }
        
        // Compression
        if let Ok(val) = env::var("LOG_COMPRESSION_AFTER_DAYS") {
            config.log_compression_after_days = val.parse().unwrap_or(90);
        }
        if let Ok(val) = env::var("LOG_COMPRESSION_FORMAT") {
            config.log_compression_format = val;
        }
        if let Ok(val) = env::var("LOG_COMPRESSION_LEVEL") {
            config.log_compression_level = val.parse().unwrap_or(9);
        }
        if let Ok(val) = env::var("LOG_DELETE_AFTER_COMPRESSION") {
            config.log_delete_after_compression = val.to_lowercase() == "true";
        }
        
        // Auth 2FA
        if let Ok(val) = env::var("AUTH_2FA_METHOD") {
            config.auth_2fa_method = match val.to_lowercase().as_str() {
                "totp" => Auth2FAMethod::Totp,
                "email" => Auth2FAMethod::Email,
                "both" => Auth2FAMethod::Both,
                _ => Auth2FAMethod::Both,
            };
        }
        if let Ok(val) = env::var("AUTH_EMAIL_CODE_VALIDITY") {
            config.auth_email_code_validity = val.parse().unwrap_or(300);
        }
        if let Ok(val) = env::var("AUTH_2FA_MAX_ATTEMPTS") {
            config.auth_2fa_max_attempts = val.parse().unwrap_or(5);
        }
        if let Ok(val) = env::var("AUTH_2FA_LOCKOUT_MINUTES") {
            config.auth_2fa_lockout_minutes = val.parse().unwrap_or(15);
        }
        
        // Email
        if let Ok(val) = env::var("EMAIL_ENABLED") {
            config.email_enabled = val.to_lowercase() == "true";
        }
        if let Ok(val) = env::var("EMAIL_CHECK_INTERNET") {
            config.email_check_internet = val.to_lowercase() == "true";
        }
        if let Ok(val) = env::var("EMAIL_SMTP_HOST") {
            config.email_smtp_host = val;
        }
        if let Ok(val) = env::var("EMAIL_SMTP_PORT") {
            config.email_smtp_port = val.parse().unwrap_or(587);
        }
        if let Ok(val) = env::var("EMAIL_SMTP_USE_TLS") {
            config.email_smtp_use_tls = val.to_lowercase() == "true";
        }
        if let Ok(val) = env::var("EMAIL_SMTP_USERNAME") {
            config.email_smtp_username = val;
        }
        if let Ok(val) = env::var("EMAIL_SMTP_PASSWORD") {
            config.email_smtp_password = val;
        }
        if let Ok(val) = env::var("EMAIL_FROM_ADDRESS") {
            config.email_from_address = val;
        }
        if let Ok(val) = env::var("EMAIL_FROM_NAME") {
            config.email_from_name = val;
        }
        if let Ok(val) = env::var("EMAIL_TIMEOUT_SECONDS") {
            config.email_timeout_seconds = val.parse().unwrap_or(10);
        }
        if let Ok(val) = env::var("EMAIL_RETRY_ATTEMPTS") {
            config.email_retry_attempts = val.parse().unwrap_or(3);
        }
        
        // Threats
        if let Ok(val) = env::var("THREAT_LOW_THRESHOLD") {
            config.threat_low_threshold = val.parse().unwrap_or(0);
        }
        if let Ok(val) = env::var("THREAT_MEDIUM_THRESHOLD") {
            config.threat_medium_threshold = val.parse().unwrap_or(40);
        }
        if let Ok(val) = env::var("THREAT_HIGH_THRESHOLD") {
            config.threat_high_threshold = val.parse().unwrap_or(60);
        }
        if let Ok(val) = env::var("THREAT_CRITICAL_THRESHOLD") {
            config.threat_critical_threshold = val.parse().unwrap_or(80);
        }
        if let Ok(val) = env::var("THREAT_CRITICAL_BLOCK_MINUTES") {
            config.threat_critical_block_minutes = val.parse().unwrap_or(30);
        }
        if let Ok(val) = env::var("THREAT_MEDIUM_RATE_LIMIT") {
            config.threat_medium_rate_limit = val.parse().unwrap_or(0.2);
        }
        if let Ok(val) = env::var("THREAT_HIGH_RATE_LIMIT") {
            config.threat_high_rate_limit = val.parse().unwrap_or(0.1);
        }
        
        // Notifications
        if let Ok(val) = env::var("NOTIFICATION_ENABLED_TYPES") {
            config.notification_enabled_types = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("NOTIFICATION_SEND_EMAIL") {
            config.notification_send_email = val.to_lowercase() == "true";
        }
        if let Ok(val) = env::var("NOTIFICATION_SEND_INAPP") {
            config.notification_send_inapp = val.to_lowercase() == "true";
        }
        
        // Database
        if let Ok(val) = env::var("DATABASE_PATH") {
            config.database_path = val;
        }
        if let Ok(val) = env::var("DATABASE_WAL_MODE") {
            config.database_wal_mode = val.to_lowercase() == "true";
        }
        if let Ok(val) = env::var("DATABASE_CACHE_SIZE") {
            config.database_cache_size = val.parse().unwrap_or(10000);
        }
        
        // Security
        if let Ok(val) = env::var("SESSION_TOKEN_VALIDITY_HOURS") {
            config.session_token_validity_hours = val.parse().unwrap_or(24);
        }
        if let Ok(val) = env::var("SHARE_DEFAULT_EXPIRY_DAYS") {
            config.share_default_expiry_days = val.parse().unwrap_or(7);
        }
        if let Ok(val) = env::var("SHARE_MAX_FILES_PER_USER") {
            config.share_max_files_per_user = val.parse().unwrap_or(100);
        }
        
        // Performance
        if let Ok(val) = env::var("MAX_FILE_SIZE_MB") {
            config.max_file_size_mb = val.parse().unwrap_or(100);
        }
        if let Ok(val) = env::var("ML_WORKER_THREADS") {
            config.ml_worker_threads = val.parse().unwrap_or(4);
        }
        if let Ok(val) = env::var("ML_AUTOSAVE_INTERVAL_SECONDS") {
            config.ml_autosave_interval_seconds = val.parse().unwrap_or(300);
        }
        
        // Logs
        if let Ok(val) = env::var("LOG_LEVEL") {
            config.log_level = val;
        }
        if let Ok(val) = env::var("LOG_ROTATION") {
            config.log_rotation = val;
        }
        if let Ok(val) = env::var("LOG_MAX_SIZE_MB") {
            config.log_max_size_mb = val.parse().unwrap_or(50);
        }
        if let Ok(val) = env::var("LOG_RETENTION_COUNT") {
            config.log_retention_count = val.parse().unwrap_or(10);
        }
        
        config
    }
    
    /// Valide la configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.email_enabled {
            if self.email_smtp_username.is_empty() {
                return Err("EMAIL_SMTP_USERNAME requis quand EMAIL_ENABLED=true".to_string());
            }
            if self.email_smtp_password.is_empty() {
                return Err("EMAIL_SMTP_PASSWORD requis quand EMAIL_ENABLED=true".to_string());
            }
        }
        
        if self.ml_training_retention_days < 7 {
            return Err("ML_TRAINING_RETENTION_DAYS doit être >= 7 jours".to_string());
        }
        
        if self.log_compression_after_days < self.ml_training_retention_days {
            return Err("LOG_COMPRESSION_AFTER_DAYS doit être >= ML_TRAINING_RETENTION_DAYS".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.ml_training_retention_days, 30);
        assert_eq!(config.auth_2fa_method, Auth2FAMethod::Both);
        assert!(config.email_enabled);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        config.email_enabled = true;
        config.email_smtp_username = String::new();
        
        assert!(config.validate().is_err());
    }
}

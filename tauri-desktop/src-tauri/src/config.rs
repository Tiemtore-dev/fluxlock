// ============================================
// MODULE DE CONFIGURATION
// ============================================
// Charge et expose toutes les variables d'environnement

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    // Authentification 2FA
    pub auth_2fa_method: Auth2FAMethod,
    pub auth_email_code_validity: i32,
    pub auth_2fa_max_attempts: i32,
    pub auth_2fa_lockout_minutes: i32,
    
    // Base de données
    pub database_path: String,
    pub database_wal_mode: bool,
    pub database_cache_size: i32,
    
    // Sécurité
    pub session_token_validity_hours: i32,
    
    // Performance
    pub max_file_size_mb: i32,
    
    // Logs & Monitoring
    pub log_level: String,
    pub log_rotation: String,
    pub log_max_size_mb: i32,
    pub log_retention_count: i32,
    
    // Réseau P2P
    pub p2p_port: u16,
    pub beacon_port: u16,
    pub multicast_group: String,
    pub wormhole_ttl_secs: u64,
    pub connect_timeout_secs: u64,
    
    // Argon2id KDF params
    pub argon2_memory_kb: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
    
    // Auto-lock
    pub auto_lock_timeout_secs: u64,
    
    // Isolation réseau
    pub isolation_enabled: bool,
    
    // Logs signés
    pub signed_logging_enabled: bool,
    
    // Cache clé vault (Keychain / Secure Enclave)
    pub cache_enabled: bool,
    pub cache_ttl_secs: u64,
    pub cache_mask_rotation_secs: u64,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("auth_2fa_method", &self.auth_2fa_method)
            .field("database_path", &self.database_path)
            .field("log_level", &self.log_level)
            .field("p2p_port", &self.p2p_port)
            .field("beacon_port", &self.beacon_port)
            .finish_non_exhaustive()
    }
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
            // Auth defaults
            auth_2fa_method: Auth2FAMethod::Both,
            auth_email_code_validity: 300,
            auth_2fa_max_attempts: 5,
            auth_2fa_lockout_minutes: 15,
            
            // Database defaults
            database_path: "./database/secure_vault.db".to_string(),
            database_wal_mode: true,
            database_cache_size: 10000,
            
            // Security defaults
            session_token_validity_hours: 24,
            
            // Performance defaults
            max_file_size_mb: 100,
            
            // Log defaults
            log_level: "info".to_string(),
            log_rotation: "daily".to_string(),
            log_max_size_mb: 50,
            log_retention_count: 10,
            
            // Réseau P2P defaults
            p2p_port: 52820,
            beacon_port: 52821,
            multicast_group: "239.255.77.77".to_string(),
            wormhole_ttl_secs: 300,
            connect_timeout_secs: 5,
            
            // Argon2id defaults (OWASP 2024)
            argon2_memory_kb: 65536,  // 64 MiB
            argon2_iterations: 3,
            argon2_parallelism: 4,
            
            // Auto-lock
            auto_lock_timeout_secs: 900, // 15 minutes
            
            // Isolation
            isolation_enabled: false,
            
            // Logs signés
            signed_logging_enabled: true,
            
            // Cache clé vault
            cache_enabled: false,
            cache_ttl_secs: 180,           // 3 minutes (OWASP)
            cache_mask_rotation_secs: 30,  // Rotation XOR mask
        }
    }
}

impl Config {
    /// Charge la configuration depuis les variables d'environnement.
    /// Note: le .env doit être chargé en amont (lib.rs::run() via dotenv::from_path).
    pub fn from_env() -> Self {
        
        let mut config = Config::default();
        
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
        
        // Performance
        if let Ok(val) = env::var("MAX_FILE_SIZE_MB") {
            config.max_file_size_mb = val.parse().unwrap_or(100);
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
        
        // Réseau P2P
        if let Ok(val) = env::var("VAULT_P2P_PORT") {
            config.p2p_port = val.parse().unwrap_or(52820);
        }
        if let Ok(val) = env::var("VAULT_BEACON_PORT") {
            config.beacon_port = val.parse().unwrap_or(52821);
        }
        if let Ok(val) = env::var("VAULT_MULTICAST_GROUP") {
            config.multicast_group = val;
        }
        if let Ok(val) = env::var("VAULT_WORMHOLE_TTL_SECS") {
            config.wormhole_ttl_secs = val.parse().unwrap_or(300);
        }
        if let Ok(val) = env::var("VAULT_CONNECT_TIMEOUT_SECS") {
            config.connect_timeout_secs = val.parse().unwrap_or(5);
        }
        
        // Argon2id — VULN-009: Enforce minimum security parameters
        if let Ok(val) = env::var("VAULT_ARGON2_MEMORY_KB") {
            let parsed = val.parse().unwrap_or(65536u32);
            config.argon2_memory_kb = parsed.max(65536); // Min 64 MiB (OWASP)
        }
        if let Ok(val) = env::var("VAULT_ARGON2_ITERATIONS") {
            let parsed = val.parse().unwrap_or(3u32);
            config.argon2_iterations = parsed.max(3); // Min 3 itérations
        }
        if let Ok(val) = env::var("VAULT_ARGON2_PARALLELISM") {
            let parsed = val.parse().unwrap_or(4u32);
            config.argon2_parallelism = parsed.max(1); // Min 1 thread
        }
        
        // Auto-lock
        if let Ok(val) = env::var("VAULT_LOCK_TIMEOUT_SECS") {
            config.auto_lock_timeout_secs = val.parse().unwrap_or(900);
        }
        
        // Isolation
        if let Ok(val) = env::var("VAULT_ISOLATION_ENABLED") {
            config.isolation_enabled = val.to_lowercase() == "true";
        }
        
        // Logs signés
        if let Ok(val) = env::var("VAULT_SIGNED_LOGGING_ENABLED") {
            config.signed_logging_enabled = val.to_lowercase() != "false";
        }
        
        // Cache clé vault
        if let Ok(val) = env::var("UTILISATION_CACHE") {
            config.cache_enabled = val.to_lowercase() != "false";
        }
        if let Ok(val) = env::var("VAULT_CACHE_TTL_SECS") {
            let parsed = val.parse().unwrap_or(180u64);
            config.cache_ttl_secs = parsed.max(60).min(600); // Min 1 min, Max 10 min
        }
        if let Ok(val) = env::var("VAULT_CACHE_MASK_ROTATION_SECS") {
            let parsed = val.parse().unwrap_or(30u64);
            config.cache_mask_rotation_secs = parsed.max(10).min(120); // Min 10s, Max 2 min
        }
        
        config
    }
    
    /// Valide la configuration
    pub fn validate(&self) -> Result<(), String> {
        let mut warnings = Vec::new();
        
        // Validation réseau
        if self.p2p_port == 0 {
            warnings.push("VAULT_P2P_PORT doit être entre 1 et 65535".to_string());
        }
        if self.beacon_port == 0 {
            warnings.push("VAULT_BEACON_PORT doit être entre 1 et 65535".to_string());
        }
        if self.p2p_port == self.beacon_port {
            warnings.push("VAULT_P2P_PORT et VAULT_BEACON_PORT doivent être différents".to_string());
        }
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > 120 {
            warnings.push("VAULT_CONNECT_TIMEOUT_SECS doit être entre 1 et 120".to_string());
        }
        if self.wormhole_ttl_secs == 0 || self.wormhole_ttl_secs > 3600 {
            warnings.push("VAULT_WORMHOLE_TTL_SECS doit être entre 1 et 3600".to_string());
        }
        
        // Validation Argon2id (OWASP minimums)
        if self.argon2_memory_kb < 19456 {
            warnings.push("VAULT_ARGON2_MEMORY_KB doit être >= 19456 (19 MiB minimum OWASP)".to_string());
        }
        if self.argon2_iterations < 1 {
            warnings.push("VAULT_ARGON2_ITERATIONS doit être >= 1".to_string());
        }
        if self.argon2_parallelism < 1 || self.argon2_parallelism > 16 {
            warnings.push("VAULT_ARGON2_PARALLELISM doit être entre 1 et 16".to_string());
        }
        
        // Validation cache
        if self.cache_ttl_secs < 60 || self.cache_ttl_secs > 600 {
            warnings.push("VAULT_CACHE_TTL_SECS doit être entre 60 et 600".to_string());
        }
        if self.cache_mask_rotation_secs < 10 || self.cache_mask_rotation_secs > 120 {
            warnings.push("VAULT_CACHE_MASK_ROTATION_SECS doit être entre 10 et 120".to_string());
        }
        if self.cache_mask_rotation_secs >= self.cache_ttl_secs {
            warnings.push("VAULT_CACHE_MASK_ROTATION_SECS doit être inférieur à VAULT_CACHE_TTL_SECS".to_string());
        }
        
        if warnings.is_empty() {
            Ok(())
        } else {
            Err(warnings.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.auth_2fa_method, Auth2FAMethod::Both);
        assert_eq!(config.p2p_port, 52820);
        assert_eq!(config.beacon_port, 52821);
        assert!(config.signed_logging_enabled);
    }
    
    #[test]
    fn test_config_validation() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_config_validation_same_ports() {
        let mut config = Config::default();
        config.p2p_port = 52820;
        config.beacon_port = 52820;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_config_validation_argon2_too_low() {
        let mut config = Config::default();
        config.argon2_memory_kb = 1000;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_parallelism_zero() {
        let mut config = Config::default();
        config.argon2_parallelism = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("PARALLELISM"));
    }

    #[test]
    fn test_config_validation_parallelism_too_high() {
        let mut config = Config::default();
        config.argon2_parallelism = 17;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_connect_timeout_zero() {
        let mut config = Config::default();
        config.connect_timeout_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_connect_timeout_too_high() {
        let mut config = Config::default();
        config.connect_timeout_secs = 121;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_wormhole_ttl_zero() {
        let mut config = Config::default();
        config.wormhole_ttl_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_wormhole_ttl_too_high() {
        let mut config = Config::default();
        config.wormhole_ttl_secs = 3601;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_port_zero() {
        let mut config = Config::default();
        config.p2p_port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validation_beacon_port_zero() {
        let mut config = Config::default();
        config.beacon_port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_argon2_owasp_minimum_accepted() {
        let mut config = Config::default();
        config.argon2_memory_kb = 19456; // Exact OWASP minimum
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_all_edge_bounds() {
        let mut config = Config::default();
        config.connect_timeout_secs = 1;
        config.wormhole_ttl_secs = 1;
        config.argon2_parallelism = 1;
        config.argon2_iterations = 1;
        assert!(config.validate().is_ok());

        config.connect_timeout_secs = 120;
        config.wormhole_ttl_secs = 3600;
        config.argon2_parallelism = 16;
        assert!(config.validate().is_ok());
    }
}

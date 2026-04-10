//! Moniteur de sécurité natif Rust
//! 
//! Ce module implémente :
//! - Détection d'activité ransomware en temps réel
//! - Mode lecture seule automatique en cas de menace

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    }
}

// ========== STRUCTURES ==========

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

// ========== MONITEUR DE SÉCURITÉ ==========

pub struct SecurityMonitor {
    /// Activité fichiers (détection ransomware)
    file_activity: Arc<Mutex<FileActivity>>,
    
    /// État de sécurité global
    security_state: Arc<Mutex<SecurityState>>,
    
    /// VULN-010: Compteur de tentatives échouées (username → (count, first_attempt_timestamp))
    failed_attempts: Arc<Mutex<std::collections::HashMap<String, (u32, u64)>>>,
}

impl SecurityMonitor {
    /// Crée un nouveau moniteur de sécurité
    pub fn new() -> Self {
        SecurityMonitor {
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
            failed_attempts: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    // ========== BRUTE-FORCE (Utilisé par main.rs) ==========

    /// Vérifie si un utilisateur est verrouillé suite à trop de tentatives échouées
    /// VULN-010: Rate limiting pour brute-force login et 2FA
    pub async fn is_user_locked(&self, username: &str) -> Option<u64> {
        let mut attempts = self.failed_attempts.lock().await;
        let now = current_timestamp();
        
        if let Some((count, first_ts)) = attempts.get(username) {
            // Fenêtre de 5 minutes
            let window = 300u64;
            if now - first_ts > window {
                // Fenêtre expirée, reset
                attempts.remove(username);
                return None;
            }
            // Verrouillage si >= 5 tentatives en 5 min
            if *count >= 5 {
                let remaining = window.saturating_sub(now - first_ts);
                return Some(remaining);
            }
        }
        None
    }

    /// VULN-010: Enregistre une tentative échouée (login ou 2FA)
    pub async fn record_failed_attempt(&self, username: &str) {
        let mut attempts = self.failed_attempts.lock().await;
        let now = current_timestamp();
        
        let entry = attempts.entry(username.to_string()).or_insert((0, now));
        // Reset si la fenêtre de 5 min a expiré
        if now - entry.1 > 300 {
            *entry = (1, now);
        } else {
            entry.0 += 1;
        }
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
        
        debug_log!("🚨 ALERTE RANSOMWARE: {}", reason);
        debug_log!("🔒 Coffre-fort passé en MODE LECTURE SEULE");
        
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
            
            debug_log!("🔒 SecurityMonitor: Mode lecture seule activé");
            debug_log!("   Raison: {}", reason);
        }
        
        Ok(())
    }

    /// Désactive le mode lecture seule (admin uniquement)
    pub async fn disable_readonly(&self, admin_password: &str) -> Result<(), String> {
        // Vérification basique — le handler Tauri doit valider le mot de passe
        // via verify_password() AVANT d'appeler cette méthode
        if admin_password.is_empty() {
            return Err("Mot de passe administrateur requis pour désactiver le mode lecture seule".to_string());
        }
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
        
        debug_log!("✅ Mode lecture seule désactivé sur les deux moniteurs");
        
        Ok(())
    }

    // ========== AUTHENTIFICATION OTP EMAIL ==========

    // ========== ÉTAT DE SÉCURITÉ ==========

    /// Récupère l'état de sécurité actuel
    pub async fn get_security_state(&self) -> SecurityState {
        self.security_state.lock().await.clone()
    }

    /// Réinitialise tous les compteurs (maintenance)
    pub async fn reset_all(&self) {
        let mut activity = self.file_activity.lock().await;
        activity.access_count = 0;
        activity.suspicious_extensions.clear();
        
        let mut state = self.security_state.lock().await;
        state.is_locked = false;
        state.is_readonly = false;
        state.threat_level = ThreatLevel::None;
        state.active_threats.clear();
    }
}

// ========== TYPES DE RÉSULTATS ==========

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

// ========== SINGLETON GLOBAL (THREAD-SAFE) ==========

static SECURITY_MONITOR: Lazy<SecurityMonitor> = Lazy::new(|| SecurityMonitor::new());

pub fn get_security_monitor() -> &'static SecurityMonitor {
    &SECURITY_MONITOR
}

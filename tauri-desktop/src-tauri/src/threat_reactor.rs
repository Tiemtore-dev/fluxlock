use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use chrono::{DateTime, Utc, Duration};
use std::path::PathBuf;

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatResponse {
    pub action_taken: String,
    pub blocked: bool,
    pub requires_2fa: bool,
    pub rate_limited: bool,
    pub notifications_sent: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
struct RateLimitEntry {
    last_action: DateTime<Utc>,
    action_count: u32,
}

pub struct ThreatReactor {
    rate_limits: Arc<Mutex<HashMap<i64, RateLimitEntry>>>,
    blocked_users: Arc<Mutex<HashMap<i64, DateTime<Utc>>>>,
    persist_path: Option<PathBuf>,
}

/// Serializable snapshot of blocked_users for disk persistence (uses RFC 3339 strings)
#[derive(Serialize, Deserialize)]
struct BlockedSnapshot(HashMap<i64, String>);

impl ThreatReactor {
    pub fn new() -> Self {
        Self {
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            blocked_users: Arc::new(Mutex::new(HashMap::new())),
            persist_path: None,
        }
    }

    /// Create a ThreatReactor that persists blocked users to disk (VULN-011)
    pub fn with_persistence(data_dir: PathBuf) -> Self {
        let path = data_dir.join("threat_blocked.json");
        let blocked = if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(data) => {
                    let snapshot: BlockedSnapshot = serde_json::from_str(&data).unwrap_or(BlockedSnapshot(HashMap::new()));
                    let now = Utc::now();
                    snapshot.0.into_iter()
                        .filter_map(|(uid, ts)| {
                            DateTime::parse_from_rfc3339(&ts).ok().map(|dt| (uid, dt.with_timezone(&Utc)))
                        })
                        .filter(|(_, until)| now < *until)
                        .collect()
                }
                Err(_) => HashMap::new(),
            }
        } else {
            HashMap::new()
        };
        Self {
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            blocked_users: Arc::new(Mutex::new(blocked)),
            persist_path: Some(path),
        }
    }

    /// Flush blocked_users to disk
    async fn persist_blocked(&self) {
        if let Some(ref path) = self.persist_path {
            let blocked = self.blocked_users.lock().await;
            let snapshot = BlockedSnapshot(
                blocked.iter().map(|(uid, dt)| (*uid, dt.to_rfc3339())).collect()
            );
            if let Ok(json) = serde_json::to_string(&snapshot) {
                let _ = std::fs::write(path, json);
            }
        }
    }

    /// Réagit à une menace détectée selon le niveau de risque
    pub async fn react_to_threat(
        &self,
        user_id: i64,
        risk_score: f64,
        threat_level: &str,
        anomalies: &[String],
    ) -> ThreatResponse {
        let mut response = ThreatResponse {
            action_taken: String::new(),
            blocked: false,
            requires_2fa: false,
            rate_limited: false,
            notifications_sent: Vec::new(),
            message: String::new(),
        };

        match threat_level {
            "critical" if risk_score >= 80.0 => {
                // CRITIQUE: Blocage immédiat
                response.blocked = true;
                response.requires_2fa = true;
                response.action_taken = "ACCOUNT_BLOCKED".to_string();
                response.message = "Activité hautement suspecte détectée. Compte bloqué pour 30 minutes. Authentification 2FA requise pour débloquer.".to_string();
                
                // Bloquer le compte
                let mut blocked = self.blocked_users.lock().await;
                blocked.insert(user_id, Utc::now() + Duration::minutes(30));
                drop(blocked);
                self.persist_blocked().await;
                
                // Notifications
                response.notifications_sent.push("email_admin".to_string());
                response.notifications_sent.push("email_user".to_string());
                response.notifications_sent.push("incident_report".to_string());
                
                debug_log!("🚨 CRITICAL: User {} blocked for 30 minutes", user_id);
            }
            
            "high" if risk_score >= 60.0 => {
                // HIGH: Challenge 2FA + Rate limiting strict
                response.requires_2fa = true;
                response.rate_limited = true;
                response.action_taken = "2FA_CHALLENGE_REQUIRED".to_string();
                response.message = "Comportement inhabituel détecté. Vérification 2FA requise. Actions limitées à 1 toutes les 10 secondes.".to_string();
                
                // Rate limiting strict: 1 action / 10 secondes
                self.apply_rate_limit(user_id, 10).await;
                
                // Notifications
                response.notifications_sent.push("email_user".to_string());
                response.notifications_sent.push("push_notification".to_string());
                response.notifications_sent.push("alert_admin".to_string());
                
                debug_log!("⚠️ HIGH: User {} requires 2FA challenge", user_id);
            }
            
            "medium" if risk_score >= 40.0 => {
                // MEDIUM: Rate limiting + Email notification
                response.rate_limited = true;
                response.action_taken = "RATE_LIMITED".to_string();
                response.message = "Activité anormale détectée. Actions limitées à 1 toutes les 5 secondes. Email de notification envoyé.".to_string();
                
                // Rate limiting modéré: 1 action / 5 secondes
                self.apply_rate_limit(user_id, 5).await;
                
                // Notifications
                response.notifications_sent.push("email_user".to_string());
                
                debug_log!("📊 MEDIUM: User {} rate limited (1 action / 5s)", user_id);
            }
            
            _ => {
                // LOW: Logging seulement
                response.action_taken = "LOGGED".to_string();
                response.message = "Activité normale. Aucune action requise.".to_string();
                debug_log!("✅ LOW: User {} activity logged", user_id);
            }
        }

        // Ajouter détails des anomalies
        if !anomalies.is_empty() {
            response.message.push_str(&format!("\n\nAnomalies détectées:\n{}", anomalies.join("\n")));
        }

        response
    }

    /// Applique un rate limiting pour un utilisateur
    async fn apply_rate_limit(&self, user_id: i64, seconds: i64) {
        let mut limits = self.rate_limits.lock().await;
        limits.insert(user_id, RateLimitEntry {
            last_action: Utc::now(),
            action_count: 0,
        });
        debug_log!("🔒 Rate limit applied: User {} - 1 action / {}s", user_id, seconds);
    }

    /// Vérifie si un utilisateur est rate limited
    pub async fn check_rate_limit(&self, user_id: i64) -> (bool, Option<u64>) {
        let limits = self.rate_limits.lock().await;
        
        if let Some(entry) = limits.get(&user_id) {
            let elapsed = Utc::now().signed_duration_since(entry.last_action);
            
            // Déterminer le délai selon le nombre d'actions
            let required_delay = if entry.action_count > 10 {
                Duration::seconds(10) // Rate limit strict
            } else {
                Duration::seconds(5) // Rate limit modéré
            };
            
            if elapsed < required_delay {
                let remaining = (required_delay - elapsed).num_seconds() as u64;
                return (true, Some(remaining));
            }
        }
        
        (false, None)
    }

    /// Vérifie si un utilisateur est bloqué
    pub async fn check_blocked(&self, user_id: i64) -> (bool, Option<String>) {
        let mut blocked = self.blocked_users.lock().await;
        
        if let Some(until) = blocked.get(&user_id) {
            if Utc::now() < *until {
                let remaining = (*until - Utc::now()).num_minutes();
                return (true, Some(format!("Compte bloqué pour {} minutes restantes", remaining)));
            } else {
                // Débloquer automatiquement
                blocked.remove(&user_id);
                drop(blocked);
                self.persist_blocked().await;
            }
        }
        
        (false, None)
    }

    /// Débloquer manuellement un utilisateur (admin)
    #[allow(dead_code)]
    pub async fn manual_unblock(&self, user_id: i64) -> bool {
        let mut blocked = self.blocked_users.lock().await;
        let removed = blocked.remove(&user_id).is_some();
        drop(blocked);
        if removed {
            self.persist_blocked().await;
        }
        removed
    }

    /// Réinitialiser le rate limit pour un utilisateur
    #[allow(dead_code)]
    pub async fn reset_rate_limit(&self, user_id: i64) {
        let mut limits = self.rate_limits.lock().await;
        limits.remove(&user_id);
    }

    /// Nettoyer les anciennes entrées (tâche de maintenance)
    #[allow(dead_code)]
    pub async fn cleanup_old_entries(&self) {
        let mut limits = self.rate_limits.lock().await;
        let mut blocked = self.blocked_users.lock().await;
        
        let now = Utc::now();
        
        // Retirer les rate limits de plus de 1 heure
        limits.retain(|_, entry| {
            now.signed_duration_since(entry.last_action) < Duration::hours(1)
        });
        
        // Retirer les blocages expirés
        blocked.retain(|_, until| now < *until);
        
        debug_log!("🧹 Cleanup: {} rate limits, {} blocked users", limits.len(), blocked.len());
        drop(limits);
        drop(blocked);
        self.persist_blocked().await;
    }
}

impl Default for ThreatReactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_critical_threat() {
        let reactor = ThreatReactor::new();
        let response = reactor.react_to_threat(
            1,
            85.0,
            "critical",
            &["Accès rapide anormal".to_string()]
        ).await;

        assert!(response.blocked);
        assert!(response.requires_2fa);
        assert_eq!(response.action_taken, "ACCOUNT_BLOCKED");
        assert!(response.notifications_sent.contains(&"email_admin".to_string()));
    }

    #[tokio::test]
    async fn test_high_threat() {
        let reactor = ThreatReactor::new();
        let response = reactor.react_to_threat(
            2,
            65.0,
            "high",
            &["IP inhabituelle".to_string()]
        ).await;

        assert!(!response.blocked);
        assert!(response.requires_2fa);
        assert!(response.rate_limited);
        assert_eq!(response.action_taken, "2FA_CHALLENGE_REQUIRED");
    }

    #[tokio::test]
    async fn test_rate_limit() {
        let reactor = ThreatReactor::new();
        reactor.apply_rate_limit(3, 5).await;

        let (limited, _) = reactor.check_rate_limit(3).await;
        assert!(limited);

        // Attendre 6 secondes
        tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;
        let (limited, _) = reactor.check_rate_limit(3).await;
        assert!(!limited);
    }

    #[tokio::test]
    async fn test_blocking() {
        let reactor = ThreatReactor::new();
        let mut blocked = reactor.blocked_users.lock().await;
        blocked.insert(4, Utc::now() + Duration::minutes(5));
        drop(blocked);

        let (is_blocked, msg) = reactor.check_blocked(4).await;
        assert!(is_blocked);
        assert!(msg.is_some());

        let unblocked = reactor.manual_unblock(4).await;
        assert!(unblocked);

        let (is_blocked, _) = reactor.check_blocked(4).await;
        assert!(!is_blocked);
    }
}

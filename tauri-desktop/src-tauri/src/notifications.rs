use serde::{Deserialize, Serialize};
use chrono::Utc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub recipient_email: String,
    pub subject: String,
    pub body: String,
    pub notification_type: NotificationType,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    FileShared,
    FileAccessed,
    ShareExpired,
    SecurityAlert,
    AccountLocked,
    TwoFactorEnabled,
}

pub struct NotificationService {
    enabled: bool,
}

impl NotificationService {
    pub fn new() -> Self {
        Self { enabled: true }
    }

    /// Envoie une notification de partage de fichier
    pub async fn notify_file_shared(
        &self,
        owner_email: &str,
        recipient_email: &str,
        filename: &str,
        expires_at: &str,
    ) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let notification = Notification {
            recipient_email: recipient_email.to_string(),
            subject: format!("📁 {} a partagé un fichier avec vous", owner_email),
            body: format!(
                "Bonjour,\n\n\
                {} a partagé le fichier \"{}\" avec vous via SecureVault.\n\n\
                Ce partage expire le: {}\n\n\
                Ouvrez SecureVault pour accéder au fichier.\n\n\
                Cordialement,\n\
                L'équipe SecureVault",
                owner_email, filename, expires_at
            ),
            notification_type: NotificationType::FileShared,
            timestamp: Utc::now().to_rfc3339(),
        };

        self.send_notification(notification).await
    }

    /// Notifie le propriétaire qu'un fichier a été accédé
    pub async fn notify_file_accessed(
        &self,
        owner_email: &str,
        filename: &str,
        accessor_email: &str,
        access_count: i64,
    ) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let notification = Notification {
            recipient_email: owner_email.to_string(),
            subject: format!("🔔 Votre fichier \"{}\" a été accédé", filename),
            body: format!(
                "Bonjour,\n\n\
                {} a accédé au fichier \"{}\" que vous avez partagé.\n\n\
                Nombre total d'accès: {}\n\
                Date et heure: {}\n\n\
                Cordialement,\n\
                L'équipe SecureVault",
                accessor_email,
                filename,
                access_count,
                Utc::now().format("%Y-%m-%d %H:%M:%S")
            ),
            notification_type: NotificationType::FileAccessed,
            timestamp: Utc::now().to_rfc3339(),
        };

        self.send_notification(notification).await
    }

    /// Notifie d'une alerte de sécurité
    pub async fn notify_security_alert(
        &self,
        user_email: &str,
        alert_type: &str,
        details: &str,
    ) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let notification = Notification {
            recipient_email: user_email.to_string(),
            subject: format!("🚨 Alerte de sécurité: {}", alert_type),
            body: format!(
                "Bonjour,\n\n\
                Une activité suspecte a été détectée sur votre compte SecureVault.\n\n\
                Type d'alerte: {}\n\
                Détails: {}\n\
                Date et heure: {}\n\n\
                Si ce n'est pas vous, veuillez sécuriser votre compte immédiatement.\n\n\
                Cordialement,\n\
                L'équipe SecureVault",
                alert_type,
                details,
                Utc::now().format("%Y-%m-%d %H:%M:%S")
            ),
            notification_type: NotificationType::SecurityAlert,
            timestamp: Utc::now().to_rfc3339(),
        };

        self.send_notification(notification).await
    }

    /// Notifie d'un blocage de compte
    pub async fn notify_account_locked(
        &self,
        user_email: &str,
        duration_minutes: i64,
        reason: &str,
    ) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }

        let notification = Notification {
            recipient_email: user_email.to_string(),
            subject: "🔒 Votre compte SecureVault a été temporairement bloqué".to_string(),
            body: format!(
                "Bonjour,\n\n\
                Votre compte a été temporairement bloqué pour des raisons de sécurité.\n\n\
                Raison: {}\n\
                Durée du blocage: {} minutes\n\
                Date et heure: {}\n\n\
                Le compte sera automatiquement débloqué après cette période.\n\
                Si vous pensez qu'il s'agit d'une erreur, contactez le support.\n\n\
                Cordialement,\n\
                L'équipe SecureVault",
                reason,
                duration_minutes,
                Utc::now().format("%Y-%m-%d %H:%M:%S")
            ),
            notification_type: NotificationType::AccountLocked,
            timestamp: Utc::now().to_rfc3339(),
        };

        self.send_notification(notification).await
    }

    /// Envoie effectivement la notification
    async fn send_notification(&self, notification: Notification) -> Result<(), String> {
        // Pour l'instant, on logue simplement
        // Dans une version production, intégrer SMTP ou un service d'email
        println!("📧 NOTIFICATION ENVOYÉE");
        println!("   To: {}", notification.recipient_email);
        println!("   Subject: {}", notification.subject);
        println!("   Type: {:?}", notification.notification_type);
        println!("   Timestamp: {}", notification.timestamp);

        // TODO: Intégrer un vrai service d'email
        // Exemples:
        // - SMTP avec lettre crate
        // - SendGrid API
        // - AWS SES
        // - Mailgun

        Ok(())
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }
}

impl Default for NotificationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_shared_notification() {
        let service = NotificationService::new();
        let result = service
            .notify_file_shared(
                "owner@example.com",
                "recipient@example.com",
                "secret.pdf",
                "2025-12-31",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_file_accessed_notification() {
        let service = NotificationService::new();
        let result = service
            .notify_file_accessed(
                "owner@example.com",
                "document.pdf",
                "viewer@example.com",
                3,
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_security_alert() {
        let service = NotificationService::new();
        let result = service
            .notify_security_alert(
                "user@example.com",
                "Connexion suspecte",
                "Tentative de connexion depuis un pays inhabituel",
            )
            .await;
        assert!(result.is_ok());
    }
}

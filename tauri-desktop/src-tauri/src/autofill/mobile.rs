//! Chromium Native Messaging is desktop-only. Mobile has no listener, browser
//! credentials, native pairing window, or registered autofill IPC commands.
//! Keep the vault lifecycle interface so lock/restore remain platform-neutral.
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct Service {
    pub busy: AtomicBool,
}
impl Service {
    pub async fn cancel(&self) {
        self.busy.store(false, Ordering::SeqCst);
    }
    pub async fn reset_vault(&self, _vault: &str) -> Result<(), String> {
        self.cancel().await;
        Ok(())
    }
}
pub fn command_allowed(label: &str, command: &str) -> bool {
    label == "main" && !command.starts_with("autofill_")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_commands_and_secondary_windows_are_rejected_on_mobile() {
        for command in [
            "autofill_enable",
            "autofill_settings",
            "autofill_authenticate",
        ] {
            assert!(!command_allowed("main", command));
        }
        assert!(!command_allowed("autofill-auth-fake", "get_passwords"));
        assert!(command_allowed("main", "lock_session"));
    }
    #[tokio::test]
    async fn lock_and_restore_can_clear_the_mobile_lifecycle_guard() {
        let service = Service::default();
        service.busy.store(true, Ordering::SeqCst);
        service.cancel().await;
        assert!(!service.busy.load(Ordering::SeqCst));
        service.busy.store(true, Ordering::SeqCst);
        service.reset_vault("selected-vault").await.unwrap();
        assert!(!service.busy.load(Ordering::SeqCst));
    }
}

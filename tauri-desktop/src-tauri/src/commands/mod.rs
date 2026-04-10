pub mod auth;
pub mod session;
pub mod passwords;
pub mod files;
pub mod keys;
pub mod sharing;
pub mod security;
pub mod biometric_cmds;
pub mod totp_2fa;
pub mod backup;
pub mod system;

// Re-export all command functions for generate_handler![]
pub use auth::*;
pub use session::*;
pub use passwords::*;
pub use files::*;
pub use keys::*;
pub use sharing::*;
pub use security::*;
pub use biometric_cmds::*;
pub use totp_2fa::*;
pub use backup::*;
pub use system::*;

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::FromRow;
use serde::{Deserialize, Serialize};
use std::path::Path;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use flate2::Compression;
use std::io::{Read, Write};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub crypto_salt: String,  // Sel pour dérivation de clé de chiffrement (base64)
    pub totp_secret: Option<String>,  // Secret TOTP (base32)
    pub totp_enabled: bool,
    pub totp_verified_at: Option<String>,
    pub backup_codes: Option<String>,  // JSON array of backup codes
    pub account_locked: bool,  // Pour blocage lors de menaces
    pub locked_until: Option<String>,  // Date de fin de blocage
    pub created_at: String,
}

// Structures ML (ajoutées)
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MLUserProfile {
    pub id: Option<i64>,
    pub user_id: i64,
    pub profile_data: String,  // JSON
    pub last_updated: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MLModel {
    pub id: Option<i64>,
    pub model_name: String,
    pub model_data: Vec<u8>,  // Pickle bytes
    pub hyperparameters: Option<String>,  // JSON
    pub training_date: String,
    pub accuracy_score: Option<f64>,
    pub n_samples_trained: Option<i64>,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MLTrainingLog {
    pub id: Option<i64>,
    pub user_id: i64,
    pub action_type: String,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub timestamp: String,
    pub metadata: Option<String>,  // JSON
    pub risk_score: f64,
    pub is_anomaly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CompressedLog {
    pub id: Option<i64>,
    pub user_id: Option<i64>,
    pub compression_format: String,
    pub compressed_data: Vec<u8>,
    pub original_size_bytes: i64,
    pub compressed_size_bytes: i64,
    pub compression_ratio: f64,
    pub log_count: i64,
    pub start_date: String,
    pub end_date: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct CompressionStats {
    pub user_id: Option<i64>,
    pub archive_count: i64,
    pub total_logs_archived: i64,
    pub total_original_bytes: i64,
    pub total_compressed_bytes: i64,
    pub avg_compression_ratio: f64,
    pub oldest_log: String,
    pub newest_log: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Password {
    pub id: i64,
    pub user_id: i64,
    pub title: String,
    pub username: Option<String>,
    pub password: String, // Encrypted
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecureFile {
    pub id: i64,
    pub user_id: i64,
    pub filename: String,
    pub file_path: String, // Path to encrypted file
    pub file_size: i64,
    pub mime_type: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SecureKey {
    pub id: i64,
    pub user_id: i64,
    pub key_name: String,
    pub key_type: String, // "private", "public", "symmetric"
    pub key_data: String, // Encrypted key data
    pub algorithm: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FileShare {
    pub id: i64,
    pub file_id: i64,
    pub owner_id: i64,
    pub recipient_email: String,
    pub share_token: String, // Token unique pour accéder au fichier
    pub encrypted_key: String, // Clé de déchiffrement chiffrée avec la clé du destinataire
    pub expires_at: String,
    pub accessed: bool,
    pub access_count: i64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct ActionLog {
    pub id: i64,
    pub user_id: i64,
    pub action_type: String,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub timestamp: String,
}

pub struct Database {
    pub pool: SqlitePool,
}

impl Database {
    pub async fn new(db_path: &Path) -> Result<Self, sqlx::Error> {
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| sqlx::Error::Io(e))?;
        }
        
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await?;
        
        Ok(Self { pool })
    }

    pub async fn initialize(&self) -> Result<(), sqlx::Error> {
        // Create users table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                crypto_salt TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled BOOLEAN DEFAULT 0,
                totp_verified_at DATETIME,
                backup_codes TEXT,
                account_locked BOOLEAN DEFAULT 0,
                locked_until DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create passwords table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                url TEXT,
                notes TEXT,
                category TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create secure_files table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS secure_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create secure_keys table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS secure_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_name TEXT NOT NULL,
                key_type TEXT NOT NULL,
                key_data TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create audit logs table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id INTEGER,
                ip_address TEXT,
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Table pour le partage de fichiers
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS file_shares (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                owner_id INTEGER NOT NULL,
                recipient_email TEXT NOT NULL,
                share_token TEXT NOT NULL UNIQUE,
                encrypted_key TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                accessed BOOLEAN DEFAULT 0,
                access_count INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (file_id) REFERENCES secure_files(id) ON DELETE CASCADE,
                FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create ML user profiles table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ml_user_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                profile_data TEXT NOT NULL,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                version TEXT NOT NULL DEFAULT '1.0',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create ML models table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ml_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL UNIQUE,
                model_data BLOB NOT NULL,
                hyperparameters TEXT,
                training_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                accuracy_score REAL,
                n_samples_trained INTEGER,
                version TEXT NOT NULL DEFAULT '1.0'
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create ML training logs table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ml_training_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                action_type TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT,
                risk_score REAL NOT NULL DEFAULT 0.0,
                is_anomaly BOOLEAN NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create compressed logs table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS compressed_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                compression_format TEXT NOT NULL DEFAULT 'gzip',
                compressed_data BLOB NOT NULL,
                original_size_bytes INTEGER NOT NULL,
                compressed_size_bytes INTEGER NOT NULL,
                compression_ratio REAL NOT NULL,
                log_count INTEGER NOT NULL,
                start_date DATETIME NOT NULL,
                end_date DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // User operations
    pub async fn create_user(&self, username: &str, email: &str, password_hash: &str, crypto_salt: &str) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO users (username, email, password_hash, crypto_salt) VALUES (?, ?, ?, ?)"
        )
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(crypto_salt)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE username = ?"
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }
    
    pub async fn get_user_by_id(&self, user_id: i64) -> Result<Option<User>, sqlx::Error> {
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = ?"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    // Password operations
    pub async fn create_password(&self, user_id: i64, title: &str, username: Option<&str>, 
                                  password: &str, url: Option<&str>, notes: Option<&str>, 
                                  category: Option<&str>) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO passwords (user_id, title, username, password, url, notes, category)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(title)
        .bind(username)
        .bind(password)
        .bind(url)
        .bind(notes)
        .bind(category)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_passwords(&self, user_id: i64) -> Result<Vec<Password>, sqlx::Error> {
        let passwords = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE user_id = ? ORDER BY updated_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(passwords)
    }

    pub async fn get_password(&self, id: i64, user_id: i64) -> Result<Option<Password>, sqlx::Error> {
        let password = sqlx::query_as::<_, Password>(
            "SELECT * FROM passwords WHERE id = ? AND user_id = ?"
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(password)
    }

    pub async fn update_password(&self, id: i64, user_id: i64, title: &str, 
                                  username: Option<&str>, password: &str, url: Option<&str>,
                                  notes: Option<&str>, category: Option<&str>) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE passwords 
            SET title = ?, username = ?, password = ?, url = ?, notes = ?, category = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
            "#
        )
        .bind(title)
        .bind(username)
        .bind(password)
        .bind(url)
        .bind(notes)
        .bind(category)
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_password(&self, id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM passwords WHERE id = ? AND user_id = ?"
        )
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // Secure file operations
    pub async fn create_secure_file(&self, user_id: i64, filename: &str, file_path: &str,
                                     file_size: i64, mime_type: Option<&str>) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO secure_files (user_id, filename, file_path, file_size, mime_type)
            VALUES (?, ?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(filename)
        .bind(file_path)
        .bind(file_size)
        .bind(mime_type)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_secure_files(&self, user_id: i64) -> Result<Vec<SecureFile>, sqlx::Error> {
        let files = sqlx::query_as::<_, SecureFile>(
            "SELECT * FROM secure_files WHERE user_id = ? ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(files)
    }

    pub async fn get_secure_file(&self, file_id: i64, user_id: i64) -> Result<Option<SecureFile>, sqlx::Error> {
        let file = sqlx::query_as::<_, SecureFile>(
            "SELECT * FROM secure_files WHERE id = ? AND user_id = ?"
        )
        .bind(file_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(file)
    }

    pub async fn delete_secure_file(&self, id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM secure_files WHERE id = ? AND user_id = ?"
        )
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // Secure key operations
    pub async fn create_secure_key(&self, user_id: i64, key_name: &str, key_type: &str,
                                    key_data: &str, algorithm: &str) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO secure_keys (user_id, key_name, key_type, key_data, algorithm)
            VALUES (?, ?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(key_name)
        .bind(key_type)
        .bind(key_data)
        .bind(algorithm)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_secure_keys(&self, user_id: i64) -> Result<Vec<SecureKey>, sqlx::Error> {
        let keys = sqlx::query_as::<_, SecureKey>(
            "SELECT * FROM secure_keys WHERE user_id = ? ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(keys)
    }

    pub async fn get_secure_key_by_id(&self, id: i64, user_id: i64) -> Result<SecureKey, sqlx::Error> {
        let key = sqlx::query_as::<_, SecureKey>(
            "SELECT * FROM secure_keys WHERE id = ? AND user_id = ?"
        )
        .bind(id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(key)
    }

    pub async fn delete_secure_key(&self, id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM secure_keys WHERE id = ? AND user_id = ?"
        )
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // File sharing operations
    pub async fn create_file_share(
        &self, 
        file_id: i64, 
        owner_id: i64, 
        recipient_email: &str, 
        share_token: &str, 
        encrypted_key: &str,
        expires_at: &str
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            "INSERT INTO file_shares (file_id, owner_id, recipient_email, share_token, encrypted_key, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(file_id)
        .bind(owner_id)
        .bind(recipient_email)
        .bind(share_token)
        .bind(encrypted_key)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn get_file_share_by_token(&self, token: &str) -> Result<Option<FileShare>, sqlx::Error> {
        let share = sqlx::query_as::<_, FileShare>(
            "SELECT * FROM file_shares WHERE share_token = ?"
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        Ok(share)
    }

    pub async fn get_user_shares(&self, user_id: i64) -> Result<Vec<FileShare>, sqlx::Error> {
        let shares = sqlx::query_as::<_, FileShare>(
            "SELECT * FROM file_shares WHERE owner_id = ? ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(shares)
    }

    pub async fn increment_share_access(&self, share_id: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE file_shares SET accessed = 1, access_count = access_count + 1 WHERE id = ?"
        )
        .bind(share_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn delete_file_share(&self, share_id: i64, owner_id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM file_shares WHERE id = ? AND owner_id = ?"
        )
        .bind(share_id)
        .bind(owner_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    // Audit log
    pub async fn log_action(&self, user_id: i64, action: &str, resource_type: &str,
                            resource_id: Option<i64>) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (user_id, action, resource_type, resource_id)
            VALUES (?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_user_action_logs(&self, user_id: i64, limit: Option<i64>) -> Result<Vec<ActionLog>, sqlx::Error> {
        let limit_value = limit.unwrap_or(100);
        let logs = sqlx::query_as::<_, ActionLog>(
            "SELECT id, user_id, action as action_type, resource_type, resource_id, created_at as timestamp 
             FROM audit_logs 
             WHERE user_id = ? 
             ORDER BY created_at DESC 
             LIMIT ?"
        )
        .bind(user_id)
        .bind(limit_value)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    // 2FA operations
    pub async fn enable_2fa(&self, user_id: i64, totp_secret: &str, backup_codes: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE users SET totp_secret = ?, totp_enabled = 1, backup_codes = ?, totp_verified_at = CURRENT_TIMESTAMP WHERE id = ?"
        )
        .bind(totp_secret)
        .bind(backup_codes)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn disable_2fa(&self, user_id: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE users SET totp_secret = NULL, totp_enabled = 0, backup_codes = NULL, totp_verified_at = NULL WHERE id = ?"
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_backup_codes(&self, user_id: i64, backup_codes: &str) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE users SET backup_codes = ? WHERE id = ?")
            .bind(backup_codes)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // Account locking for security
    pub async fn lock_account(&self, user_id: i64, duration_minutes: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE users SET account_locked = 1, locked_until = datetime('now', '+' || ? || ' minutes') WHERE id = ?"
        )
        .bind(duration_minutes)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn unlock_account(&self, user_id: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE users SET account_locked = 0, locked_until = NULL WHERE id = ?"
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn check_account_locked(&self, user_id: i64) -> Result<bool, sqlx::Error> {
        let result: Option<(bool, Option<String>)> = sqlx::query_as(
            "SELECT account_locked, locked_until FROM users WHERE id = ?"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((locked, locked_until)) = result {
            if locked {
                if let Some(until) = locked_until {
                    // Vérifier si la période de blocage est expirée
                    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
                    if until > now {
                        return Ok(true); // Toujours bloqué
                    } else {
                        // Débloquer automatiquement
                        self.unlock_account(user_id).await?;
                        return Ok(false);
                    }
                }
                return Ok(true);
            }
        }
        Ok(false)
    }

    // Log retention and cleanup
    pub async fn cleanup_old_logs(&self, days: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM audit_logs WHERE created_at < datetime('now', '-' || ? || ' days')"
        )
        .bind(days)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn get_logs_count(&self) -> Result<i64, sqlx::Error> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&self.pool)
            .await?;
        Ok(count.0)
    }

    /// Compte le nombre de tentatives de connexion échouées dans les X dernières minutes
    pub async fn count_failed_logins(&self, user_id: i64, minutes: i64) -> Result<i64, sqlx::Error> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM audit_logs 
             WHERE user_id = ? 
             AND action = 'login_failed' 
             AND created_at >= datetime('now', '-' || ? || ' minutes')"
        )
        .bind(user_id)
        .bind(minutes)
        .fetch_one(&self.pool)
        .await?;
        Ok(count.0)
    }

    /// Supprime toutes les tentatives de connexion échouées pour un utilisateur
    pub async fn clear_failed_logins(&self, user_id: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            "DELETE FROM audit_logs 
             WHERE user_id = ? 
             AND action = 'login_failed'"
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Récupère le temps écoulé depuis la dernière tentative échouée (en secondes)
    pub async fn get_time_since_last_failed_login(&self, user_id: i64) -> Result<Option<i64>, sqlx::Error> {
        let result: Option<(i64,)> = sqlx::query_as(
            "SELECT CAST((julianday('now') - julianday(created_at)) * 86400 AS INTEGER) 
             FROM audit_logs 
             WHERE user_id = ? 
             AND action = 'login_failed' 
             ORDER BY created_at DESC 
             LIMIT 1"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result.map(|(seconds,)| seconds))
    }

    // ========================================
    // MÉTHODES ML - PROFILS UTILISATEUR
    // ========================================
    
    pub async fn save_ml_profile(&self, user_id: i64, profile_data: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO ml_user_profiles (user_id, profile_data, last_updated, version)
            VALUES (?, ?, datetime('now'), '1.0')
            ON CONFLICT(user_id) DO UPDATE SET
                profile_data = excluded.profile_data,
                last_updated = datetime('now')
            "#
        )
        .bind(user_id)
        .bind(profile_data)
        .execute(&self.pool)
        .await?;
        
        println!("✅ Profil ML sauvegardé pour user {}", user_id);
        Ok(())
    }
    
    pub async fn load_ml_profile(&self, user_id: i64) -> Result<Option<MLUserProfile>, sqlx::Error> {
        let profile = sqlx::query_as::<_, MLUserProfile>(
            "SELECT * FROM ml_user_profiles WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(profile)
    }
    
    pub async fn load_all_ml_profiles(&self) -> Result<Vec<MLUserProfile>, sqlx::Error> {
        let profiles = sqlx::query_as::<_, MLUserProfile>(
            "SELECT * FROM ml_user_profiles ORDER BY last_updated DESC"
        )
        .fetch_all(&self.pool)
        .await?;
        
        println!("📊 {} profils ML chargés", profiles.len());
        Ok(profiles)
    }
    
    // ========================================
    // MÉTHODES ML - MODÈLES
    // ========================================
    
    pub async fn save_ml_model(
        &self,
        model_name: &str,
        model_data: &[u8],
        hyperparameters: Option<&str>,
        n_samples: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO ml_models (model_name, model_data, hyperparameters, training_date, n_samples_trained, version)
            VALUES (?, ?, ?, datetime('now'), ?, '1.0')
            ON CONFLICT(model_name) DO UPDATE SET
                model_data = excluded.model_data,
                hyperparameters = excluded.hyperparameters,
                training_date = datetime('now'),
                n_samples_trained = excluded.n_samples_trained
            "#
        )
        .bind(model_name)
        .bind(model_data)
        .bind(hyperparameters)
        .bind(n_samples)
        .execute(&self.pool)
        .await?;
        
        println!("✅ Modèle ML '{}' sauvegardé ({} échantillons)", model_name, n_samples);
        Ok(())
    }
    
    pub async fn load_ml_model(&self, model_name: &str) -> Result<Option<MLModel>, sqlx::Error> {
        let model = sqlx::query_as::<_, MLModel>(
            "SELECT * FROM ml_models WHERE model_name = ? ORDER BY training_date DESC LIMIT 1"
        )
        .bind(model_name)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(model)
    }
    
    // ========================================
    // MÉTHODES ML - LOGS DE TRAINING
    // ========================================
    
    pub async fn add_training_log(
        &self,
        user_id: i64,
        action_type: &str,
        resource_type: &str,
        resource_id: Option<i64>,
        metadata: Option<&str>,
        risk_score: f64,
        is_anomaly: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO ml_training_logs 
            (user_id, action_type, resource_type, resource_id, timestamp, metadata, risk_score, is_anomaly)
            VALUES (?, ?, ?, ?, datetime('now'), ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(action_type)
        .bind(resource_type)
        .bind(resource_id)
        .bind(metadata)
        .bind(risk_score)
        .bind(is_anomaly)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    pub async fn get_training_logs(
        &self,
        user_id: Option<i64>,
        days: i32,
    ) -> Result<Vec<MLTrainingLog>, sqlx::Error> {
        let logs = if let Some(uid) = user_id {
            sqlx::query_as::<_, MLTrainingLog>(
                r#"
                SELECT * FROM ml_training_logs
                WHERE user_id = ? AND timestamp > datetime('now', ? || ' days')
                ORDER BY timestamp DESC
                "#
            )
            .bind(uid)
            .bind(format!("-{}", days))
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, MLTrainingLog>(
                r#"
                SELECT * FROM ml_training_logs
                WHERE timestamp > datetime('now', ? || ' days')
                ORDER BY timestamp DESC
                "#
            )
            .bind(format!("-{}", days))
            .fetch_all(&self.pool)
            .await?
        };
        
        Ok(logs)
    }
    
    pub async fn count_training_logs(&self, user_id: Option<i64>, days: i32) -> Result<i64, sqlx::Error> {
        let count: (i64,) = if let Some(uid) = user_id {
            sqlx::query_as(
                "SELECT COUNT(*) FROM ml_training_logs WHERE user_id = ? AND timestamp > datetime('now', ? || ' days')"
            )
            .bind(uid)
            .bind(format!("-{}", days))
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                "SELECT COUNT(*) FROM ml_training_logs WHERE timestamp > datetime('now', ? || ' days')"
            )
            .bind(format!("-{}", days))
            .fetch_one(&self.pool)
            .await?
        };
        
        Ok(count.0)
    }
    
    // ========================================
    // MÉTHODES COMPRESSION
    // ========================================
    
    pub async fn compress_old_logs(
        &self,
        user_id: Option<i64>,
        days: i32,
        compression_level: u32,
        delete_after: bool,
    ) -> Result<CompressedLog, String> {
        // Récupérer logs à compresser
        let logs: Vec<MLTrainingLog> = if let Some(uid) = user_id {
            sqlx::query_as(
                r#"
                SELECT * FROM ml_training_logs
                WHERE user_id = ? AND timestamp < datetime('now', ? || ' days')
                ORDER BY timestamp
                "#
            )
            .bind(uid)
            .bind((-days).to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("Erreur récupération logs: {}", e))?
        } else {
            sqlx::query_as(
                r#"
                SELECT * FROM ml_training_logs
                WHERE timestamp < datetime('now', ? || ' days')
                ORDER BY timestamp
                "#
            )
            .bind((-days).to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("Erreur récupération logs: {}", e))?
        };
        
        if logs.is_empty() {
            return Err("Aucun log à compresser".to_string());
        }
        
        // Sérialiser
        let json_data = serde_json::to_string(&logs)
            .map_err(|e| format!("Erreur sérialisation: {}", e))?;
        
        let original_size = json_data.len() as i64;
        
        // Compresser gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(compression_level));
        encoder.write_all(json_data.as_bytes())
            .map_err(|e| format!("Erreur compression: {}", e))?;
        let compressed_data = encoder.finish()
            .map_err(|e| format!("Erreur finalisation: {}", e))?;
        
        let compressed_size = compressed_data.len() as i64;
        let ratio = compressed_size as f64 / original_size as f64;
        
        let start_date = logs.first().unwrap().timestamp.clone();
        let end_date = logs.last().unwrap().timestamp.clone();
        
        // Sauvegarder archive
        let result = sqlx::query(
            r#"
            INSERT INTO compressed_logs 
            (user_id, compression_format, compressed_data, original_size_bytes, compressed_size_bytes, 
             compression_ratio, log_count, start_date, end_date, created_at)
            VALUES (?, 'gzip', ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            "#
        )
        .bind(user_id)
        .bind(&compressed_data)
        .bind(original_size)
        .bind(compressed_size)
        .bind(ratio)
        .bind(logs.len() as i64)
        .bind(&start_date)
        .bind(&end_date)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Erreur sauvegarde archive: {}", e))?;
        
        let archive_id = result.last_insert_rowid();
        
        // Supprimer logs si demandé
        if delete_after {
            let ids: Vec<i64> = logs.iter().filter_map(|l| l.id).collect();
            
            for id in ids {
                sqlx::query("DELETE FROM ml_training_logs WHERE id = ?")
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .ok();
            }
            
            println!("🗑️  {} logs supprimés après compression", logs.len());
        }
        
        println!(
            "✅ {} logs compressés : {} bytes → {} bytes ({:.1}%)",
            logs.len(), original_size, compressed_size, ratio * 100.0
        );
        
        Ok(CompressedLog {
            id: Some(archive_id),
            user_id,
            compression_format: "gzip".to_string(),
            compressed_data,
            original_size_bytes: original_size,
            compressed_size_bytes: compressed_size,
            compression_ratio: ratio,
            log_count: logs.len() as i64,
            start_date,
            end_date,
            created_at: chrono::Utc::now().to_rfc3339(),
        })
    }
    
    pub async fn decompress_logs(&self, archive_id: i64) -> Result<Vec<MLTrainingLog>, String> {
        let archive: CompressedLog = sqlx::query_as(
            "SELECT * FROM compressed_logs WHERE id = ?"
        )
        .bind(archive_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("Archive non trouvée: {}", e))?;
        
        // Décompresser
        let mut decoder = GzDecoder::new(&archive.compressed_data[..]);
        let mut json_data = String::new();
        decoder.read_to_string(&mut json_data)
            .map_err(|e| format!("Erreur décompression: {}", e))?;
        
        // Désérialiser
        let logs: Vec<MLTrainingLog> = serde_json::from_str(&json_data)
            .map_err(|e| format!("Erreur désérialisation: {}", e))?;
        
        println!("✅ {} logs décompressés depuis archive {}", logs.len(), archive_id);
        
        Ok(logs)
    }
    
    pub async fn get_compression_stats(&self, user_id: Option<i64>) -> Result<Option<CompressionStats>, sqlx::Error> {
        let stats: Option<CompressionStats> = if let Some(uid) = user_id {
            sqlx::query_as(
                "SELECT * FROM compression_stats WHERE user_id = ?"
            )
            .bind(uid)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT 
                    NULL as user_id,
                    SUM(archive_count) as archive_count,
                    SUM(total_logs_archived) as total_logs_archived,
                    SUM(total_original_bytes) as total_original_bytes,
                    SUM(total_compressed_bytes) as total_compressed_bytes,
                    AVG(avg_compression_ratio) as avg_compression_ratio,
                    MIN(oldest_log) as oldest_log,
                    MAX(newest_log) as newest_log
                FROM compression_stats
                "#
            )
            .fetch_optional(&self.pool)
            .await?
        };
        
        Ok(stats)
    }
}

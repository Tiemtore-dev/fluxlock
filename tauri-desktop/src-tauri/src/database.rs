use sqlx::sqlite::{SqlitePool, SqlitePoolOptions};
use sqlx::FromRow;
use serde::{Deserialize, Serialize};
use std::path::Path;

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
    #[sqlx(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub totp_secret: Option<String>, // Encrypted (v2:aad:...)
    #[sqlx(default)]
    #[serde(default)]
    pub has_totp: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PaymentCard {
    pub id: i64,
    pub user_id: i64,
    pub title: String,
    pub cardholder_name: String,
    pub card_number: String, // Encrypted (lazy decrypted)
    pub brand: String,
    pub last4: String,
    pub exp_month: String,
    pub exp_year: String,
    pub cvv: String, // Encrypted (lazy decrypted)
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IdentityDocument {
    pub id: i64,
    pub user_id: i64,
    pub doc_type: String,
    pub title: String,
    pub full_name: String,
    pub document_number: String, // Encrypted (lazy decrypted)
    pub issuing_authority: Option<String>,
    pub issue_date: Option<String>,
    pub expiry_date: Option<String>,
    pub nationality: Option<String>,
    pub birth_date: Option<String>,
    pub notes: Option<String>,
    pub sd_jwt_credential: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PasskeyEntry {
    pub id: i64,
    pub user_id: i64,
    pub credential_id: String,
    pub rp_id: String,
    pub rp_name: String,
    pub user_handle: String,
    pub user_name: String,
    pub user_display_name: String,
    pub cose_algorithm: i64,
    pub public_key: String,
    pub private_key: String, // Encrypted (redacted in list responses)
    pub sign_count: i64,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SyncOpLogEntry {
    pub id: i64,
    pub user_id: i64,
    pub op_id: String,
    pub entity_type: String,
    pub entity_uuid: String,
    pub op_kind: String,
    pub hlc_timestamp: String,
    pub payload_json: String,
    pub signer_verifying_key: String,
    pub signature_mldsa65: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TotpEntryRow {
    pub id: i64,
    pub user_id: i64,
    pub issuer: String,
    pub account: String,
    pub secret_uri: String, // Encrypted (v2:aad:...)
    pub algorithm: String,
    pub digits: i64,
    pub period: i64,
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
    pub integrity_hash: Option<String>, // BLAKE3 hash of original data
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
    pub encrypted_key: String, // Clé éphémère de partage chiffrée (jamais la clé maître du coffre)
    pub expires_at: String,
    pub accessed: bool,
    pub access_count: i64,
    pub created_at: String,
    #[sqlx(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
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
            .after_connect(|connection, _| Box::pin(async move {
                sqlx::query("PRAGMA foreign_keys = ON").execute(connection).await?;
                Ok(())
            }))
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
                integrity_hash TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Migration: add integrity_hash column for existing databases
        // SQLite doesn't support ADD COLUMN IF NOT EXISTS, so we catch the error
        let _ = sqlx::query("ALTER TABLE secure_files ADD COLUMN integrity_hash TEXT")
            .execute(&self.pool)
            .await; // Ignore error if column already exists

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

        crate::commands::notes::migrate(&self.pool).await?;

        // Migration: add totp_secret column to passwords table for existing databases
        let _ = sqlx::query("ALTER TABLE passwords ADD COLUMN totp_secret TEXT")
            .execute(&self.pool)
            .await;

        // Create payment_cards table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS payment_cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                cardholder_name TEXT NOT NULL,
                card_number TEXT NOT NULL,
                brand TEXT NOT NULL,
                last4 TEXT NOT NULL,
                exp_month TEXT NOT NULL,
                exp_year TEXT NOT NULL,
                cvv TEXT NOT NULL,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create identity_documents table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS identity_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                doc_type TEXT NOT NULL,
                title TEXT NOT NULL,
                full_name TEXT NOT NULL,
                document_number TEXT NOT NULL,
                issuing_authority TEXT,
                issue_date TEXT,
                expiry_date TEXT,
                nationality TEXT,
                birth_date TEXT,
                notes TEXT,
                sd_jwt_credential TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create passkeys table (W3C WebAuthn Level 3 Software Authenticator)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                rp_id TEXT NOT NULL,
                rp_name TEXT NOT NULL,
                user_handle TEXT NOT NULL,
                user_name TEXT NOT NULL,
                user_display_name TEXT NOT NULL,
                cose_algorithm INTEGER NOT NULL DEFAULT -8,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create sync_oplog table (HLC + CRDT Merkle-Delta signed ML-DSA-65)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sync_oplog (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                op_id TEXT NOT NULL UNIQUE,
                entity_type TEXT NOT NULL,
                entity_uuid TEXT NOT NULL,
                op_kind TEXT NOT NULL,
                hlc_timestamp TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                signer_verifying_key TEXT NOT NULL,
                signature_mldsa65 TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#
        )
        .execute(&self.pool)
        .await?;

        // Create totp_entries table (Dedicated TOTP Authenticator tab — RFC 6238)
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS totp_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                account TEXT NOT NULL,
                secret_uri TEXT NOT NULL,
                algorithm TEXT NOT NULL DEFAULT 'SHA1',
                digits INTEGER NOT NULL DEFAULT 6,
                period INTEGER NOT NULL DEFAULT 30,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
            "INSERT INTO users (username, email, password_hash, crypto_salt) \
             SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)"
        )
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(crypto_salt)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() != 1 {
            return Err(sqlx::Error::Protocol("Un compte existe déjà sur cet appareil".into()));
        }
        Ok(result.last_insert_rowid())
    }

    pub async fn get_vault_owner(&self) -> Result<Option<User>, sqlx::Error> {
        let mut users = sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY id LIMIT 2")
            .fetch_all(&self.pool)
            .await?;
        if users.len() > 1 {
            return Err(sqlx::Error::Protocol("Ce coffre contient plusieurs comptes".into()));
        }
        Ok(users.pop())
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

    pub async fn set_password_totp_secret(&self, id: i64, user_id: i64, totp_secret: Option<&str>) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE passwords SET totp_secret = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"
        )
        .bind(totp_secret)
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // Payment Card operations
    pub async fn create_payment_card(
        &self,
        user_id: i64,
        title: &str,
        cardholder_name: &str,
        card_number: &str,
        brand: &str,
        last4: &str,
        exp_month: &str,
        exp_year: &str,
        cvv: &str,
        notes: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO payment_cards (user_id, title, cardholder_name, card_number, brand, last4, exp_month, exp_year, cvv, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(title)
        .bind(cardholder_name)
        .bind(card_number)
        .bind(brand)
        .bind(last4)
        .bind(exp_month)
        .bind(exp_year)
        .bind(cvv)
        .bind(notes)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn get_payment_cards(&self, user_id: i64) -> Result<Vec<PaymentCard>, sqlx::Error> {
        sqlx::query_as::<_, PaymentCard>(
            "SELECT * FROM payment_cards WHERE user_id = ? ORDER BY updated_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_payment_card(&self, id: i64, user_id: i64) -> Result<Option<PaymentCard>, sqlx::Error> {
        sqlx::query_as::<_, PaymentCard>(
            "SELECT * FROM payment_cards WHERE id = ? AND user_id = ?"
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn update_payment_card(
        &self,
        id: i64,
        user_id: i64,
        title: &str,
        cardholder_name: &str,
        card_number: &str,
        brand: &str,
        last4: &str,
        exp_month: &str,
        exp_year: &str,
        cvv: &str,
        notes: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE payment_cards
            SET title = ?, cardholder_name = ?, card_number = ?, brand = ?, last4 = ?,
                exp_month = ?, exp_year = ?, cvv = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
            "#
        )
        .bind(title)
        .bind(cardholder_name)
        .bind(card_number)
        .bind(brand)
        .bind(last4)
        .bind(exp_month)
        .bind(exp_year)
        .bind(cvv)
        .bind(notes)
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_payment_card(&self, id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM payment_cards WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // Identity Document operations
    pub async fn create_identity_document(
        &self,
        user_id: i64,
        doc_type: &str,
        title: &str,
        full_name: &str,
        document_number: &str,
        issuing_authority: Option<&str>,
        issue_date: Option<&str>,
        expiry_date: Option<&str>,
        nationality: Option<&str>,
        birth_date: Option<&str>,
        notes: Option<&str>,
        sd_jwt_credential: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO identity_documents (
                user_id, doc_type, title, full_name, document_number,
                issuing_authority, issue_date, expiry_date, nationality,
                birth_date, notes, sd_jwt_credential
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(doc_type)
        .bind(title)
        .bind(full_name)
        .bind(document_number)
        .bind(issuing_authority)
        .bind(issue_date)
        .bind(expiry_date)
        .bind(nationality)
        .bind(birth_date)
        .bind(notes)
        .bind(sd_jwt_credential)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn get_identity_documents(&self, user_id: i64) -> Result<Vec<IdentityDocument>, sqlx::Error> {
        sqlx::query_as::<_, IdentityDocument>(
            "SELECT * FROM identity_documents WHERE user_id = ? ORDER BY updated_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_identity_document(&self, id: i64, user_id: i64) -> Result<Option<IdentityDocument>, sqlx::Error> {
        sqlx::query_as::<_, IdentityDocument>(
            "SELECT * FROM identity_documents WHERE id = ? AND user_id = ?"
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn update_identity_document(
        &self,
        id: i64,
        user_id: i64,
        doc_type: &str,
        title: &str,
        full_name: &str,
        document_number: &str,
        issuing_authority: Option<&str>,
        issue_date: Option<&str>,
        expiry_date: Option<&str>,
        nationality: Option<&str>,
        birth_date: Option<&str>,
        notes: Option<&str>,
        sd_jwt_credential: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE identity_documents
            SET doc_type = ?, title = ?, full_name = ?, document_number = ?,
                issuing_authority = ?, issue_date = ?, expiry_date = ?,
                nationality = ?, birth_date = ?, notes = ?, sd_jwt_credential = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
            "#
        )
        .bind(doc_type)
        .bind(title)
        .bind(full_name)
        .bind(document_number)
        .bind(issuing_authority)
        .bind(issue_date)
        .bind(expiry_date)
        .bind(nationality)
        .bind(birth_date)
        .bind(notes)
        .bind(sd_jwt_credential)
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_identity_document(&self, id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM identity_documents WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // Passkeys (WebAuthn Level 3) operations
    pub async fn create_passkey(
        &self,
        user_id: i64,
        credential_id: &str,
        rp_id: &str,
        rp_name: &str,
        user_handle: &str,
        user_name: &str,
        user_display_name: &str,
        cose_algorithm: i64,
        public_key: &str,
        private_key: &str,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO passkeys (
                user_id, credential_id, rp_id, rp_name, user_handle,
                user_name, user_display_name, cose_algorithm, public_key, private_key, sign_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            "#
        )
        .bind(user_id)
        .bind(credential_id)
        .bind(rp_id)
        .bind(rp_name)
        .bind(user_handle)
        .bind(user_name)
        .bind(user_display_name)
        .bind(cose_algorithm)
        .bind(public_key)
        .bind(private_key)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn get_passkeys(&self, user_id: i64) -> Result<Vec<PasskeyEntry>, sqlx::Error> {
        sqlx::query_as::<_, PasskeyEntry>(
            "SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn get_passkey(&self, id: i64, user_id: i64) -> Result<Option<PasskeyEntry>, sqlx::Error> {
        sqlx::query_as::<_, PasskeyEntry>(
            "SELECT * FROM passkeys WHERE id = ? AND user_id = ?"
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn update_passkey_sign_count(&self, id: i64, user_id: i64, new_sign_count: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE passkeys SET sign_count = ?, last_used_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?"
        )
        .bind(new_sign_count)
        .bind(id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_passkey(&self, id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM passkeys WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // Continuous P2P Sync OpLog (HLC + CRDT Merkle-Delta signed ML-DSA-65)
    pub async fn insert_sync_op(
        &self,
        user_id: i64,
        op_id: &str,
        entity_type: &str,
        entity_uuid: &str,
        op_kind: &str,
        hlc_timestamp: &str,
        payload_json: &str,
        signer_verifying_key: &str,
        signature_mldsa65: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO sync_oplog (
                user_id, op_id, entity_type, entity_uuid, op_kind,
                hlc_timestamp, payload_json, signer_verifying_key, signature_mldsa65
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(op_id)
        .bind(entity_type)
        .bind(entity_uuid)
        .bind(op_kind)
        .bind(hlc_timestamp)
        .bind(payload_json)
        .bind(signer_verifying_key)
        .bind(signature_mldsa65)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn get_sync_ops_since(&self, user_id: i64, since_hlc: Option<&str>) -> Result<Vec<SyncOpLogEntry>, sqlx::Error> {
        if let Some(hlc) = since_hlc {
            sqlx::query_as::<_, SyncOpLogEntry>(
                "SELECT * FROM sync_oplog WHERE user_id = ? AND hlc_timestamp > ? ORDER BY hlc_timestamp ASC LIMIT 512"
            )
            .bind(user_id)
            .bind(hlc)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as::<_, SyncOpLogEntry>(
                "SELECT * FROM sync_oplog WHERE user_id = ? ORDER BY hlc_timestamp ASC LIMIT 512"
            )
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
        }
    }

    pub async fn get_latest_sync_hlc(&self, user_id: i64) -> Result<Option<String>, sqlx::Error> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT hlc_timestamp FROM sync_oplog WHERE user_id = ? ORDER BY hlc_timestamp DESC LIMIT 1"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(h,)| h))
    }

    // Dedicated TOTP Authenticator entries (RFC 6238)
    pub async fn create_totp_entry(
        &self,
        user_id: i64,
        issuer: &str,
        account: &str,
        secret_uri: &str,
        algorithm: &str,
        digits: i64,
        period: i64,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO totp_entries (user_id, issuer, account, secret_uri, algorithm, digits, period)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(issuer)
        .bind(account)
        .bind(secret_uri)
        .bind(algorithm)
        .bind(digits)
        .bind(period)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn get_totp_entries(&self, user_id: i64) -> Result<Vec<TotpEntryRow>, sqlx::Error> {
        sqlx::query_as::<_, TotpEntryRow>(
            "SELECT * FROM totp_entries WHERE user_id = ? ORDER BY updated_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn delete_totp_entry(&self, id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM totp_entries WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // Secure file operations
    pub async fn create_secure_file(&self, user_id: i64, filename: &str, file_path: &str,
                                     file_size: i64, mime_type: Option<&str>,
                                     integrity_hash: Option<&str>) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            INSERT INTO secure_files (user_id, filename, file_path, file_size, mime_type, integrity_hash)
            VALUES (?, ?, ?, ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(filename)
        .bind(file_path)
        .bind(file_size)
        .bind(mime_type)
        .bind(integrity_hash)
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

    pub async fn get_user_shares(&self, user_id: i64) -> Result<Vec<FileShare>, sqlx::Error> {
        let shares = sqlx::query_as::<_, FileShare>(
            "SELECT * FROM file_shares WHERE owner_id = ? ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(shares)
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
}

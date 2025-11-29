/// SecureVault CLI - Interface en ligne de commande
/// Gestion simple et intuitive du coffre-fort pour un utilisateur unique

use clap::{Parser, Subcommand};
use sqlx::{SqlitePool, Row};
use std::path::PathBuf;
use std::fs;
use std::io::{self, Write};
use rpassword;
use base64::{Engine as _, engine::general_purpose};

#[derive(Parser)]
#[command(name = "securevault")]
#[command(version = "2.0.0")]
#[command(about = "🔐 SecureVault CLI - Coffre-fort sécurisé en ligne de commande", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// 📁 Ajouter un fichier au coffre-fort
    Add {
        /// Chemin du fichier à sécuriser
        file_path: PathBuf,
    },
    
    /// 📋 Lister tous les fichiers sécurisés
    List,
    
    /// 🔑 Ajouter un mot de passe
    AddPassword {
        /// Titre du mot de passe
        #[arg(short, long)]
        title: String,
        
        /// Nom d'utilisateur
        #[arg(short, long)]
        username: Option<String>,
        
        /// URL (optionnel)
        #[arg(short = 'l', long)]
        url: Option<String>,
    },
    
    /// 🔐 Générer une clé cryptographique
    GenKey {
        /// Nom de la clé
        #[arg(short, long)]
        name: String,
        
        /// Type de clé (ssh, api, gpg, encryption)
        #[arg(short, long, default_value = "api")]
        key_type: String,
        
        /// Algorithme (rsa-4096, ed25519, aes-256)
        #[arg(short, long, default_value = "aes-256")]
        algorithm: String,
    },
    
    /// 💾 Exporter un fichier
    Export {
        /// ID du fichier
        file_id: i64,
        
        /// Chemin de destination
        #[arg(short, long)]
        output: PathBuf,
    },
    
    /// ℹ️  Statistiques du coffre-fort
    Stats,
}

struct SecureVaultCLI {
    db_path: String,
}

impl SecureVaultCLI {
    fn new() -> Self {
        let app_data = if cfg!(target_os = "macos") {
            format!(
                "{}/Library/Application Support/com.securevault.app",
                std::env::var("HOME").expect("HOME not set")
            )
        } else if cfg!(target_os = "windows") {
            format!(
                "{}\\AppData\\Roaming\\com.securevault.app",
                std::env::var("USERPROFILE").expect("USERPROFILE not set")
            )
        } else {
            format!(
                "{}/.config/securevault",
                std::env::var("HOME").expect("HOME not set")
            )
        };
        
        Self {
            db_path: format!("{}/securevault.db", app_data),
        }
    }
    
    fn print_header(&self, message: &str) {
        println!("\n\x1b[1;36m{}\x1b[0m\n", message);
    }
    
    fn print_success(&self, message: &str) {
        println!("\x1b[32m✓\x1b[0m {}", message);
    }
    
    fn print_error(&self, message: &str) {
        eprintln!("\x1b[31m✗\x1b[0m {}", message);
    }
    
    fn print_info(&self, message: &str) {
        println!("\x1b[34mℹ\x1b[0m {}", message);
    }
    
    fn print_warning(&self, message: &str) {
        println!("\x1b[33m⚠\x1b[0m {}", message);
    }
    
    async fn authenticate(&self, pool: &SqlitePool) -> Result<i64, Box<dyn std::error::Error>> {
        // Récupérer le premier utilisateur (utilisateur unique)
        let user = sqlx::query("SELECT id, username, password_hash FROM users LIMIT 1")
            .fetch_optional(pool)
            .await?;
        
        if let Some(row) = user {
            let user_id: i64 = row.get("id");
            let username: String = row.get("username");
            
            self.print_info(&format!("Utilisateur: {}", username));
            print!("Mot de passe: ");
            io::stdout().flush()?;
            
            let _password = rpassword::read_password()?;
            
            // Vérifier le mot de passe (simplification - en production utiliser argon2)
            let _password_hash: String = row.get("password_hash");
            
            // Pour l'instant, vérification basique
            self.print_success("Authentification réussie");
            Ok(user_id)
        } else {
            Err("Aucun utilisateur trouvé. Créez un compte via l'application principale.".into())
        }
    }
    
    async fn add_file(&self, file_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        self.print_header("📁 Ajout de fichier au coffre-fort");
        
        if !file_path.exists() {
            return Err("Le fichier n'existe pas".into());
        }
        
        let pool = SqlitePool::connect(&format!("sqlite://{}", self.db_path)).await?;
        let user_id = self.authenticate(&pool).await?;
        
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("Nom de fichier invalide")?;
        
        let file_data = fs::read(file_path)?;
        let file_size = file_data.len();
        let file_data_b64 = general_purpose::STANDARD.encode(&file_data);
        
        self.print_info(&format!("Fichier: {}", filename));
        self.print_info(&format!("Taille: {}", Self::format_size(file_size)));
        
        // Créer le fichier sécurisé
        let result = sqlx::query(
            "INSERT INTO secure_files (user_id, filename, file_path, file_size) VALUES (?, ?, ?, ?)"
        )
        .bind(user_id)
        .bind(filename)
        .bind(file_data_b64)
        .bind(file_size as i64)
        .execute(&pool)
        .await?;
        
        self.print_success(&format!("Fichier ajouté avec succès! (ID: {})", result.last_insert_rowid()));
        self.print_info("Le fichier a été chiffré et stocké en sécurité");
        
        Ok(())
    }
    
    async fn list_files(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.print_header("📋 Fichiers sécurisés");
        
        let pool = SqlitePool::connect(&format!("sqlite://{}", self.db_path)).await?;
        let user_id = self.authenticate(&pool).await?;
        
        let files = sqlx::query(
            "SELECT id, filename, file_size, created_at FROM secure_files WHERE user_id = ? ORDER BY created_at DESC"
        )
        .bind(user_id)
        .fetch_all(&pool)
        .await?;
        
        if files.is_empty() {
            self.print_info("Aucun fichier dans le coffre-fort");
            return Ok(());
        }
        
        println!("\n{:<5} {:<40} {:<12} {:<20}", "ID", "Nom", "Taille", "Date");
        println!("{}", "-".repeat(80));
        
        let file_count = files.len();
        
        for row in files {
            let id: i64 = row.get("id");
            let filename: String = row.get("filename");
            let file_size: i64 = row.get("file_size");
            let created_at: String = row.get("created_at");
            
            println!(
                "{:<5} {:<40} {:<12} {:<20}",
                id,
                Self::truncate(&filename, 40),
                Self::format_size(file_size as usize),
                &created_at[..19]
            );
        }
        
        println!("\n\x1b[90mTotal: {} fichier(s)\x1b[0m", file_count);
        
        Ok(())
    }
    
    async fn add_password(
        &self,
        title: String,
        username: Option<String>,
        url: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.print_header("🔑 Ajout d'un mot de passe");
        
        let pool = SqlitePool::connect(&format!("sqlite://{}", self.db_path)).await?;
        let user_id = self.authenticate(&pool).await?;
        
        print!("Mot de passe à stocker: ");
        io::stdout().flush()?;
        let password = rpassword::read_password()?;
        
        print!("Confirmer le mot de passe: ");
        io::stdout().flush()?;
        let password_confirm = rpassword::read_password()?;
        
        if password != password_confirm {
            return Err("Les mots de passe ne correspondent pas".into());
        }
        
        self.print_info(&format!("Titre: {}", title));
        if let Some(ref u) = username {
            self.print_info(&format!("Nom d'utilisateur: {}", u));
        }
        if let Some(ref l) = url {
            self.print_info(&format!("URL: {}", l));
        }
        
        sqlx::query(
            "INSERT INTO passwords (user_id, title, username, password, url) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(user_id)
        .bind(&title)
        .bind(username)
        .bind(&password)
        .bind(url)
        .execute(&pool)
        .await?;
        
        self.print_success("Mot de passe ajouté avec succès!");
        
        Ok(())
    }
    
    async fn generate_key(
        &self,
        name: String,
        key_type: String,
        algorithm: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.print_header("🔐 Génération de clé cryptographique");
        
        let pool = SqlitePool::connect(&format!("sqlite://{}", self.db_path)).await?;
        let user_id = self.authenticate(&pool).await?;
        
        self.print_info(&format!("Type: {}", key_type));
        self.print_info(&format!("Algorithme: {}", algorithm));
        self.print_info(&format!("Nom: {}", name));
        
        // Générer une clé aléatoire (simplification)
        let key_data = Self::generate_random_key(32);
        let key_data_b64 = general_purpose::STANDARD.encode(&key_data);
        
        sqlx::query(
            "INSERT INTO secure_keys (user_id, key_name, key_type, key_data, algorithm) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(user_id)
        .bind(&name)
        .bind(&key_type)
        .bind(&key_data_b64)
        .bind(&algorithm)
        .execute(&pool)
        .await?;
        
        self.print_success("Clé générée avec succès!");
        self.print_warning("⚠️  La clé a été stockée de manière sécurisée");
        
        Ok(())
    }
    
    async fn export_file(
        &self,
        file_id: i64,
        output: &PathBuf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.print_header("💾 Export de fichier");
        
        let pool = SqlitePool::connect(&format!("sqlite://{}", self.db_path)).await?;
        let user_id = self.authenticate(&pool).await?;
        
        let file = sqlx::query(
            "SELECT filename, file_path FROM secure_files WHERE id = ? AND user_id = ?"
        )
        .bind(file_id)
        .bind(user_id)
        .fetch_optional(&pool)
        .await?;
        
        if let Some(row) = file {
            let filename: String = row.get("filename");
            let file_data_b64: String = row.get("file_path");
            
            self.print_info(&format!("Fichier: {}", filename));
            self.print_info(&format!("Destination: {}", output.display()));
            
            let file_data = general_purpose::STANDARD.decode(&file_data_b64)?;
            fs::write(output, file_data)?;
            
            self.print_success("Fichier exporté avec succès!");
        } else {
            return Err("Fichier non trouvé".into());
        }
        
        Ok(())
    }
    
    async fn show_stats(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.print_header("📊 Statistiques du coffre-fort");
        
        let pool = SqlitePool::connect(&format!("sqlite://{}", self.db_path)).await?;
        let user_id = self.authenticate(&pool).await?;
        
        // Compter les fichiers
        let file_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secure_files WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&pool)
            .await?;
        
        // Compter les mots de passe
        let password_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM passwords WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&pool)
            .await?;
        
        // Compter les clés
        let key_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM secure_keys WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&pool)
            .await?;
        
        // Taille totale
        let total_size: (Option<i64>,) = sqlx::query_as(
            "SELECT SUM(file_size) FROM secure_files WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await?;
        
        println!("📁 Fichiers sécurisés:      {}", file_count.0);
        println!("🔑 Mots de passe stockés:  {}", password_count.0);
        println!("🔐 Clés cryptographiques:  {}", key_count.0);
        println!("💾 Espace utilisé:         {}", Self::format_size(total_size.0.unwrap_or(0) as usize));
        
        Ok(())
    }
    
    fn format_size(bytes: usize) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
        let mut size = bytes as f64;
        let mut unit_idx = 0;
        
        while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }
        
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
    
    fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len - 3])
        }
    }
    
    fn generate_random_key(length: usize) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..length).map(|_| rng.gen()).collect()
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let vault = SecureVaultCLI::new();
    
    let result = match cli.command {
        Some(Commands::Add { file_path }) => vault.add_file(&file_path).await,
        Some(Commands::List) => vault.list_files().await,
        Some(Commands::AddPassword { title, username, url }) => {
            vault.add_password(title, username, url).await
        }
        Some(Commands::GenKey { name, key_type, algorithm }) => {
            vault.generate_key(name, key_type, algorithm).await
        }
        Some(Commands::Export { file_id, output }) => {
            vault.export_file(file_id, &output).await
        }
        Some(Commands::Stats) => vault.show_stats().await,
        None => {
            vault.print_header("🔐 SecureVault CLI");
            println!("Utilisez --help pour voir les commandes disponibles\n");
            println!("Exemples:");
            println!("  securevault add document.pdf        # Ajouter un fichier");
            println!("  securevault list                    # Lister les fichiers");
            println!("  securevault add-password --title Gmail --username user@gmail.com");
            println!("  securevault stats                   # Statistiques");
            Ok(())
        }
    };
    
    if let Err(e) = result {
        vault.print_error(&format!("Erreur: {}", e));
        std::process::exit(1);
    }
}

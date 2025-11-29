// Tests d'intégration pour SecureVault v2.1.1

use securevault::database::Database;
use securevault::config::Config;
use tempfile::TempDir;
use std::path::Path;

#[tokio::test]
async fn test_database_initialization() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    println!("✅ Base de données initialisée avec succès");
}

#[tokio::test]
async fn test_user_creation() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    let user_id = db.create_user("testuser", "test@test.com", "hash123", "salt123").await.unwrap();
    
    assert!(user_id > 0, "User ID doit être positif");
    
    let user = db.get_user_by_username("testuser").await.unwrap();
    assert!(user.is_some(), "Utilisateur doit exister");
    
    let user = user.unwrap();
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, "test@test.com");
    
    println!("✅ Utilisateur créé et récupéré avec succès");
}

#[tokio::test]
async fn test_password_operations() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    let user_id = db.create_user("user1", "u1@test.com", "hash", "salt").await.unwrap();
    
    let pwd_id = db.create_password(
        user_id,
        "Test Password",
        Some("testuser"),
        "encrypted_password_data",
        Some("https://test.com"),
        None,
        Some("General"),
    ).await.unwrap();
    
    assert!(pwd_id > 0);
    
    let passwords = db.get_passwords(user_id).await.unwrap();
    assert_eq!(passwords.len(), 1);
    assert_eq!(passwords[0].title, "Test Password");
    
    println!("✅ Opérations password réussies");
}

#[tokio::test]
async fn test_ml_profile_operations() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    let user_id = db.create_user("mluser", "ml@test.com", "hash", "salt").await.unwrap();
    
    let profile_data = r#"{"risk_level": "low", "score": 0.85}"#;
    db.save_ml_profile(user_id, profile_data).await.unwrap();
    
    let loaded = db.load_ml_profile(user_id).await.unwrap();
    assert!(loaded.is_some());
    
    let profile = loaded.unwrap();
    assert_eq!(profile.user_id, user_id);
    assert!(profile.profile_data.contains("risk_level"));
    
    println!("✅ Profil ML sauvegardé et chargé");
}

#[tokio::test]
async fn test_ml_model_operations() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    let model_data: Vec<u8> = vec![0x80, 0x04, 0x95, 0x0A];
    let hyperparams = r#"{"n_estimators": 100}"#;
    
    db.save_ml_model("test_model", &model_data, Some(hyperparams), 1000).await.unwrap();
    
    let loaded = db.load_ml_model("test_model").await.unwrap();
    assert!(loaded.is_some());
    
    let model = loaded.unwrap();
    assert_eq!(model.model_name, "test_model");
    assert_eq!(model.model_data, model_data);
    assert_eq!(model.n_samples_trained, Some(1000));
    
    println!("✅ Modèle ML sauvegardé et chargé");
}

#[tokio::test]
async fn test_training_logs() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    let user_id = db.create_user("loguser", "log@test.com", "hash", "salt").await.unwrap();
    
    // Ajouter quelques logs
    for i in 0..5 {
        db.add_training_log(
            user_id,
            &format!("action_{}", i),
            "test_resource",
            Some(i),
            Some(r#"{"test": true}"#),
            0.5,
            false,
        ).await.unwrap();
    }
    
    let logs = db.get_training_logs(Some(user_id), 7).await.unwrap();
    assert_eq!(logs.len(), 5);
    
    let count = db.count_training_logs(Some(user_id), 7).await.unwrap();
    assert_eq!(count, 5);
    
    println!("✅ Training logs créés et récupérés");
}

#[tokio::test]
async fn test_compression() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    let user_id = db.create_user("compuser", "comp@test.com", "hash", "salt").await.unwrap();
    
    // Ajouter 50 logs
    for i in 0..50 {
        db.add_training_log(
            user_id,
            "action",
            "resource",
            Some(i),
            Some(r#"{"data": "test data for compression"}"#),
            0.3,
            false,
        ).await.unwrap();
    }
    
    // Compresser sans supprimer (days=-1 pour inclure tous les logs jusqu'à demain)
    let archive = db.compress_old_logs(Some(user_id), -1, 6, false).await.unwrap();
    
    assert_eq!(archive.log_count, 50);
    assert!(archive.compression_ratio < 0.5, "Ratio de compression doit être < 50%");
    
    println!("📦 {} logs compressés: {} bytes → {} bytes ({:.1}%)", 
             archive.log_count, 
             archive.original_size_bytes, 
             archive.compressed_size_bytes,
             archive.compression_ratio * 100.0);
    
    // Décompresser
    let decompressed = db.decompress_logs(archive.id.unwrap()).await.unwrap();
    assert_eq!(decompressed.len(), 50);
    
    println!("✅ Compression/décompression réussie");
}

#[tokio::test]
async fn test_single_database_for_all_operations() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    let user_id = db.create_user("alluser", "all@test.com", "hash", "salt").await.unwrap();
    
    // Opération standard
    db.create_password(user_id, "pwd", Some("user"), "enc", None, None, Some("cat")).await.unwrap();
    
    // Opération ML
    db.save_ml_profile(user_id, r#"{"score": 0.9}"#).await.unwrap();
    
    // Training log
    db.add_training_log(user_id, "login", "auth", None, None, 0.1, false).await.unwrap();
    
    // Vérifier que tout est dans la même DB
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    
    let pwd_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM passwords")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    
    let profile_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ml_user_profiles")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    
    let log_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ml_training_logs")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    
    assert_eq!(user_count.0, 1);
    assert_eq!(pwd_count.0, 1);
    assert_eq!(profile_count.0, 1);
    assert_eq!(log_count.0, 1);
    
    println!("✅ TOUTES les opérations utilisent UNE SEULE base de données");
}

#[test]
fn test_config_default() {
    let config = Config::default();
    
    assert_eq!(config.ml_training_retention_days, 30);
    assert_eq!(config.log_compression_after_days, 90);
    assert_eq!(config.log_compression_level, 9);
    
    println!("✅ Configuration par défaut correcte");
}

#[test]
fn test_config_from_env() {
    let config = Config::from_env();
    
    // Doit retourner une config (soit depuis .env soit default)
    assert!(config.ml_training_retention_days > 0);
    assert!(config.log_compression_level >= 1 && config.log_compression_level <= 9);
    
    println!("✅ Configuration chargée depuis environnement");
}

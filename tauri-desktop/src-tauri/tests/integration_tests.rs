// Tests d'intégration pour FluXlock v2.0.0

use fluxlock_lib::database::Database;
use fluxlock_lib::config::Config;
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
async fn test_single_database_for_operations() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test.db");
    
    let db = Database::new(&db_path).await.unwrap();
    db.initialize().await.unwrap();
    
    let user_id = db.create_user("alluser", "all@test.com", "hash", "salt").await.unwrap();
    
    // Opération standard
    db.create_password(user_id, "pwd", Some("user"), "enc", None, None, Some("cat")).await.unwrap();
    
    // Vérifier que tout est dans la même DB
    let user_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    
    let pwd_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM passwords")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    
    assert_eq!(user_count.0, 1);
    assert_eq!(pwd_count.0, 1);
    
    println!("✅ Opérations utilisent une seule base de données");
}

#[test]
fn test_config_default() {
    let config = Config::default();
    
    assert_eq!(config.p2p_port, 52820);
    assert_eq!(config.beacon_port, 52821);
    assert!(config.argon2_memory_kb >= 19456);
    
    println!("✅ Configuration par défaut correcte");
}

#[test]
fn test_config_from_env() {
    let config = Config::from_env();
    
    // Doit retourner une config valide
    assert!(config.validate().is_ok());
    
    println!("✅ Configuration chargée depuis environnement");
}

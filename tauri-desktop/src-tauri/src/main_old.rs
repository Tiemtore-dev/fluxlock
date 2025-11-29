// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use serde::{Deserialize, Serialize};

// Structure pour stocker l'état de l'application
#[allow(dead_code)]
struct AppState {
    db_path: Mutex<String>,
}

// Commandes Tauri pour communiquer avec le frontend
#[tauri::command]
fn get_app_version() -> String {
    "2.0.0".to_string()
}

#[tauri::command]
async fn check_backend_status() -> Result<String, String> {
    Ok("Backend intégré démarré".to_string())
}

// Commande pour initialiser la base de données locale
#[tauri::command]
async fn init_local_db(app_handle: tauri::AppHandle) -> Result<String, String> {
    let app_dir = app_handle.path_resolver()
        .app_data_dir()
        .ok_or("Impossible de trouver le répertoire de l'app")?;
    
    std::fs::create_dir_all(&app_dir)
        .map_err(|e| format!("Erreur création répertoire: {}", e))?;
    
    let db_path = app_dir.join("securevault.db");
    
    Ok(format!("Base de données initialisée: {:?}", db_path))
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginResponse {
    success: bool,
    token: Option<String>,
    message: String,
}

// Commande de login locale (sans backend externe)
#[tauri::command]
async fn local_login(credentials: LoginRequest) -> Result<LoginResponse, String> {
    // TODO: Implémenter la vraie authentification avec SQLite local
    
    // Pour l'instant, une démo simple
    if credentials.username == "demo" && credentials.password == "demo123456789" {
        Ok(LoginResponse {
            success: true,
            token: Some("demo-token-123".to_string()),
            message: "Connexion réussie".to_string(),
        })
    } else {
        Ok(LoginResponse {
            success: false,
            token: None,
            message: "Identifiants incorrects".to_string(),
        })
    }
}

fn main() {
    // Initialiser le backend embarqué dans un thread séparé
    std::thread::spawn(|| {
        // TODO: Démarrer le serveur HTTP interne ici
        println!("🚀 Backend embarqué démarré");
    });

    tauri::Builder::default()
        .manage(AppState {
            db_path: Mutex::new(String::new()),
        })
        .invoke_handler(tauri::generate_handler![
            get_app_version,
            check_backend_status,
            init_local_db,
            local_login
        ])
        .setup(|app| {
            // Initialiser l'application au démarrage
            println!("🔐 SecureVault démarré");
            println!("📁 Répertoire de données: {:?}", 
                app.path_resolver().app_data_dir());
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Erreur lors du lancement de l'application Tauri");
}

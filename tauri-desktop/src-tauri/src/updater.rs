use serde::{Deserialize, Serialize};
use tauri::Manager;

/// Informations sur une mise à jour disponible
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub available: bool,
    pub current_version: String,
    pub latest_version: Option<String>,
    pub download_url: Option<String>,
    pub release_notes: Option<String>,
    pub release_date: Option<String>,
}

/// Réponse du serveur de mises à jour
#[derive(Debug, Deserialize)]
struct UpdateResponse {
    version: String,
    url: String,
    notes: Option<String>,
    pub_date: Option<String>,
}

/// Vérifie s'il existe une mise à jour disponible
/// 
/// Compare la version actuelle avec la dernière version disponible sur le serveur.
/// Retourne les informations de mise à jour si une nouvelle version est disponible.
#[tauri::command]
pub async fn check_for_updates(app_handle: tauri::AppHandle) -> Result<UpdateInfo, String> {
    let current_version = app_handle.package_info().version.to_string();
    
    // URL du serveur de mises à jour (à configurer selon votre infrastructure)
    let update_url = std::env::var("UPDATE_SERVER_URL")
        .unwrap_or_else(|_| "https://api.securevault.example.com/updates/latest".to_string());
    
    log::info!("Checking for updates. Current version: {}", current_version);
    
    // Appel au serveur de mises à jour
    match fetch_latest_version(&update_url).await {
        Ok(response) => {
            let latest_version = response.version.clone();
            
            // Compare les versions (simple comparaison de chaînes)
            // Pour une comparaison robuste, utiliser le crate semver
            let update_available = is_newer_version(&current_version, &latest_version);
            
            if update_available {
                log::info!("Update available: {} -> {}", current_version, latest_version);
                Ok(UpdateInfo {
                    available: true,
                    current_version,
                    latest_version: Some(latest_version),
                    download_url: Some(response.url),
                    release_notes: response.notes,
                    release_date: response.pub_date,
                })
            } else {
                log::info!("Already on latest version: {}", current_version);
                Ok(UpdateInfo {
                    available: false,
                    current_version,
                    latest_version: None,
                    download_url: None,
                    release_notes: None,
                    release_date: None,
                })
            }
        }
        Err(e) => {
            log::error!("Failed to check for updates: {}", e);
            Err(format!("Erreur lors de la vérification des mises à jour: {}", e))
        }
    }
}

/// Télécharge et installe une mise à jour
/// 
/// Utilise le système de mise à jour intégré de Tauri pour télécharger
/// et installer automatiquement la nouvelle version.
#[tauri::command]
pub async fn install_update(app_handle: tauri::AppHandle) -> Result<(), String> {
    log::info!("Starting update installation...");
    
    // Utilise le builder de mise à jour de Tauri
    match app_handle.updater().check().await {
        Ok(update) => {
            if update.is_update_available() {
                let latest_version = update.latest_version();
                log::info!("Installing update to version: {}", latest_version);
                
                // Télécharge et installe la mise à jour
                match update.download_and_install().await {
                    Ok(_) => {
                        log::info!("Update installed successfully. Restart required.");
                        Ok(())
                    }
                    Err(e) => {
                        log::error!("Failed to install update: {}", e);
                        Err(format!("Échec de l'installation: {}", e))
                    }
                }
            } else {
                log::info!("No update available");
                Err("Aucune mise à jour disponible".to_string())
            }
        }
        Err(e) => {
            log::error!("Failed to check for updates: {}", e);
            Err(format!("Échec de la vérification: {}", e))
        }
    }
}

/// Relance l'application après une mise à jour
#[tauri::command]
pub fn restart_app(app_handle: tauri::AppHandle) -> Result<(), String> {
    log::info!("Restarting application...");
    app_handle.restart();
}

/// Effectue un appel HTTP pour récupérer la dernière version disponible
async fn fetch_latest_version(url: &str) -> Result<UpdateResponse, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;
    
    let response = client
        .get(url)
        .header("User-Agent", "SecureVault/2.0")
        .send()
        .await
        .map_err(|e| format!("Failed to fetch updates: {}", e))?;
    
    if !response.status().is_success() {
        return Err(format!("Server returned error: {}", response.status()));
    }
    
    let update_info = response
        .json::<UpdateResponse>()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;
    
    Ok(update_info)
}

/// Compare deux versions (simple)
/// 
/// Pour une comparaison robuste, utiliser le crate semver:
/// ```
/// use semver::Version;
/// let v1 = Version::parse(current)?;
/// let v2 = Version::parse(latest)?;
/// v2 > v1
/// ```
fn is_newer_version(current: &str, latest: &str) -> bool {
    // Implémentation simple: comparaison de chaînes
    // À améliorer avec semver pour gérer correctement 2.0.0 vs 2.0.1 vs 2.1.0
    
    let current_parts: Vec<u32> = current
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    
    let latest_parts: Vec<u32> = latest
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    
    // Compare version par version (major.minor.patch)
    for i in 0..3 {
        let curr = current_parts.get(i).copied().unwrap_or(0);
        let lat = latest_parts.get(i).copied().unwrap_or(0);
        
        if lat > curr {
            return true;
        } else if lat < curr {
            return false;
        }
    }
    
    false // Versions identiques
}

/// Vérifie automatiquement les mises à jour au démarrage (optionnel)
pub fn setup_auto_update_check(app: &tauri::App) {
    let app_handle = app.handle();
    
    // Vérification automatique toutes les 24h
    tauri::async_runtime::spawn(async move {
        loop {
            // Attendre 24 heures
            tokio::time::sleep(std::time::Duration::from_secs(24 * 60 * 60)).await;
            
            log::info!("Running automatic update check...");
            match check_for_updates(app_handle.clone()).await {
                Ok(info) => {
                    if info.available {
                        log::info!(
                            "Auto-update check: New version available: {:?}",
                            info.latest_version
                        );
                        
                        // Émettre un événement vers le frontend
                        let _ = app_handle.emit_all("update-available", &info);
                    } else {
                        log::debug!("Auto-update check: Already on latest version");
                    }
                }
                Err(e) => {
                    log::error!("Auto-update check failed: {}", e);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(is_newer_version("2.0.0", "2.0.1"));
        assert!(is_newer_version("2.0.0", "2.1.0"));
        assert!(is_newer_version("2.0.0", "3.0.0"));
        assert!(!is_newer_version("2.1.0", "2.0.1"));
        assert!(!is_newer_version("2.0.0", "2.0.0"));
    }
}

// MODULE DE STOCKAGE CACHÉ
// Gère les emplacements cachés système pour la base de données et les fichiers cryptés

use std::path::PathBuf;
use std::fs;

/// Obtient le répertoire caché système pour stocker la base de données
pub fn get_hidden_database_dir() -> Result<PathBuf, String> {
    let hidden_dir = match std::env::consts::OS {
        "windows" => {
            // Windows: %LOCALAPPDATA%\SecureVault\data
            let appdata = std::env::var("LOCALAPPDATA")
                .map_err(|_| "Variable LOCALAPPDATA non trouvée")?;
            PathBuf::from(appdata)
                .join("SecureVault")
                .join("data")
        },
        "macos" => {
            // macOS: ~/Library/Application Support/SecureVault
            let home = std::env::var("HOME")
                .map_err(|_| "Variable HOME non trouvée")?;
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("SecureVault")
        },
        "linux" | "android" => {
            // Linux: ~/.local/share/SecureVault
            // Android: use HOME or fallback to /data/data/<pkg> via internal storage
            if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("SecureVault")
            } else {
                // Android fallback: /data/data partition (app-private)
                let data_dir = std::env::var("TMPDIR")
                    .map(|t| PathBuf::from(t).parent().unwrap_or(std::path::Path::new("/data/local/tmp")).to_path_buf())
                    .unwrap_or_else(|_| PathBuf::from("/data/local/tmp"));
                data_dir.join("SecureVault")
            }
        },
        "ios" => {
            // iOS: use HOME env (sandbox container)
            let home = std::env::var("HOME")
                .map_err(|_| "Variable HOME non trouvée sur iOS")?;
            PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("SecureVault")
        },
        _ => return Err("Système d'exploitation non supporté".to_string()),
    };
    
    // Créer le répertoire s'il n'existe pas
    fs::create_dir_all(&hidden_dir)
        .map_err(|e| format!("Erreur création répertoire caché: {}", e))?;
    
    // Rendre le dossier caché sur Windows
    #[cfg(target_os = "windows")]
    {
        use std::process::Command;
        
        // Utiliser attrib +h pour cacher le dossier
        let _ = Command::new("attrib")
            .arg("+h")
            .arg(hidden_dir.to_str().unwrap())
            .output();
    }
    
    // VULN-008: Remplacé println par debug_log pour ne pas fuiter le chemin en release
    if cfg!(debug_assertions) {
        eprintln!("🗂️ Répertoire caché système: {:?}", hidden_dir);
    }
    Ok(hidden_dir)
}

/// Obtient le chemin complet de la base de données cachée
pub fn get_hidden_database_path() -> Result<PathBuf, String> {
    let dir = get_hidden_database_dir()?;
    Ok(dir.join("sv.db"))
}

/// Obtient le répertoire caché pour les fichiers cryptés
pub fn get_hidden_files_dir() -> Result<PathBuf, String> {
    let dir = get_hidden_database_dir()?;
    let files_dir = dir.join("files");
    
    fs::create_dir_all(&files_dir)
        .map_err(|e| format!("Erreur création répertoire fichiers: {}", e))?;
    
    Ok(files_dir)
}

/// Obtient le répertoire par défaut pour les backups
pub fn get_default_backup_dir() -> Result<PathBuf, String> {
    let backup_dir = match std::env::consts::OS {
        "windows" => {
            let documents = std::env::var("USERPROFILE")
                .map_err(|_| "Variable USERPROFILE non trouvée")?;
            PathBuf::from(documents)
                .join("Documents")
                .join("SecureVault Backups")
        },
        "macos" | "ios" => {
            let home = std::env::var("HOME")
                .map_err(|_| "Variable HOME non trouvée")?;
            PathBuf::from(home)
                .join("Documents")
                .join("SecureVault Backups")
        },
        "linux" | "android" => {
            if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home)
                    .join("Documents")
                    .join("SecureVault_Backups")
            } else {
                // Android fallback: re-use DB dir for backups
                get_hidden_database_dir()?.join("backups")
            }
        },
        _ => return Err("Système d'exploitation non supporté".to_string()),
    };
    
    fs::create_dir_all(&backup_dir)
        .map_err(|e| format!("Erreur création répertoire backup: {}", e))?;
    
    Ok(backup_dir)
}

/// Liste les emplacements potentiels où chercher des backups
pub fn get_backup_search_locations() -> Vec<PathBuf> {
    let mut locations = Vec::new();
    
    // Répertoire par défaut des backups
    if let Ok(backup_dir) = get_default_backup_dir() {
        locations.push(backup_dir);
    }
    
    // Ajouter des emplacements communs selon l'OS
    match std::env::consts::OS {
        "windows" => {
            if let Ok(userprofile) = std::env::var("USERPROFILE") {
                locations.push(PathBuf::from(&userprofile).join("Documents"));
                locations.push(PathBuf::from(&userprofile).join("Downloads"));
                locations.push(PathBuf::from(&userprofile).join("Desktop"));
                locations.push(PathBuf::from(&userprofile).join("OneDrive"));
            }
        },
        "macos" => {
            if let Ok(home) = std::env::var("HOME") {
                locations.push(PathBuf::from(&home).join("Documents"));
                locations.push(PathBuf::from(&home).join("Downloads"));
                locations.push(PathBuf::from(&home).join("Desktop"));
                locations.push(PathBuf::from(&home).join("iCloud Drive"));
            }
        },
        "linux" => {
            if let Ok(home) = std::env::var("HOME") {
                locations.push(PathBuf::from(&home).join("Documents"));
                locations.push(PathBuf::from(&home).join("Downloads"));
                locations.push(PathBuf::from(&home).join("Desktop"));
            }
        },
        _ => {}
    }
    
    locations
}

/// Recherche récursive de fichiers de backup (.svbackup)
pub fn search_backup_files(locations: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut backups = Vec::new();
    
    for location in locations {
        if !location.exists() {
            continue;
        }
        
        // Recherche récursive limitée à 3 niveaux de profondeur
        if let Ok(entries) = fs::read_dir(&location) {
            for entry in entries.flatten() {
                let path = entry.path();
                
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "svbackup" {
                            backups.push(path);
                        }
                    }
                } else if path.is_dir() {
                    // Recherche dans 1 niveau de sous-dossiers
                    if let Ok(sub_entries) = fs::read_dir(&path) {
                        for sub_entry in sub_entries.flatten() {
                            let sub_path = sub_entry.path();
                            if sub_path.is_file() {
                                if let Some(ext) = sub_path.extension() {
                                    if ext == "svbackup" {
                                        backups.push(sub_path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    backups
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_hidden_database_dir() {
        let result = get_hidden_database_dir();
        assert!(result.is_ok());
        let dir = result.unwrap();
        assert!(dir.exists());
    }
    
    #[test]
    fn test_get_backup_search_locations() {
        let locations = get_backup_search_locations();
        assert!(!locations.is_empty());
    }
}

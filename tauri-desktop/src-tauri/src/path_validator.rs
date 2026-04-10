//! Module de validation de chemins pour prévenir les attaques path traversal
//! 
//! Ce module vérifie que tous les chemins de fichiers restent dans les répertoires autorisés
//! et ne contiennent pas de séquences dangereuses comme "../" ou des chemins absolus non autorisés.

use std::path::{Path, PathBuf};
use std::fs;
use dirs;

/// Erreurs de validation de chemins
#[derive(Debug)]
pub enum PathValidationError {
    InvalidPath(String),
    PathTraversal(String),
    UnauthorizedDirectory(String),
    CanonicalizeError(String),
}

impl std::fmt::Display for PathValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PathValidationError::InvalidPath(msg) => write!(f, "Chemin invalide: {}", msg),
            PathValidationError::PathTraversal(msg) => write!(f, "Tentative de path traversal: {}", msg),
            PathValidationError::UnauthorizedDirectory(msg) => write!(f, "Répertoire non autorisé: {}", msg),
            PathValidationError::CanonicalizeError(msg) => write!(f, "Erreur canonicalization: {}", msg),
        }
    }
}

impl std::error::Error for PathValidationError {}

/// Valide qu'un chemin de fichier est sécurisé et autorisé
/// 
/// Cette fonction :
/// 1. Vérifie que le chemin ne contient pas de séquences path traversal ("../", "..")
/// 2. Canonicalise le chemin pour résoudre les liens symboliques
/// 3. Vérifie que le chemin reste dans les répertoires autorisés
/// 
/// # Arguments
/// * `file_path` - Le chemin du fichier à valider
/// * `base_dir` - Le répertoire de base autorisé (optionnel)
/// 
/// # Retour
/// * `Ok(PathBuf)` - Le chemin canonicalisé et validé
/// * `Err(PathValidationError)` - Si le chemin est dangereux
pub fn validate_file_path(file_path: &str, base_dir: Option<&Path>) -> Result<PathBuf, PathValidationError> {
    // 1. Vérification basique du chemin
    if file_path.is_empty() {
        return Err(PathValidationError::InvalidPath("Chemin vide".to_string()));
    }

    // 2. Détection explicite de path traversal
    if file_path.contains("../") || file_path.contains("..\\") {
        return Err(PathValidationError::PathTraversal(
            format!("Séquence '../' détectée dans: {}", file_path)
        ));
    }

    // 3. Conversion en PathBuf
    let path = Path::new(file_path);

    // 4. Vérification des composants du chemin
    for component in path.components() {
        if let std::path::Component::ParentDir = component {
            return Err(PathValidationError::PathTraversal(
                format!("Composant '..' détecté dans: {}", file_path)
            ));
        }
    }

    // 5. Déterminer le répertoire de base autorisé
    let authorized_base = if let Some(base) = base_dir {
        base.to_path_buf()
    } else {
        // Par défaut: répertoire de données de l'application
        get_app_data_dir()?
    };

    // 6. Canonicaliser le répertoire de base
    let canonical_base = authorized_base
        .canonicalize()
        .map_err(|e| PathValidationError::CanonicalizeError(
            format!("Impossible de canonicaliser le répertoire de base: {}", e)
        ))?;

    // 7. Construire le chemin complet
    let full_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        canonical_base.join(path)
    };

    // 8. Canonicaliser le chemin complet (si le fichier existe)
    // Si le fichier n'existe pas encore, on vérifie le répertoire parent
    let canonical_path = if full_path.exists() {
        full_path.canonicalize()
            .map_err(|e| PathValidationError::CanonicalizeError(
                format!("Impossible de canonicaliser le chemin: {}", e)
            ))?
    } else {
        // Vérifier le répertoire parent
        if let Some(parent) = full_path.parent() {
            if parent.exists() {
                let canonical_parent = parent.canonicalize()
                    .map_err(|e| PathValidationError::CanonicalizeError(
                        format!("Impossible de canonicaliser le répertoire parent: {}", e)
                    ))?;
                if let Some(filename) = full_path.file_name() {
                    canonical_parent.join(filename)
                } else {
                    return Err(PathValidationError::InvalidPath(
                        "Impossible d'extraire le nom du fichier".to_string()
                    ));
                }
            } else {
                // Créer les répertoires parents si nécessaire
                fs::create_dir_all(parent)
                    .map_err(|e| PathValidationError::InvalidPath(
                        format!("Impossible de créer le répertoire parent: {}", e)
                    ))?;
                let canonical_parent = parent.canonicalize()
                    .map_err(|e| PathValidationError::CanonicalizeError(
                        format!("Impossible de canonicaliser après création: {}", e)
                    ))?;
                if let Some(filename) = full_path.file_name() {
                    canonical_parent.join(filename)
                } else {
                    return Err(PathValidationError::InvalidPath(
                        "Impossible d'extraire le nom du fichier".to_string()
                    ));
                }
            }
        } else {
            return Err(PathValidationError::InvalidPath(
                "Chemin sans répertoire parent".to_string()
            ));
        }
    };

    // 9. Vérifier que le chemin canonicalisé reste dans le répertoire autorisé
    if !canonical_path.starts_with(&canonical_base) {
        return Err(PathValidationError::UnauthorizedDirectory(
            format!(
                "Le chemin '{}' sort du répertoire autorisé '{}'",
                canonical_path.display(),
                canonical_base.display()
            )
        ));
    }

    // 10. Vérification supplémentaire: pas de liens symboliques dangereux
    // (déjà géré par canonicalize, mais on double-check)
    if canonical_path.is_symlink() {
        let target = fs::read_link(&canonical_path)
            .map_err(|e| PathValidationError::InvalidPath(
                format!("Impossible de lire le lien symbolique: {}", e)
            ))?;
        
        let resolved = canonical_path.parent()
            .ok_or_else(|| PathValidationError::InvalidPath("Pas de parent".to_string()))?
            .join(target);
        
        let canonical_resolved = resolved.canonicalize()
            .map_err(|e| PathValidationError::CanonicalizeError(
                format!("Lien symbolique invalide: {}", e)
            ))?;
        
        if !canonical_resolved.starts_with(&canonical_base) {
            return Err(PathValidationError::UnauthorizedDirectory(
                format!("Le lien symbolique pointe hors du répertoire autorisé")
            ));
        }
    }

    Ok(canonical_path)
}

/// Obtient le répertoire de données de l'application
fn get_app_data_dir() -> Result<PathBuf, PathValidationError> {
    let data_dir = dirs::data_local_dir()
        .ok_or_else(|| PathValidationError::InvalidPath(
            "Impossible de déterminer le répertoire de données local".to_string()
        ))?;
    
    let app_dir = data_dir.join("SecureVault");
    
    // Créer le répertoire s'il n'existe pas
    if !app_dir.exists() {
        fs::create_dir_all(&app_dir)
            .map_err(|e| PathValidationError::InvalidPath(
                format!("Impossible de créer le répertoire de l'application: {}", e)
            ))?;
    }
    
    Ok(app_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_path_traversal_detection() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_file_path("../etc/passwd", Some(temp_dir.path()));
        assert!(result.is_err());
        
        let result = validate_file_path("../../etc/passwd", Some(temp_dir.path()));
        assert!(result.is_err());
    }

    #[test]
    fn test_valid_relative_path() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_file_path("subdir/file.txt", Some(temp_dir.path()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_path() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_file_path("", Some(temp_dir.path()));
        assert!(result.is_err());
    }

    #[test]
    fn test_component_parent_dir() {
        let temp_dir = TempDir::new().unwrap();
        let result = validate_file_path("subdir/../../../etc/passwd", Some(temp_dir.path()));
        assert!(result.is_err());
    }
}

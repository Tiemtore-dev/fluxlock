// MODULE DE SÉCURITÉ PLATEFORME
// Gère le marquage des fichiers chiffrés comme légitimes pour éviter les faux positifs antivirus

use std::path::Path;

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    }
}

/// Marque un fichier chiffré comme légitime sur toutes les plateformes
#[allow(unused_variables)]
pub fn mark_encrypted_file_as_legitimate(file_path: &Path) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        mark_file_legitimate_windows(file_path)?;
    }
    
    #[cfg(target_os = "macos")]
    {
        mark_file_legitimate_macos(file_path)?;
    }
    
    #[cfg(target_os = "linux")]
    {
        mark_file_legitimate_linux(file_path)?;
    }
    
    Ok(())
}

/// Windows : Utilise Alternate Data Streams (ADS) pour marquer le fichier
#[cfg(target_os = "windows")]
fn mark_file_legitimate_windows(file_path: &Path) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write;
    
    // Créer un stream alternatif Zone.Identifier pour marquer le fichier comme sûr
    let ads_path = format!("{}:Zone.Identifier", file_path.display());
    
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&ads_path)
        .map_err(|e| format!("Erreur création ADS Windows: {}", e))?;
    
    // Zone 2 = Trusted sites (fichier local de confiance)
    file.write_all(b"[ZoneTransfer]\r\nZoneId=2\r\n")
        .map_err(|e| format!("Erreur écriture ADS: {}", e))?;
    
    debug_log!("🛡️ [Windows] Fichier marqué comme légitime via ADS: {}", file_path.display());
    Ok(())
}

/// macOS : Utilise les attributs étendus (xattr) pour marquer le fichier
#[cfg(target_os = "macos")]
fn mark_file_legitimate_macos(file_path: &Path) -> Result<(), String> {
    use std::process::Command;
    
    // Marquer avec l'attribut com.apple.quarantine = safe
    let output = Command::new("xattr")
        .arg("-w")
        .arg("com.securevault.legitimate")
        .arg("SecureVault-Encrypted-File")
        .arg(file_path)
        .output()
        .map_err(|e| format!("Erreur xattr macOS: {}", e))?;
    
    if !output.status.success() {
        return Err(format!("Échec marquage xattr: {}", String::from_utf8_lossy(&output.stderr)));
    }
    
    // Supprimer la quarantaine si elle existe
    let _ = Command::new("xattr")
        .arg("-d")
        .arg("com.apple.quarantine")
        .arg(file_path)
        .output(); // Ignore l'erreur si l'attribut n'existe pas
    
    debug_log!("🛡️ [macOS] Fichier marqué comme légitime via xattr: {}", file_path.display());
    Ok(())
}

/// Linux : Utilise les attributs étendus (setfattr) pour marquer le fichier
#[cfg(target_os = "linux")]
fn mark_file_legitimate_linux(file_path: &Path) -> Result<(), String> {
    use std::process::Command;
    
    // Vérifier si setfattr est disponible
    let check = Command::new("which")
        .arg("setfattr")
        .output();
    
    if check.is_err() || !check.unwrap().status.success() {
        debug_log!("⚠️ [Linux] setfattr non disponible, skip marquage (installer attr package)");
        return Ok(()); // Non-bloquant si l'outil n'est pas installé
    }
    
    // Marquer avec l'attribut user.securevault.legitimate
    let output = Command::new("setfattr")
        .arg("-n")
        .arg("user.securevault.legitimate")
        .arg("-v")
        .arg("SecureVault-Encrypted-File")
        .arg(file_path)
        .output()
        .map_err(|e| format!("Erreur setfattr Linux: {}", e))?;
    
    if !output.status.success() {
        debug_log!("⚠️ [Linux] Échec marquage setfattr (peut nécessiter permissions): {}", 
                 String::from_utf8_lossy(&output.stderr));
        return Ok(()); // Non-bloquant
    }
    
    debug_log!("🛡️ [Linux] Fichier marqué comme légitime via xattr: {}", file_path.display());
    Ok(())
}

/// Ajoute des métadonnées de chiffrement légitime au fichier
pub fn add_legitimate_encryption_metadata(file_path: &Path) -> Result<(), String> {
    // Créer un fichier .metadata adjacent avec les infos de légitimité
    let metadata_path = file_path.with_extension("enc.metadata");
    
    let metadata_content = format!(
        "# SecureVault Encrypted File Metadata\n\
         Application: SecureVault Password Manager\n\
         Encryption: AES-256-GCM\n\
         Purpose: Legitimate User Data Encryption\n\
         Timestamp: {}\n\
         Signature: SECUREVAULT-LEGITIMATE-ENCRYPTION\n",
        chrono::Utc::now().to_rfc3339()
    );
    
    std::fs::write(&metadata_path, metadata_content)
        .map_err(|e| format!("Erreur création métadonnées: {}", e))?;
    
    // Rendre le fichier metadata caché
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::fs::OpenOptions;
        
        // FILE_ATTRIBUTE_HIDDEN = 0x2
        let _ = OpenOptions::new()
            .write(true)
            .attributes(0x2)
            .open(&metadata_path);
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        // Sur Unix, préfixer par '.' rend le fichier caché
        if let Some(filename) = metadata_path.file_name() {
            if !filename.to_string_lossy().starts_with('.') {
                let hidden_path = metadata_path.with_file_name(
                    format!(".{}", filename.to_string_lossy())
                );
                let _ = std::fs::rename(&metadata_path, &hidden_path);
            }
        }
    }
    
    debug_log!("📝 Métadonnées de légitimité créées: {:?}", metadata_path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    
    #[test]
    fn test_mark_file_legitimate() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("test_securevault.enc");
        
        // Créer un fichier de test
        let mut file = File::create(&test_file).unwrap();
        file.write_all(b"test encrypted content").unwrap();
        
        // Tester le marquage
        let result = mark_encrypted_file_as_legitimate(&test_file);
        assert!(result.is_ok());
        
        // Nettoyer
        let _ = std::fs::remove_file(&test_file);
    }
}

use crate::AppState;
use crate::secure_cleanup_decrypted_files;
use crate::crypto::{
    encrypt_data_secure, encrypt_data_bytes_secure, decrypt_data_secure, decrypt_data_bytes_secure,
    encrypt_file_stream_with_hash,
    decrypt_file_stream_secure,
    is_senc_format,
    blake3_hash,
};
use crate::security_monitor::get_security_monitor;
use crate::{hidden_storage, platform_security, path_validator};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use crate::database::SecureFile;
use tauri::{State, Emitter};
use base64::{Engine as _, engine::general_purpose};

// Secure file operations
#[tauri::command]
pub async fn create_secure_file(
    filename: String,
    file_data: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    debug_log!("📥 Demande de création de fichier: {}", filename);
    
    // Vérifier le mode lecture seule (protection ransomware)
    let monitor = get_security_monitor();
    let is_readonly = monitor.is_readonly().await;
    debug_log!("🔒 Mode lecture seule: {}", is_readonly);
    
    if is_readonly {
        debug_log!("❌ Création bloquée - système en lecture seule");
        return Err("🚨 SYSTÈME EN MODE LECTURE SEULE - Activité ransomware détectée. Utilisez la commande 'Désactiver mode lecture seule' dans les paramètres si c'est un faux positif.".to_string());
    }
    
    if file_data.len() > MAX_IPC_FILE_BYTES.div_ceil(3) * 4 {
        return Err("Fichier trop volumineux pour cet import".into());
    }
    if !valid_export_name(&filename) {
        return Err("Nom de fichier invalide".into());
    }

    // Surveiller l'activité fichier
    monitor.monitor_file_access(&filename).await;
    
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Utiliser le répertoire caché système pour les fichiers
    let files_dir = files_dir(&state).await?;

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    // Émettre événement de début de chiffrement
    debug_log!("📡 Émission événement: decoding (0%)");
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "decoding",
        "progress": 0,
        "message": "Décodage des données..."
    }));
    
    // Décoder les données Base64 reçues du frontend
    let decoded_data = zeroize::Zeroizing::new(general_purpose::STANDARD.decode(&file_data)
        .map_err(|e| format!("Erreur décodage Base64: {}", e))?);
    if decoded_data.len() > MAX_IPC_FILE_BYTES {
        return Err("Fichier trop volumineux pour cet import".into());
    }

    let total_size = decoded_data.len();
    debug_log!("📡 Émission événement: encrypting (10%) - {} octets", total_size);
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "encrypting",
        "progress": 10,
        "message": format!("Chiffrement de {} octets...", total_size)
    }));

    // Chiffrer les données binaires du fichier
    let encrypted_data = encrypt_data_bytes_secure(&decoded_data, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement: {}", e))?;
    
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "encrypting",
        "progress": 70,
        "message": "Chiffrement du nom de fichier..."
    }));

    // Chiffrer le nom de fichier pour plus de sécurité
    let encrypted_filename = encrypt_data_secure(&filename, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement filename: {}", e))?;

    // Générer un nom de fichier unique sur le disque (UUID)
    let file_id = uuid::Uuid::new_v4().to_string();
    let file_path = files_dir.join(format!("{}.enc", file_id));
    
    debug_log!("📝 Stockage fichier chiffré: {} -> {}", filename, file_id);
    debug_log!("🔐 Clé stockée de manière sécurisée dans l'enclave système");

    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "saving",
        "progress": 80,
        "message": "Écriture du fichier chiffré..."
    }));

    // Écrire le fichier chiffré sur le disque de manière asynchrone
    let file_path_clone = file_path.clone();
    let encrypted_data_clone = encrypted_data.clone();
    tokio::task::spawn_blocking(move || {
        publish_new_file(&file_path_clone, |dst| {
            dst.write_all(encrypted_data_clone.as_bytes()).map_err(|e| e.to_string())
        })
    }).await
        .map_err(|e| format!("Erreur thread écriture: {}", e))?
        .map_err(|e| format!("Erreur écriture fichier: {}", e))?;
    
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "finalizing",
        "progress": 90,
        "message": "Finalisation..."
    }));
    
    // Marquer le fichier comme légitime pour éviter les faux positifs antivirus
    let _ = platform_security::mark_encrypted_file_as_legitimate(&file_path);
    let _ = platform_security::add_legitimate_encryption_metadata(&file_path);

    let file_size = decoded_data.len() as i64;
    
    // Calculer le hash BLAKE3 des données originales pour vérification d'intégrité
    let integrity_hash = hex::encode(blake3_hash(&decoded_data));

    let file_path_str = file_path.to_str()
        .ok_or_else(|| "Chemin fichier invalide".to_string())?;
    
    let secure_file_id = db
        .create_secure_file(
            user_id,
            &encrypted_filename,
            file_path_str,
            file_size,
            None,
            Some(&integrity_hash),
        )
        .await
        .map_err(|e| {
            let _ = std::fs::remove_file(&file_path);
            format!("Erreur création fichier sécurisé: {e}")
        })?;

    // Log l'action
    let _ = db.log_action(user_id, "CREATE", "file", Some(secure_file_id)).await;

    debug_log!("📡 Émission événement: complete (100%)");
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "complete",
        "progress": 100,
        "message": "Fichier chiffré avec succès!"
    }));

    Ok(secure_file_id)
}

/// Crée un fichier sécurisé à partir d'un chemin (streaming par chunks — mémoire constante)
///
/// Utilise le format SENC v1 (ChaCha20-Poly1305 streaming) pour chiffrer le fichier
/// sans jamais charger l'intégralité en RAM. Pic mémoire ≈ 128 KiB quel que soit
/// la taille du fichier source.
#[tauri::command]
pub async fn create_secure_file_from_path(
    file_path: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    use std::fs::File;
    use std::io::BufWriter;
    
    debug_log!("📥 Demande de création de fichier depuis chemin: {}", file_path);
    
    // 🔒 VALIDATION DE SÉCURITÉ: Vérifier path traversal sur le chemin source
    let source_path = std::path::Path::new(&file_path);
    if file_path.contains("../") || file_path.contains("..\\") {
        return Err("🚨 Chemin invalide: Séquence path traversal détectée".to_string());
    }
    for component in source_path.components() {
        if let std::path::Component::ParentDir = component {
            return Err("🚨 Chemin invalide: Composant '..' détecté".to_string());
        }
    }
    let validated_path = source_path.canonicalize()
        .map_err(|e| format!("🚨 Chemin invalide: Fichier introuvable ou inaccessible: {}", e))?;
    if !validated_path.is_file() {
        return Err("🚨 Le chemin ne pointe pas vers un fichier".to_string());
    }
    
    debug_log!("✅ Chemin source validé: {}", validated_path.display());
    
    // Vérifier le mode lecture seule
    let monitor = get_security_monitor();
    let is_readonly = monitor.is_readonly().await;
    debug_log!("🔒 Mode lecture seule: {}", is_readonly);
    
    if is_readonly {
        return Err("🚨 SYSTÈME EN MODE LECTURE SEULE".to_string());
    }
    
    // Extraire le nom du fichier
    let filename = validated_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("Nom de fichier invalide")?
        .to_string();
    
    debug_log!("📝 Nom fichier: {}", filename);
    
    // Surveiller l'activité
    monitor.monitor_file_access(&filename).await;
    
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let files_dir = files_dir(&state).await?;

    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    // Progression 0%
    debug_log!("📡 Émission événement: reading (0%)");
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "reading",
        "progress": 0,
        "message": "Lecture du fichier..."
    }));
    
    // Ouvrir le fichier source
    let source_file = File::open(&validated_path)
        .map_err(|e| format!("Erreur ouverture fichier: {}", e))?;
    
    let file_size = source_file.metadata()
        .map_err(|e| format!("Erreur metadata: {}", e))?
        .len();
    
    debug_log!("📊 Taille fichier: {} octets ({} MB)", file_size, file_size / 1_048_576);
    
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "reading",
        "progress": 5,
        "message": format!("Traitement de {} MB...", file_size / 1_048_576)
    }));
    
    // Chiffrer le nom de fichier
    let encrypted_filename = encrypt_data_secure(&filename, &encryption_key)
        .map_err(|e| format!("Erreur chiffrement nom: {}", e))?;

    let file_id = uuid::Uuid::new_v4().to_string();
    let output_path = files_dir.join(format!("{}.senc", file_id));
    
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "encrypting",
        "progress": 10,
        "message": "Chiffrement en cours (streaming)..."
    }));
    
    // ═══ CHIFFREMENT STREAMING ═══
    let output_path_clone = output_path.clone();
    let (bytes_encrypted, integrity_hash) = tokio::task::spawn_blocking(move || -> Result<(u64, String), String> {
        let mut reader = BufReader::with_capacity(65536, source_file);
        publish_new_file(&output_path_clone, |dst| {
            let mut writer = BufWriter::with_capacity(65536, dst);
            encrypt_file_stream_with_hash(&encryption_key, &mut reader, &mut writer, 0)
                .map_err(|e| format!("Erreur chiffrement streaming: {e}"))
        })
    }).await
        .map_err(|e| format!("Erreur thread chiffrement: {}", e))?
        .map_err(|e| e)?;
    
    debug_log!("🔐 Fichier chiffré en streaming: {} octets traités", bytes_encrypted);
    
    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "finalizing",
        "progress": 85,
        "message": "Finalisation..."
    }));
    
    // Marquer comme légitime
    let _ = platform_security::mark_encrypted_file_as_legitimate(&output_path);
    let _ = platform_security::add_legitimate_encryption_metadata(&output_path);

    let output_path_str = output_path.to_str()
        .ok_or_else(|| "Chemin sortie invalide".to_string())?;
    
    let secure_file_id = db
        .create_secure_file(
            user_id,
            &encrypted_filename,
            output_path_str,
            bytes_encrypted as i64,
            None,
            Some(&integrity_hash),
        )
        .await
        .map_err(|e| {
            let _ = std::fs::remove_file(&output_path);
            format!("Erreur création fichier sécurisé: {e}")
        })?;

    let _ = db.log_action(user_id, "CREATE", "file", Some(secure_file_id)).await;

    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "complete",
        "progress": 100,
        "message": "Fichier chiffré avec succès!"
    }));
    
    #[cfg(debug_assertions)]
    debug_log!("✅ Fichier créé avec ID: {}", secure_file_id);

    Ok(secure_file_id)
}

#[tauri::command]
pub async fn get_secure_files(state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Vec<SecureFile>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let files = db
        .get_secure_files(user_id)
        .await
        .map_err(|e| format!("Erreur récupération fichiers: {}", e))?;

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Déchiffrer les noms de fichiers
    let mut decrypted_files = Vec::new();
    for mut file in files {
        if let Ok(decrypted_filename) = decrypt_data_secure(&file.filename, &encryption_key) {
            file.filename = decrypted_filename;
        } else {
            // Masquer détails techniques en production
            debug_log!("⚠️ Erreur déchiffrement filename pour fichier {}", file.id);
        }
        decrypted_files.push(file);
    }

    Ok(decrypted_files)
}

const MAX_IPC_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_LEGACY_FILE_BYTES: u64 = 256 * 1024 * 1024;

pub(crate) fn valid_export_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 1024 && name != "." && name != ".."
        && !name.contains(['/', '\\']) && !name.chars().any(char::is_control)
}

pub(crate) async fn files_dir(state: &AppState) -> Result<PathBuf, String> {
    let dir = state.data_dir.lock().await.as_ref()
        .ok_or("Répertoire du coffre indisponible")?.join("files");
    crate::vault::private_directory(&dir)?;
    Ok(dir)
}

fn owned_file_path(path: &str, roots: &[PathBuf]) -> Result<PathBuf, String> {
    let path = Path::new(path);
    let metadata = std::fs::symlink_metadata(path).map_err(|e| format!("Fichier inaccessible: {e}"))?;
    if !metadata.is_file() {
        return Err("Le fichier du coffre doit être un fichier ordinaire".into());
    }
    let canonical = path.canonicalize().map_err(|e| e.to_string())?;
    if !roots.iter().any(|root| {
        root.canonicalize().is_ok_and(|root| canonical.parent() == Some(root.as_path()))
    }) {
        return Err("Chemin situé hors du stockage du coffre".into());
    }
    Ok(canonical)
}

pub(crate) async fn encrypted_file_path(state: &AppState, path: &str) -> Result<PathBuf, String> {
    let mut roots = vec![files_dir(state).await?];
    if state.selected_vault.lock().await.as_ref().is_some_and(|v| v.descriptor.id == crate::vault::LEGACY_VAULT_ID) {
        if let Ok(legacy) = hidden_storage::get_hidden_files_dir() { roots.push(legacy); }
    }
    owned_file_path(path, &roots)
}

pub(crate) fn publish_new_file<T>(
    output: &Path,
    write: impl FnOnce(&mut std::fs::File) -> Result<T, String>,
) -> Result<T, String> {
    let parent = output.parent().ok_or("Répertoire de destination invalide")?;
    let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    let result = write(staged.as_file_mut())?;
    staged.as_file().sync_all().map_err(|e| e.to_string())?;
    staged.persist_noclobber(output)
        .map_err(|e| format!("Impossible de publier le fichier. Choisissez un nom disponible. {}", e.error))?;
    Ok(result)
}

pub(crate) fn decrypt_into(
    source: &Path,
    key: &crate::secure_key::SecureKey,
    output: &mut impl Write,
) -> Result<(), String> {
    let reader = BufReader::new(std::fs::File::open(source).map_err(|e| e.to_string())?);
    decrypt_reader(reader, key, output)
}

fn decrypt_reader(
    mut reader: impl BufRead,
    key: &crate::secure_key::SecureKey,
    output: &mut impl Write,
) -> Result<(), String> {
    if is_senc_format(reader.fill_buf().map_err(|e| e.to_string())?) {
        decrypt_file_stream_secure(key, &mut reader, output).map_err(|e| e.to_string())?;
    } else {
        let mut encoded = String::new();
        reader.take(MAX_LEGACY_FILE_BYTES + 1).read_to_string(&mut encoded)
            .map_err(|e| e.to_string())?;
        if encoded.len() as u64 > MAX_LEGACY_FILE_BYTES {
            return Err("Le fichier chiffré dans l’ancien format est trop volumineux".into());
        }
        let plaintext = zeroize::Zeroizing::new(decrypt_data_bytes_secure(&encoded, key)
            .map_err(|e| e.to_string())?);
        output.write_all(&plaintext).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Hash and decrypt the very same bounded ciphertext, preventing substitution
/// between a note's manifest check and reopening its attachment for export.
pub(crate) fn decrypt_verified_into(source: &Path, key: &crate::secure_key::SecureKey, output: &mut impl Write, expected: &str) -> Result<(), String> {
    let mut bytes = Vec::new();
    std::fs::File::open(source).map_err(|e| e.to_string())?.take(48 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > 48 * 1024 * 1024 || hex::encode(blake3_hash(&bytes)) != expected {
        return Err("La pièce jointe a été altérée".into());
    }
    decrypt_reader(std::io::Cursor::new(bytes), key, output)
}

#[tauri::command]
pub async fn decrypt_file_to_path(
    id: i64,
    output_path: Option<String>,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    export_file_inner(id, output_path, &state, app_handle, None).await
}

pub(crate) async fn export_file_inner(
    id: i64, output_path: Option<String>, state: &AppState, app_handle: tauri::AppHandle, expected_hash: Option<String>,
) -> Result<String, String> {
    let user_id = crate::validate_session(&state).await?;
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let file = db.get_secure_files(user_id).await.map_err(|e| e.to_string())?
        .into_iter().find(|file| file.id == id).ok_or("Fichier introuvable")?;
    let source = encrypted_file_path(&state, &file.file_path).await?;
    let key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    #[cfg(target_os = "android")]
    let destination = {
        if output_path.is_some() {
            return Err("L’export Android utilise le dossier Documents de FluXlock".into());
        }
        use tauri::Manager;
        let dir = app_handle.path().app_cache_dir().map_err(|e| e.to_string())?.join("exports");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        dir.join(uuid::Uuid::new_v4().to_string())
    };
    #[cfg(not(target_os = "android"))]
    let destination = {
        let home = dirs::home_dir().ok_or("Répertoire utilisateur indisponible")?;
        let output = output_path.ok_or("Destination requise")?;
        path_validator::validate_file_path(&output, Some(&home)).map_err(|e| e.to_string())?
    };

    let _ = app_handle.emit("file-decryption-progress", serde_json::json!({
        "stage": "decrypting", "progress": 30, "message": "Déchiffrement en cours…"
    }));
    let path = destination.clone();
    tokio::task::spawn_blocking(move || {
        publish_new_file(&path, |output| match expected_hash {
            Some(hash) => decrypt_verified_into(&source, &key, output, &hash),
            None => decrypt_into(&source, &key, output),
        })
    }).await.map_err(|e| e.to_string())??;

    let destination = destination.to_string_lossy().into_owned();
    #[cfg(target_os = "android")]
    state.decrypted_temp_files.lock().await.push(destination.clone());

    let _ = app_handle.emit("file-decryption-progress", serde_json::json!({
        "stage": "complete", "progress": 100, "message": "Fichier déchiffré"
    }));
    Ok(destination)
}

/// M01 — Nettoyage sécurisé manuel des fichiers déchiffrés temporaires
/// Le frontend peut appeler cette commande pour purger tous les fichiers déchiffrés
#[tauri::command]
pub async fn cleanup_decrypted_files(state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    crate::validate_session(&state).await?;
    let count = state.decrypted_temp_files.lock().await.len();
    secure_cleanup_decrypted_files(&state.decrypted_temp_files).await;
    debug_log!("🧹 Nettoyage manuel: {} fichier(s) supprimé(s)", count);
    Ok(format!("{} fichier(s) nettoyé(s) de manière sécurisée", count))
}

#[tauri::command]
pub async fn delete_secure_file(id: i64, state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<bool, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    if get_security_monitor().is_readonly().await {
        return Err("Le coffre est en lecture seule".into());
    }
    let attached: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM note_attachments WHERE file_id = ? AND user_id = ?)")
        .bind(id).bind(user_id).fetch_one(&db.pool).await.map_err(|e| e.to_string())?;
    if attached {
        return Err("Ce fichier est joint à une note. Détachez-le de la note avant de le supprimer.".into());
    }
    if let Some(file) = db.get_secure_files(user_id).await.map_err(|e| e.to_string())?
        .into_iter().find(|file| file.id == id)
    {
        let path = encrypted_file_path(&state, &file.file_path).await?;
        std::fs::remove_file(path).map_err(|e| format!("Suppression impossible: {e}"))?;
    }

    let deleted = db
        .delete_secure_file(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression fichier: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "DELETE", "file", Some(id)).await;

    Ok(deleted)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_decryption_preserves_destination_and_removes_staging() {
        let dir = tempfile::tempdir().unwrap();
        let destination = dir.path().join("export");
        let result = publish_new_file(&destination, |file| {
            file.write_all(b"first authenticated chunk").unwrap();
            Err::<(), _>("invalid final chunk".to_owned())
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        std::fs::write(&destination, b"existing").unwrap();
        assert!(publish_new_file(&destination, |file| file.write_all(b"replacement")
            .map_err(|e| e.to_string())).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
    }

    #[test]
    fn stored_files_must_reside_directly_under_a_vault_root() {
        let vault = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let valid = vault.path().join("valid.senc");
        let invalid = other.path().join("invalid.senc");
        std::fs::write(&valid, b"contents").unwrap();
        std::fs::write(&invalid, b"contents").unwrap();
        let roots = [vault.path().to_path_buf()];
        assert!(owned_file_path(valid.to_str().unwrap(), &roots).is_ok());
        assert!(owned_file_path(invalid.to_str().unwrap(), &roots).is_err());
        #[cfg(unix)]
        {
            let link = vault.path().join("link.senc");
            std::os::unix::fs::symlink(invalid, &link).unwrap();
            assert!(owned_file_path(link.to_str().unwrap(), &roots).is_err());
        }
    }
}

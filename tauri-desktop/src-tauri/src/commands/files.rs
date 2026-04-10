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
) -> Result<i64, String> {
    debug_log!("📥 Demande de création de fichier: {}", filename);
    
    // Vérifier le mode lecture seule (protection ransomware)
    let monitor = get_security_monitor();
    let is_readonly = monitor.is_readonly().await;
    debug_log!("🔒 Mode lecture seule: {}", is_readonly);
    
    if is_readonly {
        debug_log!("❌ Création bloquée - système en lecture seule");
        return Err("🚨 SYSTÈME EN MODE LECTURE SEULE - Activité ransomware détectée. Utilisez la commande 'Désactiver mode lecture seule' dans les paramètres si c'est un faux positif.".to_string());
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
    let files_dir = hidden_storage::get_hidden_files_dir()
        .map_err(|e| format!("Erreur obtention dossier fichiers caché: {}", e))?;

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
    let decoded_data = general_purpose::STANDARD.decode(&file_data)
        .map_err(|e| format!("Erreur décodage Base64: {}", e))?;

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
        std::fs::write(&file_path_clone, encrypted_data_clone.as_bytes())
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
        .map_err(|e| format!("Erreur création fichier sécurisé: {}", e))?;

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
) -> Result<i64, String> {
    use std::fs::File;
    use std::io::{BufReader, BufWriter};
    
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

    let files_dir = hidden_storage::get_hidden_files_dir()
        .map_err(|e| format!("Erreur dossier: {}", e))?;

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
    let validated_path_clone = validated_path.clone();
    let (bytes_encrypted, integrity_hash) = tokio::task::spawn_blocking(move || -> Result<(u64, String), String> {
        let src = File::open(&validated_path_clone)
            .map_err(|e| format!("Erreur ouverture source: {}", e))?;
        let mut reader = BufReader::with_capacity(65536, src);
        
        let dst = File::create(&output_path_clone)
            .map_err(|e| format!("Erreur création sortie: {}", e))?;
        let mut writer = BufWriter::with_capacity(65536, dst);
        
        encrypt_file_stream_with_hash(&encryption_key, &mut reader, &mut writer, 0)
            .map_err(|e| format!("Erreur chiffrement streaming: {}", e))
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
            file_size as i64,
            None,
            Some(&integrity_hash),
        )
        .await
        .map_err(|e| format!("Erreur DB: {}", e))?;

    let _ = db.log_action(user_id, "CREATE", "file", Some(secure_file_id)).await;

    let _ = app_handle.emit("file-encryption-progress", serde_json::json!({
        "stage": "deleting_original",
        "progress": 95,
        "message": "Suppression du fichier original..."
    }));
    
    // Effacement sécurisé du fichier original (remplissage par zéros avant suppression)
    debug_log!("🗑️ Effacement sécurisé du fichier original: {}", file_path);
    tokio::task::spawn_blocking({
        let file_path = file_path.clone();
        move || {
            if let Ok(metadata) = std::fs::metadata(&file_path) {
                let size = metadata.len() as usize;
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(&file_path) {
                    use std::io::Write;
                    let zeros = vec![0u8; std::cmp::min(size, 1_048_576)];
                    let mut written = 0;
                    while written < size {
                        let to_write = std::cmp::min(zeros.len(), size - written);
                        if f.write_all(&zeros[..to_write]).is_err() { break; }
                        written += to_write;
                    }
                    let _ = f.flush();
                }
            }
            std::fs::remove_file(&file_path)
        }
    }).await
        .map_err(|e| format!("Erreur thread suppression: {}", e))?
        .map_err(|e| format!("Erreur suppression fichier original: {}", e))?;
    
    debug_log!("✅ Fichier original supprimé");
    
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
pub async fn get_secure_files(state: State<'_, AppState>) -> Result<Vec<SecureFile>, String> {
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

#[tauri::command]
pub async fn decrypt_file(id: i64, state: State<'_, AppState>) -> Result<String, String> {
    use std::io::Cursor;
    
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let file = db
        .get_secure_files(user_id)
        .await
        .map_err(|e| format!("Erreur récupération fichiers: {}", e))?
        .into_iter()
        .find(|f| f.id == id)
        .ok_or("Fichier non trouvé")?;

    debug_log!("📥 Téléchargement fichier chiffré depuis: {}", file.file_path);

    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Lire les premiers octets pour détecter le format
    let header = {
        let mut f = std::fs::File::open(&file.file_path)
            .map_err(|e| format!("Erreur lecture fichier: {}", e))?;
        let mut buf = [0u8; 6];
        use std::io::Read;
        let _ = f.read(&mut buf).map_err(|e| format!("Erreur lecture header: {}", e))?;
        buf
    };

    let decrypted_bytes = if is_senc_format(&header) {
        // ═══ Format SENC v1: déchiffrement streaming vers mémoire ═══
        let file_path = file.file_path.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
            let src = std::fs::File::open(&file_path)
                .map_err(|e| format!("Erreur ouverture: {}", e))?;
            let mut reader = std::io::BufReader::with_capacity(65536, src);
            let mut output = Vec::new();
            let mut writer = Cursor::new(&mut output);
            decrypt_file_stream_secure(&encryption_key, &mut reader, &mut writer)
                .map_err(|e| format!("Erreur déchiffrement streaming: {}", e))?;
            Ok(output)
        }).await
            .map_err(|e| format!("Erreur thread: {}", e))?
            .map_err(|e| e)?
    } else {
        // ═══ Format legacy (v2:base64): déchiffrement classique ═══
        let encrypted_data = std::fs::read_to_string(&file.file_path)
            .map_err(|e| format!("Erreur lecture fichier: {}", e))?;
        decrypt_data_bytes_secure(&encrypted_data, &encryption_key)
            .map_err(|e| format!("Erreur déchiffrement: {}", e))?
    };

    let base64_data = general_purpose::STANDARD.encode(&decrypted_bytes);
    debug_log!("✅ Fichier déchiffré et prêt pour téléchargement");
    Ok(base64_data)
}

/// Déchiffre un fichier et le sauvegarde directement au chemin spécifié (streaming si SENC)
#[tauri::command]
pub async fn decrypt_file_to_path(
    id: i64,
    output_path: String,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<String, String> {
    
    #[cfg(debug_assertions)]
    debug_log!("📥 Demande de déchiffrement du fichier ID: {} vers {}", id, output_path);
    
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let file = db
        .get_secure_files(user_id)
        .await
        .map_err(|e| format!("Erreur récupération fichiers: {}", e))?
        .into_iter()
        .find(|f| f.id == id)
        .ok_or("Fichier non trouvé")?;

    debug_log!("📥 Fichier chiffré: {}", file.file_path);
    
    let _ = app_handle.emit("file-decryption-progress", serde_json::json!({
        "stage": "reading",
        "progress": 0,
        "message": "Lecture du fichier chiffré..."
    }));

    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // EXP-004 fix: Validation du chemin de sortie contre path traversal
    let home_dir = dirs::home_dir()
        .ok_or("Impossible de déterminer le répertoire utilisateur")?;
    let validated_output = path_validator::validate_file_path(&output_path, Some(&home_dir))
        .map_err(|e| format!("Chemin de sortie invalide: {}", e))?;
    let safe_output_path = validated_output.to_string_lossy().to_string();

    // Détecter le format (SENC v1 vs legacy)
    let header = {
        let mut f = std::fs::File::open(&file.file_path)
            .map_err(|e| format!("Erreur lecture fichier: {}", e))?;
        let mut buf = [0u8; 6];
        use std::io::Read;
        let _ = f.read(&mut buf).map_err(|e| format!("Erreur lecture header: {}", e))?;
        buf
    };

    let _ = app_handle.emit("file-decryption-progress", serde_json::json!({
        "stage": "decrypting",
        "progress": 30,
        "message": "Déchiffrement en cours..."
    }));

    if is_senc_format(&header) {
        // ═══ Format SENC v1: déchiffrement streaming direct vers fichier ═══
        let file_path = file.file_path.clone();
        let out_path = safe_output_path.clone();
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            let src = std::fs::File::open(&file_path)
                .map_err(|e| format!("Erreur ouverture source: {}", e))?;
            let mut reader = std::io::BufReader::with_capacity(65536, src);
            let dst = std::fs::File::create(&out_path)
                .map_err(|e| format!("Erreur création sortie: {}", e))?;
            let mut writer = std::io::BufWriter::with_capacity(65536, dst);
            decrypt_file_stream_secure(&encryption_key, &mut reader, &mut writer)
                .map_err(|e| format!("Erreur déchiffrement streaming: {}", e))?;
            Ok(())
        }).await
            .map_err(|e| format!("Erreur thread: {}", e))?
            .map_err(|e| e)?;
    } else {
        // ═══ Format legacy (v2:base64): déchiffrement classique ═══
        let encrypted_data = tokio::task::spawn_blocking({
            let file_path = file.file_path.clone();
            move || std::fs::read_to_string(&file_path)
        }).await
            .map_err(|e| format!("Erreur thread lecture: {}", e))?
            .map_err(|e| format!("Erreur lecture fichier: {}", e))?;

        let decrypted_bytes = decrypt_data_bytes_secure(&encrypted_data, &encryption_key)
            .map_err(|e| format!("Erreur déchiffrement: {}", e))?;

        tokio::task::spawn_blocking({
            let output_path = safe_output_path.clone();
            move || std::fs::write(&output_path, &decrypted_bytes)
        }).await
            .map_err(|e| format!("Erreur thread écriture: {}", e))?
            .map_err(|e| format!("Erreur écriture: {}", e))?;
    }
    
    debug_log!("✅ Fichier sauvegardé: {}", safe_output_path);
    
    // M01 — Enregistrer le fichier déchiffré pour nettoyage sécurisé ultérieur
    {
        let mut temp_files = state.decrypted_temp_files.lock().await;
        temp_files.push(safe_output_path.clone());
    }
    
    let _ = app_handle.emit("file-decryption-progress", serde_json::json!({
        "stage": "complete",
        "progress": 100,
        "message": "Fichier téléchargé avec succès!"
    }));

    Ok(format!("Fichier sauvegardé: {}", output_path))
}

/// M01 — Nettoyage sécurisé manuel des fichiers déchiffrés temporaires
/// Le frontend peut appeler cette commande pour purger tous les fichiers déchiffrés
#[tauri::command]
pub async fn cleanup_decrypted_files(state: State<'_, AppState>) -> Result<String, String> {
    let count = state.decrypted_temp_files.lock().await.len();
    secure_cleanup_decrypted_files(&state.decrypted_temp_files).await;
    debug_log!("🧹 Nettoyage manuel: {} fichier(s) supprimé(s)", count);
    Ok(format!("{} fichier(s) nettoyé(s) de manière sécurisée", count))
}

#[tauri::command]
pub async fn delete_secure_file(id: i64, state: State<'_, AppState>) -> Result<bool, String> {
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer le fichier pour supprimer le fichier physique
    if let Ok(Some(file)) = db.get_secure_files(user_id).await.map(|files| {
        files.into_iter().find(|f| f.id == id)
    }) {
        debug_log!("🗑️ Suppression du fichier physique: {}", file.file_path);
        let _ = std::fs::remove_file(&file.file_path);
    }

    let deleted = db
        .delete_secure_file(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression fichier: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "DELETE", "file", Some(id)).await;

    Ok(deleted)
}

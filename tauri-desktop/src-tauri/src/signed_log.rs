// ============================================
// MODULE DE LOGS SIGNÉS ET IMMUABLES
// ============================================
// Hash chain SHA3-256 + Signature ML-DSA-65 par entrée.
// Clé de signature dédiée (pas K_vault).
// Fichier append-only (O_APPEND, 0600).
// Vérification d'intégrité disponible comme commande Tauri.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use secure_vault_crypto::{MlDsaKeyPair, sha3_256_hash, verify_ml_dsa};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;

/// Entrée de log signée avec hash chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedLogEntry {
    pub seq: u64,
    pub timestamp: String,
    pub event: String,
    pub metadata: serde_json::Value,
    pub prev_hash: String, // hex SHA3-256
    pub signature: String, // base64 ML-DSA-65
}

/// Résultat de la vérification d'intégrité
#[derive(Debug, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub total_entries: u64,
    pub valid: bool,
    pub first_invalid_seq: Option<u64>,
    pub error: Option<String>,
}

/// Gestionnaire de logs signés
#[allow(dead_code)]
pub struct SignedLogManager {
    log_path: PathBuf,
    key_path: PathBuf,
    signing_key: MlDsaKeyPair,
    verifying_key_der: Vec<u8>,
    last_seq: u64,
    last_hash: String,
}

/// Hash de genèse (première entrée)
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Service Keychain pour la KEK du log signé
const LOG_KEK_SERVICE: &str = "com.fluxlock.signed-log";
const LOG_KEK_ACCOUNT: &str = "signing_key_kek";

/// VULN-005: Récupère ou génère la KEK (Key Encryption Key) pour protéger la clé de signature.
/// La KEK est stockée dans le Keychain OS, pas sur le disque.
fn get_or_create_log_kek() -> Result<[u8; 32], String> {
    use base64::{Engine as _, engine::general_purpose};
    
    // Mobile fallback: pas de keyring disponible, utiliser une clé fixe dérivée
    if cfg!(target_os = "android") || cfg!(target_os = "ios") {
        // Sur mobile, la protection OS du répertoire privé est suffisante
        let mut key = [0u8; 32];
        // Dériver une clé stable à partir d'un sel fixe (protection minimum)
        let salt = b"fluxlock-signed-log-mobile-kek-v1";
        key.copy_from_slice(&secure_vault_crypto::sha3_256_hash(salt)[..32]);
        return Ok(key);
    }
    
    let entry = keyring::Entry::new(LOG_KEK_SERVICE, LOG_KEK_ACCOUNT)
        .map_err(|e| format!("Keyring entry error: {}", e))?;
    
    // Essayer de lire la KEK existante
    match entry.get_password() {
        Ok(b64_key) => {
            let key_bytes = general_purpose::STANDARD.decode(&b64_key)
                .map_err(|e| format!("Décodage KEK: {}", e))?;
            if key_bytes.len() != 32 {
                return Err("KEK corrompue dans le Keychain".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            Ok(key)
        }
        Err(_) => {
            // Générer une nouvelle KEK et la stocker
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            let b64 = general_purpose::STANDARD.encode(&key);
            entry.set_password(&b64)
                .map_err(|e| format!("Stockage KEK dans Keychain: {}", e))?;
            Ok(key)
        }
    }
}

/// VULN-005: Chiffre les données de clé privée avec la KEK (ChaCha20-Poly1305)
fn encrypt_signing_key(sk_der: &[u8], kek: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(kek)
        .map_err(|e| format!("Init cipher: {}", e))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, sk_der)
        .map_err(|e| format!("Chiffrement clé de signature: {}", e))?;
    // Format: [12 bytes nonce][ciphertext]
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// VULN-005: Déchiffre les données de clé privée avec la KEK
fn decrypt_signing_key(encrypted: &[u8], kek: &[u8; 32]) -> Result<Vec<u8>, String> {
    if encrypted.len() < 12 + 16 { // nonce + min tag
        return Err("Données chiffrées trop courtes".to_string());
    }
    let cipher = ChaCha20Poly1305::new_from_slice(kek)
        .map_err(|e| format!("Init cipher: {}", e))?;
    let nonce = Nonce::from_slice(&encrypted[..12]);
    let plaintext = cipher.decrypt(nonce, &encrypted[12..])
        .map_err(|_| "Déchiffrement clé de signature échoué — KEK invalide ou données corrompues".to_string())?;
    Ok(plaintext)
}

/// Sérialise une entrée pour le calcul du hash (sans la signature)
fn entry_hash_payload(entry: &SignedLogEntry) -> Vec<u8> {
    format!(
        "{}|{}|{}|{}|{}",
        entry.seq, entry.timestamp, entry.event, entry.metadata, entry.prev_hash
    )
    .into_bytes()
}

/// Sérialise une entrée pour la signature (sans le champ signature)
fn entry_sign_payload(entry: &SignedLogEntry) -> Vec<u8> {
    entry_hash_payload(entry)
}

impl SignedLogManager {
    /// Initialise le gestionnaire. Crée ou charge la clé de signature dédiée.
    pub fn init(data_dir: &Path) -> Result<Self, String> {
        let log_dir = data_dir.join("signed_logs");
        fs::create_dir_all(&log_dir).map_err(|e| format!("Impossible de créer le répertoire de logs: {}", e))?;

        let log_path = log_dir.join("audit.jsonl");
        let key_path = log_dir.join("log_signing_key.bin");
        let vk_path = log_dir.join("log_verifying_key.bin");

        // VULN-005: Obtenir la KEK depuis le Keychain OS
        let kek = get_or_create_log_kek()?;

        // Charger ou générer la clé de signature dédiée (chiffrée au repos)
        let (signing_key, verifying_key_der) = if key_path.exists() && vk_path.exists() {
            let encrypted_sk = fs::read(&key_path)
                .map_err(|e| format!("Impossible de lire la clé de signature: {}", e))?;
            let vk_bytes = fs::read(&vk_path)
                .map_err(|e| format!("Impossible de lire la clé de vérification: {}", e))?;
            
            // Déchiffrer la clé privée avec la KEK
            match decrypt_signing_key(&encrypted_sk, &kek) {
                Ok(sk_bytes) => {
                    let kp = MlDsaKeyPair::from_pkcs8_der(&sk_bytes)
                        .map_err(|e| format!("Clé corrompue: {}", e))?;
                    (kp, vk_bytes)
                }
                Err(_e) => {
                    // KEK désynchronisée (reset Keychain, réinstallation…) :
                    // régénérer la clé de signature. Les anciens logs restent
                    // vérifiables avec l'ancienne clé publique archivée.
                    eprintln!("⚠️  KEK désynchronisée — régénération de la clé de signature des logs");
                    
                    // Archiver l'ancienne clé publique pour vérification ultérieure
                    let archive_name = format!(
                        "log_verifying_key_{}.bin.old",
                        chrono::Utc::now().format("%Y%m%d_%H%M%S")
                    );
                    let _ = fs::rename(&vk_path, log_dir.join(&archive_name));
                    let _ = fs::remove_file(&key_path);
                    
                    // Générer une nouvelle paire de clés
                    let kp = MlDsaKeyPair::generate()
                        .map_err(|e| format!("Génération de clé échouée: {}", e))?;
                    let sk_der = kp.to_pkcs8_der()
                        .map_err(|e| format!("Export clé privée échoué: {}", e))?;
                    let vk_der = kp.verifying_key_bytes()
                        .map_err(|e| format!("Export clé publique échoué: {}", e))?;
                    
                    let encrypted_sk = encrypt_signing_key(&sk_der, &kek)?;
                    
                    fs::write(&key_path, &encrypted_sk)
                        .map_err(|e| format!("Impossible d'écrire la clé privée: {}", e))?;
                    fs::write(&vk_path, &vk_der)
                        .map_err(|e| format!("Impossible d'écrire la clé publique: {}", e))?;
                    
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let perms = fs::Permissions::from_mode(0o600);
                        let _ = fs::set_permissions(&key_path, perms.clone());
                        let _ = fs::set_permissions(&vk_path, perms);
                    }
                    
                    (kp, vk_der)
                }
            }
        } else {
            let kp = MlDsaKeyPair::generate()
                .map_err(|e| format!("Génération de clé échouée: {}", e))?;
            let sk_der = kp.to_pkcs8_der()
                .map_err(|e| format!("Export clé privée échoué: {}", e))?;
            let vk_der = kp.verifying_key_bytes()
                .map_err(|e| format!("Export clé publique échoué: {}", e))?;

            // VULN-005: Chiffrer la clé privée avant écriture sur disque
            let encrypted_sk = encrypt_signing_key(&sk_der, &kek)?;
            
            fs::write(&key_path, &encrypted_sk)
                .map_err(|e| format!("Impossible d'écrire la clé privée: {}", e))?;
            fs::write(&vk_path, &vk_der)
                .map_err(|e| format!("Impossible d'écrire la clé publique: {}", e))?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = fs::Permissions::from_mode(0o600);
                let _ = fs::set_permissions(&key_path, perms.clone());
                let _ = fs::set_permissions(&vk_path, perms);
            }

            (kp, vk_der)
        };

        // Lire le dernier seq et hash depuis le fichier existant
        let (last_seq, last_hash) = Self::read_last_entry(&log_path)?;

        Ok(Self {
            log_path,
            key_path: key_path.clone(),
            signing_key,
            verifying_key_der,
            last_seq,
            last_hash,
        })
    }

    /// Lit la dernière entrée du fichier de logs
    fn read_last_entry(log_path: &Path) -> Result<(u64, String), String> {
        if !log_path.exists() {
            return Ok((0, GENESIS_HASH.to_string()));
        }

        let file = fs::File::open(log_path)
            .map_err(|e| format!("Impossible d'ouvrir le fichier de logs: {}", e))?;
        let reader = BufReader::new(file);

        let mut last_seq = 0u64;
        let mut last_hash = GENESIS_HASH.to_string();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Erreur de lecture: {}", e))?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(entry) = serde_json::from_str::<SignedLogEntry>(&line) {
                // Calculer le hash de cette entrée pour la chaîne
                let payload = entry_hash_payload(&entry);
                last_hash = hex::encode(sha3_256_hash(&payload));
                last_seq = entry.seq;
            }
        }

        Ok((last_seq, last_hash))
    }

    /// Ajoute une entrée signée au journal
    #[allow(dead_code)]
    pub fn append(&mut self, event: &str, metadata: serde_json::Value) -> Result<SignedLogEntry, String> {
        self.last_seq += 1;

        let mut entry = SignedLogEntry {
            seq: self.last_seq,
            timestamp: Utc::now().to_rfc3339(),
            event: event.to_string(),
            metadata,
            prev_hash: self.last_hash.clone(),
            signature: String::new(),
        };

        // Signer le payload
        let sign_payload = entry_sign_payload(&entry);
        let sig_bytes = self.signing_key.sign(&sign_payload)
            .map_err(|e| format!("Erreur de signature: {}", e))?;
        entry.signature = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &sig_bytes,
        );

        // Calculer le hash pour la prochaine entrée
        let hash_payload = entry_hash_payload(&entry);
        self.last_hash = hex::encode(sha3_256_hash(&hash_payload));

        // Écrire en append-only
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .map_err(|e| format!("Impossible d'ouvrir le fichier: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.log_path, fs::Permissions::from_mode(0o600));
        }

        let json = serde_json::to_string(&entry)
            .map_err(|e| format!("Sérialisation échouée: {}", e))?;
        writeln!(file, "{}", json)
            .map_err(|e| format!("Écriture échouée: {}", e))?;

        Ok(entry)
    }

    /// Vérifie l'intégrité complète de la chaîne de logs
    pub fn verify_integrity(&self) -> Result<IntegrityReport, String> {
        if !self.log_path.exists() {
            return Ok(IntegrityReport {
                total_entries: 0,
                valid: true,
                first_invalid_seq: None,
                error: None,
            });
        }

        let file = fs::File::open(&self.log_path)
            .map_err(|e| format!("Impossible d'ouvrir le fichier: {}", e))?;
        let reader = BufReader::new(file);

        let mut prev_hash = GENESIS_HASH.to_string();
        let mut count = 0u64;

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Erreur de lecture: {}", e))?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: SignedLogEntry = serde_json::from_str(&line)
                .map_err(|e| format!("Entrée corrompue (JSON): {}", e))?;

            count += 1;

            // Vérifier la chaîne de hash
            if entry.prev_hash != prev_hash {
                return Ok(IntegrityReport {
                    total_entries: count,
                    valid: false,
                    first_invalid_seq: Some(entry.seq),
                    error: Some(format!(
                        "Hash chain brisée à seq {}: attendu {}, trouvé {}",
                        entry.seq, prev_hash, entry.prev_hash
                    )),
                });
            }

            // Vérifier la signature ML-DSA-65
            let sign_payload = entry_sign_payload(&entry);
            let sig_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.signature,
            )
            .map_err(|e| format!("Signature base64 invalide à seq {}: {}", entry.seq, e))?;

            match verify_ml_dsa(&self.verifying_key_der, &sign_payload, &sig_bytes) {
                Ok(true) => {}
                Ok(false) => {
                    return Ok(IntegrityReport {
                        total_entries: count,
                        valid: false,
                        first_invalid_seq: Some(entry.seq),
                        error: Some(format!("Signature invalide à seq {}", entry.seq)),
                    });
                }
                Err(e) => {
                    return Ok(IntegrityReport {
                        total_entries: count,
                        valid: false,
                        first_invalid_seq: Some(entry.seq),
                        error: Some(format!("Erreur vérification signature seq {}: {}", entry.seq, e)),
                    });
                }
            }

            // Mettre à jour prev_hash pour l'entrée suivante
            let hash_payload = entry_hash_payload(&entry);
            prev_hash = hex::encode(sha3_256_hash(&hash_payload));
        }

        Ok(IntegrityReport {
            total_entries: count,
            valid: true,
            first_invalid_seq: None,
            error: None,
        })
    }

    /// Vérifie l'intégrité en lecture seule (utilise uniquement la clé publique)
    #[allow(dead_code)]
    pub fn verify_integrity_readonly(log_path: &Path, vk_path: &Path) -> Result<IntegrityReport, String> {
        let vk_der = fs::read(vk_path)
            .map_err(|e| format!("Impossible de lire la clé de vérification: {}", e))?;

        if !log_path.exists() {
            return Ok(IntegrityReport {
                total_entries: 0,
                valid: true,
                first_invalid_seq: None,
                error: None,
            });
        }

        let file = fs::File::open(log_path)
            .map_err(|e| format!("Impossible d'ouvrir le fichier: {}", e))?;
        let reader = BufReader::new(file);

        let mut prev_hash = GENESIS_HASH.to_string();
        let mut count = 0u64;

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Erreur de lecture: {}", e))?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: SignedLogEntry = serde_json::from_str(&line)
                .map_err(|e| format!("Entrée corrompue: {}", e))?;

            count += 1;

            if entry.prev_hash != prev_hash {
                return Ok(IntegrityReport {
                    total_entries: count,
                    valid: false,
                    first_invalid_seq: Some(entry.seq),
                    error: Some(format!("Hash chain brisée à seq {}", entry.seq)),
                });
            }

            let sign_payload = entry_sign_payload(&entry);
            let sig_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.signature,
            )
            .map_err(|e| format!("Signature invalide à seq {}: {}", entry.seq, e))?;

            match verify_ml_dsa(&vk_der, &sign_payload, &sig_bytes) {
                Ok(true) => {}
                _ => {
                    return Ok(IntegrityReport {
                        total_entries: count,
                        valid: false,
                        first_invalid_seq: Some(entry.seq),
                        error: Some(format!("Signature invalide à seq {}", entry.seq)),
                    });
                }
            }

            let hash_payload = entry_hash_payload(&entry);
            prev_hash = hex::encode(sha3_256_hash(&hash_payload));
        }

        Ok(IntegrityReport {
            total_entries: count,
            valid: true,
            first_invalid_seq: None,
            error: None,
        })
    }
}

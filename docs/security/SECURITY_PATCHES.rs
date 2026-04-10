// ============================================
// PATCH 1: Remplacer static mut par Lazy<Mutex<T>>
// ============================================
// Fichier: src-tauri/src/security_monitor.rs

// AVANT (DANGEREUX):
/*
static mut SECURITY_MONITOR: Option<SecurityMonitor> = None;

pub fn get_security_monitor() -> &'static SecurityMonitor {
    unsafe {
        if SECURITY_MONITOR.is_none() {
            SECURITY_MONITOR = Some(SecurityMonitor::new());
        }
        SECURITY_MONITOR.as_ref().expect("Security monitor not initialized")
    }
}
*/

// APRÈS (SÉCURISÉ):
use once_cell::sync::Lazy;
use std::sync::Mutex;

static SECURITY_MONITOR: Lazy<Mutex<SecurityMonitor>> = Lazy::new(|| {
    Mutex::new(SecurityMonitor::new())
});

pub fn get_security_monitor() -> &'static Lazy<Mutex<SecurityMonitor>> {
    &SECURITY_MONITOR
}

// Utilisation:
// let monitor = get_security_monitor().lock().unwrap();
// monitor.method();


// ============================================
// PATCH 2: Validation des chemins de fichiers
// ============================================
// Fichier: src-tauri/src/main.rs

use std::path::{Path, PathBuf, Component};

/// Valide et sécurise un chemin de fichier
fn validate_file_path(file_path: &str) -> Result<PathBuf, String> {
    let path = Path::new(file_path);
    
    // Canonicaliser le chemin (résout .., ., liens symboliques)
    let canonical = path.canonicalize()
        .map_err(|e| format!("Chemin invalide ou inexistant: {}", e))?;
    
    // Vérifier qu'il n'y a pas de composants dangereux
    for component in canonical.components() {
        if matches!(component, Component::ParentDir) {
            return Err("Path traversal détecté: utilisation de '..' non autorisée".to_string());
        }
    }
    
    // Définir les répertoires autorisés
    let home = dirs::home_dir()
        .ok_or_else(|| "Impossible de déterminer le répertoire home".to_string())?;
    
    let allowed_dirs = vec![
        home.join("Documents"),
        home.join("Downloads"),
        home.join("Desktop"),
        home.join("Pictures"),
        home.join("Music"),
        home.join("Videos"),
    ];
    
    // Vérifier que le chemin canonique est dans un répertoire autorisé
    let is_allowed = allowed_dirs.iter().any(|allowed| {
        canonical.starts_with(allowed)
    });
    
    if !is_allowed {
        return Err(format!(
            "Accès refusé: le fichier doit être dans Documents, Downloads, Desktop, Pictures, Music ou Videos"
        ));
    }
    
    Ok(canonical)
}

// UTILISATION dans create_secure_file_from_path:
#[tauri::command]
async fn create_secure_file_from_path(
    file_path: String,
    state: State<'_, AppState>,
    window: Window,
) -> Result<SecureFile, String> {
    // VALIDER LE CHEMIN EN PREMIER
    let validated_path = validate_file_path(&file_path)?;
    let file_path = validated_path.to_string_lossy().to_string();
    
    // ... reste du code existant
}


// ============================================
// PATCH 3: Rate Limiting
// ============================================
// Fichier: src-tauri/src/rate_limiter.rs (NOUVEAU FICHIER)

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    attempts: Mutex<HashMap<String, Vec<Instant>>>,
    max_attempts: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_attempts: usize, window_secs: u64) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            max_attempts,
            window: Duration::from_secs(window_secs),
        }
    }
    
    /// Vérifie si une action est autorisée pour cette clé
    /// Retourne Ok(()) si autorisé, Err avec temps d'attente sinon
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().unwrap();
        
        // Récupérer ou créer l'entrée
        let entry = attempts.entry(key.to_string()).or_insert_with(Vec::new);
        
        // Nettoyer les tentatives expirées
        entry.retain(|&time| now.duration_since(time) < self.window);
        
        // Vérifier si la limite est atteinte
        if entry.len() >= self.max_attempts {
            // Calculer le temps d'attente
            let oldest = entry.first().unwrap();
            let wait_time = self.window.checked_sub(now.duration_since(*oldest))
                .unwrap_or(Duration::from_secs(0));
            return Err(wait_time);
        }
        
        // Enregistrer cette tentative
        entry.push(now);
        Ok(())
    }
    
    /// Réinitialise le compteur pour une clé (après succès par exemple)
    pub fn reset(&self, key: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        attempts.remove(key);
    }
    
    /// Nettoie toutes les entrées expirées
    pub fn cleanup(&self) {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().unwrap();
        
        attempts.retain(|_, times| {
            times.retain(|&time| now.duration_since(time) < self.window);
            !times.is_empty()
        });
    }
}

// Fichier: src-tauri/src/main.rs
mod rate_limiter;
use rate_limiter::RateLimiter;

pub struct AppState {
    pub db: Arc<Mutex<Option<Database>>>,
    pub current_user_id: Arc<Mutex<Option<i64>>>,
    pub login_limiter: Arc<RateLimiter>,
    pub register_limiter: Arc<RateLimiter>,
    pub decrypt_limiter: Arc<RateLimiter>,
}

// Dans fn main():
fn main() {
    tauri::Builder::default()
        .manage(AppState {
            db: Arc::new(Mutex::new(None)),
            current_user_id: Arc::new(Mutex::new(None)),
            // 5 tentatives max par 5 minutes pour le login
            login_limiter: Arc::new(RateLimiter::new(5, 300)),
            // 3 inscriptions max par heure
            register_limiter: Arc::new(RateLimiter::new(3, 3600)),
            // 100 déchiffrements max par minute
            decrypt_limiter: Arc::new(RateLimiter::new(100, 60)),
        })
        // ...
}

// UTILISATION dans login:
#[tauri::command]
async fn login(
    credentials: LoginCredentials,
    state: State<'_, AppState>,
) -> Result<LoginResponse, String> {
    // VÉRIFIER RATE LIMIT
    match state.login_limiter.check(&credentials.username) {
        Ok(()) => {},
        Err(wait_time) => {
            let secs = wait_time.as_secs();
            return Err(format!(
                "Trop de tentatives de connexion. Réessayez dans {} minutes et {} secondes.",
                secs / 60,
                secs % 60
            ));
        }
    }
    
    // Après succès de connexion:
    // state.login_limiter.reset(&credentials.username);
    
    // ... reste du code existant
}


// ============================================
// PATCH 4: Clés en mémoire sécurisée
// ============================================
// Fichier: src-tauri/Cargo.toml

// Ajouter ces dépendances:
/*
[dependencies]
secrecy = "0.8"
zeroize = "1.7"
*/

// Fichier: src-tauri/src/secure_key.rs (NOUVEAU)

use secrecy::{Secret, ExposeSecret, Zeroize};
use serde::{Serialize, Deserialize};

/// Wrapper sécurisé pour une clé de chiffrement
/// La clé est automatiquement effacée de la mémoire lors de la destruction
#[derive(Clone)]
pub struct SecureKey {
    key: Secret<Vec<u8>>,
}

impl SecureKey {
    /// Crée une nouvelle clé sécurisée
    pub fn new(key: Vec<u8>) -> Self {
        Self { 
            key: Secret::new(key) 
        }
    }
    
    /// Utilise la clé dans un contexte limité
    /// La clé n'est jamais exposée en dehors de la closure
    pub fn use_key<F, R>(&self, f: F) -> R 
    where 
        F: FnOnce(&[u8]) -> R 
    {
        f(self.key.expose_secret())
    }
    
    /// Crée une clé depuis une string (pour compatibilité)
    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex)
            .map_err(|e| format!("Erreur décodage hex: {}", e))?;
        Ok(Self::new(bytes))
    }
    
    /// Exporte en hex (usage limité, pour stockage seulement)
    pub fn to_hex(&self) -> String {
        hex::encode(self.key.expose_secret())
    }
}

// Implémentation Debug qui ne révèle pas la clé
impl std::fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureKey([REDACTED])")
    }
}

// UTILISATION dans main.rs:
// Au lieu de:
// let encryption_key: Vec<u8> = ...;

// Utiliser:
// let encryption_key = SecureKey::new(raw_key_bytes);

// Pour utiliser la clé:
// encryption_key.use_key(|key_bytes| {
//     encrypt_data_bytes(data, key_bytes)
// })


// ============================================
// PATCH 5: Amélioration gestion erreurs crypto
// ============================================
// Fichier: rust-crypto-core/src/crypto/aes_gcm.rs

use rand::RngCore;

pub fn encrypt_aes_gcm(data: &[u8], key: &[u8]) -> Result<EncryptedData> {
    // Vérifier la longueur de la clé
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength {
            expected: 32,
            got: key.len(),
        });
    }
    
    // Générer un nonce sécurisé avec vérification
    let mut nonce_bytes = vec![0u8; 12];
    OsRng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    
    // Vérifier que le nonce n'est pas tous des zéros (sanity check)
    if nonce_bytes.iter().all(|&b| b == 0) {
        return Err(CryptoError::RandomGenerationFailed(
            "Le générateur de nombres aléatoires a produit un nonce invalide".to_string()
        ));
    }
    
    // Logger en mode debug uniquement
    #[cfg(debug_assertions)]
    eprintln!("🔐 Chiffrement: taille={} octets", data.len());
    
    // Effectuer le chiffrement
    match perform_encryption_internal(data, key, &nonce_bytes) {
        Ok(result) => {
            #[cfg(debug_assertions)]
            eprintln!("✅ Chiffrement réussi");
            Ok(result)
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            eprintln!("❌ Échec chiffrement: {:?}", e);
            Err(e)
        }
    }
}

// Ajouter dans errors.rs:
#[derive(Debug)]
pub enum CryptoError {
    InvalidKeyLength { expected: usize, got: usize },
    RandomGenerationFailed(String),
    EncryptionFailed(String),
    DecryptionFailed(String),
    // ... autres variantes
}


// ============================================
// INSTRUCTIONS D'APPLICATION
// ============================================

/*
1. Ajouter les dépendances dans Cargo.toml:
   [dependencies]
   once_cell = "1.19"
   secrecy = "0.8"
   zeroize = "1.7"
   dirs = "5.0"

2. Créer les nouveaux fichiers:
   - src-tauri/src/rate_limiter.rs
   - src-tauri/src/secure_key.rs

3. Modifier les fichiers existants:
   - src-tauri/src/security_monitor.rs (remplacer static mut)
   - src-tauri/src/filesystem_monitor.rs (remplacer static mut)
   - src-tauri/src/main.rs (ajouter validation + rate limiting)
   - rust-crypto-core/src/crypto/aes_gcm.rs (améliorer erreurs)

4. Compiler et tester:
   cargo check
   cargo test
   cargo clippy

5. Tester manuellement:
   - Tentatives de login multiples (rate limiting)
   - Upload de fichiers avec chemins invalides (path validation)
   - Vérifier que les logs ne contiennent plus d'infos sensibles
*/

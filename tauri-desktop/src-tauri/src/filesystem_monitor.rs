use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use crossbeam_channel::{bounded, Receiver, Sender};
use std::thread;

use crate::security_monitor::get_security_monitor;
use once_cell::sync::Lazy;

macro_rules! debug_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            eprintln!($($arg)*);
        }
    }
}

// ========== STRUCTURES DE DONNÉES ==========

/// Activité suspecte détectée sur un fichier
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SuspiciousActivity {
    pub file_path: String,
    pub activity_type: ActivityType,
    pub timestamp: u64,
    pub severity: ThreatSeverity,
}

/// Types d'activités suspectes
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ActivityType {
    MassEncryption,        // Chiffrement massif de fichiers
    SuspiciousExtension,   // Extension ransomware connue
    RapidModification,     // Modifications trop rapides
    MassRename,            // Renommage en masse
    MassDeletion,          // Suppression en masse
    UnauthorizedAccess,    // Accès à zones sensibles
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Statistiques de surveillance en temps réel
#[derive(Debug, Clone, serde::Serialize)]
pub struct MonitoringStats {
    pub total_events: u64,
    pub modifications: u64,
    pub creations: u64,
    pub deletions: u64,
    pub renames: u64,
    pub suspicious_extensions: u64,
    pub rapid_changes: u64,
    pub monitored_paths: Vec<String>,
    pub active_threats: Vec<String>,
    pub threat_level: String,
    pub monitoring_enabled: bool,  // État de la surveillance
}

/// Structure interne pour suivre l'activité d'un fichier
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct FileActivity {
    path: String,
    last_modified: u64,
    modification_count: u32,
    last_events: Vec<u64>, // Timestamps des 10 derniers événements
}

/// Moniteur de système de fichiers
pub struct FilesystemMonitor {
    stats: Arc<Mutex<MonitoringStats>>,
    file_activities: Arc<Mutex<HashMap<String, FileActivity>>>,
    suspicious_activities: Arc<Mutex<Vec<SuspiciousActivity>>>,
    readonly_mode: Arc<Mutex<bool>>,
    monitoring_enabled: Arc<Mutex<bool>>,  // Toggle surveillance
    
    // Canaux de communication
    event_sender: Option<Sender<Event>>,
    event_receiver: Option<Receiver<Event>>,
    
    // F03 — Watcher stocké pour un arrêt propre (au lieu de mem::forget)
    #[allow(dead_code)]
    _watcher: Option<RecommendedWatcher>,
    
    // Configuration
    monitored_paths: Vec<PathBuf>,
    suspicious_extensions: Vec<String>,
}

// Extensions ransomware connues (plus de 50 variantes)
const RANSOMWARE_EXTENSIONS: &[&str] = &[
    // Classiques
    ".encrypted", ".locked", ".crypto", ".crypted", ".crypt",
    
    // Ransomwares célèbres
    ".wannacry", ".wcry", ".wncry",
    ".locky", ".zepto", ".odin", ".thor", ".aesir",
    ".cerber", ".cerber2", ".cerber3",
    ".cryptolocker", ".cryptowall",
    ".teslacrypt", ".vvv", ".exx", ".ezz", ".ecc",
    ".petya", ".mischa", ".goldeneye",
    ".jigsaw", ".fun", ".kkk", ".btc",
    ".dharma", ".wallet",
    ".ryuk", ".sodinokibi", ".revil",
    ".maze", ".egregor", ".conti",
    
    // Nouveaux variants 2023-2024
    ".lockbit", ".lockbit3", ".blackcat", ".alphv",
    ".hive", ".blackmatter", ".darkside",
    ".babuk", ".avaddon", ".ragnarok",
    
    // Extensions génériques
    ".enc", ".lock", ".key", ".kraken", ".onion",
    ".r5a", ".xtbl", ".micro", ".xxx", ".zzz",
    ".aaa", ".abc", ".xyz", ".encrypted123",
    ".cryptolocker", ".encrypt", ".coded",
];

// ========== IMPLÉMENTATION ==========

impl FilesystemMonitor {
    pub fn new() -> Self {
        let (sender, receiver) = bounded(1000);
        
        Self {
            stats: Arc::new(Mutex::new(MonitoringStats {
                total_events: 0,
                modifications: 0,
                creations: 0,
                deletions: 0,
                renames: 0,
                suspicious_extensions: 0,
                rapid_changes: 0,
                monitored_paths: Vec::new(),
                active_threats: Vec::new(),
                threat_level: "NONE".to_string(),
                monitoring_enabled: true,  // Activé par défaut
            })),
            file_activities: Arc::new(Mutex::new(HashMap::new())),
            suspicious_activities: Arc::new(Mutex::new(Vec::new())),
            readonly_mode: Arc::new(Mutex::new(false)),
            monitoring_enabled: Arc::new(Mutex::new(true)),  // Activé par défaut
            event_sender: Some(sender),
            event_receiver: Some(receiver),
            _watcher: None,
            monitored_paths: Vec::new(),
            suspicious_extensions: RANSOMWARE_EXTENSIONS.iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
    
    /// Démarre la surveillance des répertoires critiques du système
    pub fn start_monitoring(&mut self) -> Result<(), String> {
        debug_log!("🔍 Démarrage de la surveillance du système de fichiers...");
        
        // Déterminer les répertoires à surveiller selon l'OS
        self.monitored_paths = Self::get_critical_paths();
        
        // Mettre à jour les stats
        {
            let mut stats = self.stats.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            stats.monitored_paths = self.monitored_paths.iter()
                .map(|p| p.display().to_string())
                .collect();
        }
        
        // Créer le watcher
        let sender = self.event_sender.clone()
            .ok_or("Event sender non initialisé")?;
        let mut watcher: RecommendedWatcher = Watcher::new(
            move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    let _ = sender.send(event);
                }
            },
            Config::default()
                .with_poll_interval(Duration::from_millis(500)),
        ).map_err(|e| format!("Erreur création watcher: {}", e))?;
        
        // Surveiller tous les chemins critiques
        for path in &self.monitored_paths {
            if path.exists() {
                match watcher.watch(path, RecursiveMode::Recursive) {
                    Ok(_) => debug_log!("  ✅ Surveillance: {}", path.display()),
                    Err(e) => debug_log!("  ⚠️  Impossible de surveiller {}: {}", path.display(), e),
                }
            }
        }
        
        // Démarrer le thread de traitement des événements
        self.start_event_processor();
        
        // F03 — Stocker le watcher pour un arrêt propre (au lieu de mem::forget)
        self._watcher = Some(watcher);
        
        debug_log!("✅ Surveillance active sur {} répertoires", self.monitored_paths.len());
        Ok(())
    }
    
    /// Retourne les chemins critiques à surveiller selon l'OS
    fn get_critical_paths() -> Vec<PathBuf> {
        #[allow(unused_mut)]
        let mut paths = Vec::new();
        
        #[cfg(target_os = "macos")]
        {
            // macOS - Répertoires utilisateur critiques
            if let Some(home) = dirs::home_dir() {
                paths.push(home.join("Documents"));
                paths.push(home.join("Desktop"));
                paths.push(home.join("Downloads"));
                paths.push(home.join("Pictures"));
                paths.push(home.join("Movies"));
                paths.push(home.join("Music"));
            }
        }
        
        #[cfg(target_os = "windows")]
        {
            // Windows - Répertoires critiques
            if let Some(home) = dirs::home_dir() {
                paths.push(home.join("Documents"));
                paths.push(home.join("Desktop"));
                paths.push(home.join("Downloads"));
                paths.push(home.join("Pictures"));
                paths.push(home.join("Videos"));
                paths.push(home.join("Music"));
            }
            
            // Lecteurs système (C:\, D:\, etc.)
            for drive in 'C'..='Z' {
                let drive_path = PathBuf::from(format!("{}:\\", drive));
                if drive_path.exists() {
                    paths.push(drive_path);
                }
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            // Linux - Répertoires utilisateur
            if let Some(home) = dirs::home_dir() {
                paths.push(home.clone());
                paths.push(home.join("Documents"));
                paths.push(home.join("Downloads"));
                paths.push(home.join("Pictures"));
                paths.push(home.join("Videos"));
                paths.push(home.join("Music"));
            }
        }
        
        paths
    }
    
    /// Démarre le thread de traitement des événements
    fn start_event_processor(&self) {
        let Some(receiver) = self.event_receiver.as_ref() else {
            debug_log!("Event receiver non initialisé");
            return;
        };
        let receiver = receiver.clone();
        let stats = Arc::clone(&self.stats);
        let file_activities = Arc::clone(&self.file_activities);
        let suspicious_activities = Arc::clone(&self.suspicious_activities);
        let readonly_mode = Arc::clone(&self.readonly_mode);
        let monitoring_enabled = Arc::clone(&self.monitoring_enabled);
        let suspicious_extensions = self.suspicious_extensions.clone();
        
        thread::spawn(move || {
            debug_log!("🔄 Thread de surveillance démarré");
            
            loop {
                match receiver.recv_timeout(Duration::from_secs(1)) {
                    Ok(event) => {
                        // Vérifier si la surveillance est activée
                        if !*monitoring_enabled.lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner()) {
                            continue;
                        }
                        
                        Self::process_event(
                            event,
                            &stats,
                            &file_activities,
                            &suspicious_activities,
                            &readonly_mode,
                            &suspicious_extensions,
                        );
                    }
                    Err(_) => {
                        // Timeout normal, continuer
                        continue;
                    }
                }
            }
        });
    }
    
    /// Traite un événement de modification de fichier
    fn process_event(
        event: Event,
        stats: &Arc<Mutex<MonitoringStats>>,
        file_activities: &Arc<Mutex<HashMap<String, FileActivity>>>,
        suspicious_activities: &Arc<Mutex<Vec<SuspiciousActivity>>>,
        readonly_mode: &Arc<Mutex<bool>>,
        suspicious_extensions: &[String],
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();
        
        // Extraire les chemins affectés
        let paths: Vec<String> = event.paths.iter()
            .filter_map(|p| p.to_str().map(|s| s.to_string()))
            .collect();
        
        if paths.is_empty() {
            return;
        }
        
        // Mettre à jour les statistiques
        {
            let mut stats = stats.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            stats.total_events += 1;
            
            match event.kind {
                EventKind::Create(_) => stats.creations += 1,
                EventKind::Remove(_) => stats.deletions += 1,
                EventKind::Modify(notify::event::ModifyKind::Name(_)) => stats.renames += 1,
                EventKind::Modify(_) => stats.modifications += 1,
                _ => {}
            }
        }
        
        // Analyser chaque fichier affecté
        for path in paths {
            // 1. Vérifier l'extension
            if Self::has_suspicious_extension(&path, suspicious_extensions) {
                Self::record_threat(
                    &path,
                    ActivityType::SuspiciousExtension,
                    ThreatSeverity::Critical,
                    now,
                    stats,
                    suspicious_activities,
                    readonly_mode,
                );
                continue;
            }
            
            // 2. Suivre l'activité du fichier
            let mut activities = file_activities.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let activity = activities.entry(path.clone()).or_insert(FileActivity {
                path: path.clone(),
                last_modified: now,
                modification_count: 0,
                last_events: Vec::new(),
            });
            
            activity.modification_count += 1;
            activity.last_modified = now;
            activity.last_events.push(now);
            
            // Garder seulement les 20 derniers événements
            if activity.last_events.len() > 20 {
                activity.last_events.remove(0);
            }
            
            // 3. Détecter modifications rapides (>15 en 10 secondes)
            let recent_events: Vec<u64> = activity.last_events.iter()
                .filter(|&&t| now - t <= 10)
                .copied()
                .collect();
            
            if recent_events.len() > 15 {
                drop(activities); // Libérer le lock
                Self::record_threat(
                    &path,
                    ActivityType::RapidModification,
                    ThreatSeverity::High,
                    now,
                    stats,
                    suspicious_activities,
                    readonly_mode,
                );
            }
        }
        
        // 4. Détecter chiffrement massif (>30 fichiers modifiés en 30 secondes)
        Self::detect_mass_encryption(
            now,
            file_activities,
            stats,
            suspicious_activities,
            readonly_mode,
        );
    }
    
    /// Vérifie si un fichier a une extension suspecte
    fn has_suspicious_extension(path: &str, extensions: &[String]) -> bool {
        let path_lower = path.to_lowercase();
        extensions.iter().any(|ext| path_lower.ends_with(ext))
    }
    
    /// Enregistre une menace détectée
    fn record_threat(
        path: &str,
        activity_type: ActivityType,
        severity: ThreatSeverity,
        timestamp: u64,
        stats: &Arc<Mutex<MonitoringStats>>,
        suspicious_activities: &Arc<Mutex<Vec<SuspiciousActivity>>>,
        readonly_mode: &Arc<Mutex<bool>>,
    ) {
        let activity = SuspiciousActivity {
            file_path: path.to_string(),
            activity_type: activity_type.clone(),
            timestamp,
            severity: severity.clone(),
        };
        
        // Enregistrer l'activité suspecte
        {
            let mut activities = suspicious_activities.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            activities.push(activity.clone());
            
            // Garder seulement les 100 dernières
            if activities.len() > 100 {
                activities.remove(0);
            }
        }
        
        // Mettre à jour les stats
        {
            let mut stats = stats.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            
            match activity_type {
                ActivityType::SuspiciousExtension => stats.suspicious_extensions += 1,
                ActivityType::RapidModification => stats.rapid_changes += 1,
                _ => {}
            }
            
            // Ajouter à la liste des menaces actives
            let threat_desc = format!("{:?}: {}", activity_type, path);
            if !stats.active_threats.contains(&threat_desc) {
                stats.active_threats.push(threat_desc);
            }
            
            // Mettre à jour le niveau de menace
            stats.threat_level = match severity {
                ThreatSeverity::Critical => "CRITICAL".to_string(),
                ThreatSeverity::High if stats.threat_level != "CRITICAL" => "HIGH".to_string(),
                ThreatSeverity::Medium if stats.threat_level == "NONE" || stats.threat_level == "LOW" => "MEDIUM".to_string(),
                ThreatSeverity::Low if stats.threat_level == "NONE" => "LOW".to_string(),
                _ => stats.threat_level.clone(),
            };
        }
        
        // Activer le mode lecture seule si menace critique
        if severity == ThreatSeverity::Critical {
            let mut readonly = readonly_mode.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !*readonly {
                *readonly = true;
                debug_log!("🚨 MODE LECTURE SEULE ACTIVÉ - Menace ransomware détectée: {:?}", activity_type);
                debug_log!("   Fichier: {}", path);
                
                // SYNCHRONISER avec security_monitor en créant un runtime Tokio
                let monitor = get_security_monitor();
                let path_owned = path.to_string();
                let activity_type_owned = activity_type.clone();
                
                // Utiliser un runtime tokio pour l'appel async
                std::thread::spawn(move || {
                    let Ok(rt) = tokio::runtime::Runtime::new() else {
                        debug_log!("❌ Erreur création runtime Tokio");
                        return;
                    };
                    rt.block_on(async {
                        let _ = monitor.activate_readonly_for_ransomware(
                            &format!("Détection filesystem: {:?} - {}", activity_type_owned, path_owned)
                        ).await;
                    });
                });
            }
        }
    }
    
    /// Détecte un chiffrement massif de fichiers
    fn detect_mass_encryption(
        now: u64,
        file_activities: &Arc<Mutex<HashMap<String, FileActivity>>>,
        stats: &Arc<Mutex<MonitoringStats>>,
        suspicious_activities: &Arc<Mutex<Vec<SuspiciousActivity>>>,
        readonly_mode: &Arc<Mutex<bool>>,
    ) {
        let activities = file_activities.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        
        // Compter les fichiers modifiés récemment (30 dernières secondes)
        let recent_modifications = activities.values()
            .filter(|a| now - a.last_modified <= 30)
            .count();
        
        // Si >30 fichiers modifiés en 30s = probable ransomware
        if recent_modifications > 30 {
            drop(activities);
            Self::record_threat(
                &format!("{} fichiers", recent_modifications),
                ActivityType::MassEncryption,
                ThreatSeverity::Critical,
                now,
                stats,
                suspicious_activities,
                readonly_mode,
            );
        }
    }
    
    /// Retourne les statistiques actuelles
    pub fn get_stats(&self) -> MonitoringStats {
        self.stats.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
    
    /// Vérifie si le mode lecture seule est actif
    #[allow(dead_code)]
    pub fn is_readonly(&self) -> bool {
        *self.readonly_mode.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    
    /// Désactive le mode lecture seule
    pub fn disable_readonly(&self) {
        let mut readonly = self.readonly_mode.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *readonly = false;
        
        let mut stats = self.stats.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stats.threat_level = "NONE".to_string();
        stats.active_threats.clear();
        
        debug_log!("✅ Mode lecture seule désactivé");
    }
    
    /// Active la surveillance des fichiers
    pub fn enable_monitoring(&self) {
        let mut enabled = self.monitoring_enabled.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *enabled = true;
        
        let mut stats = self.stats.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stats.monitoring_enabled = true;
        
        debug_log!("🔍 Surveillance des fichiers ACTIVÉE");
    }
    
    /// Désactive la surveillance des fichiers
    pub fn disable_monitoring(&self) {
        let mut enabled = self.monitoring_enabled.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *enabled = false;
        
        let mut stats = self.stats.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stats.monitoring_enabled = false;
        
        debug_log!("⏸️  Surveillance des fichiers DÉSACTIVÉE");
    }
    
    /// Vérifie si la surveillance est active
    #[allow(dead_code)]
    pub fn is_monitoring_enabled(&self) -> bool {
        *self.monitoring_enabled.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    
    /// Réinitialise toutes les statistiques
    pub fn reset_stats(&self) {
        let mut stats = self.stats.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        stats.suspicious_extensions = 0;
        stats.rapid_changes = 0;
        stats.threat_level = "NONE".to_string();
        stats.active_threats.clear();
        
        let mut activities = self.file_activities.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        activities.clear();
        
        let mut suspicious = self.suspicious_activities.lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        suspicious.clear();
        
        debug_log!("🔄 Statistiques réinitialisées");
    }
}

// ========== SINGLETON GLOBAL (THREAD-SAFE) ==========

static FILESYSTEM_MONITOR: Lazy<Arc<Mutex<FilesystemMonitor>>> = Lazy::new(|| {
    let mut monitor = FilesystemMonitor::new();
    if let Err(e) = monitor.start_monitoring() {
        eprintln!("❌ Erreur démarrage surveillance: {}", e);
    }
    Arc::new(Mutex::new(monitor))
});

pub fn get_filesystem_monitor() -> Arc<Mutex<FilesystemMonitor>> {
    FILESYSTEM_MONITOR.clone()
}

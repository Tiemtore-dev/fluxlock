//! Bridge Python ML Engine pour la détection d'intrusion et d'anomalies
//! 
//! Ce module intègre le moteur ML Python dans Rust via PyO3 pour:
//! - Analyse comportementale des utilisateurs
//! - Détection d'anomalies avec Isolation Forest  
//! - Détection de patterns ransomware
//!
//! # Architecture
//! ```
//! Rust (Tauri) <--> PyO3 <--> Python ML Engine
//! ```

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Résultat d'analyse comportementale
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralScore {
    pub is_normal: bool,
    pub anomaly_score: f64,
    pub risk_level: String,  // "LOW", "MEDIUM", "HIGH"
    pub details: HashMap<String, String>,
}

/// Résultat de détection d'anomalie
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub is_anomaly: bool,
    pub confidence: f64,
    pub anomaly_type: String,
    pub recommendation: String,
}

/// Résultat de scan ransomware
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareScanResult {
    pub is_suspicious: bool,
    pub threat_level: f64,  // 0.0 - 1.0
    pub detected_patterns: Vec<String>,
    pub should_block: bool,
}

/// Moteur ML Python embedde
pub struct MLEngine {
    behavioral_analyzer: Py<PyAny>,
    anomaly_detector: Py<PyAny>,
    ransomware_detector: Py<PyAny>,
}

impl MLEngine {
    /// Initialise le moteur ML en chargeant les modules Python
    pub fn new() -> PyResult<Self> {
        // Initialiser l'interpréteur Python (requis avec abi3)
        pyo3::prepare_freethreaded_python();
        
        Python::with_gil(|py| {
            // Ajouter le chemin du python-ml-engine au sys.path
            let sys = py.import("sys")?;
            let path: &PyList = sys.getattr("path")?.downcast()?;
            
            // Chemin absolu vers python-ml-engine/src
            // Depuis tauri-desktop/src-tauri, remonter 2 niveaux puis aller à python-ml-engine/src
            let current_dir = std::env::current_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            let ml_engine_path = current_dir
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("python-ml-engine").join("src"))
                .and_then(|p| p.to_str().map(|s| s.to_string()))
                .unwrap_or_else(|| "../../python-ml-engine/src".to_string());
            
            println!("🐍 Ajout chemin ML Python: {}", ml_engine_path);
            path.call_method1("append", (ml_engine_path,))?;
            
            // Importer le module wrapper (API simplifiée)
            let ml_wrapper = py.import("ml_wrapper")?;
            
            // Créer les instances
            let behavioral_analyzer = ml_wrapper
                .getattr("BehavioralAnalyzer")?
                .call0()?
                .into();
            
            let anomaly_detector = ml_wrapper
                .getattr("AnomalyDetector")?
                .call0()?
                .into();
            
            let ransomware_detector = ml_wrapper
                .getattr("RansomwareDetector")?
                .call0()?
                .into();
            
            Ok(MLEngine {
                behavioral_analyzer,
                anomaly_detector,
                ransomware_detector,
            })
        })
    }
    
    /// Analyse le comportement d'un utilisateur
    ///
    /// # Arguments
    /// * `user_id` - ID de l'utilisateur
    /// * `action` - Action effectuée (login, password_access, file_upload, etc.)
    /// * `timestamp` - Timestamp Unix de l'action
    ///
    /// # Returns
    /// Score d'analyse comportementale
    pub fn analyze_behavior(
        &self,
        user_id: i64,
        action: &str,
        timestamp: i64,
    ) -> PyResult<BehavioralScore> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            // Convertir user_id en string pour l'API Python
            kwargs.set_item("user_id", format!("user_{}", user_id))?;
            kwargs.set_item("action", action)?;
            // Convertir timestamp en float pour l'API Python
            kwargs.set_item("timestamp", timestamp as f64)?;
            
            let result = self.behavioral_analyzer
                .as_ref(py)
                .call_method("analyze", (), Some(kwargs))?;
            
            // Le résultat est un dict Python, pas un objet
            let result_dict = result.downcast::<PyDict>()?;
            
            // Extraire les résultats du dict
            let is_normal: bool = result_dict.get_item("is_normal")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("is_normal not found"))?
                .extract()?;
            let anomaly_score: f64 = result_dict.get_item("anomaly_score")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("anomaly_score not found"))?
                .extract()?;
            let risk_level: String = result_dict.get_item("risk_level")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("risk_level not found"))?
                .extract()?;
            let details_str: String = result_dict.get_item("details")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("details not found"))?
                .extract()?;
            
            let mut details = HashMap::new();
            details.insert("message".to_string(), details_str);
            
            Ok(BehavioralScore {
                is_normal,
                anomaly_score,
                risk_level,
                details,
            })
        })
    }
    
    /// Détecte des anomalies dans les features d'activité
    ///
    /// # Arguments
    /// * `features` - Vecteur de features (temps d'accès, nombre d'actions, etc.)
    ///
    /// # Returns
    /// Résultat de détection d'anomalie
    pub fn detect_anomaly(&self, features: Vec<f64>) -> PyResult<AnomalyResult> {
        Python::with_gil(|py| {
            let py_features = PyList::new(py, &features);
            
            let result = self.anomaly_detector
                .as_ref(py)
                .call_method1("detect", (py_features,))?;
            
            // Le résultat est un dict Python
            let result_dict = result.downcast::<PyDict>()?;
            
            let is_anomaly: bool = result_dict.get_item("is_anomaly")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("is_anomaly not found"))?
                .extract()?;
            let confidence: f64 = result_dict.get_item("confidence")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("confidence not found"))?
                .extract()?;
            let anomaly_type: String = result_dict.get_item("anomaly_type")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("anomaly_type not found"))?
                .extract()?;
            let recommendation: String = result_dict.get_item("recommendation")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("recommendation not found"))?
                .extract()?;
            
            Ok(AnomalyResult {
                is_anomaly,
                confidence,
                anomaly_type,
                recommendation,
            })
        })
    }
    
    /// Scan un fichier pour détecter des patterns ransomware
    ///
    /// # Arguments
    /// * `filename` - Nom du fichier
    /// * `extension` - Extension du fichier
    /// * `file_size` - Taille en bytes
    ///
    /// # Returns
    /// Résultat du scan ransomware
    pub fn scan_for_ransomware(
        &self,
        filename: &str,
        extension: &str,
        file_size: u64,
    ) -> PyResult<RansomwareScanResult> {
        Python::with_gil(|py| {
            let kwargs = PyDict::new(py);
            kwargs.set_item("filename", filename)?;
            kwargs.set_item("extension", extension)?;
            kwargs.set_item("file_size", file_size)?;
            
            let result = self.ransomware_detector
                .as_ref(py)
                .call_method("scan", (), Some(kwargs))?;
            
            // Le résultat est un dict Python
            let result_dict = result.downcast::<PyDict>()?;
            
            let is_suspicious: bool = result_dict.get_item("is_suspicious")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("is_suspicious not found"))?
                .extract()?;
            let threat_level: f64 = result_dict.get_item("threat_level")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("threat_level not found"))?
                .extract()?;
            let should_block: bool = result_dict.get_item("should_block")?
                .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyKeyError, _>("should_block not found"))?
                .extract()?;
            
            let mut detected_patterns = Vec::new();
            if let Ok(Some(patterns_list)) = result_dict.get_item("detected_patterns") {
                if let Ok(list) = patterns_list.downcast::<PyList>() {
                    for item in list.iter() {
                        if let Ok(pattern) = item.extract::<String>() {
                            detected_patterns.push(pattern);
                        }
                    }
                }
            }
            
            Ok(RansomwareScanResult {
                is_suspicious,
                threat_level,
                detected_patterns,
                should_block,
            })
        })
    }
    
    /// Entraîne le modèle d'anomalie avec de nouvelles données
    ///
    /// # Arguments
    /// * `training_data` - Vecteur de vecteurs de features
    pub fn train_anomaly_model(&self, training_data: Vec<Vec<f64>>) -> PyResult<()> {
        Python::with_gil(|py| {
            let py_data = training_data
                .iter()
                .map(|row| PyList::new(py, row))
                .collect::<Vec<_>>();
            
            let py_training_data = PyList::new(py, py_data);
            
            self.anomaly_detector
                .as_ref(py)
                .call_method1("train", (py_training_data,))?;
            
            Ok(())
        })
    }
    
    /// Sauvegarde les modèles ML
    pub fn save_models(&self, output_dir: &str) -> PyResult<()> {
        Python::with_gil(|py| {
            // Sauvegarder le modèle d'anomalie
            self.anomaly_detector
                .as_ref(py)
                .call_method1("save_model", (output_dir,))?;
            
            Ok(())
        })
    }
    
    /// Charge les modèles ML depuis le disque
    pub fn load_models(&self, input_dir: &str) -> PyResult<()> {
        Python::with_gil(|py| {
            // Charger le modèle d'anomalie
            self.anomaly_detector
                .as_ref(py)
                .call_method1("load_model", (input_dir,))?;
            
            Ok(())
        })
    }
}

/// Singleton global pour le moteur ML
static mut ML_ENGINE: Option<MLEngine> = None;

/// Initialise le moteur ML global
pub fn initialize_ml_engine() -> Result<(), String> {
    unsafe {
        if ML_ENGINE.is_some() {
            return Ok(());
        }
        
        match MLEngine::new() {
            Ok(engine) => {
                ML_ENGINE = Some(engine);
                Ok(())
            }
            Err(e) => Err(format!("Failed to initialize ML engine: {}", e)),
        }
    }
}

/// Récupère une référence au moteur ML global
pub fn get_ml_engine() -> Result<&'static MLEngine, String> {
    unsafe {
        ML_ENGINE
            .as_ref()
            .ok_or_else(|| "ML engine not initialized. Call initialize_ml_engine() first.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[ignore]  // Nécessite Python et les modules installés
    fn test_ml_engine_initialization() {
        let engine = MLEngine::new();
        assert!(engine.is_ok(), "ML engine should initialize successfully");
    }
    
    #[test]
    #[ignore]
    fn test_behavioral_analysis() {
        let engine = MLEngine::new().unwrap();
        let result = engine.analyze_behavior(1, "login", 1699999999);
        assert!(result.is_ok(), "Behavioral analysis should work");
        
        let score = result.unwrap();
        assert!(score.anomaly_score >= 0.0 && score.anomaly_score <= 1.0);
    }
    
    #[test]
    #[ignore]
    fn test_anomaly_detection() {
        let engine = MLEngine::new().unwrap();
        let features = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let result = engine.detect_anomaly(features);
        assert!(result.is_ok(), "Anomaly detection should work");
    }
    
    #[test]
    #[ignore]
    fn test_ransomware_scan() {
        let engine = MLEngine::new().unwrap();
        let result = engine.scan_for_ransomware("test.exe.encrypted", "encrypted", 10240);
        assert!(result.is_ok(), "Ransomware scan should work");
        
        let scan = result.unwrap();
        assert!(scan.is_suspicious, "Should detect suspicious file");
    }
}

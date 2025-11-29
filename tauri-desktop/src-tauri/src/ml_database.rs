// ============================================
// MODULE ML DATABASE & COMPRESSION
// ============================================

use crate::config::Config;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sqlx::{SqlitePool, FromRow};
use std::io::{Read, Write};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MLUserProfile {
    pub id: Option<i64>,
    pub user_id: i64,
    pub profile_data: String,  // JSON
    pub last_updated: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MLModel {
    pub id: Option<i64>,
    pub model_name: String,
    pub model_data: Vec<u8>,  // Pickle bytes
    pub hyperparameters: Option<String>,  // JSON
    pub training_date: String,
    pub accuracy_score: Option<f64>,
    pub n_samples_trained: Option<i64>,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MLTrainingLog {
    pub id: Option<i64>,
    pub user_id: i64,
    pub action_type: String,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub timestamp: String,
    pub metadata: Option<String>,  // JSON
    pub risk_score: f64,
    pub is_anomaly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CompressedLog {
    pub id: Option<i64>,
    pub user_id: Option<i64>,
    pub compression_format: String,
    pub compressed_data: Vec<u8>,
    pub original_size_bytes: i64,
    pub compressed_size_bytes: i64,
    pub compression_ratio: f64,
    pub log_count: i64,
    pub start_date: String,
    pub end_date: String,
    pub created_at: String,
}

pub struct MLDatabaseService {
    pool: SqlitePool,
    config: Config,
}

impl MLDatabaseService {
    pub fn new(pool: SqlitePool, config: Config) -> Self {
        MLDatabaseService { pool, config }
    }
    
    // ========================================
    // PROFILS UTILISATEUR ML
    // ========================================
    
    /// Sauvegarder un profil ML utilisateur
    pub async fn save_user_profile(
        &self,
        user_id: i64,
        profile_data: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO ml_user_profiles (user_id, profile_data, last_updated, version)
            VALUES (?, ?, datetime('now'), '1.0')
            ON CONFLICT(user_id) DO UPDATE SET
                profile_data = excluded.profile_data,
                last_updated = datetime('now')
            "#
        )
        .bind(user_id)
        .bind(profile_data)
        .execute(&self.pool)
        .await?;
        
        println!("✅ Profil ML sauvegardé pour user {}", user_id);
        Ok(())
    }
    
    /// Charger un profil ML utilisateur
    pub async fn load_user_profile(
        &self,
        user_id: i64,
    ) -> Result<Option<MLUserProfile>, sqlx::Error> {
        let profile = sqlx::query_as::<_, MLUserProfile>(
            "SELECT * FROM ml_user_profiles WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(profile)
    }
    
    /// Charger tous les profils ML
    pub async fn load_all_profiles(&self) -> Result<Vec<MLUserProfile>, sqlx::Error> {
        let profiles = sqlx::query_as::<_, MLUserProfile>(
            "SELECT * FROM ml_user_profiles ORDER BY last_updated DESC"
        )
        .fetch_all(&self.pool)
        .await?;
        
        println!("📊 {} profils ML chargés", profiles.len());
        Ok(profiles)
    }
    
    // ========================================
    // MODÈLES ML
    // ========================================
    
    /// Sauvegarder un modèle ML
    pub async fn save_model(
        &self,
        model_name: &str,
        model_data: &[u8],
        hyperparameters: Option<&str>,
        n_samples: i64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO ml_models (model_name, model_data, hyperparameters, training_date, n_samples_trained, version)
            VALUES (?, ?, ?, datetime('now'), ?, '1.0')
            ON CONFLICT(model_name) DO UPDATE SET
                model_data = excluded.model_data,
                hyperparameters = excluded.hyperparameters,
                training_date = datetime('now'),
                n_samples_trained = excluded.n_samples_trained
            "#
        )
        .bind(model_name)
        .bind(model_data)
        .bind(hyperparameters)
        .bind(n_samples)
        .execute(&self.pool)
        .await?;
        
        println!("✅ Modèle ML '{}' sauvegardé ({} échantillons)", model_name, n_samples);
        Ok(())
    }
    
    /// Charger un modèle ML
    pub async fn load_model(&self, model_name: &str) -> Result<Option<MLModel>, sqlx::Error> {
        let model = sqlx::query_as::<_, MLModel>(
            "SELECT * FROM ml_models WHERE model_name = ? ORDER BY training_date DESC LIMIT 1"
        )
        .bind(model_name)
        .fetch_optional(&self.pool)
        .await?;
        
        Ok(model)
    }
    
    // ========================================
    // LOGS DE TRAINING
    // ========================================
    
    /// Ajouter un log pour le training ML
    pub async fn add_training_log(
        &self,
        user_id: i64,
        action_type: &str,
        resource_type: &str,
        resource_id: Option<i64>,
        metadata: Option<&str>,
        risk_score: f64,
        is_anomaly: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO ml_training_logs 
            (user_id, action_type, resource_type, resource_id, timestamp, metadata, risk_score, is_anomaly)
            VALUES (?, ?, ?, ?, datetime('now'), ?, ?, ?)
            "#
        )
        .bind(user_id)
        .bind(action_type)
        .bind(resource_type)
        .bind(resource_id)
        .bind(metadata)
        .bind(risk_score)
        .bind(is_anomaly)
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Récupérer les logs pour training (X derniers jours)
    pub async fn get_training_logs(
        &self,
        user_id: Option<i64>,
    ) -> Result<Vec<MLTrainingLog>, sqlx::Error> {
        let days = self.config.ml_training_retention_days;
        
        let logs = if let Some(uid) = user_id {
            sqlx::query_as::<_, MLTrainingLog>(
                r#"
                SELECT * FROM ml_training_logs
                WHERE user_id = ? AND timestamp > datetime('now', ? || ' days')
                ORDER BY timestamp DESC
                "#
            )
            .bind(uid)
            .bind(format!("-{}", days))
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, MLTrainingLog>(
                r#"
                SELECT * FROM ml_training_logs
                WHERE timestamp > datetime('now', ? || ' days')
                ORDER BY timestamp DESC
                "#
            )
            .bind(format!("-{}", days))
            .fetch_all(&self.pool)
            .await?
        };
        
        Ok(logs)
    }
    
    /// Compter les logs disponibles pour training
    pub async fn count_training_logs(&self, user_id: Option<i64>) -> Result<i64, sqlx::Error> {
        let days = self.config.ml_training_retention_days;
        
        let count: (i64,) = if let Some(uid) = user_id {
            sqlx::query_as(
                "SELECT COUNT(*) FROM ml_training_logs WHERE user_id = ? AND timestamp > datetime('now', ? || ' days')"
            )
            .bind(uid)
            .bind(format!("-{}", days))
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                "SELECT COUNT(*) FROM ml_training_logs WHERE timestamp > datetime('now', ? || ' days')"
            )
            .bind(format!("-{}", days))
            .fetch_one(&self.pool)
            .await?
        };
        
        Ok(count.0)
    }
    
    // ========================================
    // COMPRESSION DES LOGS
    // ========================================
    
    /// Compresser les logs anciens
    pub async fn compress_old_logs(&self, user_id: Option<i64>) -> Result<CompressedLog, String> {
        let days = self.config.log_compression_after_days;
        
        // Récupérer les logs à compresser
        let logs: Vec<MLTrainingLog> = if let Some(uid) = user_id {
            sqlx::query_as(
                r#"
                SELECT * FROM ml_training_logs
                WHERE user_id = ? AND timestamp < datetime('now', ? || ' days')
                ORDER BY timestamp
                "#
            )
            .bind(uid)
            .bind(format!("-{}", days))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("Erreur récupération logs: {}", e))?
        } else {
            sqlx::query_as(
                r#"
                SELECT * FROM ml_training_logs
                WHERE timestamp < datetime('now', ? || ' days')
                ORDER BY timestamp
                "#
            )
            .bind(format!("-{}", days))
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("Erreur récupération logs: {}", e))?
        };
        
        if logs.is_empty() {
            return Err("Aucun log à compresser".to_string());
        }
        
        // Sérialiser en JSON
        let json_data = serde_json::to_string(&logs)
            .map_err(|e| format!("Erreur sérialisation: {}", e))?;
        
        let original_size = json_data.len() as i64;
        
        // Compresser
        let compressed_data = match self.config.log_compression_format.as_str() {
            "gzip" => self.compress_gzip(json_data.as_bytes())?,
            _ => return Err(format!("Format '{}' non supporté", self.config.log_compression_format)),
        };
        
        let compressed_size = compressed_data.len() as i64;
        let ratio = compressed_size as f64 / original_size as f64;
        
        // Dates
        let start_date = logs.first().unwrap().timestamp.clone();
        let end_date = logs.last().unwrap().timestamp.clone();
        
        // Sauvegarder l'archive
        sqlx::query(
            r#"
            INSERT INTO compressed_logs 
            (user_id, compression_format, compressed_data, original_size_bytes, compressed_size_bytes, 
             compression_ratio, log_count, start_date, end_date, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            "#
        )
        .bind(user_id)
        .bind(&self.config.log_compression_format)
        .bind(&compressed_data)
        .bind(original_size)
        .bind(compressed_size)
        .bind(ratio)
        .bind(logs.len() as i64)
        .bind(&start_date)
        .bind(&end_date)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Erreur sauvegarde archive: {}", e))?;
        
        // Supprimer les logs compressés si configuré
        if self.config.log_delete_after_compression {
            let ids: Vec<i64> = logs.iter().filter_map(|l| l.id).collect();
            
            for id in ids {
                sqlx::query("DELETE FROM ml_training_logs WHERE id = ?")
                    .bind(id)
                    .execute(&self.pool)
                    .await
                    .ok();
            }
            
            println!("🗑️  {} logs supprimés après compression", logs.len());
        }
        
        println!(
            "✅ {} logs compressés : {} bytes → {} bytes ({:.1}%)",
            logs.len(), original_size, compressed_size, ratio * 100.0
        );
        
        Ok(CompressedLog {
            id: None,
            user_id,
            compression_format: self.config.log_compression_format.clone(),
            compressed_data,
            original_size_bytes: original_size,
            compressed_size_bytes: compressed_size,
            compression_ratio: ratio,
            log_count: logs.len() as i64,
            start_date,
            end_date,
            created_at: chrono::Utc::now().to_rfc3339(),
        })
    }
    
    /// Décompresser une archive de logs
    pub async fn decompress_logs(&self, archive_id: i64) -> Result<Vec<MLTrainingLog>, String> {
        let archive: CompressedLog = sqlx::query_as(
            "SELECT * FROM compressed_logs WHERE id = ?"
        )
        .bind(archive_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| format!("Archive non trouvée: {}", e))?;
        
        // Décompresser
        let json_data = match archive.compression_format.as_str() {
            "gzip" => self.decompress_gzip(&archive.compressed_data)?,
            _ => return Err(format!("Format '{}' non supporté", archive.compression_format)),
        };
        
        // Désérialiser
        let logs: Vec<MLTrainingLog> = serde_json::from_str(&json_data)
            .map_err(|e| format!("Erreur désérialisation: {}", e))?;
        
        println!("✅ {} logs décompressés depuis archive {}", logs.len(), archive_id);
        
        Ok(logs)
    }
    
    /// Compresser avec gzip
    fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut encoder = GzEncoder::new(
            Vec::new(),
            Compression::new(self.config.log_compression_level as u32)
        );
        
        encoder.write_all(data)
            .map_err(|e| format!("Erreur compression: {}", e))?;
        
        encoder.finish()
            .map_err(|e| format!("Erreur finalisation: {}", e))
    }
    
    /// Décompresser avec gzip
    fn decompress_gzip(&self, data: &[u8]) -> Result<String, String> {
        let mut decoder = GzDecoder::new(data);
        let mut result = String::new();
        
        decoder.read_to_string(&mut result)
            .map_err(|e| format!("Erreur décompression: {}", e))?;
        
        Ok(result)
    }
    
    /// Obtenir statistiques de compression
    pub async fn get_compression_stats(&self, user_id: Option<i64>) -> Result<CompressionStats, sqlx::Error> {
        let stats: CompressionStats = if let Some(uid) = user_id {
            sqlx::query_as(
                "SELECT * FROM compression_stats WHERE user_id = ?"
            )
            .bind(uid)
            .fetch_one(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT 
                    NULL as user_id,
                    SUM(archive_count) as archive_count,
                    SUM(total_logs_archived) as total_logs_archived,
                    SUM(total_original_bytes) as total_original_bytes,
                    SUM(total_compressed_bytes) as total_compressed_bytes,
                    AVG(avg_compression_ratio) as avg_compression_ratio,
                    MIN(oldest_log) as oldest_log,
                    MAX(newest_log) as newest_log
                FROM compression_stats
                "#
            )
            .fetch_one(&self.pool)
            .await?
        };
        
        Ok(stats)
    }
}

#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct CompressionStats {
    pub user_id: Option<i64>,
    pub archive_count: i64,
    pub total_logs_archived: i64,
    pub total_original_bytes: i64,
    pub total_compressed_bytes: i64,
    pub avg_compression_ratio: f64,
    pub oldest_log: String,
    pub newest_log: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_gzip_compression() {
        let config = Config::default();
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let service = MLDatabaseService::new(pool, config);
        
        let original = b"Test data to compress";
        let compressed = service.compress_gzip(original).unwrap();
        let decompressed = service.decompress_gzip(&compressed).unwrap();
        
        assert_eq!(decompressed, String::from_utf8_lossy(original));
        assert!(compressed.len() < original.len());
    }
}

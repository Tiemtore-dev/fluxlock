-- ============================================
-- MIGRATION: ML EN BASE DE DONNÉES + COMPRESSION
-- ============================================

-- 1. Table pour les profils ML utilisateur
CREATE TABLE IF NOT EXISTS ml_user_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    profile_data TEXT NOT NULL,  -- JSON contenant toutes les stats comportementales
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    version TEXT DEFAULT '1.0',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_ml_profiles_user ON ml_user_profiles(user_id);
CREATE INDEX idx_ml_profiles_updated ON ml_user_profiles(last_updated);

-- 2. Table pour les modèles ML sérialisés
CREATE TABLE IF NOT EXISTS ml_models (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_name TEXT NOT NULL UNIQUE,  -- 'isolation_forest', 'behavioral_analyzer', etc.
    model_data BLOB NOT NULL,  -- Modèle sérialisé (pickle)
    hyperparameters TEXT,  -- JSON des hyperparamètres
    training_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    accuracy_score REAL,
    n_samples_trained INTEGER,
    version TEXT DEFAULT '1.0'
);

CREATE INDEX idx_ml_models_name ON ml_models(model_name);
CREATE INDEX idx_ml_models_date ON ml_models(training_date);

-- 3. Table pour les logs actifs (utilisés pour training)
-- Les logs de action_logs sont conservés ML_TRAINING_RETENTION_DAYS jours
CREATE TABLE IF NOT EXISTS ml_training_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT,  -- JSON avec IP, device, etc.
    risk_score REAL DEFAULT 0.0,
    is_anomaly BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_ml_training_user ON ml_training_logs(user_id);
CREATE INDEX idx_ml_training_timestamp ON ml_training_logs(timestamp);
CREATE INDEX idx_ml_training_anomaly ON ml_training_logs(is_anomaly);

-- 4. Table pour les logs compressés (archives)
CREATE TABLE IF NOT EXISTS compressed_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    compression_format TEXT NOT NULL,  -- 'gzip', 'zstd', 'brotli'
    compressed_data BLOB NOT NULL,  -- Logs compressés
    original_size_bytes INTEGER NOT NULL,
    compressed_size_bytes INTEGER NOT NULL,
    compression_ratio REAL,
    log_count INTEGER NOT NULL,  -- Nombre de logs dans l'archive
    start_date DATETIME NOT NULL,
    end_date DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_compressed_user ON compressed_logs(user_id);
CREATE INDEX idx_compressed_dates ON compressed_logs(start_date, end_date);

-- 5. Table de métriques ML (pour monitoring)
CREATE TABLE IF NOT EXISTS ml_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    metric_type TEXT NOT NULL,  -- 'training', 'prediction', 'anomaly_rate'
    metric_value REAL NOT NULL,
    metadata TEXT,  -- JSON
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ml_metrics_type ON ml_metrics(metric_type);
CREATE INDEX idx_ml_metrics_date ON ml_metrics(recorded_at);

-- 6. Ajouter colonnes 2FA au users (si pas déjà fait)
ALTER TABLE users ADD COLUMN two_factor_method TEXT DEFAULT 'both';  -- 'totp', 'email', 'both'
ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN last_2fa_at DATETIME;

-- 7. Vue pour logs récents (non-compressés)
CREATE VIEW IF NOT EXISTS recent_activity AS
SELECT 
    u.username,
    l.action_type,
    l.resource_type,
    l.timestamp,
    l.risk_score,
    l.is_anomaly
FROM ml_training_logs l
JOIN users u ON l.user_id = u.id
WHERE l.timestamp > datetime('now', '-30 days')
ORDER BY l.timestamp DESC;

-- 8. Vue pour statistiques de compression
CREATE VIEW IF NOT EXISTS compression_stats AS
SELECT 
    user_id,
    COUNT(*) as archive_count,
    SUM(log_count) as total_logs_archived,
    SUM(original_size_bytes) as total_original_bytes,
    SUM(compressed_size_bytes) as total_compressed_bytes,
    ROUND(AVG(compression_ratio), 2) as avg_compression_ratio,
    MIN(start_date) as oldest_log,
    MAX(end_date) as newest_log
FROM compressed_logs
GROUP BY user_id;

-- 9. Trigger pour auto-archiver les vieux logs
CREATE TRIGGER IF NOT EXISTS auto_log_training_retention
AFTER INSERT ON ml_training_logs
BEGIN
    -- Marquer les logs anciens pour compression (sera géré par Rust)
    UPDATE ml_training_logs
    SET metadata = json_set(COALESCE(metadata, '{}'), '$.marked_for_compression', 1)
    WHERE timestamp < datetime('now', '-90 days')
    AND metadata IS NULL OR json_extract(metadata, '$.marked_for_compression') IS NULL;
END;

-- 10. Fonction pour obtenir les logs pour training
-- (à utiliser dans le code Rust)
CREATE VIEW IF NOT EXISTS ml_training_data AS
SELECT 
    user_id,
    action_type,
    resource_type,
    timestamp,
    metadata,
    risk_score,
    is_anomaly,
    julianday('now') - julianday(timestamp) as days_ago
FROM ml_training_logs
WHERE timestamp > datetime('now', '-30 days')
ORDER BY timestamp DESC;

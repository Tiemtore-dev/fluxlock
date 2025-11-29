-- Script SQL pour insérer des logs de test dans audit_logs
-- À exécuter si aucun événement ne s'affiche

-- Logs de connexion
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, created_at)
VALUES 
  (1, 'LOGIN', 'session', NULL, datetime('now', '-5 minutes')),
  (1, 'LOGIN', 'session', NULL, datetime('now', '-2 hours')),
  (1, 'LOGIN', 'session', NULL, datetime('now', '-1 day'));

-- Logs de création de mots de passe
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, created_at)
VALUES 
  (1, 'CREATE', 'password', 1, datetime('now', '-30 minutes')),
  (1, 'CREATE', 'password', 2, datetime('now', '-1 hour')),
  (1, 'CREATE', 'password', 3, datetime('now', '-3 hours'));

-- Logs d'accès aux fichiers
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, created_at)
VALUES 
  (1, 'ACCESS', 'file', 1, datetime('now', '-15 minutes')),
  (1, 'ACCESS', 'file', 2, datetime('now', '-45 minutes'));

-- Logs de création de clés
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, created_at)
VALUES 
  (1, 'CREATE', 'key', 1, datetime('now', '-20 minutes')),
  (1, 'CREATE', 'key', 2, datetime('now', '-2 hours'));

-- Logs de mise à jour
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, created_at)
VALUES 
  (1, 'UPDATE', 'password', 1, datetime('now', '-10 minutes')),
  (1, 'UPDATE', 'password', 2, datetime('now', '-1 hour'));

-- Logs de suppression
INSERT INTO audit_logs (user_id, action, resource_type, resource_id, created_at)
VALUES 
  (1, 'DELETE', 'password', 4, datetime('now', '-5 hours')),
  (1, 'DELETE', 'file', 3, datetime('now', '-1 day'));

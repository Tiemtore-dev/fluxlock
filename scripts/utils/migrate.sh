#!/bin/bash
# ============================================
# MIGRATION ML → BASE DE DONNÉES
# Script automatique de migration
# ============================================

set -e  # Arrêter en cas d'erreur

echo "🚀 MIGRATION SECUREVAULT v2.0 → v2.1"
echo "===================================="
echo ""

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Répertoire racine
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$SCRIPT_DIR"

echo -e "${YELLOW}📁 Répertoire racine: $ROOT_DIR${NC}"
echo ""

# ============================================
# 1. VÉRIFIER PRÉREQUIS
# ============================================

echo "1️⃣  Vérification des prérequis..."

if ! command -v sqlite3 &> /dev/null; then
    echo -e "${RED}❌ sqlite3 non installé${NC}"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo -e "${RED}❌ cargo non installé${NC}"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ python3 non installé${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Tous les prérequis sont installés${NC}"
echo ""

# ============================================
# 2. BACKUP BASE DE DONNÉES
# ============================================

echo "2️⃣  Backup de la base de données..."

DB_PATH="$ROOT_DIR/database/secure_vault.db"
BACKUP_PATH="$ROOT_DIR/database/secure_vault_backup_$(date +%Y%m%d_%H%M%S).db"

if [ -f "$DB_PATH" ]; then
    cp "$DB_PATH" "$BACKUP_PATH"
    echo -e "${GREEN}✅ Backup créé: $BACKUP_PATH${NC}"
else
    echo -e "${YELLOW}⚠️  Base de données inexistante, sera créée${NC}"
fi
echo ""

# ============================================
# 3. APPLIQUER MIGRATION SQL
# ============================================

echo "3️⃣  Application de la migration SQL..."

MIGRATION_SQL="$ROOT_DIR/database/migrations/003_ml_storage.sql"

if [ ! -f "$MIGRATION_SQL" ]; then
    echo -e "${RED}❌ Fichier de migration non trouvé: $MIGRATION_SQL${NC}"
    exit 1
fi

sqlite3 "$DB_PATH" < "$MIGRATION_SQL"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Migration SQL appliquée avec succès${NC}"
else
    echo -e "${RED}❌ Erreur lors de la migration SQL${NC}"
    echo "Restauration du backup..."
    cp "$BACKUP_PATH" "$DB_PATH"
    exit 1
fi
echo ""

# ============================================
# 4. MIGRER PROFILS ML (JSON → DB)
# ============================================

echo "4️⃣  Migration des profils ML..."

PROFILES_DIR="$ROOT_DIR/python-ml-engine/ml_profiles"
MODELS_DIR="$ROOT_DIR/python-ml-engine/ml_models"

if [ -d "$PROFILES_DIR" ] && [ "$(ls -A $PROFILES_DIR)" ]; then
    echo "   Profils JSON détectés, migration en cours..."
    
    # Créer script Python de migration
    cat > /tmp/migrate_ml.py << 'EOF'
import sqlite3
import json
import os
import sys
from pathlib import Path

def migrate_profiles_to_db(db_path, profiles_dir):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    migrated = 0
    
    for profile_file in Path(profiles_dir).glob("user_*.json"):
        try:
            with open(profile_file, 'r') as f:
                profile_data = json.load(f)
            
            user_id = profile_data.get('user_id')
            
            if user_id:
                cursor.execute("""
                    INSERT INTO ml_user_profiles (user_id, profile_data, last_updated, version)
                    VALUES (?, ?, datetime('now'), '1.0')
                    ON CONFLICT(user_id) DO UPDATE SET
                        profile_data = excluded.profile_data,
                        last_updated = datetime('now')
                """, (user_id, json.dumps(profile_data)))
                
                migrated += 1
                print(f"✅ Profil user {user_id} migré")
        except Exception as e:
            print(f"⚠️  Erreur migration {profile_file}: {e}")
    
    conn.commit()
    conn.close()
    
    return migrated

if __name__ == "__main__":
    db_path = sys.argv[1]
    profiles_dir = sys.argv[2]
    
    count = migrate_profiles_to_db(db_path, profiles_dir)
    print(f"\n✅ {count} profils migrés vers la base de données")
EOF

    python3 /tmp/migrate_ml.py "$DB_PATH" "$PROFILES_DIR"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Profils ML migrés${NC}"
        
        # Archiver les anciens fichiers
        ARCHIVE_DIR="$PROFILES_DIR/../ml_profiles_archived_$(date +%Y%m%d)"
        mv "$PROFILES_DIR" "$ARCHIVE_DIR"
        echo "   Anciens profils archivés dans: $ARCHIVE_DIR"
    else
        echo -e "${YELLOW}⚠️  Erreur migration profils${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Aucun profil ML à migrer${NC}"
fi
echo ""

# ============================================
# 5. CRÉER .env
# ============================================

echo "5️⃣  Configuration .env..."

ENV_FILE="$ROOT_DIR/.env"
ENV_EXAMPLE="$ROOT_DIR/.env.example"

if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
        cp "$ENV_EXAMPLE" "$ENV_FILE"
        echo -e "${GREEN}✅ .env créé depuis .env.example${NC}"
        echo -e "${YELLOW}⚠️  IMPORTANT: Éditer .env et configurer:${NC}"
        echo "   - EMAIL_SMTP_USERNAME"
        echo "   - EMAIL_SMTP_PASSWORD"
    else
        echo -e "${RED}❌ .env.example non trouvé${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  .env existe déjà${NC}"
fi
echo ""

# ============================================
# 6. COMPILER RUST
# ============================================

echo "6️⃣  Compilation du backend Rust..."

cd "$ROOT_DIR/tauri-desktop/src-tauri"

# Vérifier la compilation
cargo check

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Compilation vérifiée${NC}"
    
    # Compiler en release
    echo "   Compilation release en cours..."
    cargo build --release
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Build release réussi${NC}"
    else
        echo -e "${YELLOW}⚠️  Build release échoué (check OK quand même)${NC}"
    fi
else
    echo -e "${RED}❌ Erreur de compilation${NC}"
    exit 1
fi
echo ""

# ============================================
# 7. VÉRIFIER INSTALLATION
# ============================================

echo "7️⃣  Vérification de l'installation..."

# Vérifier tables
TABLES=$(sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ml_%';")

if echo "$TABLES" | grep -q "ml_user_profiles"; then
    echo -e "${GREEN}✅ Table ml_user_profiles créée${NC}"
else
    echo -e "${RED}❌ Table ml_user_profiles manquante${NC}"
fi

if echo "$TABLES" | grep -q "ml_models"; then
    echo -e "${GREEN}✅ Table ml_models créée${NC}"
else
    echo -e "${RED}❌ Table ml_models manquante${NC}"
fi

if echo "$TABLES" | grep -q "ml_training_logs"; then
    echo -e "${GREEN}✅ Table ml_training_logs créée${NC}"
else
    echo -e "${RED}❌ Table ml_training_logs manquante${NC}"
fi

if echo "$TABLES" | grep -q "compressed_logs"; then
    echo -e "${GREEN}✅ Table compressed_logs créée${NC}"
else
    echo -e "${RED}❌ Table compressed_logs manquante${NC}"
fi

echo ""

# ============================================
# 8. RÉCAPITULATIF
# ============================================

echo ""
echo "=========================================="
echo "✅ MIGRATION TERMINÉE"
echo "=========================================="
echo ""
echo "📊 Résumé:"
echo "   - Base de données: $DB_PATH"
echo "   - Backup: $BACKUP_PATH"
echo "   - Configuration: $ENV_FILE"
echo ""
echo "⚠️  Actions requises:"
echo "   1. Éditer .env et configurer EMAIL_SMTP_USERNAME et EMAIL_SMTP_PASSWORD"
echo "   2. Lancer l'application: cd tauri-desktop && npm run tauri:dev"
echo "   3. Tester 2FA et compression des logs"
echo ""
echo "📚 Documentation:"
echo "   - SYSTEM_ML_2FA_COMPRESSION.md"
echo "   - GUIDE_DEMARRAGE_RAPIDE.md"
echo ""

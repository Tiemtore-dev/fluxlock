#!/bin/bash

# Script de démarrage complet pour SecureVault
# Ce script lance tous les services nécessaires

set -e

echo "🔐 Démarrage de SecureVault..."

# Couleurs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

PROJECT_ROOT="/Users/tiemtorefahim/Desktop/Projet coffre fort/secure-vault-next-gen"

# Vérifier que nous sommes dans le bon répertoire
cd "$PROJECT_ROOT"

# Fonction pour vérifier si un port est utilisé
check_port() {
    lsof -i :$1 >/dev/null 2>&1
}

# Fonction pour attendre qu'un service soit prêt
wait_for_service() {
    local url=$1
    local name=$2
    echo -e "${YELLOW}⏳ Attente de $name...${NC}"
    until curl -s -f -o /dev/null "$url"; do
        sleep 1
    done
    echo -e "${GREEN}✓ $name est prêt${NC}"
}

# 1. Démarrer l'API Go
echo -e "\n${YELLOW}1. Démarrage de l'API Go...${NC}"
if check_port 8080; then
    echo -e "${GREEN}✓ API Go déjà en cours d'exécution${NC}"
else
    cd go-api-server
    go run cmd/server/main.go &
    API_PID=$!
    cd ..
    echo -e "${GREEN}✓ API Go démarrée (PID: $API_PID)${NC}"
    wait_for_service "http://localhost:8080/api/v1/health" "API Go"
fi

# 2. Démarrer le moteur ML Python
echo -e "\n${YELLOW}2. Démarrage du moteur ML Python...${NC}"
if check_port 8000; then
    echo -e "${GREEN}✓ ML Engine déjà en cours d'exécution${NC}"
else
    cd python-ml-engine
    if [ ! -d "venv" ]; then
        echo "Création de l'environnement virtuel..."
        python3 -m venv venv
        source venv/bin/activate
        pip install -r requirements.txt
    else
        source venv/bin/activate
    fi
    python src/main.py &
    ML_PID=$!
    deactivate
    cd ..
    echo -e "${GREEN}✓ ML Engine démarré (PID: $ML_PID)${NC}"
    wait_for_service "http://localhost:8000/health" "ML Engine"
fi

# 3. Démarrer l'application Tauri
echo -e "\n${YELLOW}3. Démarrage de l'application Tauri...${NC}"
cd tauri-desktop
npm run tauri:dev

echo -e "\n${GREEN}🎉 SecureVault est maintenant lancé !${NC}"

#!/bin/bash

# Script de test complet pour SecureVault Next-Gen
set -e

# Couleurs
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🧪 Tests SecureVault Next-Gen"
echo "=============================="

# Fonction pour afficher le résultat
check_result() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $1${NC}"
    else
        echo -e "${RED}✗ $1${NC}"
        exit 1
    fi
}

# 1. Tests Rust Crypto Core
echo -e "\n${YELLOW}1. Tests Rust Crypto Core${NC}"
cd rust-crypto-core
cargo test --release
check_result "Tests Rust réussis"
cd ..

# 2. Tests Go API
echo -e "\n${YELLOW}2. Tests Go API${NC}"
cd go-api-server
go test ./... -v
check_result "Tests Go réussis"
cd ..

# 3. Tests Python ML
echo -e "\n${YELLOW}3. Tests Python ML Engine${NC}"
cd python-ml-engine
if [ -d "venv" ]; then
    source venv/bin/activate
else
    python3 -m venv venv
    source venv/bin/activate
    pip install -q -r requirements.txt
fi
pip install -q pytest
pytest
check_result "Tests Python réussis"
deactivate
cd ..

echo -e "\n${GREEN}=============================="
echo -e "✓ TOUS LES TESTS RÉUSSIS${NC}"

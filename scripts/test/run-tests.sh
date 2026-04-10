#!/bin/bash
# Script de test pour les modules database, compression, ML, config

cd "$(dirname "$0")/tauri-desktop/src-tauri"

echo "🧪 Exécution des tests SecureVault v2.1.1"
echo "============================================"
echo ""

echo "📊 Test 1: Base de données unifiée"
cargo test --test test_database_unified --no-fail-fast -- --test-threads=1 --nocapture

echo ""
echo "📦 Test 2: Compression des logs"
cargo test --test test_compression --no-fail-fast -- --test-threads=1 --nocapture

echo ""
echo "🤖 Test 3: Opérations ML"
cargo test --test test_ml_operations --no-fail-fast -- --test-threads=1 --nocapture

echo ""
echo "⚙️  Test 4: Configuration"
cargo test --test test_config --no-fail-fast -- --test-threads=1 --nocapture

echo ""
echo "============================================"
echo "✅ Tests terminés"

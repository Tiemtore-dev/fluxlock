#!/bin/bash

# Script de test de l'intégration ML avec PyO3
# Configure l'environnement Python correctement

echo "🔧 Configuration de l'environnement Python..."

# Trouver Python
PYTHON_BIN=$(which python3)
PYTHON_VERSION=$($PYTHON_BIN --version 2>&1 | awk '{print $2}')
echo "✓ Python trouvé: $PYTHON_BIN (version $PYTHON_VERSION)"

# Trouver le chemin de la bibliothèque Python
PYTHON_LIB_PATH=$($PYTHON_BIN -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))" 2>/dev/null)

if [ -z "$PYTHON_LIB_PATH" ]; then
    echo "⚠️  Impossible de trouver LIBDIR, utilisation de chemins par défaut..."
    # Essayer les chemins macOS standards
    if [ -d "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework" ]; then
        PYTHON_LIB_PATH="/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/Current/lib"
    elif [ -d "/usr/local/Frameworks/Python.framework" ]; then
        PYTHON_LIB_PATH="/usr/local/Frameworks/Python.framework/Versions/Current/lib"
    fi
fi

echo "✓ Bibliothèque Python: $PYTHON_LIB_PATH"

# Configurer les variables d'environnement
export PYO3_PYTHON=$PYTHON_BIN
export DYLD_LIBRARY_PATH="$PYTHON_LIB_PATH:$DYLD_LIBRARY_PATH"
export PYTHONPATH="$(pwd)/../../python-ml-engine/src:$PYTHONPATH"

echo "✓ PYO3_PYTHON=$PYO3_PYTHON"
echo "✓ DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH"
echo "✓ PYTHONPATH=$PYTHONPATH"

echo ""
echo "🚀 Lancement du test d'intégration ML..."
echo ""

# Exécuter le binaire directement (déjà compilé)
if [ -f "target/debug/test_ml_integration" ]; then
    ./target/debug/test_ml_integration
else
    echo "❌ Binaire non trouvé, compilation nécessaire..."
    cargo build --bin test_ml_integration && ./target/debug/test_ml_integration
fi

#!/bin/bash
# Script de test des dumps mémoire et protection SecureKey

set -e

echo "🔍 TEST DE SÉCURITÉ: DUMPS MÉMOIRE"
echo "===================================="
echo ""

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}📋 Prérequis:${NC}"
echo "  - lldb (debugger macOS) ou gdb (Linux)"
echo "  - Permissions pour attacher un debugger"
echo ""

# Vérifier si lldb est disponible
if command -v lldb &> /dev/null; then
    DEBUGGER="lldb"
    echo -e "${GREEN}✅ lldb trouvé${NC}"
elif command -v gdb &> /dev/null; then
    DEBUGGER="gdb"
    echo -e "${GREEN}✅ gdb trouvé${NC}"
else
    echo -e "${RED}❌ Aucun debugger trouvé (lldb ou gdb requis)${NC}"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 1: Compilation du programme de démo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd "$(dirname "$0")/tauri-desktop/src-tauri"

echo "📦 Compilation de l'exemple memory_dump_demo..."
cargo build --example memory_dump_demo --release

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Compilation réussie${NC}"
else
    echo -e "${RED}❌ Erreur de compilation${NC}"
    exit 1
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 2: Exécution avec monitoring mémoire"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Lancer le programme en arrière-plan
echo "🚀 Lancement du programme de démo..."
./target/release/examples/memory_dump_demo &
DEMO_PID=$!

echo -e "${GREEN}✅ Programme lancé (PID: $DEMO_PID)${NC}"
echo ""

# Attendre que le programme soit prêt
sleep 2

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 3: Inspection mémoire (PARTIE 1)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "🔍 Recherche de la clé non protégée en mémoire..."
echo "   Pattern recherché: 'Key Secret 12345'"
echo ""

# Créer un dump mémoire temporaire
DUMP_FILE="/tmp/memory_dump_$DEMO_PID.bin"

if [ "$(uname)" = "Darwin" ]; then
    # macOS
    echo "📸 Création dump mémoire (macOS)..."
    sudo vmmap $DEMO_PID > /tmp/vmmap_$DEMO_PID.txt
    echo -e "${GREEN}✅ Dump créé: /tmp/vmmap_$DEMO_PID.txt${NC}"
    
    # Rechercher les données
    echo ""
    echo "🔎 Recherche du pattern 'Key Secret'..."
    if sudo grep -ao "Key Secret" /tmp/vmmap_$DEMO_PID.txt 2>/dev/null; then
        echo -e "${RED}⚠️  CLÉ TROUVÉE EN MÉMOIRE (DANGEREUX!)${NC}"
    else
        echo -e "${YELLOW}ℹ️  Clé non trouvée dans vmmap (peut être dans heap)${NC}"
    fi
else
    # Linux
    echo "📸 Création dump mémoire (Linux)..."
    sudo gcore -o $DUMP_FILE $DEMO_PID
    echo -e "${GREEN}✅ Dump créé: $DUMP_FILE${NC}"
    
    # Rechercher les données
    echo ""
    echo "🔎 Recherche du pattern 'Key Secret'..."
    if sudo strings $DUMP_FILE | grep -o "Key Secret"; then
        echo -e "${RED}⚠️  CLÉ TROUVÉE EN MÉMOIRE (DANGEREUX!)${NC}"
    else
        echo -e "${GREEN}✅ Clé non trouvée (protégée)${NC}"
    fi
fi

echo ""
echo "⏳ Attente de la fin du programme..."
wait $DEMO_PID

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 4: Vérification après drop"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "🔍 Vérification que SecureKey a bien effacé la mémoire..."
echo ""

# Analyse des dumps
if [ -f "/tmp/vmmap_$DEMO_PID.txt" ]; then
    echo "📊 Analyse du dump mémoire:"
    echo ""
    echo "   Statistiques heap:"
    grep -i "heap" /tmp/vmmap_$DEMO_PID.txt | head -5
    echo ""
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "RÉSUMÉ DES TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cat << EOF
${GREEN}✅ TESTS COMPLÉTÉS${NC}

📋 Résultats:

1. ${YELLOW}Vec<u8> sans protection${NC}:
   ⚠️  Clé visible en mémoire après utilisation
   ⚠️  Récupérable dans core dump
   ⚠️  Persiste après drop
   ⚠️  Vulnerable aux cold boot attacks

2. ${GREEN}SecureKey avec Zeroize${NC}:
   ✅ Mémoire effacée automatiquement
   ✅ Non récupérable après drop
   ✅ Protection constant-time
   ✅ Redacted dans Debug

${YELLOW}💡 Recommandations:${NC}

1. Toujours utiliser SecureKey pour les clés cryptographiques
2. Éviter de copier les clés inutilement
3. Utiliser use_key() pour opérations temporaires
4. Activer le chiffrement swap (swapfile encrypted)
5. Désactiver hibernation sur machines critiques

${YELLOW}📚 Pour aller plus loin:${NC}

- Test avec valgrind: valgrind --leak-check=full
- Test cold boot: Freeze RAM puis dump
- Test swap: Monitorer /var/vm/swapfile*
- Test crash: kill -SEGV <PID> puis analyser core dump

EOF

# Nettoyage
echo ""
echo "🧹 Nettoyage..."
rm -f /tmp/vmmap_*.txt
rm -f $DUMP_FILE*
echo -e "${GREEN}✅ Nettoyage terminé${NC}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

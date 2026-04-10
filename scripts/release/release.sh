#!/bin/bash

# ============================================================================
# Script Complet de Release FluXlock
# Compile, signe et génère le package de mise à jour en une seule commande
# ============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

print_header() {
    echo ""
    echo -e "${MAGENTA}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  $1${NC}"
    echo -e "${MAGENTA}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    echo ""
    echo -e "${CYAN}▶ $1${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Variables
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VERSION=$(node -p "require('$SCRIPT_DIR/package.json').version")

clear

print_header "🚀 FluXlock - Release Complète v$VERSION"

echo "Ce script va :"
echo "  1. ✅ Vérifier la configuration"
echo "  2. 🔨 Compiler l'application"
echo "  3. 🔐 Signer le package"
echo "  4. 📦 Générer le manifest de mise à jour"
echo "  5. 📤 Préparer les fichiers pour distribution"
echo ""
read -p "Continuer ? (o/n): " confirm

if [ "$confirm" != "o" ] && [ "$confirm" != "O" ]; then
    print_info "Opération annulée"
    exit 0
fi

# ============================================================================
# ÉTAPE 1 : Vérification
# ============================================================================

print_step "ÉTAPE 1/5 : Vérification de la configuration"

# Vérifier la clé privée
PRIVATE_KEY_PATH="$HOME/.tauri/fluxlock.key"
if [ ! -f "$PRIVATE_KEY_PATH" ]; then
    print_error "Clé privée non trouvée: $PRIVATE_KEY_PATH"
    echo ""
    echo "Pour générer une clé :"
    echo "  npx @tauri-apps/cli signer generate -w ~/.tauri/fluxlock.key"
    exit 1
fi
print_success "Clé privée trouvée"

# Vérifier les outils
if ! command -v node &> /dev/null; then
    print_error "Node.js n'est pas installé"
    exit 1
fi
print_success "Node.js installé"

if ! command -v cargo &> /dev/null; then
    print_error "Cargo n'est pas installé"
    exit 1
fi
print_success "Cargo installé"

# Vérifier les dépendances npm
if [ ! -d "$SCRIPT_DIR/node_modules" ]; then
    print_warning "Dépendances npm non installées"
    print_info "Installation des dépendances..."
    cd "$SCRIPT_DIR"
    npm install
fi
print_success "Dépendances npm OK"

# ============================================================================
# ÉTAPE 2 : Compilation
# ============================================================================

print_step "ÉTAPE 2/5 : Compilation de l'application"

echo "Choisissez le type de build :"
echo "  1. Build rapide (sans nettoyage)"
echo "  2. Build complet (avec nettoyage)"
read -p "Votre choix (1-2): " build_choice

cd "$SCRIPT_DIR"

case "$build_choice" in
    1)
        print_info "Build rapide en cours..."
        ;;
    2)
        print_info "Nettoyage..."
        cargo clean -p fluxlock 2>/dev/null || true
        rm -rf dist/ 2>/dev/null || true
        print_success "Nettoyage terminé"
        ;;
    *)
        print_warning "Choix invalide, build rapide sélectionné"
        ;;
esac

print_info "Compilation du frontend..."
npm run build

print_success "Frontend compilé"

# ============================================================================
# ÉTAPE 3 : Build Tauri avec Signature
# ============================================================================

print_step "ÉTAPE 3/5 : Compilation Tauri avec signature"

export TAURI_PRIVATE_KEY="$PRIVATE_KEY_PATH"

print_warning "Le mot de passe de la clé privée sera demandé"
echo ""

npm run tauri build

if [ $? -eq 0 ]; then
    print_success "Build Tauri réussi avec signature"
else
    print_error "Échec du build Tauri"
    exit 1
fi

# ============================================================================
# ÉTAPE 4 : Vérification de la Signature
# ============================================================================

print_step "ÉTAPE 4/5 : Vérification de la signature"

# Détecter la plateforme
OS_TYPE=$(uname -s)
ARCH_TYPE=$(uname -m)

case "$OS_TYPE" in
    Darwin)
        BUNDLE_DIR="$SCRIPT_DIR/src-tauri/target/release/bundle/macos"
        BUNDLE_FILE="FluXlock.app.tar.gz"
        ;;
    Linux)
        BUNDLE_DIR="$SCRIPT_DIR/src-tauri/target/release/bundle/appimage"
        BUNDLE_FILE="fluxlock_${VERSION}_amd64.AppImage.tar.gz"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        BUNDLE_DIR="$SCRIPT_DIR/src-tauri/target/release/bundle/msi"
        BUNDLE_FILE="FluXlock_${VERSION}_x64_en-US.msi.zip"
        ;;
esac

SIG_FILE="$BUNDLE_DIR/$BUNDLE_FILE.sig"

if [ -f "$SIG_FILE" ]; then
    print_success "Signature trouvée: $(basename $SIG_FILE)"
    print_info "Taille: $(du -h $SIG_FILE | cut -f1)"
else
    print_error "Fichier de signature non trouvé"
    print_warning "La signature a peut-être échoué. Vérifiez les logs ci-dessus."
    exit 1
fi

# ============================================================================
# ÉTAPE 5 : Génération du Manifest
# ============================================================================

print_step "ÉTAPE 5/5 : Génération du manifest de mise à jour"

print_info "Lancement du générateur de mise à jour..."
echo ""

"$SCRIPT_DIR/generate-update.sh"

# ============================================================================
# RÉSUMÉ FINAL
# ============================================================================

print_header "✨ Release Complète Terminée !"

OUTPUT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)/release-packages"

echo -e "${CYAN}📊 Résumé de la Release:${NC}"
echo ""
echo "  🏷️  Version: $VERSION"
echo "  📦 Package: $BUNDLE_FILE"
echo "  🔐 Signature: ✅ Présente"
echo "  📁 Dossier: $OUTPUT_DIR"
echo ""

print_info "Fichiers générés:"
ls -lh "$OUTPUT_DIR/" 2>/dev/null || echo "  (Aucun fichier)"
echo ""

print_header "📤 Distribution"

echo "Pour distribuer cette version :"
echo ""
echo "1️⃣  Testez localement :"
echo "   open $BUNDLE_DIR/FluXlock.app"
echo ""
echo "2️⃣  Uploadez sur votre serveur :"
echo "   cd $OUTPUT_DIR"
echo "   scp * user@server:/var/www/releases/"
echo ""
echo "3️⃣  Configurez le serveur de mise à jour :"
echo "   Consultez: $OUTPUT_DIR/README.md"
echo ""
echo "4️⃣  Annoncez la release :"
echo "   - Créez un GitHub Release"
echo "   - Publiez les notes de version"
echo "   - Informez les utilisateurs"
echo ""

print_success "Tout est prêt pour la distribution ! 🎉"
echo ""

# Proposer d'ouvrir le dossier
read -p "Voulez-vous ouvrir le dossier release-packages ? (o/n): " open_folder

if [ "$open_folder" = "o" ] || [ "$open_folder" = "O" ]; then
    if [ "$OS_TYPE" = "Darwin" ]; then
        open "$OUTPUT_DIR"
    elif [ "$OS_TYPE" = "Linux" ]; then
        xdg-open "$OUTPUT_DIR" 2>/dev/null || nautilus "$OUTPUT_DIR" 2>/dev/null || echo "Ouvrez manuellement: $OUTPUT_DIR"
    fi
fi

echo ""
print_info "Processus terminé ! Bonne distribution 🚀"

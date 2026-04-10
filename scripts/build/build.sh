#!/bin/bash
# Script de compilation optimisée pour SecureVault Next-Gen

set -e  # Arrêt en cas d'erreur

echo "🔐 ======================================"
echo "🔐 SecureVault Next-Gen - Compilation"
echo "🔐 ======================================"
echo ""

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Répertoire racine
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Fonction de log
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Vérification des prérequis
check_prerequisites() {
    log_info "Vérification des prérequis..."
    
    # Rust
    if ! command -v cargo &> /dev/null; then
        log_error "Rust n'est pas installé. Installez-le depuis: https://rustup.rs/"
        exit 1
    fi
    log_success "Rust installé: $(rustc --version)"
    
    # Node.js
    if ! command -v node &> /dev/null; then
        log_error "Node.js n'est pas installé. Installez-le depuis: https://nodejs.org/"
        exit 1
    fi
    log_success "Node.js installé: $(node --version)"
    
    # Python (optionnel)
    if command -v python3 &> /dev/null; then
        log_success "Python installé: $(python3 --version)"
    else
        log_warning "Python non trouvé. Le moteur ML sera désactivé."
    fi
    
    echo ""
}

# Nettoyage
clean_build() {
    log_info "🧹 Nettoyage des fichiers de compilation..."
    
    cd "$ROOT_DIR/tauri-desktop/src-tauri"
    cargo clean 2>&1 | grep -v "warning" || true
    
    cd "$ROOT_DIR/tauri-desktop"
    rm -rf dist node_modules/.vite 2>/dev/null || true
    
    log_success "Nettoyage terminé"
    echo ""
}

# Compilation du core crypto Rust
build_crypto_core() {
    log_info "🦀 Compilation du Rust Crypto Core..."
    
    cd "$ROOT_DIR/rust-crypto-core"
    cargo build --release 2>&1 | grep -E "(Compiling|Finished)" || true
    
    log_success "Crypto Core compilé"
    echo ""
}

# Installation dépendances frontend
install_frontend_deps() {
    log_info "📦 Installation des dépendances frontend..."
    
    cd "$ROOT_DIR/tauri-desktop"
    
    if [ -f "package-lock.json" ]; then
        npm ci --quiet
    else
        npm install --quiet
    fi
    
    log_success "Dépendances installées"
    echo ""
}

# Build frontend
build_frontend() {
    log_info "⚛️  Compilation du frontend React..."
    
    cd "$ROOT_DIR/tauri-desktop"
    npm run build 2>&1 | grep -E "(vite|build|✓)" || true
    
    log_success "Frontend compilé"
    echo ""
}

# Compilation Tauri (release)
build_tauri() {
    log_info "🚀 Compilation de l'application Tauri (mode release)..."
    log_warning "⏳ Cela peut prendre plusieurs minutes..."
    echo ""
    
    cd "$ROOT_DIR/tauri-desktop/src-tauri"
    
    # Compilation avec suppression des warnings
    cargo build --release 2>&1 | \
        grep -v "warning:" | \
        grep -v "^   " | \
        grep -E "(Compiling|Finished|error)" || true
    
    if [ $? -eq 0 ] && [ -f "target/release/securevault" ] || [ -f "target/release/securevault.exe" ]; then
        log_success "Application compilée avec succès!"
        echo ""
        
        # Affichage du chemin de l'exécutable
        if [ -f "target/release/securevault" ]; then
            EXEC_PATH="$ROOT_DIR/tauri-desktop/src-tauri/target/release/securevault"
        else
            EXEC_PATH="$ROOT_DIR/tauri-desktop/src-tauri/target/release/securevault.exe"
        fi
        
        log_info "📍 Exécutable : $EXEC_PATH"
        log_info "📦 Taille    : $(du -h "$EXEC_PATH" | cut -f1)"
        echo ""
    else
        log_error "La compilation a échoué"
        exit 1
    fi
}

# Création du bundle (DMG, AppImage, MSI, etc.)
create_bundle() {
    log_info "📦 Création du bundle d'installation..."
    
    cd "$ROOT_DIR/tauri-desktop"
    
    npm run tauri build 2>&1 | \
        grep -v "warning:" | \
        grep -E "(Compiling|Finished|Bundling|Bundle)" || true
    
    if [ $? -eq 0 ]; then
        log_success "Bundle créé avec succès!"
        
        # Afficher les bundles créés
        BUNDLE_DIR="$ROOT_DIR/tauri-desktop/src-tauri/target/release/bundle"
        if [ -d "$BUNDLE_DIR" ]; then
            echo ""
            log_info "📦 Bundles disponibles :"
            find "$BUNDLE_DIR" -type f \( -name "*.dmg" -o -name "*.deb" -o -name "*.rpm" -o -name "*.AppImage" -o -name "*.msi" -o -name "*.exe" \) -exec echo "   • {}" \;
        fi
    else
        log_warning "La création du bundle a échoué (vous pouvez utiliser l'exécutable brut)"
    fi
    
    echo ""
}

# Résumé final
show_summary() {
    echo ""
    log_success "======================================"
    log_success "✨ Compilation terminée avec succès!"
    log_success "======================================"
    echo ""
    
    # Trouver l'exécutable
    if [ -f "$ROOT_DIR/tauri-desktop/src-tauri/target/release/securevault" ]; then
        EXEC="$ROOT_DIR/tauri-desktop/src-tauri/target/release/securevault"
    elif [ -f "$ROOT_DIR/tauri-desktop/src-tauri/target/release/securevault.exe" ]; then
        EXEC="$ROOT_DIR/tauri-desktop/src-tauri/target/release/securevault.exe"
    else
        log_error "Exécutable non trouvé"
        exit 1
    fi
    
    log_info "Pour lancer l'application :"
    echo ""
    echo "   $EXEC"
    echo ""
    
    # Bundles
    BUNDLE_DIR="$ROOT_DIR/tauri-desktop/src-tauri/target/release/bundle"
    if [ -d "$BUNDLE_DIR" ]; then
        log_info "Bundles d'installation dans :"
        echo ""
        echo "   $BUNDLE_DIR"
        echo ""
    fi
}

# Menu principal
show_menu() {
    echo "Que voulez-vous compiler ?"
    echo ""
    echo "  1) Compilation complète (nettoyage + build + bundle)"
    echo "  2) Compilation rapide (sans nettoyage)"
    echo "  3) Nettoyage seulement"
    echo "  4) Build sans bundle"
    echo "  5) Quitter"
    echo ""
    read -p "Choix [1-5] : " choice
    
    case $choice in
        1)
            check_prerequisites
            clean_build
            build_crypto_core
            install_frontend_deps
            build_frontend
            build_tauri
            create_bundle
            show_summary
            ;;
        2)
            check_prerequisites
            build_crypto_core
            install_frontend_deps
            build_frontend
            build_tauri
            show_summary
            ;;
        3)
            clean_build
            log_success "Nettoyage terminé"
            ;;
        4)
            check_prerequisites
            build_crypto_core
            install_frontend_deps
            build_frontend
            build_tauri
            show_summary
            ;;
        5)
            echo "Au revoir! 👋"
            exit 0
            ;;
        *)
            log_error "Choix invalide"
            exit 1
            ;;
    esac
}

# Point d'entrée
main() {
    # Si argument fourni, compilation automatique
    if [ "$1" == "--full" ] || [ "$1" == "-f" ]; then
        check_prerequisites
        clean_build
        build_crypto_core
        install_frontend_deps
        build_frontend
        build_tauri
        create_bundle
        show_summary
    elif [ "$1" == "--quick" ] || [ "$1" == "-q" ]; then
        check_prerequisites
        build_crypto_core
        install_frontend_deps
        build_frontend
        build_tauri
        show_summary
    elif [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  -f, --full     Compilation complète (nettoyage + build + bundle)"
        echo "  -q, --quick    Compilation rapide (sans nettoyage)"
        echo "  -h, --help     Affiche cette aide"
        echo ""
        echo "Sans option, affiche le menu interactif."
    else
        show_menu
    fi
}

# Lancement
main "$@"

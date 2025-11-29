#!/bin/bash

# ============================================================================
# Script de build multi-plateforme pour SecureVault
# Compile et crée les installeurs pour Windows, Linux et macOS
# ============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Variables
VERSION="2.0.0"
APP_NAME="SecureVault"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
TAURI_DIR="$PROJECT_ROOT/tauri-desktop"
BUILD_DIR="$PROJECT_ROOT/build-output"
CRYPTO_DIR="$PROJECT_ROOT/rust-crypto-core"

# ============================================================================
# Fonctions utilitaires
# ============================================================================

print_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}========================================${NC}"
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

check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_error "La commande '$1' n'est pas installée"
        return 1
    fi
    return 0
}

# ============================================================================
# Vérification des prérequis
# ============================================================================

check_prerequisites() {
    print_header "Vérification des prérequis"
    
    local all_ok=true
    
    # Rust et Cargo
    if check_command cargo; then
        print_success "Cargo $(cargo --version | cut -d' ' -f2)"
    else
        all_ok=false
    fi
    
    # Node.js et npm
    if check_command node; then
        print_success "Node.js $(node --version)"
    else
        all_ok=false
    fi
    
    if check_command npm; then
        print_success "npm $(npm --version)"
    else
        all_ok=false
    fi
    
    # Python (optionnel pour ML)
    if check_command python3; then
        print_success "Python $(python3 --version | cut -d' ' -f2)"
    else
        print_warning "Python non trouvé (ML désactivé)"
    fi
    
    if [ "$all_ok" = false ]; then
        print_error "Certains prérequis sont manquants"
        exit 1
    fi
    
    print_success "Tous les prérequis sont installés"
}

# ============================================================================
# Nettoyage
# ============================================================================

clean_build() {
    print_header "Nettoyage des anciennes compilations"
    
    # Nettoyer les builds Rust
    if [ -d "$CRYPTO_DIR/target" ]; then
        print_info "Nettoyage du crypto core..."
        cd "$CRYPTO_DIR"
        cargo clean
    fi
    
    if [ -d "$TAURI_DIR/src-tauri/target" ]; then
        print_info "Nettoyage de Tauri..."
        cd "$TAURI_DIR/src-tauri"
        cargo clean
    fi
    
    # Nettoyer les bundles
    if [ -d "$TAURI_DIR/src-tauri/target/release/bundle" ]; then
        print_info "Suppression des anciens bundles..."
        rm -rf "$TAURI_DIR/src-tauri/target/release/bundle"
    fi
    
    # Nettoyer le dossier de sortie
    if [ -d "$BUILD_DIR" ]; then
        print_info "Nettoyage du dossier de sortie..."
        rm -rf "$BUILD_DIR"
    fi
    
    print_success "Nettoyage terminé"
}

# ============================================================================
# Compilation du crypto core
# ============================================================================

build_crypto_core() {
    print_header "Compilation du Crypto Core (Rust)"
    
    cd "$CRYPTO_DIR"
    
    print_info "Compilation en mode release..."
    cargo build --release --quiet
    
    print_success "Crypto core compilé"
}

# ============================================================================
# Installation des dépendances frontend
# ============================================================================

install_frontend_deps() {
    print_header "Installation des dépendances frontend"
    
    cd "$TAURI_DIR"
    
    if [ -f "package-lock.json" ]; then
        print_info "Utilisation de npm ci..."
        npm ci --silent
    else
        print_info "Installation avec npm install..."
        npm install --silent
    fi
    
    print_success "Dépendances frontend installées"
}

# ============================================================================
# Build du frontend
# ============================================================================

build_frontend() {
    print_header "Compilation du Frontend (React + TypeScript)"
    
    cd "$TAURI_DIR"
    
    print_info "Build de production avec Vite..."
    npm run build
    
    if [ -d "dist" ]; then
        print_success "Frontend compilé ($(du -sh dist | cut -f1))"
    else
        print_error "Le dossier dist n'a pas été créé"
        exit 1
    fi
}

# ============================================================================
# Build Tauri pour toutes les plateformes
# ============================================================================

build_tauri_all_platforms() {
    print_header "Compilation Tauri multi-plateforme"
    
    cd "$TAURI_DIR"
    
    print_info "Début de la compilation Tauri..."
    print_warning "Cela peut prendre 5-10 minutes..."
    echo ""
    
    # Build pour toutes les cibles disponibles sur la plateforme actuelle
    npm run tauri build
    
    if [ $? -eq 0 ]; then
        print_success "Compilation Tauri terminée"
    else
        print_error "Échec de la compilation Tauri"
        exit 1
    fi
}

# ============================================================================
# Création du DMG personnalisé pour macOS
# ============================================================================

create_macos_dmg() {
    print_header "Création du DMG macOS personnalisé"
    
    local APP_PATH="$TAURI_DIR/src-tauri/target/release/bundle/macos/${APP_NAME}.app"
    local DMG_NAME="${APP_NAME}_${VERSION}_macOS_Installer.dmg"
    local DMG_PATH="$TAURI_DIR/src-tauri/target/release/bundle/dmg/${DMG_NAME}"
    local TMP_DIR="/tmp/securevault-dmg-$$"
    
    # Vérifier que l'app existe
    if [ ! -d "$APP_PATH" ]; then
        print_warning "Application macOS non trouvée, DMG non créé"
        return 0
    fi
    
    print_info "Application trouvée: $APP_PATH"
    
    # Créer un dossier temporaire
    mkdir -p "$TMP_DIR"
    
    # Copier l'application
    print_info "Copie de l'application..."
    cp -R "$APP_PATH" "$TMP_DIR/"
    
    # Créer un lien vers Applications
    print_info "Création du lien vers Applications..."
    ln -s /Applications "$TMP_DIR/Applications"
    
    # Créer le dossier de destination
    mkdir -p "$(dirname "$DMG_PATH")"
    
    # Supprimer l'ancien DMG s'il existe
    rm -f "$DMG_PATH"
    
    # Créer le DMG
    print_info "Compression du DMG..."
    hdiutil create -volname "${APP_NAME} Installer" \
        -srcfolder "$TMP_DIR" \
        -ov \
        -format UDZO \
        -imagekey zlib-level=9 \
        "$DMG_PATH" > /dev/null 2>&1
    
    # Nettoyer
    rm -rf "$TMP_DIR"
    
    if [ -f "$DMG_PATH" ]; then
        local SIZE=$(du -h "$DMG_PATH" | cut -f1)
        print_success "DMG créé: $DMG_NAME ($SIZE)"
    else
        print_error "Échec de la création du DMG"
    fi
}

# ============================================================================
# Collecte des artefacts de build
# ============================================================================

collect_artifacts() {
    print_header "Collecte des artefacts de distribution"
    
    mkdir -p "$BUILD_DIR"
    
    local BUNDLE_DIR="$TAURI_DIR/src-tauri/target/release/bundle"
    local found_any=false
    
    # Collecter les artefacts macOS
    if [ -d "$BUNDLE_DIR/macos" ]; then
        print_info "Collecte des bundles macOS..."
        mkdir -p "$BUILD_DIR/macOS"
        
        if [ -d "$BUNDLE_DIR/macos/${APP_NAME}.app" ]; then
            cp -R "$BUNDLE_DIR/macos/${APP_NAME}.app" "$BUILD_DIR/macOS/"
            found_any=true
            print_success "  → ${APP_NAME}.app"
        fi
        
        if [ -d "$BUNDLE_DIR/dmg" ]; then
            find "$BUNDLE_DIR/dmg" -name "*.dmg" -exec cp {} "$BUILD_DIR/macOS/" \;
            for dmg in "$BUILD_DIR/macOS"/*.dmg; do
                if [ -f "$dmg" ]; then
                    print_success "  → $(basename "$dmg") ($(du -h "$dmg" | cut -f1))"
                fi
            done
        fi
    fi
    
    # Collecter les artefacts Windows
    if [ -d "$BUNDLE_DIR/nsis" ] || [ -d "$BUNDLE_DIR/msi" ]; then
        print_info "Collecte des bundles Windows..."
        mkdir -p "$BUILD_DIR/Windows"
        
        if [ -d "$BUNDLE_DIR/nsis" ]; then
            find "$BUNDLE_DIR/nsis" -name "*.exe" -exec cp {} "$BUILD_DIR/Windows/" \;
            for exe in "$BUILD_DIR/Windows"/*.exe; do
                if [ -f "$exe" ]; then
                    found_any=true
                    print_success "  → $(basename "$exe") ($(du -h "$exe" | cut -f1))"
                fi
            done
        fi
        
        if [ -d "$BUNDLE_DIR/msi" ]; then
            find "$BUNDLE_DIR/msi" -name "*.msi" -exec cp {} "$BUILD_DIR/Windows/" \;
            for msi in "$BUILD_DIR/Windows"/*.msi; do
                if [ -f "$msi" ]; then
                    found_any=true
                    print_success "  → $(basename "$msi") ($(du -h "$msi" | cut -f1))"
                fi
            done
        fi
    fi
    
    # Collecter les artefacts Linux
    if [ -d "$BUNDLE_DIR/deb" ] || [ -d "$BUNDLE_DIR/rpm" ] || [ -d "$BUNDLE_DIR/appimage" ]; then
        print_info "Collecte des bundles Linux..."
        mkdir -p "$BUILD_DIR/Linux"
        
        if [ -d "$BUNDLE_DIR/deb" ]; then
            find "$BUNDLE_DIR/deb" -name "*.deb" -exec cp {} "$BUILD_DIR/Linux/" \;
            for deb in "$BUILD_DIR/Linux"/*.deb; do
                if [ -f "$deb" ]; then
                    found_any=true
                    print_success "  → $(basename "$deb") ($(du -h "$deb" | cut -f1))"
                fi
            done
        fi
        
        if [ -d "$BUNDLE_DIR/rpm" ]; then
            find "$BUNDLE_DIR/rpm" -name "*.rpm" -exec cp {} "$BUILD_DIR/Linux/" \;
            for rpm in "$BUILD_DIR/Linux"/*.rpm; do
                if [ -f "$rpm" ]; then
                    found_any=true
                    print_success "  → $(basename "$rpm") ($(du -h "$rpm" | cut -f1))"
                fi
            done
        fi
        
        if [ -d "$BUNDLE_DIR/appimage" ]; then
            find "$BUNDLE_DIR/appimage" -name "*.AppImage" -exec cp {} "$BUILD_DIR/Linux/" \;
            for appimage in "$BUILD_DIR/Linux"/*.AppImage; do
                if [ -f "$appimage" ]; then
                    found_any=true
                    print_success "  → $(basename "$appimage") ($(du -h "$appimage" | cut -f1))"
                fi
            done
        fi
    fi
    
    if [ "$found_any" = false ]; then
        print_warning "Aucun artefact de distribution trouvé"
        print_info "Note: Sur macOS, seuls les bundles macOS sont créés"
        print_info "Compilez sur Windows pour .exe/.msi et sur Linux pour .deb/.rpm/.AppImage"
    else
        print_success "Artefacts collectés dans: $BUILD_DIR"
    fi
}

# ============================================================================
# Création des archives de distribution
# ============================================================================

create_distribution_archives() {
    print_header "Création des archives de distribution"
    
    cd "$BUILD_DIR"
    
    # Créer une archive pour chaque plateforme
    for platform_dir in macOS Windows Linux; do
        if [ -d "$platform_dir" ] && [ "$(ls -A "$platform_dir")" ]; then
            local archive_name="${APP_NAME}_${VERSION}_${platform_dir}.tar.gz"
            print_info "Création de $archive_name..."
            tar -czf "$archive_name" "$platform_dir"
            print_success "  → $archive_name ($(du -h "$archive_name" | cut -f1))"
        fi
    done
    
    # Créer une archive complète
    if [ "$(ls -A .)" ]; then
        local full_archive="${APP_NAME}_${VERSION}_All_Platforms.tar.gz"
        print_info "Création de l'archive complète..."
        tar -czf "$full_archive" */
        print_success "  → $full_archive ($(du -h "$full_archive" | cut -f1))"
    fi
}

# ============================================================================
# Résumé final
# ============================================================================

show_summary() {
    print_header "Résumé de la compilation"
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}║           ✅  COMPILATION TERMINÉE AVEC SUCCÈS             ║${NC}"
    echo -e "${GREEN}║                                                            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    print_info "Application: $APP_NAME"
    print_info "Version: $VERSION"
    echo ""
    
    if [ -d "$BUILD_DIR" ]; then
        echo -e "${BLUE}📦 Artefacts de distribution:${NC}"
        echo ""
        
        # Afficher la structure
        if command -v tree &> /dev/null; then
            tree -L 2 -h "$BUILD_DIR"
        else
            ls -lhR "$BUILD_DIR"
        fi
        
        echo ""
        echo -e "${BLUE}📁 Emplacement: ${NC}$BUILD_DIR"
        echo ""
        
        # Taille totale
        local total_size=$(du -sh "$BUILD_DIR" | cut -f1)
        print_info "Taille totale: $total_size"
    fi
    
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BLUE}📋 Instructions de distribution:${NC}"
    echo ""
    echo "  macOS:"
    echo "    • Distribuez le fichier .dmg"
    echo "    • Les utilisateurs glissent l'app dans Applications"
    echo ""
    echo "  Windows:"
    echo "    • Distribuez le fichier .exe (NSIS) ou .msi"
    echo "    • Les utilisateurs exécutent l'installeur"
    echo ""
    echo "  Linux:"
    echo "    • .deb pour Debian/Ubuntu: sudo dpkg -i *.deb"
    echo "    • .rpm pour Fedora/RHEL: sudo rpm -i *.rpm"
    echo "    • .AppImage: chmod +x *.AppImage && ./app.AppImage"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    
    print_success "Prêt pour la distribution ! 🚀"
    echo ""
}

# ============================================================================
# Menu principal
# ============================================================================

show_menu() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                            ║${NC}"
    echo -e "${BLUE}║        SecureVault - Build Multi-Plateforme v2.0.0        ║${NC}"
    echo -e "${BLUE}║                                                            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "1. Build complet (clean + compile + bundle)"
    echo "2. Build rapide (sans nettoyage)"
    echo "3. Nettoyer uniquement"
    echo "4. Créer les archives de distribution"
    echo "5. Quitter"
    echo ""
    read -p "Choisissez une option (1-5): " choice
    echo ""
}

# ============================================================================
# Programme principal
# ============================================================================

main() {
    # Si des arguments sont passés
    if [ $# -gt 0 ]; then
        case "$1" in
            --full|-f)
                print_header "🔨 BUILD COMPLET (avec nettoyage)"
                check_prerequisites
                clean_build
                build_crypto_core
                install_frontend_deps
                build_frontend
                build_tauri_all_platforms
                create_macos_dmg
                collect_artifacts
                create_distribution_archives
                show_summary
                ;;
            --quick|-q)
                print_header "⚡ BUILD RAPIDE (sans nettoyage)"
                check_prerequisites
                build_crypto_core
                install_frontend_deps
                build_frontend
                build_tauri_all_platforms
                create_macos_dmg
                collect_artifacts
                create_distribution_archives
                show_summary
                ;;
            --clean|-c)
                print_header "🧹 NETTOYAGE"
                clean_build
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -f, --full     Build complet avec nettoyage"
                echo "  -q, --quick    Build rapide sans nettoyage"
                echo "  -c, --clean    Nettoyer uniquement"
                echo "  -h, --help     Afficher cette aide"
                echo ""
                echo "Sans option: affiche le menu interactif"
                ;;
            *)
                print_error "Option inconnue: $1"
                echo "Utilisez --help pour voir les options disponibles"
                exit 1
                ;;
        esac
        return
    fi
    
    # Menu interactif si aucun argument
    while true; do
        show_menu
        
        case $choice in
            1)
                print_header "🔨 BUILD COMPLET"
                check_prerequisites
                clean_build
                build_crypto_core
                install_frontend_deps
                build_frontend
                build_tauri_all_platforms
                create_macos_dmg
                collect_artifacts
                create_distribution_archives
                show_summary
                break
                ;;
            2)
                print_header "⚡ BUILD RAPIDE"
                check_prerequisites
                build_crypto_core
                install_frontend_deps
                build_frontend
                build_tauri_all_platforms
                create_macos_dmg
                collect_artifacts
                create_distribution_archives
                show_summary
                break
                ;;
            3)
                clean_build
                break
                ;;
            4)
                collect_artifacts
                create_distribution_archives
                break
                ;;
            5)
                echo "Au revoir ! 👋"
                exit 0
                ;;
            *)
                print_error "Option invalide. Choisissez 1-5."
                ;;
        esac
    done
}

# Exécuter le programme principal
main "$@"

#!/bin/bash

# ============================================================================
# Script de build multi-plateforme pour FluXlock
# Compile et crée les installeurs pour Windows, Linux, macOS et Android
# ============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables
VERSION="2.0.0"
APP_NAME="FluXlock"
PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TAURI_DIR="$PROJECT_ROOT/tauri-desktop"
BUILD_DIR="$PROJECT_ROOT/build-output"
CRYPTO_DIR="$PROJECT_ROOT/rust-crypto-core"
ANDROID_TARGET="aarch64"   # Par défaut: ARM64 uniquement (plus rapide)
ANDROID_BUILD_MODE="debug" # Par défaut: debug (installable directement via ADB)
ADB_INSTALL=false          # Par défaut: pas d'installation ADB automatique
MIN_DISK_SPACE_GB=5        # Espace disque minimum requis en Go

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
# Vérification de l'espace disque
# ============================================================================

check_disk_space() {
    print_info "Vérification de l'espace disque..."

    local available_kb
    if [[ "$(uname)" == "Darwin" ]]; then
        available_kb=$(df -k "$PROJECT_ROOT" | tail -1 | awk '{print $4}')
    else
        available_kb=$(df -k "$PROJECT_ROOT" | tail -1 | awk '{print $4}')
    fi

    local available_gb=$((available_kb / 1024 / 1024))
    print_info "Espace disponible: ${available_gb} Go"

    if [ "$available_gb" -lt "$MIN_DISK_SPACE_GB" ]; then
        print_error "Espace disque insuffisant! ${available_gb} Go disponible, ${MIN_DISK_SPACE_GB} Go requis"
        print_info "Astuce: le dossier target/ peut peser 10+ Go."
        print_info "Essayez: $0 --clean  ou  cargo clean dans src-tauri/"
        return 1
    fi

    # Avertissement si espace limité
    if [ "$available_gb" -lt 15 ]; then
        print_warning "Espace disque limité (${available_gb} Go). Le build Rust peut nécessiter 10+ Go."
        print_info "Si le build échoue par manque d'espace: $0 --clean"
    fi

    print_success "Espace disque suffisant (${available_gb} Go)"
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
    
    # Vérifier l'espace disque
    check_disk_space
    
    print_success "Tous les prérequis sont installés"
}

# ============================================================================
# Nettoyage
# ============================================================================

clean_build() {
    print_header "Nettoyage profond (deep clean)"

    # ── 1. Cargo targets (Rust) ──
    if [ -d "$TAURI_DIR/src-tauri/target" ]; then
        print_info "cargo clean (tauri-desktop)..."
        cd "$TAURI_DIR/src-tauri" && cargo clean --quiet 2>/dev/null || true
    fi
    if [ -d "$CRYPTO_DIR/target" ]; then
        print_info "cargo clean (rust-crypto-core)..."
        cd "$CRYPTO_DIR" && cargo clean --quiet 2>/dev/null || true
    fi

    # ── 2. Frontend (node_modules, dist, cache Vite) ──
    for dir in node_modules dist .vite; do
        if [ -d "$TAURI_DIR/$dir" ]; then
            print_info "Suppression de $dir..."
            rm -rf "$TAURI_DIR/$dir"
        fi
    done

    # ── 3. Android build artifacts ──
    for dir in gen/android/app/build gen/android/.gradle gen/android/build; do
        if [ -d "$TAURI_DIR/src-tauri/$dir" ]; then
            print_info "Suppression de src-tauri/$dir..."
            rm -rf "$TAURI_DIR/src-tauri/$dir"
        fi
    done

    # ── 4. Tauri bundles résiduels ──
    if [ -d "$TAURI_DIR/src-tauri/target/release/bundle" ]; then
        print_info "Suppression des anciens bundles..."
        rm -rf "$TAURI_DIR/src-tauri/target/release/bundle"
    fi

    # ── 5. Dossier de sortie global ──
    if [ -d "$BUILD_DIR" ]; then
        print_info "Nettoyage du dossier de sortie..."
        rm -rf "$BUILD_DIR"
    fi

    print_success "Nettoyage profond terminé ✨"
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
    local TMP_DIR="/tmp/fluxlock-dmg-$$"
    
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
# Build Android APK
# ============================================================================

build_android_apk() {
    print_header "Compilation Android APK (mode: $ANDROID_BUILD_MODE, cible: $ANDROID_TARGET)"

    # Vérifier et configurer ANDROID_HOME
    if [ -z "$ANDROID_HOME" ]; then
        if [ -d "$HOME/Library/Android/sdk" ]; then
            export ANDROID_HOME="$HOME/Library/Android/sdk"
        elif [ -d "$HOME/Android/Sdk" ]; then
            export ANDROID_HOME="$HOME/Android/Sdk"
        else
            print_error "ANDROID_HOME non défini et SDK non trouvé"
            return 1
        fi
        print_info "ANDROID_HOME détecté: $ANDROID_HOME"
    fi

    # Ajouter les outils du SDK au PATH
    export PATH="$ANDROID_HOME/platform-tools:$PATH"

    # Configurer NDK_HOME
    if [ -z "$NDK_HOME" ]; then
        local ndk_dir=$(find "$ANDROID_HOME/ndk" -maxdepth 1 -mindepth 1 -type d | sort -V | tail -1)
        if [ -n "$ndk_dir" ]; then
            export NDK_HOME="$ndk_dir"
            print_info "NDK_HOME détecté: $NDK_HOME"
        else
            print_error "NDK non trouvé dans $ANDROID_HOME/ndk/"
            return 1
        fi
    fi

    # Forcer JAVA_HOME vers JDK 17 (requis pour Gradle/AGP — JDK 21+ casse Gradle 8.x)
    if /usr/libexec/java_home -v 17 &>/dev/null; then
        export JAVA_HOME=$(/usr/libexec/java_home -v 17)
        print_info "JAVA_HOME forcé à JDK 17: $JAVA_HOME"
    else
        print_error "JDK 17 non trouvé. Installez-le avec: brew install openjdk@17"
        print_info "Note: JDK 21+ est incompatible avec Gradle 8.x (erreur '> 25')"
        return 1
    fi

    # Résoudre apksigner depuis le SDK
    local APKSIGNER=""
    local BT_DIR=$(find "$ANDROID_HOME/build-tools" -maxdepth 1 -mindepth 1 -type d | sort -V | tail -1)
    if [ -n "$BT_DIR" ] && [ -f "$BT_DIR/apksigner" ]; then
        APKSIGNER="$BT_DIR/apksigner"
        print_info "apksigner: $APKSIGNER"
    elif command -v apksigner &>/dev/null; then
        APKSIGNER="apksigner"
    fi

    cd "$TAURI_DIR"

    # Construire la commande de build
    local BUILD_CMD="npm run tauri android build"
    local TARGET_FLAG=""

    # Ajouter le target Android si spécifié (aarch64, armv7, x86_64, i686)
    case "$ANDROID_TARGET" in
        aarch64)   TARGET_FLAG="--target aarch64" ;;
        armv7)     TARGET_FLAG="--target armv7" ;;
        x86_64)    TARGET_FLAG="--target x86_64" ;;
        i686)      TARGET_FLAG="--target i686" ;;
        universal) TARGET_FLAG="" ;;  # Pas de --target = toutes les architectures
        *)
            print_warning "Cible '$ANDROID_TARGET' inconnue, utilisation de aarch64 par défaut"
            TARGET_FLAG="--target aarch64"
            ;;
    esac

    if [ "$ANDROID_BUILD_MODE" = "debug" ]; then
        BUILD_CMD="$BUILD_CMD -- $TARGET_FLAG --debug"
        print_info "Build DEBUG $ANDROID_TARGET en cours..."
    else
        BUILD_CMD="$BUILD_CMD -- $TARGET_FLAG"
        print_info "Build RELEASE $ANDROID_TARGET en cours..."
    fi

    print_warning "Cela peut prendre 5-15 minutes..."
    eval "$BUILD_CMD"

    # Chercher l'APK généré (chemin différent selon debug/release)
    local APK_PATH=""
    local APK_SEARCH_DIR="$TAURI_DIR/src-tauri/gen/android/app/build/outputs/apk"

    if [ "$ANDROID_BUILD_MODE" = "debug" ]; then
        # Chercher l'APK debug
        APK_PATH=$(find "$APK_SEARCH_DIR" -name "*-debug.apk" 2>/dev/null | head -1)
    else
        # Chercher l'APK release (signé ou non)
        APK_PATH=$(find "$APK_SEARCH_DIR" -name "*-release*.apk" 2>/dev/null | head -1)
    fi

    if [ -n "$APK_PATH" ] && [ -f "$APK_PATH" ]; then
        local SIZE=$(du -h "$APK_PATH" | cut -f1)
        print_success "APK généré ($SIZE): $(basename "$APK_PATH")"

        if [ "$ANDROID_BUILD_MODE" = "debug" ]; then
            # Debug APK: copier directement (déjà signé avec debug keystore)
            mkdir -p "$BUILD_DIR"
            local OUTPUT_APK="$BUILD_DIR/${APP_NAME}_${VERSION}_android_${ANDROID_TARGET}_debug.apk"
            cp "$APK_PATH" "$OUTPUT_APK"
            print_success "APK debug copié: $OUTPUT_APK"

            # Installation ADB si demandée
            if [ "$ADB_INSTALL" = true ]; then
                install_apk_via_adb "$OUTPUT_APK"
            fi
        else
            # Release APK: signer avec keystore
            sign_release_apk "$APK_PATH" "$APKSIGNER"
        fi
    else
        print_error "APK non trouvé à l'emplacement attendu"
        print_info "Recherche dans: $APK_SEARCH_DIR"
        print_info "Fichiers trouvés:"
        find "$APK_SEARCH_DIR" -name "*.apk" 2>/dev/null | while read f; do
            print_info "  → $f"
        done
    fi
}

# ============================================================================
# Signature de l'APK release
# ============================================================================

sign_release_apk() {
    local APK_PATH="$1"
    local APKSIGNER="$2"

    local KEYSTORE=""
    local KS_ALIAS=""
    local KS_PASS=""
    local KEY_PASS=""

    if [ -f "$HOME/fluxlock-release.keystore" ]; then
        KEYSTORE="$HOME/fluxlock-release.keystore"
        KS_ALIAS="fluxlock"
        KS_PASS="pass:fluxlock2024"
        KEY_PASS="pass:fluxlock2024"
        print_info "Utilisation du keystore RELEASE"
    elif [ -f "$HOME/.android/debug.keystore" ]; then
        KEYSTORE="$HOME/.android/debug.keystore"
        KS_ALIAS="androiddebugkey"
        KS_PASS="pass:android"
        KEY_PASS="pass:android"
        print_warning "Keystore release non trouvé, utilisation du keystore DEBUG"
    fi

    if [ -n "$KEYSTORE" ] && [ -n "$APKSIGNER" ]; then
        print_info "Signature de l'APK avec $KS_ALIAS..."
        local SIGNED_APK="$BUILD_DIR/${APP_NAME}_${VERSION}_android.apk"
        mkdir -p "$BUILD_DIR"
        "$APKSIGNER" sign --ks "$KEYSTORE" \
            --ks-key-alias "$KS_ALIAS" \
            --ks-pass "$KS_PASS" \
            --key-pass "$KEY_PASS" \
            --v2-signing-enabled true \
            --v3-signing-enabled true \
            --out "$SIGNED_APK" \
            "$APK_PATH"
        if [ -f "$SIGNED_APK" ]; then
            print_success "APK signé: $SIGNED_APK ($(du -h "$SIGNED_APK" | cut -f1))"

            # Installation ADB si demandée
            if [ "$ADB_INSTALL" = true ]; then
                install_apk_via_adb "$SIGNED_APK"
            fi
        else
            print_error "Échec de la signature de l'APK"
        fi
    else
        if [ -z "$APKSIGNER" ]; then
            print_warning "apksigner non trouvé dans $ANDROID_HOME/build-tools/"
        fi
        if [ -z "$KEYSTORE" ]; then
            print_warning "Aucun keystore trouvé (ni release ni debug)"
        fi
        print_info "APK non signé copié dans le répertoire de sortie"
        mkdir -p "$BUILD_DIR"
        cp "$APK_PATH" "$BUILD_DIR/${APP_NAME}_${VERSION}_android-unsigned.apk"
    fi
}

# ============================================================================
# Installation via ADB
# ============================================================================

install_apk_via_adb() {
    local APK_FILE="$1"

    if ! command -v adb &>/dev/null; then
        print_warning "adb non trouvé. Ajoutez platform-tools au PATH:"
        print_info "  export PATH=\"\$ANDROID_HOME/platform-tools:\$PATH\""
        return 0
    fi

    # Vérifier qu'un appareil est connecté
    local DEVICE_COUNT=$(adb devices | grep -c -E "^\S+\s+device$")
    if [ "$DEVICE_COUNT" -eq 0 ]; then
        print_warning "Aucun appareil Android connecté via ADB"
        print_info "Connectez votre téléphone en USB avec le débogage USB activé"
        return 0
    fi

    local DEVICE_ID=$(adb devices | grep -E "^\S+\s+device$" | head -1 | awk '{print $1}')
    print_info "Appareil détecté: $DEVICE_ID"
    print_info "Installation de l'APK sur l'appareil..."

    if adb install -r "$APK_FILE" 2>&1; then
        print_success "APK installé sur $DEVICE_ID"
        print_info "Lancement de l'application..."
        adb shell am start -n com.fluxlock.app/.MainActivity 2>/dev/null || true
    else
        print_error "Échec de l'installation ADB"
        print_info "Essayez: adb uninstall com.fluxlock.app && adb install $APK_FILE"
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
    echo -e "${BLUE}║         FluXlock - Build Multi-Plateforme v2.0.0          ║${NC}"
    echo -e "${BLUE}║                                                            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "1. Build complet (clean + compile + bundle)"
    echo "2. Build rapide (sans nettoyage)"
    echo "3. Build Android APK (release)"
    echo "4. Build Android APK (debug) + install ADB"
    echo "5. Nettoyer uniquement"
    echo "6. Créer les archives de distribution"
    echo "7. Quitter"
    echo ""
    read -p "Choisissez une option (1-7): " choice
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
            --android|-a)
                # Parser les sous-options Android
                shift
                while [ $# -gt 0 ]; do
                    case "$1" in
                        --debug|-d)    ANDROID_BUILD_MODE="debug" ;;
                        --release|-r)  ANDROID_BUILD_MODE="release" ;;
                        --target|-t)   shift; ANDROID_TARGET="${1:-aarch64}" ;;
                        --install|-i)  ADB_INSTALL=true ;;
                        *) print_warning "Option Android inconnue: $1" ;;
                    esac
                    shift
                done
                print_header "📱 BUILD ANDROID ($ANDROID_BUILD_MODE / $ANDROID_TARGET)"
                check_prerequisites
                build_crypto_core
                install_frontend_deps
                build_android_apk
                show_summary
                ;;
            --android-debug|-ad)
                ANDROID_BUILD_MODE="debug"
                ADB_INSTALL=true
                print_header "📱 BUILD ANDROID DEBUG + INSTALL ADB"
                check_prerequisites
                build_crypto_core
                install_frontend_deps
                build_android_apk
                show_summary
                ;;
            --clean|-c)
                print_header "🧹 NETTOYAGE"
                clean_build
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options générales:"
                echo "  -f,  --full            Build complet (clean + compile + bundle)"
                echo "  -q,  --quick           Build rapide (sans nettoyage)"
                echo "  -c,  --clean           Nettoyer les artefacts de build"
                echo "  -h,  --help            Afficher cette aide"
                echo ""
                echo "Options Android:"
                echo "  -a,  --android         Build Android APK (avec sous-options)"
                echo "       --debug  / -d     Mode debug (défaut)"
                echo "       --release / -r    Mode release (signé)"
                echo "       --target / -t     Architecture: aarch64|armv7|x86_64|universal"
                echo "       --install / -i    Installer via ADB après le build"
                echo "  -ad, --android-debug   Raccourci: Android debug + install ADB"
                echo ""
                echo "Exemples:"
                echo "  $0 --android --debug --target aarch64 --install"
                echo "  $0 --android-debug           # Équivalent du précédent"
                echo "  $0 --android --release       # APK signé pour distribution"
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
                ANDROID_BUILD_MODE="release"
                print_header "📱 BUILD ANDROID (release)"
                check_prerequisites
                build_crypto_core
                install_frontend_deps
                build_android_apk
                show_summary
                break
                ;;
            4)
                ANDROID_BUILD_MODE="debug"
                ADB_INSTALL=true
                print_header "📱 BUILD ANDROID (debug) + INSTALL ADB"
                check_prerequisites
                build_crypto_core
                install_frontend_deps
                build_android_apk
                show_summary
                break
                ;;
            5)
                clean_build
                break
                ;;
            6)
                collect_artifacts
                create_distribution_archives
                break
                ;;
            7)
                echo "Au revoir ! 👋"
                exit 0
                ;;
            *)
                print_error "Option invalide. Choisissez 1-7."
                ;;
        esac
    done
}

# Exécuter le programme principal
main "$@"

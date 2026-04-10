#!/bin/bash

# ============================================================================
# Script de build signé pour FluXlock (Cross-Platform)
# Compile l'application avec signature des mises à jour
# Compatible: macOS, Linux, Windows (Git Bash/WSL)
# ============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

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

# Détection du système
OS="$(uname -s)"
case "$OS" in
    Linux*)     MACHINE=Linux;;
    Darwin*)    MACHINE=Mac;;
    CYGWIN*)    MACHINE=Windows;;
    MINGW*)     MACHINE=Windows;;
    MSYS*)      MACHINE=Windows;;
    *)          MACHINE="UNKNOWN:$OS"
esac

# Vérifier que la clé privée existe
# Sur Windows (Git Bash), $HOME pointe généralement vers /c/Users/NomUtilisateur
PRIVATE_KEY_PATH="$HOME/.tauri/fluxlock.key"

if [ ! -f "$PRIVATE_KEY_PATH" ]; then
    print_error "Clé privée non trouvée: $PRIVATE_KEY_PATH"
    echo ""
    echo "Pour générer une nouvelle clé:"
    echo "  npx @tauri-apps/cli signer generate -w ~/.tauri/fluxlock.key"
    echo ""
    exit 1
fi

print_header "🔐 Build Signé FluXlock v2.0.0 ($MACHINE)"

print_info "Clé privée trouvée: $PRIVATE_KEY_PATH"
echo ""

# Définir les variables d'environnement
export TAURI_PRIVATE_KEY="$PRIVATE_KEY_PATH"

# Demander le mot de passe (ou utiliser la variable si déjà définie)
if [ -z "$TAURI_KEY_PASSWORD" ]; then
    print_warning "Le mot de passe de la clé sera demandé pendant le build"
    print_info "Pour éviter cela, définissez: export TAURI_KEY_PASSWORD=votre_mot_de_passe"
    echo ""
fi

# Choix du type de build
echo "Choisissez le type de build:"
echo "1. Build complet (clean + compile)"
echo "2. Build rapide (sans nettoyage)"
echo "3. Annuler"
echo ""
read -p "Votre choix (1-3): " choice
echo ""

case "$choice" in
    1)
        print_header "🔨 Build Complet avec Signature"
        cd "$(dirname "$0")"

        # Auto-fix tauri.conf.json
        if command -v python3 &> /dev/null; then
            python3 fix_tauri_conf.py
        elif command -v python &> /dev/null; then
            python fix_tauri_conf.py
        fi
        
        print_info "Nettoyage..."
        # Correction: Cibler explicitement le Cargo.toml dans src-tauri
        if [ -f "src-tauri/Cargo.toml" ]; then
            cargo clean --manifest-path src-tauri/Cargo.toml
        else
            print_warning "Cargo.toml non trouvé dans src-tauri, nettoyage cargo ignoré."
        fi
        rm -rf ../dist
        
        print_info "Compilation..."
        if [ ! -d "node_modules" ]; then
            print_warning "node_modules non trouvé. Installation des dépendances..."
            npm install
        fi
        
        # Vérifier si la commande tauri est disponible via npm
        if npm run tauri -- --version &> /dev/null; then
            npm run tauri build
        else
            print_warning "Commande 'npm run tauri' échouée. Tentative avec npx @tauri-apps/cli..."
            npx @tauri-apps/cli build
        fi
        
        if [ $? -eq 0 ]; then
            print_success "Build complet terminé !"
        else
            print_error "Le build a échoué."
            if command -v python3 &> /dev/null; then
                print_info "Vérification de la clé privée..."
                python3 check_key.py
            fi
            exit 1
        fi
        ;;
    2)
        print_header "⚡ Build Rapide avec Signature"
        cd "$(dirname "$0")"

        # Auto-fix tauri.conf.json
        if command -v python3 &> /dev/null; then
            python3 fix_tauri_conf.py
        elif command -v python &> /dev/null; then
            python fix_tauri_conf.py
        fi
        
        print_info "Compilation..."
        if [ ! -d "node_modules" ]; then
            print_warning "node_modules non trouvé. Installation des dépendances..."
            npm install
        fi
        
        # Vérifier si la commande tauri est disponible via npm
        if npm run tauri -- --version &> /dev/null; then
            npm run tauri build
        else
            print_warning "Commande 'npm run tauri' échouée. Tentative avec npx @tauri-apps/cli..."
            npx @tauri-apps/cli build
        fi
        
        if [ $? -eq 0 ]; then
            print_success "Build rapide terminé !"
        else
            print_error "Le build a échoué."
            if command -v python3 &> /dev/null; then
                print_info "Vérification de la clé privée..."
                python3 check_key.py
            fi
            exit 1
        fi
        ;;
    3)
        print_info "Opération annulée"
        exit 0
        ;;
    *)
        print_error "Choix invalide"
        exit 1
        ;;
esac

# Vérifier que la signature a été créée
echo ""
print_header "📦 Résultats du Build"

# Recherche du fichier de signature selon l'OS
SIG_FILE=""
if [ "$MACHINE" == "Mac" ]; then
    SIG_FILE=$(ls src-tauri/target/release/bundle/macos/*.app.tar.gz.sig 2>/dev/null | head -n 1)
elif [ "$MACHINE" == "Windows" ]; then
    # Sur Windows, Tauri produit souvent des .zip.sig pour les updates
    SIG_FILE=$(ls src-tauri/target/release/bundle/*/*.zip.sig 2>/dev/null | head -n 1)
else
    # Linux
    SIG_FILE=$(ls src-tauri/target/release/bundle/*/*.tar.gz.sig 2>/dev/null | head -n 1)
fi

if [ -n "$SIG_FILE" ] && [ -f "$SIG_FILE" ]; then
    print_success "Signature créée: $SIG_FILE"
    
    echo ""
    print_info "Fichiers de distribution:"
    echo ""
    
    if [ "$MACHINE" == "Mac" ]; then
        ls -lh src-tauri/target/release/bundle/macos/*.tar.gz*
        ls -lh src-tauri/target/release/bundle/dmg/*.dmg 2>/dev/null || true
    elif [ "$MACHINE" == "Windows" ]; then
        ls -lh src-tauri/target/release/bundle/*/*.zip*
        ls -lh src-tauri/target/release/bundle/msi/*.msi 2>/dev/null || true
        ls -lh src-tauri/target/release/bundle/nsis/*.exe 2>/dev/null || true
    else
        ls -lh src-tauri/target/release/bundle/*/*.tar.gz*
        ls -lh src-tauri/target/release/bundle/deb/*.deb 2>/dev/null || true
        ls -lh src-tauri/target/release/bundle/appimage/*.AppImage 2>/dev/null || true
    fi
    
    echo ""
    print_success "Build signé réussi ! 🎉"
    echo ""
    print_info "Pour distribuer:"
    echo "  1. Récupérez l'archive (.tar.gz ou .zip) et le fichier .sig"
    echo "  2. Créez un manifest JSON (voir SIGNING.md)"
    echo ""
else
    print_error "La signature n'a pas été trouvée."
    print_warning "Vérifiez que TAURI_PRIVATE_KEY et TAURI_KEY_PASSWORD sont corrects"
    exit 1
fi

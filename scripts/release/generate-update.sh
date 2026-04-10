#!/bin/bash

# ============================================================================
# Script de Génération de Mise à Jour pour FluXlock
# Crée automatiquement le manifest JSON pour le serveur de mises à jour
# ============================================================================

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
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
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# Variables
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TAURI_DIR="$SCRIPT_DIR/src-tauri"
BUNDLE_DIR="$TAURI_DIR/target/release/bundle"
OUTPUT_DIR="$PROJECT_ROOT/release-packages"

# Lire la version depuis package.json
VERSION=$(node -p "require('$SCRIPT_DIR/package.json').version")

print_header "🚀 Générateur de Mise à Jour FluXlock v$VERSION"

# Vérifier que les bundles existent
if [ ! -d "$BUNDLE_DIR" ]; then
    print_error "Aucun bundle trouvé. Vous devez d'abord compiler l'application."
    echo ""
    echo "Exécutez d'abord :"
    echo "  ./build-signed.sh"
    echo ""
    exit 1
fi

# Créer le dossier de sortie
mkdir -p "$OUTPUT_DIR"

print_info "Recherche des bundles compilés..."
echo ""

# Fonction pour extraire la signature d'un fichier .sig
get_signature() {
    local sig_file="$1"
    if [ -f "$sig_file" ]; then
        cat "$sig_file"
    else
        echo "SIGNATURE_MANQUANTE"
    fi
}

# Fonction pour obtenir la taille d'un fichier
get_file_size() {
    local file="$1"
    if [ -f "$file" ]; then
        du -h "$file" | cut -f1
    else
        echo "N/A"
    fi
}

# Détecter la plateforme et l'architecture
OS_TYPE=$(uname -s)
ARCH_TYPE=$(uname -m)

# Mapper vers les identifiants Tauri
case "$OS_TYPE" in
    Darwin)
        if [ "$ARCH_TYPE" = "arm64" ]; then
            PLATFORM="darwin-aarch64"
            BUNDLE_PATH="$BUNDLE_DIR/macos"
            BUNDLE_FILE="FluXlock.app.tar.gz"
        else
            PLATFORM="darwin-x86_64"
            BUNDLE_PATH="$BUNDLE_DIR/macos"
            BUNDLE_FILE="FluXlock.app.tar.gz"
        fi
        ;;
    Linux)
        PLATFORM="linux-x86_64"
        BUNDLE_PATH="$BUNDLE_DIR/appimage"
        BUNDLE_FILE="fluxlock_${VERSION}_amd64.AppImage.tar.gz"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        PLATFORM="windows-x86_64"
        BUNDLE_PATH="$BUNDLE_DIR/msi"
        BUNDLE_FILE="FluXlock_${VERSION}_x64_en-US.msi.zip"
        ;;
    *)
        print_error "Système d'exploitation non supporté: $OS_TYPE"
        exit 1
        ;;
esac

print_info "Plateforme détectée: $PLATFORM"
print_info "Architecture: $ARCH_TYPE"
echo ""

# Vérifier que le bundle existe
BUNDLE_FULL_PATH="$BUNDLE_PATH/$BUNDLE_FILE"
SIG_FILE="$BUNDLE_FULL_PATH.sig"

if [ ! -f "$BUNDLE_FULL_PATH" ]; then
    print_error "Bundle non trouvé: $BUNDLE_FULL_PATH"
    echo ""
    print_info "Bundles disponibles dans $BUNDLE_DIR:"
    find "$BUNDLE_DIR" -name "*.tar.gz" -o -name "*.zip" -o -name "*.AppImage" 2>/dev/null || echo "Aucun"
    exit 1
fi

if [ ! -f "$SIG_FILE" ]; then
    print_error "Fichier de signature non trouvé: $SIG_FILE"
    echo ""
    print_warning "Le bundle n'a pas été signé. Relancez le build avec signature :"
    echo "  export TAURI_PRIVATE_KEY=~/.tauri/fluxlock.key"
    echo "  npm run tauri build"
    exit 1
fi

print_success "Bundle trouvé: $(basename $BUNDLE_FULL_PATH) ($(get_file_size $BUNDLE_FULL_PATH))"
print_success "Signature trouvée: $(basename $SIG_FILE)"
echo ""

# Extraire la signature
SIGNATURE=$(get_signature "$SIG_FILE")

# Demander l'URL de base pour le serveur
print_header "📡 Configuration du Serveur"
echo "Entrez l'URL de base où les fichiers seront hébergés"
echo "Exemple: https://releases.fluxlock.com"
echo "         https://cdn.exemple.com/fluxlock"
echo "         https://github.com/user/repo/releases/download/v$VERSION"
echo ""
read -p "URL de base: " BASE_URL

if [ -z "$BASE_URL" ]; then
    BASE_URL="https://releases.fluxlock.example.com"
    print_warning "Aucune URL fournie, utilisation de l'exemple: $BASE_URL"
fi

# Enlever le slash final si présent
BASE_URL="${BASE_URL%/}"

# Construire l'URL complète
DOWNLOAD_URL="$BASE_URL/$BUNDLE_FILE"

print_info "URL de téléchargement: $DOWNLOAD_URL"
echo ""

# Demander les notes de version
print_header "📝 Notes de Version"
echo "Entrez les notes de version (ou appuyez sur Entrée pour utiliser les notes par défaut)"
echo "Conseil: Décrivez les nouvelles fonctionnalités, corrections et améliorations"
echo ""
read -p "Notes de version: " RELEASE_NOTES

if [ -z "$RELEASE_NOTES" ]; then
    RELEASE_NOTES="FluXlock v$VERSION

🔒 Fonctionnalités de sécurité:
- Chiffrement AES-256-GCM
- Protection anti-brute force
- Détection ransomware
- Système de menaces avancé

🚀 Améliorations:
- Interface utilisateur modernisée
- Performance optimisée
- Backup/restore intégré

📝 Corrections:
- Stabilité améliorée
- Tests validés"
fi

# Date de publication (ISO 8601)
PUB_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Créer le manifest JSON
MANIFEST_FILE="$OUTPUT_DIR/latest-$PLATFORM.json"

print_header "📦 Génération du Manifest"

cat > "$MANIFEST_FILE" << EOF
{
  "version": "$VERSION",
  "notes": "$RELEASE_NOTES",
  "pub_date": "$PUB_DATE",
  "platforms": {
    "$PLATFORM": {
      "signature": "$SIGNATURE",
      "url": "$DOWNLOAD_URL"
    }
  }
}
EOF

print_success "Manifest créé: $MANIFEST_FILE"
echo ""

# Copier les fichiers dans le dossier de release
print_header "📁 Préparation des Fichiers de Release"

cp "$BUNDLE_FULL_PATH" "$OUTPUT_DIR/"
cp "$SIG_FILE" "$OUTPUT_DIR/"

print_success "Fichiers copiés dans: $OUTPUT_DIR"
echo ""
ls -lh "$OUTPUT_DIR/"
echo ""

# Créer un README pour le dossier release
README_FILE="$OUTPUT_DIR/README.md"
cat > "$README_FILE" << 'EOF'
# 📦 Package de Release FluXlock

Ce dossier contient tous les fichiers nécessaires pour distribuer la mise à jour.

## 📋 Fichiers

- `*.tar.gz` / `*.zip` / `*.AppImage` - Package de l'application
- `*.sig` - Signature cryptographique
- `latest-*.json` - Manifest de mise à jour

## 🚀 Déploiement

### 1. Upload sur Serveur/CDN

Uploadez les fichiers suivants sur votre serveur :

```bash
# Package de l'application
scp *.tar.gz user@server:/var/www/releases/

# Signature
scp *.sig user@server:/var/www/releases/
```

### 2. Configurer le Serveur de Mise à Jour

Le manifest JSON doit être accessible à l'URL configurée dans `tauri.conf.json` :

```
https://api.fluxlock.example.com/updates/{target}/{current_version}
```

Exemple avec nginx :

```nginx
location /updates/ {
    root /var/www/releases;
    add_header Content-Type application/json;
    
    # Retourner le manifest selon la plateforme
    rewrite ^/updates/darwin-aarch64/(.*)$ /latest-darwin-aarch64.json break;
    rewrite ^/updates/darwin-x86_64/(.*)$ /latest-darwin-x86_64.json break;
    rewrite ^/updates/linux-x86_64/(.*)$ /latest-linux-x86_64.json break;
    rewrite ^/updates/windows-x86_64/(.*)$ /latest-windows-x86_64.json break;
}
```

### 3. Vérification

Testez que l'URL fonctionne :

```bash
curl https://api.fluxlock.example.com/updates/darwin-aarch64/2.0.0
```

Doit retourner le contenu du manifest JSON.

### 4. GitHub Releases (Optionnel)

Si vous utilisez GitHub Releases :

1. Créez un nouveau release sur GitHub
2. Uploadez les fichiers `.tar.gz` et `.sig`
3. Copiez l'URL du fichier depuis la release
4. Mettez à jour le manifest avec cette URL

## 🔒 Sécurité

- ✅ Ne modifiez JAMAIS les fichiers `.sig`
- ✅ Vérifiez l'intégrité après upload
- ✅ Utilisez HTTPS obligatoirement
- ✅ Conservez les anciennes versions pour rollback

## 📱 Test de Mise à Jour

1. Installez l'ancienne version de FluXlock
2. Lancez l'application
3. L'application devrait détecter la mise à jour
4. Suivez le processus d'installation
5. Vérifiez la nouvelle version après redémarrage

## 🆘 Dépannage

### Mise à jour non détectée
- Vérifier que l'URL dans `tauri.conf.json` est correcte
- Vérifier que le serveur retourne bien le JSON
- Vérifier que la version dans le manifest > version installée

### Erreur de signature
- Vérifier que la clé publique dans `tauri.conf.json` correspond
- Vérifier que le fichier `.sig` n'a pas été modifié
- Recompiler avec la bonne clé privée

### Erreur de téléchargement
- Vérifier que l'URL du package est accessible
- Vérifier les permissions CORS si nécessaire
- Vérifier la taille du fichier
EOF

print_success "README créé pour la release"
echo ""

# Résumé final
print_header "✅ Génération Terminée"

echo -e "${CYAN}📊 Résumé:${NC}"
echo ""
echo "  Version: $VERSION"
echo "  Plateforme: $PLATFORM"
echo "  Bundle: $(basename $BUNDLE_FULL_PATH)"
echo "  Taille: $(get_file_size $BUNDLE_FULL_PATH)"
echo "  Signature: ✅ Présente"
echo "  Manifest: latest-$PLATFORM.json"
echo "  URL: $DOWNLOAD_URL"
echo ""

print_header "📤 Prochaines Étapes"

echo "1. Vérifiez les fichiers dans : $OUTPUT_DIR"
echo ""
echo "2. Uploadez les fichiers sur votre serveur :"
echo "   - $(basename $BUNDLE_FULL_PATH)"
echo "   - $(basename $SIG_FILE)"
echo ""
echo "3. Configurez votre serveur pour servir le manifest JSON :"
echo "   URL: https://api.fluxlock.example.com/updates/$PLATFORM/{version}"
echo "   Contenu: $MANIFEST_FILE"
echo ""
echo "4. Testez la mise à jour :"
echo "   curl $BASE_URL/$BUNDLE_FILE"
echo ""

print_success "Package de release prêt ! 🎉"
echo ""
print_info "Consultez $OUTPUT_DIR/README.md pour plus de détails"

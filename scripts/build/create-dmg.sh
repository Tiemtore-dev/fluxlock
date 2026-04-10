#!/bin/bash

# Script pour créer un DMG d'installation propre pour SecureVault
# Usage: ./create-dmg.sh

set -e

echo "🔨 Création du DMG d'installation pour SecureVault..."

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Variables
APP_NAME="SecureVault"
VERSION="2.0.0"
APP_PATH="tauri-desktop/src-tauri/target/release/bundle/macos/${APP_NAME}.app"
DMG_NAME="${APP_NAME}_${VERSION}_macOS.dmg"
DMG_PATH="tauri-desktop/src-tauri/target/release/bundle/dmg/${DMG_NAME}"
VOLUME_NAME="SecureVault Installer"
TMP_DMG="tmp_${DMG_NAME}"

# Vérification que l'app existe
if [ ! -d "$APP_PATH" ]; then
    echo -e "${RED}❌ Erreur: L'application ${APP_PATH} n'existe pas${NC}"
    echo "   Exécutez d'abord: cd tauri-desktop && npm run tauri build"
    exit 1
fi

echo -e "${BLUE}📦 Application trouvée: ${APP_PATH}${NC}"

# Créer le dossier de destination
mkdir -p "$(dirname "$DMG_PATH")"

# Supprimer les anciens DMG temporaires
rm -f "$TMP_DMG" "$DMG_PATH"

echo -e "${BLUE}🔧 Création du DMG temporaire...${NC}"

# Créer un DMG temporaire avec hdiutil
hdiutil create -volname "$VOLUME_NAME" \
    -srcfolder "$APP_PATH" \
    -ov -format UDRW \
    "$TMP_DMG"

echo -e "${BLUE}📝 Ajout du lien vers Applications...${NC}"

# Monter le DMG temporaire
MOUNT_DIR=$(hdiutil attach -readwrite -noverify -noautoopen "$TMP_DMG" | \
    egrep '^/dev/' | sed 1q | awk '{print $3}')

if [ -z "$MOUNT_DIR" ]; then
    echo -e "${RED}❌ Erreur: Impossible de monter le DMG${NC}"
    exit 1
fi

echo -e "${BLUE}   Monté sur: ${MOUNT_DIR}${NC}"

# Créer un lien symbolique vers /Applications
ln -s /Applications "$MOUNT_DIR/Applications"

# Attendre que les changements soient écrits
sync
sleep 2

# Démonter le DMG temporaire
hdiutil detach "$MOUNT_DIR"

echo -e "${BLUE}🗜️  Compression du DMG final...${NC}"

# Convertir en DMG final compressé
hdiutil convert "$TMP_DMG" \
    -format UDZO \
    -imagekey zlib-level=9 \
    -o "$DMG_PATH"

# Nettoyer le DMG temporaire
rm -f "$TMP_DMG"

# Vérifier que le DMG existe
if [ -f "$DMG_PATH" ]; then
    SIZE=$(du -h "$DMG_PATH" | cut -f1)
    echo ""
    echo -e "${GREEN}✅ DMG créé avec succès !${NC}"
    echo -e "${GREEN}   Fichier : ${DMG_PATH}${NC}"
    echo -e "${GREEN}   Taille  : ${SIZE}${NC}"
    echo ""
    echo -e "${BLUE}📋 Instructions d'installation :${NC}"
    echo "   1. Double-cliquez sur ${DMG_NAME}"
    echo "   2. Glissez SecureVault.app vers le dossier Applications"
    echo "   3. Éjectez l'image disque"
    echo "   4. Lancez SecureVault depuis Launchpad ou Applications"
    echo ""
    echo -e "${BLUE}💡 Si macOS bloque l'ouverture :${NC}"
    echo "   • Clic droit sur l'app → Ouvrir"
    echo "   • Ou exécutez : xattr -cr /Applications/SecureVault.app"
    echo ""
else
    echo -e "${RED}❌ Erreur: Le DMG n'a pas été créé${NC}"
    exit 1
fi

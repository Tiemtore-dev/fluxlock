#!/bin/bash

# Script simplifié pour créer un DMG pour SecureVault
# Usage: ./create-simple-dmg.sh

set -e

echo "🔨 Création du DMG d'installation pour SecureVault..."

# Variables
APP_NAME="SecureVault"
VERSION="2.0.0"
APP_PATH="tauri-desktop/src-tauri/target/release/bundle/macos/${APP_NAME}.app"
DMG_NAME="${APP_NAME}_${VERSION}_macOS_Installer.dmg"
OUTPUT_DIR="tauri-desktop/src-tauri/target/release/bundle/dmg"
DMG_PATH="${OUTPUT_DIR}/${DMG_NAME}"
SOURCE_DIR="/tmp/securevault-dmg-source"

# Vérification que l'app existe
if [ ! -d "$APP_PATH" ]; then
    echo "❌ Erreur: L'application ${APP_PATH} n'existe pas"
    exit 1
fi

echo "📦 Application trouvée: ${APP_PATH}"

# Créer un dossier temporaire pour le contenu du DMG
rm -rf "$SOURCE_DIR"
mkdir -p "$SOURCE_DIR"

# Copier l'application
echo "📋 Copie de l'application..."
cp -R "$APP_PATH" "$SOURCE_DIR/"

# Créer un alias vers /Applications
echo "🔗 Création du lien vers Applications..."
ln -s /Applications "$SOURCE_DIR/Applications"

# Créer le dossier de destination
mkdir -p "$OUTPUT_DIR"

# Supprimer l'ancien DMG s'il existe
rm -f "$DMG_PATH"

echo "🗜️  Création du DMG..."
# Créer le DMG directement à partir du dossier source
hdiutil create -volname "SecureVault Installer" \
    -srcfolder "$SOURCE_DIR" \
    -ov \
    -format UDZO \
    -imagekey zlib-level=9 \
    "$DMG_PATH"

# Nettoyer
rm -rf "$SOURCE_DIR"

# Vérifier le résultat
if [ -f "$DMG_PATH" ]; then
    SIZE=$(du -h "$DMG_PATH" | cut -f1)
    echo ""
    echo "✅ DMG créé avec succès !"
    echo "   📁 Fichier : ${DMG_PATH}"
    echo "   📊 Taille  : ${SIZE}"
    echo ""
    echo "📋 Instructions d'installation :"
    echo "   1. Double-cliquez sur ${DMG_NAME}"
    echo "   2. Glissez SecureVault.app vers Applications"
    echo "   3. Lancez SecureVault depuis Launchpad"
    echo ""
    echo "💡 Si macOS bloque l'app au premier lancement :"
    echo "   Faites : Clic droit sur l'app → Ouvrir"
    echo ""
else
    echo "❌ Erreur: Le DMG n'a pas été créé"
    exit 1
fi

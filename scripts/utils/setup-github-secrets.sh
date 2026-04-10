#!/bin/bash

# Script pour afficher les informations nécessaires aux secrets GitHub

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  🔐 Configuration des Secrets GitHub pour FluXlock            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Vérifier que la clé existe
KEY_PATH="$HOME/.tauri/fluxlock.key"
if [ ! -f "$KEY_PATH" ]; then
    echo "❌ Erreur : Clé de signature non trouvée"
    echo ""
    echo "Générez d'abord une clé avec :"
    echo "  npx @tauri-apps/cli signer generate -w ~/.tauri/fluxlock.key"
    exit 1
fi

echo "✅ Clé de signature trouvée : $KEY_PATH"
echo ""

# Afficher le contenu de la clé
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 TAURI_PRIVATE_KEY (Copiez tout le contenu ci-dessous)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
cat "$KEY_PATH"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Demander le mot de passe
echo "🔑 TAURI_KEY_PASSWORD"
echo ""
echo -n "Entrez votre mot de passe de clé (ne sera pas affiché) : "
read -s KEY_PASSWORD
echo ""
echo ""

if [ -z "$KEY_PASSWORD" ]; then
    echo "⚠️  Aucun mot de passe entré (si votre clé n'a pas de mot de passe, ignorez ce message)"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📝 Instructions pour ajouter les secrets sur GitHub"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Ouvrez cette URL dans votre navigateur :"
echo "   https://github.com/Tiemtore-dev/fluxlock/settings/secrets/actions"
echo ""
echo "2. Cliquez sur 'New repository secret'"
echo ""
echo "3. Ajoutez le premier secret :"
echo "   Name  : TAURI_PRIVATE_KEY"
echo "   Value : Copiez tout le contenu affiché ci-dessus (entre les lignes)"
echo ""
echo "4. Cliquez sur 'Add secret'"
echo ""
echo "5. Cliquez à nouveau sur 'New repository secret'"
echo ""
echo "6. Ajoutez le deuxième secret :"
echo "   Name  : TAURI_KEY_PASSWORD"
echo "   Value : $KEY_PASSWORD"
echo ""
echo "7. Cliquez sur 'Add secret'"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "✅ Une fois les secrets ajoutés, vous pourrez publier des releases avec :"
echo ""
echo "   npm version patch"
echo "   git push --tags"
echo ""
echo "GitHub Actions compilera automatiquement pour toutes les plateformes !"
echo ""

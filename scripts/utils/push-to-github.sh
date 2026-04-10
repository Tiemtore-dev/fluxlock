#!/bin/bash

# Script pour pusher SecureVault sur GitHub
# Exécutez ce script après avoir créé le dépôt sur GitHub

set -e

echo "🚀 Push SecureVault vers GitHub"
echo "================================"
echo ""

# Vérifie si le remote existe déjà
if git remote | grep -q "origin"; then
    echo "✓ Remote 'origin' existe déjà"
    git remote -v
else
    echo "📍 Ajout du remote GitHub..."
    read -p "Entrez l'URL de votre dépôt GitHub (ex: https://github.com/Tiemtore-dev/fluxlock.git): " REPO_URL
    git remote add origin "$REPO_URL"
    echo "✓ Remote ajouté"
fi

echo ""
echo "📦 Renommage de la branche en 'main'..."
git branch -M main

echo ""
echo "⬆️  Push vers GitHub..."
git push -u origin main

echo ""
echo "✅ Succès! Votre projet est maintenant sur GitHub"
echo ""
echo "🔗 Étapes suivantes:"
echo "1. Visitez https://github.com/Tiemtore-dev/fluxlock"
echo "2. Ajoutez une belle description et des tags"
echo "3. Les GitHub Actions vont compiler automatiquement pour Windows, macOS et Linux"
echo "4. Créez un tag pour déclencher une release: git tag v2.0.0 && git push origin v2.0.0"
echo ""
echo "📊 Les builds seront disponibles dans Actions > Build Multi-Platform"

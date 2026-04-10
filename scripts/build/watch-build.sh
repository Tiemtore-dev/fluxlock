#!/bin/bash

# Script pour suivre le build GitHub Actions

echo "🔍 Suivi du build GitHub Actions pour SecureVault v2.0.0"
echo "=========================================================="
echo ""

# Attendre que le build démarre
echo "⏳ Attente du démarrage du build..."
sleep 5

# ID du dernier run
RUN_ID=$(gh run list --limit 1 --json databaseId --jq '.[0].databaseId')

echo "📊 Run ID: $RUN_ID"
echo ""

# URL du run
echo "🔗 Voir le build en ligne:"
echo "   https://github.com/Tiemtore-dev/fluxlock/actions/runs/$RUN_ID"
echo ""

# Suivre le build
echo "👀 Suivi en temps réel (Ctrl+C pour quitter):"
echo ""

gh run watch $RUN_ID --interval 30

# Vérifier le résultat
echo ""
echo "📈 Résultat final:"
gh run view $RUN_ID

# Si succès, afficher les artifacts
if gh run view $RUN_ID --json conclusion --jq '.conclusion' | grep -q "success"; then
    echo ""
    echo "✅ Build réussi! Téléchargement des artifacts disponible:"
    echo ""
    gh run view $RUN_ID --log | grep "Upload artifacts" || echo "Vérifiez les Releases sur GitHub"
    echo ""
    echo "🎉 Une release a été créée automatiquement:"
    echo "   https://github.com/Tiemtore-dev/fluxlock/releases/tag/v2.0.0"
fi

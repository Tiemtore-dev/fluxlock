# Vérification du multi-coffre — 22 novembre 2026

Implémentation locale terminée et relue. Voir [le modèle et la migration](multi-vault.md).

## Résultats exécutés

| Contrôle | Résultat | Preuve et portée |
| --- | --- | --- |
| Compilation TypeScript et Vite | Réussite | `npm run build` ; aucun ajout de dépendance applicative. |
| Compilation Rust hors configuration de test | Réussite | `cargo check --locked --lib`, depuis `tauri-desktop/src-tauri`. Trois avertissements de code inutilisé restent présents. |
| Tests applicatifs Rust | Réussite | `RUST_MIN_STACK=16777216 CARGO_INCREMENTAL=0 cargo test --locked --lib` : **134 réussis, 0 échec**. |
| Parcours multi-coffres | Réussite | `tests/multi-vault-ui.mjs`, à 320, 768 et 1280 px. |
| Parcours existants | Réussite | `tests/vault-ui.mjs`, de 320 à 1280 px, thèmes clair et sombre, biométrie macOS/Android simulée. |
| Format des nouveaux modules Rust | Réussite | `rustfmt --check` sur `vault.rs` et `vault/tests.rs`. |
| Relecture et espaces du diff | Réussite | `git diff --check`, inventaire des 82 commandes existantes et revue des quatre nouvelles commandes du catalogue. |
| Couverture instrumentée | Non mesurée | Le nombre de tests ne constitue pas un pourcentage de couverture. |
| Capteurs et paquets des autres plateformes | Non exécuté | Validation sur appareils réels nécessaire avant publication. |

## Scénarios vérifiés

Les tests Rust utilisent des bases SQLite et de la cryptographie réelles dans des répertoires temporaires :

- adoption du coffre historique sans changement de ses emplacements ;
- refus d’ouvrir/créer/sélectionner un deuxième coffre tant qu’une session existe ;
- séparation des données et des clés malgré des identifiants d’utilisateur locaux identiques ;
- refus d’un mauvais mot de passe, d’un ancien contexte, d’une requête visant un autre coffre et d’une ancienne demande de verrouillage ;
- attente des opérations en cours avant la transition exclusive ;
- nettoyage des clés de session et fichiers déchiffrés temporaires ;
- annulation d’une création invalide, renommage persistant et redémarrage verrouillé ;
- refus des identifiants contenant des chemins, catalogues corrompus et liens symboliques concernés ;
- verrou OS du catalogue, permissions privées sur Unix ;
- réinitialisation du coffre historique conservant catalogue, sauvegardes et autres coffres ;
- restauration du contenu A dans B sans modifier A ni l’identité de B ;
- conservation de la compatibilité des métadonnées des anciennes sauvegardes ;
- accès aux autres coffres lorsque la dernière base sélectionnée est absente ;
- comptes de trousseau et compteurs biométriques séparés par coffre.

Les tests navigateur simulent l’IPC et vérifient les parcours correspondants. Ils vérifient également le blocage de la sélection pendant un verrouillage retardé, les caches de vue, l’effacement du mot de passe saisi, le presse-papiers simulé, la reconfiguration après réinitialisation et la suppression de l’alias biométrique Android simulé. Un sélecteur d’export laissé ouvert dans A puis terminé dans B ne provoque aucune commande de déchiffrement.

La revue du code couvre aussi les tâches réseau détenues et arrêtées, le renouvellement et le retrait des credentials biométriques, la récupération après échec de restauration, le rechargement de la webview et le nettoyage des anciens caches de session du trousseau. La biométrie matérielle et les permissions de chaque système restent à vérifier sur leurs plateformes ; les simulations ne remplacent pas ces essais.

## Auto-évaluation du livrable

| Axe | Note / 5 | Éléments concrets et limite |
| --- | --- | --- |
| Exactitude | 4 | Compilations et 134 tests Rust réussis ; les branches Windows/Linux/Android n’ont pas été compilées ici. |
| Complétude | 4 | Création, nom, sélection, exclusivité, migration, restauration et réinitialisation couverts ; essais matériels non réalisés. |
| Clarté | 4 | Modèle, stockage et invariants documentés ; l’IPC conserve des noms historiques pour l’intégration existante. |
| Utilisation | 4 | Source exécutable avec les commandes documentées ; aucun installeur ou paquet de publication produit. |
| Concision | 4 | Contrôle centralisé du contexte, types de contenu conservés ; l’adaptation touche de nombreuses signatures IPC. |

Moyenne : 4,0/5. Les vérifications suivantes concernent les paquets natifs et les vrais capteurs avant publication. Cette appréciation porte sur les preuves locales ; elle n’équivaut pas à un audit de sécurité indépendant ou à une certification.

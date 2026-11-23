# Publication de FluXlock 2.4.0

Cette livraison regroupe les notes chiffrées et leurs pièces jointes, l’isolation des coffres, l’extension Chromium 0.4.0 et le relais natif 0.2.0. Le canal d’extension exige un nouvel appairage ; son [profil cryptographique et ses limites](autofill-post-quantum-v2.md) restent documentés séparément.

## Déclenchement et protections

Une PR vers `main` déclenche `Build Multi-Platform` : noyau crypto, applications desktop/Android, tests du coffre, et tests de l’extension/du relais sur Linux, macOS et Windows. La PR ne publie aucune version et n’accède pas aux secrets de publication.

Après fusion, le push de `main` relance ces contrôles. Le job de release ne démarre que si les deux workflows réutilisés réussissent. Il valide la concordance des versions npm, npm lockfile, Cargo, Cargo lockfile et Tauri. Il vérifie que le commit est toujours le `main` distant courant et ne crée `v2.4.0` que si le tag n’existe pas. Aucun tag n’est déplacé ou forcé. Les commits ultérieurs sans changement de version ne republient pas la même version.

Le tag créé par `GITHUB_TOKEN` ne déclenche pas un second workflow GitHub ; l’invocation courante poursuit elle-même la release. Le déclenchement historique par push explicite d’un tag correspondant à la version reste disponible, ainsi que la relance GitHub d’une exécution ayant échoué.

Tous les jobs de release sont liés au même SHA validé. Les installeurs desktop, l’APK signé, les quatre relais (macOS ARM64/Intel, Windows x64, Linux x64) et l’extension doivent être construits avant publication sur [fluxlock-releases](https://github.com/Tiemtore-dev/fluxlock-releases/releases). Le manifeste de mise à jour conserve les signatures des paquets Tauri. `SHA256SUMS` couvre les assets de release, sans remplacer leurs signatures. Un échec de build empêche la publication finale et le remplacement de `latest.json`.

Le relais n’est pas enregistré automatiquement. Ses archives incluent le binaire, `install-browser-host.py` et les instructions d’installation avec simulation par défaut. L’extension reste une extension à décompresser, sans publication Chrome Web Store. Android reçoit l’application ; AutofillService Android reste hors de cette livraison.

## Vérification avant PR

- Validation statique des quatre workflows par actionlint 1.7.12 (sans shellcheck/pyflakes locaux).
- Sept tests des gardes de release : versions cohérentes/incohérentes, nouveau main, main dépassé, tag existant, relance explicite, mauvais événement/branche/tag.
- Build frontend 2.4.0 et construction/contrôle des archives à partir du vrai relais macOS ARM64 et de l’extension compilée.
- Les résultats fonctionnels de la passe précédente sont conservés : 156 tests du coffre, 10 du protocole, 11 de l’extension, 2 du relais, tests Chromium/Brave, contrôles de compilation Windows/Linux. La nouvelle CI devra qualifier les nouveaux paquets sur ses runners ; ces résultats locaux ne prouvent pas une release distante réussie.

Les valeurs des secrets GitHub ne sont jamais téléchargées. Les noms requis restent ceux du circuit existant : signatures Tauri, signature APK et `RELEASES_PAT` pour le dépôt de téléchargement.

## Corrections après la première CI de la PR

La première exécution a réussi pour le coffre Linux, le noyau crypto et l’extension macOS/Windows. Trois problèmes distincts ont été identifiés dans ses logs :

- Android compilait le pont Chromium et ses fenêtres desktop, avec cinq erreurs de méthodes Tauri indisponibles. Le module desktop et ses huit commandes sont maintenant exclus des builds mobiles. Le service mobile ne conserve que l’interface de cycle de vie nécessaire au verrouillage/restauration et refuse toute commande `autofill_` ; aucun listener ou registre navigateur n’y est ouvert. Deux tests de ce contrat sont aussi exécutés sur desktop.
- Les tests Windows s’arrêtaient dans le chargeur avant leur exécution (`0xc0000139`). Le [problème Tauri de manifeste Common Controls v6](https://github.com/tauri-apps/tauri/issues/13419) correspond à ce cas. Le build embarque désormais le manifeste dans tous les artefacts liés, dont les tests, et désactive la copie de ressource par défaut pour éviter un doublon. Les tests restent actifs.
- Le test Linux détectait un débordement horizontal à 200 % de taille de texte. Les blocs et boutons permettent maintenant la réduction et le retour à la ligne ; la régression force aussi des barres de défilement classiques et produit une capture ainsi qu’un diagnostic détaillé des éléments débordants.

Les deux jobs macOS de l’application étaient en file d’attente sur `macos-15`, sans runner attribué ni étape exécutée. Ils utilisent désormais `macos-latest`, comme le job d’extension macOS qui avait réussi (image macOS 26 ARM64 dans cette exécution). Les cibles de compilation ARM64 et Intel sont conservées, y compris pour les relais de release.

Ces corrections doivent être confirmées par la nouvelle exécution de CI ; un résultat local ne remplace pas ce contrôle distant.

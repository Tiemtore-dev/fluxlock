# Modèle unifié et gestion de plusieurs coffres

## Comportement

FluXlock propose la création de coffres nommés, leur sélection avant déverrouillage et leur renommage dans Paramètres. Chaque coffre a son mot de passe maître, son sel de dérivation, sa base SQLite et ses fichiers chiffrés. Un seul coffre peut être déverrouillé à la fois.

« Changer de coffre » verrouille d’abord la session et ramène au sélecteur. L’interface masque immédiatement les vues contenant des secrets et attend la confirmation du backend avant de permettre une sélection. Le mot de passe saisi est effacé lors du changement. Les noms des coffres et leurs dates de création sont des métadonnées visibles avant authentification.

La réinitialisation efface le contenu du coffre sélectionné, conserve son nom et permet de le configurer à nouveau. Elle conserve les sauvegardes, le catalogue et les autres coffres. La restauration remplace le contenu du coffre de destination et ferme sa session, sans modifier son identifiant ou son nom. Le mot de passe de l’archive devient celui du contenu restauré.

## Modèle

- `VaultDescriptor` : identifiant stable, nom, version du modèle et date de création. Aucun secret.
- `Vault` : descripteur et emplacement privé calculé par Rust. Le frontend ne fournit jamais de chemin de coffre.
- `VaultSession` : identifiant du coffre, propriétaire et clé de déchiffrement dans un `SecureKey`. Une unique option en mémoire représente la session ouverte.
- `VaultContext` : identifiant de coffre et jeton éphémère attachés à chaque requête concernée.
- `VaultCatalog` : catalogue atomique, dernière sélection et verrou exclusif de l’instance.

Les types spécialisés `Password`, `SecureFile` et `SecureKey` restent les modèles du contenu. Leurs tables peuvent conserver des identifiants numériques locaux : la base et la session qui les contiennent déterminent le coffre. Les commandes passent toutes par le même contrôle de contexte avant d’accéder au contenu.

## Stockage et adoption du coffre existant

```text
répertoire privé FluXlock/
  vaults.json                 # Métadonnées publiques, versionnées
  vaults.lock                 # Verrou OS, conservé ouvert par le processus
  sv.db, files/, ...          # Coffre historique, identifiant « legacy »
  vaults/
    <UUID>/
      sv.db
      files/
      .biometric_enrollment.json
      trust_store.enc
      signed_logs/
```

La migration adopte le coffre historique sur place sous le nom « Personnel ». Elle ne déplace pas sa base ni ses fichiers et ne modifie pas ses clés pour créer le catalogue. Les installations neuves commencent avec un catalogue vide.

Le catalogue est écrit dans un fichier temporaire privé, synchronisé puis publié par renommage atomique. Les identifiants sont validés ; les noms ne servent jamais de noms de dossiers. Les liens symboliques sont refusés pour les emplacements de stockage contrôlés par le nouveau modèle. Un catalogue corrompu n’est pas remplacé silencieusement. Une base manquante n’est pas recréée lors d’une sélection ; les autres coffres restent accessibles.

## Invariants de sécurité

1. Les opérations de contenu détiennent un verrou de lecture sur le cycle de session pendant toute leur exécution. Création, sélection, verrouillage, restauration et réinitialisation détiennent son verrou exclusif. Une transition attend la fin des opérations en cours avant de remplacer le stockage.
2. Le backend refuse une sélection, une création ou un nouveau déverrouillage tant qu’une session est ouverte. Le verrou OS du catalogue empêche deux instances de cette version d’utiliser le même ensemble de coffres simultanément.
3. Une requête de contenu exige l’identité du coffre sélectionné et le jeton du déverrouillage actuel. Un ancien jeton ne fonctionne pas après réouverture du même coffre. Une ancienne demande de verrouillage ne peut pas fermer une nouvelle session.
4. Les clés de session restent en mémoire Rust sur toutes les plateformes et sont effacées par `SecureKey` à leur destruction. La récupération d’une clé vérifie aussi son coffre et son propriétaire. Les jetons et clés ne sont pas conservés dans le stockage web du frontend.
5. Le verrouillage annule et attend les tâches de transfert et de découverte, ferme les connexions, verrouille le registre de confiance et nettoie les fichiers temporaires déchiffrés. Le frontend vide ses caches de requêtes. Il tente aussi d’effacer le presse-papiers utilisé par FluXlock ; cette opération dépend des autorisations du système.
6. Les enrôlements biométriques natifs ont des identifiants de credential distincts. Les alias Android incluent l’identifiant de coffre ; l’ancien alias reste lisible pour le coffre historique. Les compteurs biométriques sont séparés par coffre. Les credentials Touch ID en mode compatibilité conservent leurs UUID propres.
7. Les registres de confiance, journaux signés et compteurs du réacteur de menaces utilisent le répertoire du coffre. La clé de protection des journaux des nouveaux coffres de bureau utilise un compte de trousseau distinct. Les protections générales de l’appareil, comme l’isolation réseau et la surveillance du système de fichiers, restent des politiques de l’application.
8. Les nouvelles sauvegardes incluent l’identité et le nom du coffre dans leurs métadonnées authentifiées. Ces champs sont optionnels et omis pour les anciens formats afin de conserver leur vérification cryptographique. Ils ne remplacent jamais l’identité du coffre de destination.
9. Un rechargement de la webview ferme la session dont le jeton frontend a été perdu, avant de réafficher la liste. Les réponses asynchrones destinées à une ancienne vue sont ignorées. Les sélecteurs de fichiers, lectures CSV et étapes d’enrôlement Android conservent aussi leur contexte d’origine, y compris avant le premier appel IPC.

Les transferts, archives et formats cryptographiques de contenu conservent leurs formats existants. Ce changement ne transforme pas les transferts manuels en synchronisation automatique du contenu. Le CLI historique indépendant n’est pas une interface de gestion du nouveau catalogue.

## Vérification reproductible

Depuis `tauri-desktop` :

```sh
npm ci --no-audit --no-fund
npm run build
```

Depuis `tauri-desktop/src-tauri` (pour appliquer sa configuration Cargo) :

```sh
RUST_MIN_STACK=16777216 CARGO_INCREMENTAL=0 cargo test --locked --lib
cargo check --locked --lib
```

La pile élargie est nécessaire aux opérations post-quantiques en mode test/debug. Les fixtures du nouveau module utilisent des répertoires temporaires et des données synthétiques. Leur journal signé n’accède pas au trousseau de production. Certains tests préexistants nécessitent le trousseau et des sockets locales.

Depuis `tauri-desktop`, avec Playwright et Chromium installés dans un environnement de test et Vite lancé :

```sh
FLUXLOCK_PLAYWRIGHT=/chemin/vers/playwright node tests/multi-vault-ui.mjs
FLUXLOCK_PLAYWRIGHT=/chemin/vers/playwright node tests/vault-ui.mjs
```

Les tests navigateur simulent l’IPC : ils vérifient l’interface et ses contextes de requête, et complètent les tests Rust sur le stockage et la cryptographie réels. Ils ne constituent pas un test matériel Touch ID, Windows Hello ou Android Keystore. Les paquets Windows, Linux et Android et leurs capteurs doivent être validés sur leurs plateformes avant publication.

## Références et revue

L’implémentation applique les recommandations de gestion du cycle de vie et de protection des clés de l’[OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html), ainsi que les mécanismes de [commandes Tauri 2](https://v2.tauri.app/develop/calling-rust/) et de [verrouillage de fichiers de Rust](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock). Elle conserve les primitives cryptographiques déjà présentes ; il ne s’agit pas d’une certification de conformité.

Skills ECC appliqués : `intent-driven-development`, `security-review`, `database-migrations`, `verification-loop` et `agent-self-evaluation`. La relecture porte sur l’accès par coffre, les sessions obsolètes, les courses pendant les transitions, les clés biométriques, les tâches réseau, les sauvegardes, les liens symboliques et les chemins d’échec.

Résultats détaillés : [rapport de vérification](multi-vault-verification.md).

# Notes chiffrées : implémentation et vérifications

22 novembre 2026. Fonctionnalité implémentée dans les sources locales ; aucun installateur ni publication n’a été produit. Les modifications multi-coffres présentes avant ce travail sont conservées.

## Fonctionnement livré

- Route `/notes`, navigation ordinateur et menu mobile, entrée et compteur au tableau de bord.
- Création, lecture, modification et suppression de notes ; recherche sur les titres dans tout le coffre avec pagination. Limites backend : titre de 256 caractères, corps de 1 Mio UTF-8, 10 000 notes par coffre.
- Une pièce jointe facultative de 32 Mio maximum : import par chemin natif ou données Android, ou rattachement d’un fichier existant du même propriétaire dans le coffre sélectionné.
- Export de la pièce jointe depuis la note avec contrôle de son rattachement et des octets chiffrés exacts qui vont être déchiffrés. Publication sans écraser un fichier existant, après authentification du contenu.
- Détacher ou supprimer la note conserve le fichier dans Fichiers. Une pièce jointe encore rattachée bloque la suppression du fichier. Les contraintes SQL complètent le contrôle de la commande native.
- Sauvegarde et restauration des notes et pièces jointes, y compris dans un coffre de destination différent ; validation des références et des pièces jointes avant publication de la restauration.
- Transfert sélectif Notes dans l’interface ; une note et son fichier constituent un élément complet, rechiffré avec la clé du destinataire. Capacité `secure-notes-v1` vérifiée avant d’envoyer le nouveau type à un ancien pair.

## Chiffrement et autorisations

`commands/notes.rs` utilise ChaCha20-Poly1305, un nonce aléatoire par chiffrement et des clés séparées par HKDF-SHA3-256, à partir de la clé du coffre. Le titre et le corps sont chiffrés avant tout passage à SQLite. Le format `note1:` est strict, sans repli sur du texte en clair.

L’AAD authentifie le domaine/version, l’UUID cryptographique, l’identifiant SQL de la note, son propriétaire, sa révision et le champ. L’ID SQL est réservé dans la transaction avec des champs vides, puis remplacé par les valeurs chiffrées avant commit. Cela empêche aussi de déplacer ensemble un ciphertext et son UUID vers une autre ligne.

Le corps chiffré contient le texte et le manifeste de pièce jointe : ID, nom, taille et empreinte BLAKE3 du blob chiffré. Une relation SQL différente ou un blob substitué est refusé dans le parcours de lecture/export de la note. Le fichier conserve le format chiffré existant SENC ; aucun fichier temporaire en clair n’est créé pendant son import ou son transfert.

Chaque commande Notes passe par `vault::access` et déduit le propriétaire de la session native. Les réponses d’une ancienne session sont rejetées par `vault-context.ts`. Les révisions empêchent l’écrasement d’une modification concurrente. Le mode lecture seule est appliqué aux mutations. Le titre et le corps ne sont pas journalisés ; la recherche ne crée pas d’index en clair.

L’interface rend les notes comme texte, désactive la correction orthographique sur la rédaction et ne persiste ni corps ni brouillon dans le stockage web. Le verrouillage démonte les vues et vide les caches du coffre. JavaScript ne permet pas de garantir l’effacement physique de toutes ses copies mémoire.

## Cohérence et corrections issues de la relecture

Les nouvelles tables `secure_notes`, `note_attachments` et leur version sont créées dans une migration transactionnelle. Les clés étrangères sont activées sur chaque connexion et les relations entre note, fichier et propriétaire sont contraintes.

La transaction SQLite enregistre la note, le manifeste, le fichier importé et la liaison ensemble. Les blobs sont chiffrés et publiés dans le stockage privé avant commit. Les erreurs ordinaires suppriment le blob non référencé ; au redémarrage, la récupération ne collecte que les blobs `note-<UUID>.senc` absents de `secure_files`. Une sauvegarde conserve le verrou applicatif de base pendant la capture et la collecte des fichiers.

Corrections appliquées pendant la revue :

- **Commit annulé** : une fois le commit commencé, ne pas supprimer un blob dont l’enregistrement pourrait avoir réussi. Le récupérer au prochain montage uniquement s’il est réellement orphelin.
- **Collision de publication** : le nettoyage ne revendique le fichier qu’après sa publication réussie ; un échec `persist_noclobber` ne supprime pas un fichier préexistant.
- **Substitution entre vérification et export** : vérifier et déchiffrer le même buffer borné de ciphertext ; ne pas vérifier un chemin puis rouvrir sans authentifier les nouveaux octets.
- **Permutation de lignes** : inclure aussi l’ID SQL dans l’AAD, en plus de l’UUID et du propriétaire.
- **Expansion JSON** : borner les buffers chiffrés et de transfert en tenant compte de l’expansion des caractères de contrôle, sans réduire silencieusement le texte autorisé.
- **Type de transfert trompeur** : conserver les types de l’offre et vérifier la correspondance du payload reçu, le nombre d’éléments et la fin du flux. Refuser les réceptions en mode lecture seule.
- **Accessibilité de l’éditeur** : séparer le libellé du textarea afin que le texte de la note ne soit pas incorporé dans son nom accessible.

## Vérifications réalisées

| Vérification | Résultat |
| --- | --- |
| `npm run build` | Réussi : TypeScript et build Vite. |
| Suite Rust applicative `cargo test --locked --lib` | **144 tests réussis**, aucun échec. Accès au trousseau et aux sockets locales nécessaire pour deux tests préexistants. |
| Dix tests Notes dédiés | Chiffrement DB/WAL, absence de corps dans les listes, AAD, mauvaise clé/propriétaire/révision, blob altéré, export refusé sans fichier partiel, rollback d’import, détachement/conflit, session ancienne, transfert rechiffré, migration/récupération et restauration. |
| `tests/notes-ui.mjs` | Réussi à 390 et 1280 px : navigation, ajout avec fichier, texte HTML inerte, lecture/export, modification, détachement, recherche, brouillon, verrouillage/réponse tardive, lecture seule et suppression. |
| `tests/multi-vault-ui.mjs` | Réussi à 320, 768 et 1280 px : changement, verrouillage, caches, sessions, renommage et réinitialisation des coffres. |
| `git diff --check`, rustfmt sur les nouveaux modules Notes | Réussis. Le dépôt historique dans son ensemble n’a pas été reformaté. |

Les tests Rust utilisent des répertoires temporaires et des secrets synthétiques. Le test d’absence de plaintext inspecte la base et les journaux SQLite présents après checkpoint. Le test de restauration utilise les véritables formats cryptographiques et une autre destination. Les tests navigateur simulent l’IPC ; ils ne constituent pas des tests natifs Windows/Android ou des capteurs biométriques.

## Reproduire

Depuis `tauri-desktop` :

```sh
npm run build
```

Depuis `tauri-desktop/src-tauri` :

```sh
RUST_MIN_STACK=16777216 CARGO_INCREMENTAL=0 cargo test --locked --lib
```

Avec Vite lancé, Playwright et Chromium installés, depuis `tauri-desktop` :

```sh
FLUXLOCK_PLAYWRIGHT=/chemin/vers/playwright node tests/notes-ui.mjs
FLUXLOCK_PLAYWRIGHT=/chemin/vers/playwright node tests/multi-vault-ui.mjs
```

## Limites pratiques

Les IDs, dates, tailles et relations restent des métadonnées visibles en base. Le titre, le corps, le manifeste et le nom de fichier sont chiffrés. Un export choisi est une copie en clair ; supprimer la note ne détruit pas les copies exportées ni les originaux. L’authentification des enregistrements ne fournit pas une protection globale contre le retour à une ancienne image complète du coffre.

Les transferts et imports Android de pièces jointes sont bornés en mémoire, mais peuvent charger un fichier de 32 Mio ; valider ce parcours et les sélecteurs sur les appareils Android cibles. Les installateurs Windows/Linux/Android et les tests matériels restent à exécuter sur leurs plateformes avant publication. Une revue dédiée à l’extension sera nécessaire avant son développement final et sa distribution : [plan et analyse des attaques](browser-extension-plan.md).

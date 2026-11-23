# Extension d’autofill et notes avec pièces jointes

Analyse du 22 novembre 2026, fondée sur les fichiers présents dans l’espace de travail, y compris les évolutions multi-coffres non commitées. Ce document décrit une proposition d’implémentation ; les fonctionnalités ne sont pas encore développées. Il ne constitue pas un audit exhaustif de l’application.

Mise à jour après cette analyse : les Notes sont désormais implémentées, voir [implémentation et vérifications](notes-verification.md). Le plan navigateur approfondi et sa relecture des attaques sont dans [browser-extension-plan.md](browser-extension-plan.md). Le contenu ci-dessous conserve l’état et les propositions de l’analyse initiale.

## Décision proposée

Conserver FluXlock comme autorité locale pour l’authentification, les clés et les données. Ajouter deux fonctionnalités séparées :

- Une extension de navigateur de bureau, reliée au processus Rust de l’application par un hôte Native Messaging et un canal IPC local authentifié. Première version : remplissage déclenché par l’utilisateur, application ouverte et coffre déverrouillé.
- Un onglet Notes indépendant, avec titre et texte chiffrés, et une pièce jointe facultative dans la première interface. Réutiliser le stockage chiffré des fichiers du coffre et ajouter une relation explicite note–fichier.

Développer les Notes d’abord : elles restent dans le périmètre de confiance existant. L’extension ajoute le navigateur et les pages web à l’analyse des menaces et demande une revue spécifique avant distribution.

## 1. Ce que le projet fournit déjà

| Élément vérifié | Conséquence pour ces fonctionnalités |
| --- | --- |
| `tauri-desktop/src/App.tsx`, `src/design-system/organisms/Sidebar.tsx` | Routes et navigation extensibles ; aucune page Notes actuelle. Prévoir également le menu mobile. |
| `src-tauri/src/database.rs` | Tables `passwords`, `secure_files`, `secure_keys`. Le champ `passwords.notes` appartient à un identifiant ; ce n’est pas un modèle de note autonome. |
| `src-tauri/src/commands/passwords.rs` | Création et modification chiffrent titre, identifiant, mot de passe, URL, notes et catégorie. `get_passwords` déchiffre toutes les fiches et leurs mots de passe avant de les rendre à la webview. `get_password` retourne actuellement l’enregistrement stocké, donc n’est pas une API prête pour l’autofill. |
| `src-tauri/src/vault.rs`, `commands/session.rs`, `lib.rs` | Une session ouverte, clé dans `SecureKey`, contexte coffre + jeton et verrou du cycle de session. Les nouvelles opérations doivent conserver ces contrôles. |
| `src-tauri/src/crypto.rs`, `rust-crypto-core/src/crypto/cipher.rs` | Argon2id pour la dérivation et ChaCha20-Poly1305 pour les nouveaux champs. Le helper générique de champs ne prend pas de contexte AAD : ajouter une API dédiée pour les notes, sans modifier silencieusement le format existant. |
| `src-tauri/src/commands/files.rs` | Nom de fichier chiffré, nom physique aléatoire, import natif par flux, export explicite et contrôle des chemins du coffre. Import base64 limité à 32 Mio. |
| `src/lib/vault-context.ts`, `src/main.tsx`, `src/stores/authStore.ts` | Rejet des réponses d’une ancienne session, démontage des vues sensibles et purge du cache React Query au verrouillage. Les nouvelles vues doivent suivre ce fonctionnement. |
| `src-tauri/src/backup_manager.rs` | Sauvegarde par capture SQLite et inclusion du répertoire `files/`, restauration avec réécriture des chemins de `secure_files`. Les nouvelles tables entreraient dans la capture ; il reste à vérifier leurs invariants à la restauration. |
| `src-tauri/src/transfer/protocol.rs` | Types actuels : mot de passe, fichier, clé et sauvegarde. Le transfert sélectif d’une note avec ses pièces jointes exige une extension du protocole. |

Les chemins du tableau sont relatifs à `tauri-desktop/`, sauf indication contraire. Aucune extension ni passerelle Native Messaging n’a été trouvée dans le code applicatif examiné. Les sockets de transfert existantes ont une autre fonction et ne doivent pas devenir une API de lecture du coffre pour le navigateur.

## 2. Extension : parcours et architecture

Parcours initial proposé : ouvrir une page HTTPS, cliquer sur FluXlock dans le navigateur, choisir l’identifiant correspondant, puis cliquer sur « Remplir ». Si le coffre est verrouillé, l’extension demande de le déverrouiller dans l’application. Le mot de passe maître reste dans le parcours natif existant.

```text
Interface de l’extension
    → service worker de l’extension
    → Native Messaging : hôte Rust distinct lancé par le navigateur
    → IPC local authentifié : socket Unix / named pipe Windows
    → service autofill du processus FluXlock déjà ouvert
    → session du coffre sélectionné

Retour du seul identifiant choisi
    → service worker
    → script du document autorisé
    → champs du formulaire
```

Native Messaging lance un processus séparé : il ne partage ni `AppState` ni la clé du processus Tauri. L’hôte proposé sert seulement de relais. Il ne monte pas une deuxième base, ne déverrouille pas un coffre et ne récupère aucune clé de coffre. Le verrou d’instance du catalogue actuel reste respecté. Les anciens CLI utilisent leurs propres chemins et parcours ; ils ne conviennent pas comme relais.

Chrome documente le transport par entrée/sortie standard et la liste `allowed_origins` des extensions autorisées. Firefox utilise `allowed_extensions` et un enregistrement distinct. Sources : [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging), [Mozilla Native Messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging).

### Autorisation du navigateur et de la connexion locale

- Déclarer uniquement les identifiants d’extensions distribuées, avec des identifiants différents pour développement, test et production. Ne pas accepter un identifiant fourni dans un message JSON comme preuve d’identité.
- Associer explicitement un profil de navigateur au coffre depuis l’application. Prévoir une page « Navigateurs connectés » et une révocation. Le credential d’appairage doit être aléatoire, dédié, protégé au repos et indépendant de la clé du coffre et du jeton de la webview.
- Authentifier l’IPC entre le relais et Tauri : permissions du socket/répertoire ou ACL du pipe, contrôle du compte OS du pair et du processus lorsque disponible, contrôle de l’exécutable selon la plateforme, et authentification cryptographique de la connexion liée à l’appairage. Prévoir une spécification et une revue du bootstrap ; ne pas déposer un secret de connexion en clair dans un fichier lisible par tous les processus.
- Utiliser une construction de canal authentifié existante et revue ; éviter de créer un protocole de chiffrement ad hoc. Des permissions de fichier seules ne prouvent pas l’identité de l’extension. Un argument de lancement d’hôte peut également être imité par un processus local.
- Émettre des autorisations éphémères limitées au coffre, à la session et à l’autofill. Ne jamais transmettre le jeton général `VaultContext` au navigateur. Révoquer ces autorisations au verrouillage, changement de coffre, restauration, réinitialisation, révocation de profil ou fermeture de l’application.
- Ne pas conserver une autorisation pendant une attente utilisateur sous le verrou de lecture du cycle de session. Attendre l’action, puis reprendre le verrou et revérifier session, coffre, expiration et demande avant de déchiffrer.

Le modèle protège contre les pages malveillantes, les extensions non autorisées et les connexions locales non authentifiées. Une extension autorisée compromise et un poste dont le compte utilisateur est compromis restent des menaces majeures. Native Messaging n’est pas une garantie contre un malware local.

### API limitée à l’autofill

Créer un service Rust distinct de l’IPC général Tauri, avec un protocole versionné et des messages strictement validés :

| Opération proposée | Réponse autorisée |
| --- | --- |
| `get_status` | Application disponible, coffre verrouillé/déverrouillé, état d’autorisation du profil. Pas de catalogue complet de coffres. |
| `find_candidates(origin, request_id)` | Quelques fiches correspondant à l’origine autorisée : identifiant opaque éphémère, titre et nom d’utilisateur. Aucun mot de passe ni notes. |
| `fill_candidate(handle, request_id)` | Un identifiant et un mot de passe après action explicite, contrôles répétés et consommation d’une autorisation à usage unique. |

Le handle doit être imprévisible et lié à la connexion, à la session, à l’origine et à une expiration courte. Il ne doit pas être un simple ID SQLite. Le contexte conservé dans le navigateur comprend aussi `tabId`, `frameId` et l’identité du document. Une navigation invalide la demande, y compris une navigation vers un autre document de même origine.

Les URL étant chiffrées, la première implémentation peut les déchiffrer côté Rust pour trouver les candidats, sans déchiffrer leurs mots de passe. Déchiffrer uniquement le secret sélectionné à la dernière étape. Un éventuel index de recherche futur doit être conçu séparément ; ne pas recopier les domaines en clair dans SQLite pour accélérer la recherche.

Ne pas exposer au relais `get_passwords`, `decrypt_password`, les commandes de fichiers, notes, clés, exports, sauvegardes ou transferts. Le déchiffrement arbitraire n’appartient pas au protocole autofill.

Limiter tailles, nombre de candidats, fréquence et demandes en attente. Refuser les messages inconnus, les versions incompatibles et les réponses périmées. Réserver stdout au protocole Native Messaging et exclure tout secret des logs et diagnostics.

### Permissions, origine et remplissage

Première version Chromium : Manifest V3 avec `nativeMessaging`, `activeTab` et `scripting`, pour un déclenchement par clic ou raccourci utilisateur. `activeTab` donne un accès temporaire après une action ; il ne suffit pas à proposer en permanence une icône dans tous les formulaires. Cette évolution demanderait des permissions de sites supplémentaires, de préférence optionnelles. Source : [permission activeTab](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab).

La politique proposée est la suivante :

1. Construire l’origine à partir des informations du navigateur, et vérifier l’expéditeur des messages dans le service worker. Ne pas faire confiance à une URL ou à un événement annoncé par la page. Chrome demande explicitement de vérifier `sender.origin` ou `sender.url` avant de relayer les messages des scripts de contenu : [consignes Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
2. Comparer une origine canonique HTTPS — schéma, hôte IDNA et port effectif — à l’origine enregistrée. Refuser les URL ambiguës et les identifiants intégrés dans l’URL. Aucun test par sous-chaîne : `banque.fr.evil.test` ne correspond pas à `banque.fr`. Pas d’élargissement automatique aux sous-domaines ; les exceptions éventuelles sont explicites et limitées.
3. Pour commencer, remplir seulement le document principal et refuser les iframes, les origines opaques et les protocoles autres que HTTPS. Prévoir une politique séparée pour les intranets et les iframes de connexion, sans désactiver globalement ces contrôles.
4. Vérifier encore l’onglet actif et le document juste avant l’injection. Cibler seulement les champs visibles, modifiables et attendus ; refuser les champs masqués ou les destinations de formulaire manifestement incohérentes.
5. Faire choisir la fiche dans l’interface de l’extension, séparée du DOM de la page. Ne pas accepter une demande de remplissage par `window.postMessage` ou par un canal externe exposé aux sites. Ne pas soumettre le formulaire automatiquement.
6. Ne pas stocker les secrets dans `chrome.storage`, IndexedDB, localStorage ou le presse-papiers. Les libérer dès le remplissage ou l’annulation ; JavaScript ne garantit pas leur effacement physique en mémoire.

Une fois inséré dans le formulaire, le secret est lisible par les scripts du site destinataire. Le remplissage doit donc rester un acte de confiance envers ce site. La vérification d’origine réduit l’hameçonnage ; elle ne protège pas d’un site légitime compromis.

### Prérequis : expiration réellement contrôlée côté Rust

`validate_session` vérifie actuellement l’inactivité par rapport à 24 heures. Le délai configurable de 0 à 60 minutes est appliqué dans `check_auto_lock`, appelé par le hook de l’interface toutes les 30 secondes. Avant d’ajouter un client navigateur, contrôler aussi ce délai à chaque requête sensible et prévoir un mécanisme Rust indépendant de la webview pour invalider la session. Le polling du navigateur ne doit pas entretenir artificiellement l’activité.

Centraliser l’invalidation pour fermer aussi les connexions autofill et détruire leurs autorisations. Implémenter cela sans tenter de prendre le verrou exclusif du cycle de session alors qu’une requête détient déjà son verrou de lecture. Vérifier l’ordre de prise des verrous et les courses avec un verrouillage en cours.

### Distribution et plateformes

Ajouter le binaire relais et son enregistrement aux installateurs macOS, Windows et Linux, avec désinstallation et mise à jour cohérentes. Installer l’hôte ne suffit pas : l’extension reste à distribuer et à connecter. Vérifier séparément Chrome, Edge, Brave et Firefox ; les chemins et identifiants de distribution diffèrent. Tester les profils multiples et les navigateurs installés en sandbox. L’application et le relais doivent refuser une version de protocole incompatible.

Safari nécessite son intégration Apple propre, à étudier séparément : [Safari web extensions](https://developer.apple.com/documentation/safariservices/safari-web-extensions). Pour l’autofill dans les applications Android, prévoir un service natif `AutofillService`, disponible depuis Android 8/API 26 ; l’extension desktop ne fournit pas cette fonction. Le projet annonçant aussi Android 7, conserver cette distinction de compatibilité. Source : [Android AutofillService](https://developer.android.com/identity/autofill/autofill-services).

## 3. Notes : modèle et parcours

Dans la navigation, ajouter « Notes » avec une liste, une recherche, un bouton « Nouvelle note » et une vue de lecture/édition. Champs : titre, texte libre, pièce jointe facultative. Actions : enregistrer, modifier, joindre, détacher, exporter la pièce jointe et supprimer la note. L’interface peut commencer avec une pièce jointe par note ; le modèle relationnel peut permettre plusieurs pièces jointes ultérieurement.

Première version en texte brut, rendu par React et `white-space: pre-wrap`, sans interprétation HTML. Pas de contenu distant, d’aperçu actif de fichier ni de brouillon persistant dans le stockage web. Une sauvegarde explicite évite d’introduire un historique implicite. Proposer un avertissement de modifications non enregistrées lors d’une navigation normale ; le verrouillage de sécurité reste prioritaire.

### Modèle de données proposé

| Table | Champs conceptuels |
| --- | --- |
| `secure_notes` | `id` UUID, `user_id`, `encrypted_title`, `encrypted_body`, `format_version`, `revision`, `created_at`, `updated_at` |
| `note_attachments` | `id` UUID de liaison, `note_id`, `file_id`, `user_id`, `position` |

`encrypted_body` contient le texte et un manifeste authentifié des pièces jointes : identifiant de liaison, référence du fichier et empreinte attendue du blob chiffré. Les noms de fichier restent chiffrés par le stockage existant. Le manifeste permet de détecter une substitution de lien ou de blob, même si le fichier substitué a lui-même un tag AEAD valide.

Les titres et corps utilisent un format AEAD dédié et versionné, avec séparation de clés par usage via HKDF et contexte authentifié AAD : domaine « note », UUID, version et champ. Utiliser les primitives existantes avec une nouvelle API acceptant l’AAD. Refuser strictement une erreur d’authentification ; ne jamais interpréter le contenu comme du texte en clair en cas d’échec.

Ne pas lier aveuglément l’AAD à l’identifiant du catalogue de l’installation : la restauration actuelle conserve l’ID du coffre de destination, qui peut différer de celui de la sauvegarde. La clé propre au contenu du coffre fournit déjà une séparation ; si un namespace cryptographique de coffre est ajouté, définir sa conservation à la restauration et le rechiffrement lors d’un transfert.

Les IDs, dates, tailles et relations restent des métadonnées visibles en base ; les cacher demanderait un modèle supplémentaire. Ne pas ajouter d’index FTS en clair sur les textes. La recherche initiale peut porter sur les titres déchiffrés en mémoire Rust, avec pagination ; retourner le corps seulement à l’ouverture de la note. Fixer des limites backend explicites, par exemple 256 caractères pour le titre et 1 Mio UTF-8 pour le texte, et rejeter un dépassement sans troncature silencieuse.

### Autorisations et intégrité relationnelle

Chaque commande doit utiliser `vault::access`, déduire `user_id` de la session et vérifier que la note et le fichier appartiennent au même propriétaire dans le coffre sélectionné. Un `user_id` ou un chemin transmis par le frontend ne constitue pas une autorisation. Appliquer aussi le mode lecture seule aux mutations.

Définir les clés étrangères et contraintes composites pour empêcher les liaisons entre propriétaires, activer et vérifier `PRAGMA foreign_keys` sur toutes les connexions du pool, et contrôler l’intégrité après migration/restauration. Une déclaration `FOREIGN KEY` seule ne suffit pas à prouver son application sur les connexions existantes. Conserver les vérifications applicatives.

Utiliser `revision` pour refuser l’écrasement d’une modification concurrente. La mise à jour du texte, du manifeste et des liaisons se fait dans une même transaction SQLite. La liste ne doit pas charger toutes les notes et tous leurs contenus dans React Query.

### Pièces jointes et suppression

Importer une copie chiffrée dans le répertoire `files/` du coffre ; ne pas enregistrer seulement un lien vers l’original. L’original reste à son emplacement, comme dans le parcours Fichiers actuel. Sur ordinateur, réutiliser le chiffrement par flux depuis un sélecteur natif ; sur Android, conserver la limite de 32 Mio du chemin IPC. Pour une première version cohérente avec les transferts, une limite de 32 Mio par pièce jointe est une proposition de produit à appliquer également côté Rust.

Extraire les opérations de stockage de `commands/files.rs` vers un service interne réutilisable plutôt qu’appeler une commande Tauri depuis une autre. Garder les contrôles de chemins, noms de sortie, non-écrasement et contexte d’origine pendant les sélecteurs. Ne pas recopier les logs actuels qui exposent parfois un nom de fichier ou un chemin en mode debug.

SQLite et le système de fichiers ne partagent pas de transaction. Prévoir : écriture privée provisoire, authentification et publication du blob, transaction enregistrant fichier + note + liaison, puis récupération des blobs orphelins après interruption. Un simple enchaînement de deux appels frontend « importer » puis « attacher » ne garantit pas cette cohérence. La sauvegarde doit obtenir un état cohérent avec les mutations de notes et de fichiers.

Règles de suppression proposées :

- Détacher retire la relation et met à jour le manifeste ; cela ne détruit pas implicitement un fichier partagé.
- Supprimer une note retire ses relations. Le fichier reste disponible dans Fichiers ; une suppression de fichier reste une action explicite.
- Supprimer un fichier encore rattaché est bloqué, avec indication des notes concernées. Éviter une suppression en cascade qui ferait disparaître silencieusement une pièce jointe.
- Exporter crée une copie en clair à la destination choisie. Informer l’utilisateur de cette conséquence ; ne pas ouvrir automatiquement la pièce jointe dans une application externe. Le nettoyage des temporaires ne garantit pas l’effacement des copies déjà exportées ou des traces du système.

### Sauvegarde, restauration et transfert

Les nouvelles tables seront incluses par `VACUUM INTO` et les blobs par la collecte de `files/`. Cela facilite l’intégration sans garantir à lui seul un cycle complet : valider les références, les manifestes et les pièces jointes après restauration, gérer les anciennes bases sans ces tables et sérialiser sauvegarde et mutations pour éviter une capture DB/blob incohérente. Tester la restauration dans un coffre d’ID différent.

Prévoir une migration transactionnelle versionnée ; ne pas réutiliser le numéro de version du catalogue comme version de schéma SQL. Ne pas se contenter d’ignorer toutes les erreurs `ALTER TABLE`. Vérifier la réinitialisation du coffre sélectionné et le refus d’une base d’une version future par un ancien client.

Pour le transfert sélectif, ajouter une capacité négociée `secure-notes-v1` et un type de payload qui transporte la note et son ensemble de pièces jointes. Le destinataire attribue ses références locales, rechiffre le contenu et reconstruit le manifeste avant publication. Une réception partielle ne doit pas produire une note annoncée comme complète. Un ancien pair doit refuser clairement cette capacité sans recevoir silencieusement la note comme un mot de passe ou un fichier isolé. La restauration d’une sauvegarde et le transfert sélectif sont deux parcours différents.

## 4. Emplacements de développement

| Périmètre | Fichiers à créer ou adapter |
| --- | --- |
| Interface Notes | `src/pages/NotesPage.tsx` à créer ; `src/App.tsx`, `src/design-system/organisms/Sidebar.tsx`, `src/lib/vault-service.ts` ; compteur et raccourci éventuels dans `DashboardPage.tsx`. |
| Backend Notes | `src-tauri/src/commands/notes.rs` à créer ; `commands/mod.rs`, `lib.rs`, `database.rs` et migrations ; helper AEAD avec AAD ; service de fichiers extrait pour les pièces jointes. |
| Cycle de vie Notes | Verrouillage, caches, sélecteurs, sauvegarde/restauration, réinitialisation et transfert sélectif. |
| Extension | Dossier racine `browser-extension/` à créer : manifestes, interface, service worker, script de remplissage et tests. Aucun secret dans le paquet. |
| Passerelle | `src-tauri/src/bin/fluxlock-browser-host.rs` et module `src-tauri/src/autofill/` à créer ; configuration Cargo, service de session, expiration Rust et réglages d’appairage/révocation. |
| Installation | Manifestes hôtes par navigateur/plateforme, empaquetage et signature du relais, scripts d’installation/désinstallation, mise à jour et documentation utilisateur. |

Les chemins `src/` et `src-tauri/` de ce tableau sont relatifs à `tauri-desktop/`. Ces noms sont proposés, pas des modules déjà disponibles.

## 5. Validation nécessaire avant livraison

| Fonctionnalité | Tests ayant une valeur de sécurité |
| --- | --- |
| Autofill et session | Refus lorsque verrouillé ou après expiration sans polling webview ; révocation ; changement de coffre ; rejeu d’un handle ; réponses tardives ; fermeture/reconnexion du relais ; aucun secret fourni par une simple recherche. |
| Autofill et page | Faux domaine, sous-domaines, ports, IDN, HTTP, iframe, champ masqué, formulaire externe, navigation entre sélection et injection ; message forgé par la page ; sélection de plusieurs comptes et formulaire de connexion en plusieurs étapes. |
| Passerelle | Hôte lancé manuellement, identité de pair invalide, manifeste altéré, message trop grand ou tronqué, ordre de messages invalide ; tests réels de l’IPC sur chaque OS. |
| Notes et chiffrement | Aucun titre, texte ou nom de pièce jointe en clair dans les nouvelles écritures DB/WAL ; altération AEAD, substitution d’une note/liaison/fichier ; erreur d’authentification bloquante. |
| Notes et isolation | IDs valides d’un autre coffre/propriétaire, ancienne session, conflit de révision, mode lecture seule, verrouillage pendant sélection ou import, absence de corps de notes dans un cache après verrouillage. |
| Fichiers et cohérence | Fichier vide, limite de taille, chemin malveillant, lien symbolique, échec disque ou DB, arrêt à chaque étape de publication/suppression, récupération d’orphelins sans perte de fichiers référencés. |
| Compatibilité | Ancien coffre migré, sauvegarde/restauration avec et sans notes, coffre de destination différent, pièce jointe absente, réception interrompue, ancien pair incompatible, navigation mobile et accessibilité. |

Compléter les tests Rust par des tests navigateur de l’extension réellement chargée et des parcours natifs sur les plateformes cibles. Des mocks Tauri seuls ne valident ni Native Messaging, ni la biométrie, ni les ACL d’un pipe Windows. Les mises à jour de l’extension constituent aussi un accès aux identifiants : permissions minimales, dépendances limitées, code embarqué et compte éditeur protégé, conformément aux [recommandations de sécurité Chrome](https://developer.chrome.com/docs/extensions/develop/security-privacy/stay-secure).

## 6. Découpage recommandé

1. Notes : migration, format chiffré, CRUD, onglet et pièces jointes ; sauvegarde/restauration, règles de suppression et tests de session inclus dans ce lot.
2. Compatibilité des notes : transfert sélectif avec négociation de capacité et reprise des réceptions interrompues.
3. Prérequis autofill : expiration et invalidation Rust autonomes, spécification du canal local, appairage et API de recherche/révélation limitée.
4. Extension Chromium : remplissage sur action explicite, hôte installé et tests de sécurité de bout en bout.
5. Firefox puis étude Safari ; autofill Android comme chantier natif distinct. Évaluer le remplissage proactif après validation du parcours manuel.

Les questions de confort — plusieurs pièces jointes, recherche plein texte, aperçu, remplissage proactif — peuvent évoluer ensuite. Les contrôles d’origine, d’autorisation, de cohérence et de cycle de session font partie de chaque première livraison.

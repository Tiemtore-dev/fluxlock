# Extension FluXlock : plan revu après analyse des attaques

**Mise à jour du 23 novembre :** le [profil hybride post-quantique v2](autofill-post-quantum-v2.md) est implémenté et remplace la proposition cryptographique v1 ci-dessous. ML-KEM-768 contribue au secret Noise XXpsk3/SHA-512 et ML-DSA-65 authentifie les deux pairs. Extension 0.4.0, relais 0.2.0 et nouvel appairage obligatoires. Les exigences d’origine exacte, de preuve native fraîche et de verrouillage avant remise restent en vigueur.

Plan établi le 22 novembre 2026, implémentation locale au 23 novembre 2026. Les lots 1 à 5 disposent désormais de code et de tests ; le relais et le paquet Chromium sont construits. L’installation multiplateforme et la revue avant publication restent à qualifier : voir [les résultats et limites de vérification](browser-extension-verification.md) et [les instructions d’installation](../../browser-extension/README.md). Le texte ci-dessous conserve les objectifs du plan et ne constitue pas une déclaration que chaque scénario de qualification a été exécuté.

Choix utilisateur retenu : authentification dans FluXlock, puis liste des emails/usernames du site exact dans la popup de l’extension, sans mots de passe. Seul le mot de passe choisi est ensuite récupéré ; le coffre se verrouille avant sa remise. L’implémentation garde identité de transport et registre dans **une seule entrée atomique du trousseau OS**, plutôt qu’un fichier authentifié avec une génération séparée. Les sauvegardes de coffre ne l’incluent pas ; une restauration complète du trousseau/OS dépasse la protection anti-retour arrière. Chromium 106 est le minimum déclaré pour le ciblage par document.

## Langages et périmètre

| Composant | Langage retenu | Responsabilité |
| --- | --- | --- |
| Popup, service worker, script de formulaire | TypeScript strict, HTML et CSS, compilés en JavaScript Manifest V3 | Déclenchement, attente de la validation native, liste des seuls emails/usernames correspondants sans mots de passe, sélection et ciblage du document. Aucun champ d’authentification dans le navigateur. |
| Hôte `fluxlock-browser-host` | Rust | Relais Native Messaging vers le processus Tauri ; aucun accès SQLite ni clé du coffre. |
| Service autofill du processus Tauri | Rust | Autorisation, session, recherche et révélation du seul credential choisi. |
| Canal authentifié partagé | Rust natif et Rust compilé en WebAssembly, embarqué dans le worker | Même implémentation cryptographique aux deux extrémités ; le relais ne voit pas les identifiants. |

Premier lot : Chromium desktop, remplissage sur clic, application FluXlock ouverte ; le coffre peut être verrouillé. Chaque demande déclenche une authentification dans l’application, y compris lorsqu’une session manuelle est déjà ouverte. L’opération ne crée pas une session générale de consultation du coffre. Pas de remplissage au chargement, de soumission automatique, de collecte des mots de passe saisis, de passkeys ou de support des iframes dans ce lot. Firefox vient ensuite ; Safari et les applications Android demandent des intégrations natives distinctes. Fixer les versions minimales après les prototypes et les inscrire dans les manifestes et la CI.

## Contrat de sécurité demandé par l’utilisateur

1. Sur un site, le clic ouvre une petite fenêtre d’extension indiquant « Authentifiez-vous dans FluXlock ». Elle ne contient ni mot de passe maître, ni saisie biométrique, ni bouton capable de déclarer l’authentification réussie.
2. L’extension transmet uniquement une demande liée au document et à l’origine, via le relais et le canal appairé. La route dédiée est un service IPC Rust, pas une route HTTP accessible aux sites.
3. Rust ouvre une fenêtre de l’application FluXlock pour une authentification fraîche par mot de passe maître ou biométrie native réellement prise en charge. Le backend vérifie la preuve ; ni le navigateur ni le relais ne fournissent un booléen « authentifié » faisant autorité.
4. Après cette preuve seulement, Rust recherche les fiches dont l’origine canonique enregistrée correspond exactement à celle de la demande. La popup de l’extension affiche uniquement les emails/usernames de ces comptes et des handles temporaires ; aucun mot de passe n’est déchiffré ou transmis pour cette liste. L’utilisateur choisit explicitement une entrée, même s’il n’y en a qu’une. La fenêtre FluXlock sert à l’authentification, sans seconde interface de sélection des comptes.
5. La popup transmet uniquement le handle choisi dans sa demande de remplissage. Rust vérifie la preuve, le handle, l’origine, le document et la version courante de la fiche, puis déchiffre le seul mot de passe choisi. La réponse contient le mot de passe et le username/email autoritatif de cette même fiche pour éviter un mélange avec un libellé altéré. Aucun titre de fiche, notes, autre origine, clé de coffre ou jeton de session générale n’accompagne ces données.
6. Construire et chiffrer la réponse à usage unique, effacer les secrets transitoires et verrouiller effectivement le coffre **avant** de publier cette réponse sur le canal. Ainsi le coffre est déjà fermé quand les identifiants arrivent au navigateur ; aucun accusé de réception n’est nécessaire au verrouillage.
7. Annulation, absence de correspondance, expiration ou erreur après le début de l’opération native ferment également la session temporaire. Un nouvel essai exige une nouvelle authentification. Un simple message non approuvé ne doit pas pouvoir fermer une session manuelle de l’utilisateur.

Ces règles sont obligatoires dans la première livraison. Elles remplacent la sélection native proposée précédemment ; une session de coffre déjà ouverte reste insuffisante pour dispenser d’authentification fraîche.

### Choix du compte et signification de « le navigateur ne peut pas lire »

La liste des comptes éligibles est présentée **après** authentification, dans la popup propre à l’extension. Le service Rust restitue uniquement les emails/usernames du site exact et des handles non prédictibles à durée courte, jamais les mots de passe de tous les comptes. L’utilisateur clique sur une entrée pour demander son remplissage. Le backend vérifie que le handle appartient à cette demande, à cette origine et à ce résultat de recherche, avant de déchiffrer le seul mot de passe choisi. Ne pas ajouter une deuxième confirmation de sélection dans l’application.

Trois frontières doivent être distinguées :

| Lecteur potentiel | Garantie visée |
| --- | --- |
| Site visité et scripts de sa page | La liste reste dans les contextes de l’extension, sans être insérée dans le DOM du site ou envoyée au script de contenu. Le couple choisi devient accessible au document lorsqu’il est inséré dans son formulaire. |
| Popup et worker de l’extension | Emails/usernames des seuls comptes du site, sans mots de passe pendant le choix. Au remplissage, le worker reçoit transitoirement le seul couple choisi ; ne pas renvoyer ce mot de passe à la popup pour l’afficher. |
| Relais natif | Uniquement des trames chiffrées, jamais la liste ou un mot de passe en clair. |
| Navigateur lui-même ou code de l’extension compromis | Pas de garantie d’invisibilité du couple choisi pendant le remplissage. Le navigateur exécute le worker et gère le DOM ; chiffrer les échanges ou employer WASM ne permet pas de cacher à cet environnement les valeurs qu’il doit insérer. |

Le choix utilisateur accepte que les emails/usernames affichés dans la popup soient lisibles par le navigateur. Les mots de passe non choisis restent protégés dans le coffre ; celui qui est choisi devient nécessairement accessible à l’environnement navigateur au moment du remplissage. Cette distinction évite d’ajouter une interface de sélection native pour une garantie de confidentialité de la liste qui n’est plus demandée.

L’isolation des scripts d’extension protège leurs variables du JavaScript ordinaire de la page, mais le DOM du formulaire est partagé avec le site. Chrome demande de traiter les scripts de contenu comme moins fiables et de considérer que leurs données peuvent fuiter vers la page. Sources : [Content scripts](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts), [Message passing](https://developer.chrome.com/docs/extensions/develop/concepts/messaging).

Si l’objectif devient « aucun mot de passe ne doit entrer dans le navigateur, même pour le compte choisi », un autofill de mot de passe classique ne peut pas le satisfaire. Il faut un mécanisme pris en charge par le site qui transmet une preuve plutôt qu’un mot de passe, par exemple WebAuthn/passkeys ; cela ne remplace pas de façon transparente les comptes existants à mot de passe. [WebAuthn](https://www.w3.org/TR/webauthn-3/).

## Résultats des recherches

- Native Messaging lance un processus distinct et transporte du JSON encadré par stdin/stdout. La liste d’IDs autorisés ne prouve pas l’identité d’un programme qui lance manuellement l’hôte. [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
- Les scripts de contenu sont moins fiables que le worker ; les données envoyées à un script peuvent atteindre la page. [Chrome Message passing](https://developer.chrome.com/docs/extensions/develop/concepts/messaging).
- `activeTab` ouvre l’accès après une action utilisateur et peut le conserver lors d’une navigation de même origine. Il faut contrôler le document, pas seulement le domaine. [Chrome activeTab](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab).
- L’injection peut viser un document précis dans un monde isolé. Cela ne cache pas les valeurs au site après insertion dans son DOM. [Chrome scripting](https://developer.chrome.com/docs/extensions/reference/api/scripting).
- Le worker peut redémarrer. Une connexion native peut prolonger sa vie, sans garantir la reprise d’une opération après un crash. [Cycle de vie du worker](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle/).
- Les named pipes Windows nécessitent une ACL explicite et un refus des clients réseau ; les paramètres par défaut ne suffisent pas. [Sécurité des pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [Named pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes).
- Noise fournit des constructions de canal authentifié ; l’association entre clés et identités reste à assurer dans l’application. `snow` en est une implémentation Rust. [Spécification Noise](https://noiseprotocol.org/noise.html), [snow](https://docs.rs/snow/latest/snow/).

Ces mécanismes ne certifient pas la composition FluXlock : le bootstrap et le protocole applicatif demandent leurs propres vecteurs, tests et revue.

## Menaces et limites

Protéger contre les pages hostiles, messages forgés, domaines trompeurs, iframes, extensions voisines, lancement manuel du relais, faux endpoint local, rejeu, ancienne session, mélange de coffres et panne pendant un échange.

Un navigateur ou une extension FluXlock compromis, une injection dans Tauri ou un poste dont le compte utilisateur est compromis restent des menaces majeures. Un site légitime compromis peut lire les valeurs remplies. Une valeur livrée ne peut pas être révoquée rétroactivement. Le backend ne peut pas attester seul l’onglet réel ou la réalité d’un clic : ces contrôles dépendent du navigateur et de l’extension appairée.

## Architecture et authentification

```text
Popup TS : clic et attente, sans saisie d’authentification
  → worker TS + Rust/WASM : canal Noise
  → Native Messaging : trames chiffrées
  → relais Rust : socket Unix / named pipe Windows
  → route autofill Tauri → authentification fraîche dans FluXlock
  → comparaison exacte de l’origine → emails/usernames et handles vers la popup
  → choix dans la popup → handle lié à la demande vers Rust
  → revérification et déchiffrement du seul mot de passe choisi
  → réponse chiffrée unique → effacement et verrouillage natifs
  → remise de la réponse → worker → document précis → formulaire
```

Le relais n’ouvre pas de coffre, ne réutilise pas les CLI historiques et ne transforme pas le serveur de transfert P2P en API navigateur.

Sur Unix, socket dans un dossier 0700, socket 0600, refus de liens symboliques et contrôle de l’UID du pair, puis du PID si disponible. Sur Windows, ACL limitée au compte attendu, `PIPE_REJECT_REMOTE_CLIENTS`, protection contre l’occupation préalable du nom et contrôle des processus pairs. Un PID, le même UID, un argument de lancement ou un chemin caché ne donnent pas de droits de lecture à eux seuls.

### Appairage et canal de bout en bout

Prototype v1 historique, remplacé : `Noise_XX_25519_ChaChaPoly_SHA256`. L’implémentation actuelle est exclusivement le [profil v2 documenté](autofill-post-quantum-v2.md), `Noise_XXpsk3_25519_ChaChaPoly_SHA512` avec contribution ML-KEM-768 et authentification ML-DSA-65. Aucun secret du coffre dans le handshake, aucun 0-RTT, aucun repli v1. Les primitives viennent de bibliothèques Rust épinglées, avec aléa OS/Web Crypto et tests communs natif/WASM.

1. L’utilisateur déverrouille le coffre et active « Connecter un navigateur » dans l’application : fenêtre de 60 secondes, une tentative active, essais limités et annulation possible.
2. L’extension génère une identité dédiée au profil et au coffre ; l’application génère une identité indépendante de la clé maître. Le handshake donne un transcript commun.
3. Afficher dans les deux interfaces une empreinte de comparaison de 256 bits dérivée du transcript avec un domaine explicite. Comparaison et confirmation aux deux extrémités avant tout accès. Le nom annoncé du navigateur reste une étiquette.
4. Épingler les deux clés publiques. À chaque reconnexion, refuser une clé différente même si le handshake est valide. Aucun réappairage silencieux.
5. La route doit fonctionner coffre verrouillé : conserver l’identité de transport native dans le trousseau OS, indépendante de la clé du coffre. Un registre d’appairages disponible verrouillé contient seulement les clés publiques, identifiants de profil/coffre et états de révocation ; authentifier son intégrité avec un secret OS dédié. Il ne contient aucune URL, fiche ou clé de déchiffrement du coffre. Si le trousseau ou le registre est indisponible/invalide, refuser la connexion sans repli sur un fichier de secret en clair. Cela corrige la dépendance circulaire d’une clé de transport uniquement chiffrée dans le coffre verrouillé.
6. Côté extension, envelopper la clé Noise persistante avec une clé Web Crypto non exportable conservée dans IndexedDB. Le secret brut existe transitoirement en mémoire WASM. Cette enveloppe limite les copies accidentelles ; le code compromis de l’extension peut encore l’utiliser. « Non exportable » ne signifie pas « matériellement protégé ». [CryptoKey.extractable](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey/extractable).
7. Une révocation ferme les connexions et détruit les autorisations. Une restauration/réinitialisation invalide les appairages du coffre remplacé dans le registre OS ; ni une archive ni un ancien registre copié ne doivent réactiver les profils révoqués. Aucun appairage par P2P ou `storage.sync`. La preuve d’appairage autorise une demande native, jamais la lecture d’une fiche sans authentification fraîche.

Les manifestes Native Messaging n’autorisent que les IDs distribués et utilisent des identités distinctes pour dev, test et production. Le chiffrement worker–Tauri empêche un relais substitué de lire les secrets ; les contrôles OS et signatures des paquets restent nécessaires pour limiter les autres attaques locales.

L’intégrité seule d’un registre sur disque ne suffit pas à empêcher son remplacement par une ancienne copie valide. L’implémentation conserve donc **tout le registre et l’identité dans la même entrée du trousseau OS**, hors sauvegarde du coffre, sans fichier de registre à restaurer séparément. Une indisponibilité/entrée invalide refuse le canal ; elle ne réinitialise pas silencieusement la confiance. Le retour à une image complète du système et de son trousseau dépasse cette protection.

## Protocole minimal et contrôle de session

Enveloppe JSON extérieure : version et trame Noise base64, champs inconnus refusés, taille maximale 64 Kio ; charge utile déchiffrée limitée à 32 Kio. Contrôler les longueurs avant allocation, puis après décodage. Aucun chemin de fichier, commande système ou nom de commande Tauri choisi par le client.

| Opération | Résultat autorisé |
| --- | --- |
| `begin_fill` | Demande native liée à une origine ASCII et à un document ; retourne un identifiant opaque de demande, sans fiche ni autorisation de lecture. |
| `status(request_id)` | Attente, annulation, expiration ou fin de la demande du profil ; aucune fiche avant authentification native. |
| `list_candidates(request_id, cursor)` | Après preuve native seulement : page bornée d’emails/usernames du site exact et handles, sans mots de passe, titres, notes ou IDs SQL. La recherche d’origine est fixée par la demande, pas par un filtre libre du client. |
| `select_and_fill(request_id, handle, context)` | Choix dans la popup et contexte actuel du document. Rust vérifie la preuve native, le résultat d’origine, le handle et la révision avant de révéler un seul couple. La sélection consomme atomiquement l’autorisation entière. |
| `cancel` | Annule la demande ; ferme et efface la session temporaire si l’opération native a commencé. |
| Réponse finale `fill_once` | Un seul `username/password` ou `email/password`, après comparaison exacte, authentification native et verrouillage confirmé du coffre. Aucun rejeu de cette réponse. |
| Événements `locked` / `revoked` | Invalident les opérations ordinaires et les demandes annulées. La réponse scellée unique suit le chemin de remise décrit ci-dessous. |

Les identifiants de demande et handles sont aléatoires à 256 bits, liés à la connexion, au profil, au coffre, à l’opération native, à la génération d’ouverture, à l’origine et à `tabId/frameId/documentId/requestNonce`. Les handles désignent aussi une fiche et sa révision dans le résultat autorisé. Valeurs initiales à tester : attente native de 60 secondes, choix dans la popup de 30 secondes et revalidation du document de 5 secondes. La liste est paginée, au plus dix identités par réponse dans la limite de taille du protocole. Un seul remplissage est autorisé par authentification : choisir une entrée invalide tous les handles de la liste, y compris en cas de demandes concurrentes. Aucun second choix avec la même preuve.

Les URL existantes sont chiffrées : les rechercher côté Rust après authentification, sans déchiffrer les mots de passe des autres fiches. Ne révéler le secret sélectionné qu’au dernier stade. La recherche est interne à FluXlock ; le choix parmi son résultat revient à la popup. Aucun index de domaines en clair. Borner cadence, demandes en attente et durée des opérations. Une réponse trop volumineuse échoue sans tronquer le mot de passe.

Ne pas exposer `get_passwords`, `decrypt_password`, Notes, Fichiers, Clés, sauvegardes ou exports. Les métadonnées d’affichage passent par du texte échappé et ne sont pas journalisées.

Avant l’extension, appliquer le délai configurable depuis Rust, indépendamment du polling de la webview. Vérifier l’expiration à chaque opération sensible ; polling et reconnexions ne prolongent jamais la session. Première version : le remplissage ne prolonge pas non plus automatiquement le délai.

Un contrôleur Rust central invalide clés de coffre, connexions de remplissage et autorisations au verrouillage externe, changement de coffre, restauration, réinitialisation et fermeture, ainsi qu’à la veille/verrouillage OS selon la politique supportée. La remise finale après le verrouillage prévu de l’opération suit le chemin à usage unique ci-dessous ; elle n’autorise aucune autre lecture. Ne pas garder le verrou de lecture du cycle de vie pendant un choix utilisateur ou une attente réseau. Définir l’ordre des verrous, borner l’envoi et annuler les tâches lors des transitions.

### Session temporaire native et reverrouillage

Créer un type `AutofillTransaction`, distinct de `VaultSession`. Il peut posséder une clé protégée et le résultat d’une authentification fraîche pour la seule demande courante. Il ne crée pas de `current_user_id/session_token` utilisable par les commandes générales Tauri ; ne pas appeler simplement `local_login` puis rendre sa réponse au navigateur.

La fenêtre d’authentification appartient à l’application locale, avec ressources embarquées et commandes limitées à cette fenêtre. Rust lie la réponse du mot de passe ou du dialogue OS à l’instance de fenêtre, au nonce de demande et à l’origine affichée. Réutiliser les contrôles d’échecs, de blocage et de biométrie du coffre ; une nouvelle route ne doit pas permettre des tentatives illimitées ni considérer un ancien succès biométrique comme frais.

Après cette authentification, `list_candidates` fournit à la popup les seules identités du résultat. La popup conserve les handles en mémoire, rend les emails/usernames comme texte et transmet le handle cliqué à `select_and_fill`. Ne pas accepter un ID SQL, un email fourni comme autorisation, une origine de remplacement ou un nom de commande de déchiffrement générique. La preuve native reste dans le coordinateur Rust. L’absence de correspondance termine la demande sans élargir la recherche à d’autres sites.

Le passage de focus vers l’authentification native peut fermer automatiquement la popup du navigateur. La demande reste alors en mémoire dans le worker et le coordinateur pendant son délai ; rouvrir la popup pour le même document peut afficher le résultat de cette même opération, sans nouvelle fenêtre de sélection dans FluXlock. Cette continuation ne permet qu’un seul remplissage, sans redémarrage du worker, reconnexion, changement de document ou prolongation de la preuve. Une annulation explicite ou une fermeture pendant le choix termine la demande ; expiration et disparition du worker détruisent la session temporaire.

Concrètement, extraire de `commands/auth.rs::unlock` un service de vérification qui peut restituer une clé protégée au coordinateur sans publier de session générale ; conserver `local_login` pour le parcours manuel. Faire de même avec les fonctions natives de `biometric.rs`, en gardant la vérification de la clé et de son propriétaire. Ne jamais accepter dans le protocole navigateur un mot de passe maître, une clé base64 de coffre ou la réussite déclarée d’une biométrie ; la route qui complète l’authentification est réservée à la fenêtre native autorisée et à son défi.

Si une session manuelle est ouverte, la demande distante affiche seulement le dialogue de consentement natif. Lors de l’acceptation native, verrouiller la session manuelle puis démarrer l’authentification dédiée. Bloquer les commandes de contenu et les changements de coffre pendant l’opération réservée. Ce verrouillage réel élimine la possibilité de conserver une autre copie active de la clé dans la session habituelle. Un coffre déjà ouvert ne dispense jamais de la nouvelle preuve.

Une seule transaction active par application. Une demande concurrente échoue occupée ; elle ne prend pas la place d’une fenêtre existante et ne réutilise aucune preuve. Les callbacks tardifs sont rejetés par nonce/génération. Une expiration est appliquée par Rust, même si popup, relais ou fenêtre disparaissent.

À la fin, revalider le document et la session, consommer l’autorisation interne, déchiffrer le couple sélectionné et le chiffrer dans une enveloppe Noise finale liée à la demande. Garder cette enveloppe seulement en mémoire, sans journalisation, persistance ni retransmission. Détruire tous les buffers plaintext, la clé temporaire et les clones de clé ; appeler le chemin central de verrouillage et purger les vues/caches natifs. Ne rendre l’enveloppe éligible à l’écriture sur le canal qu’après la réussite de ce nettoyage. Un échec de verrouillage interdit la remise.

Le coordinateur doit attendre la fin des tâches qui détiennent une clé ; un simple événement UI « verrouillé » n’est pas suffisant. Utiliser des gardes d’effacement sur les erreurs et un contrôleur supervisé pour l’annulation/crash du dialogue. Ni une attente utilisateur, ni un envoi réseau ne conservent le verrou de lecture du cycle de vie. La réservation native empêche une nouvelle session de s’ouvrir entre le scellement de la réponse et la fin de l’opération ; un client muet ne peut pas conserver cette réservation au-delà du délai d’envoi.

Le canal appairé est une autorisation de transport, indépendante de l’état du coffre : il peut porter cette dernière enveloppe alors que la clé du coffre est déjà détruite. La réponse finale est consommable avant fermeture du canal ; ne pas envoyer un événement `locked` générique qui ferait supprimer au worker cette réponse attendue. Une transition externe (verrouillage manuel, révocation, veille, changement de coffre) annule en revanche toute enveloppe non encore remise. Après émission, fermer le canal de remplissage et imposer une nouvelle demande et une nouvelle authentification pour la suivante.

Aucun ACK du navigateur, événement d’insertion ni succès réseau ne commande le reverrouillage. Une coupure après scellement ou remise laisse le coffre verrouillé, sans renvoi automatique du secret. Si le document a changé au dernier instant, le worker jette la réponse ; il ne remplit aucun autre document et ne demande pas une nouvelle révélation avec la preuve précédente.

Les secrets ne sont pas persistés dans le navigateur, les logs ou le presse-papiers. Seul le credential choisi existe transitoirement dans le worker et le script d’insertion. Purger sur succès, erreur, expiration et déconnexion ; effacer les buffers Rust/WASM sans promettre l’effacement physique de toutes les copies JavaScript.

## Origine et insertion dans le formulaire

Permissions initiales : `nativeMessaging`, `activeTab`, `scripting`. Pas de `<all_urls>`, cookies, historique, presse-papiers ou écoute réseau. Déclenchement par clic sur l’icône ; raccourci après validation de ses permissions et de son geste utilisateur.

Machine à états : `idle → clic → document validé → authentification native fraîche → origine exacte → liste sans mots de passe dans la popup → choix d’un handle → document revalidé → réponse scellée → coffre verrouillé → remise unique → insertion → purge`. Navigation, fermeture du document ou changement de contexte annulent le flux ; la fermeture automatique de la popup pendant l’authentification suit l’exception bornée décrite plus haut. Un message de page ne déclenche jamais une authentification réussie ou une révélation.

La comparaison d’origine utilise des parseurs standards TypeScript/Rust et des vecteurs communs : HTTPS, hôte ASCII canonique obtenu par IDNA/UTS #46 non transitionnel, port effectif. Appliquer le même traitement à l’URL enregistrée et à l’origine du navigateur, puis comparer le tuple entier `(schéma, hôte_ASCII, port_effectif)` par égalité. Ce traitement repose sur [le standard URL](https://url.spec.whatwg.org/#concept-domain-to-ascii) et [Unicode UTS #46](https://www.unicode.org/reports/tr46/).

Ne jamais employer `includes`, recherche partielle, suffixe approximatif, distance entre chaînes, translittération, suppression d’accents, « skeleton » de caractères ressemblants ou extraction du seul domaine enregistrable pour autoriser le remplissage. Les mécanismes de détection de ressemblances Unicode peuvent avertir, mais ne doivent jamais créer une correspondance. [Unicode UTS #39](https://www.unicode.org/reports/tr39/).

Refuser userinfo, origine opaque, label invalide et URL ambiguë ; refuser les hôtes avec point final dans cette première politique plutôt que d’inventer une équivalence. Aucun élargissement aux sous-domaines, aucun retrait de `www`, alias ou redirection SSO autorisé implicitement. Une fiche sans URL HTTPS valide reste exclue tant qu’elle n’est pas corrigée dans l’application. Un chemin différent sur la même origine reste le même site ; si deux services partagent une origine et nécessitent un cloisonnement par chemin, ne pas annoncer que ce mécanisme fournit ce cloisonnement. Ne transmettre ni path ni query string quand seule l’origine est nécessaire.

La conversion concerne l’hôte : ne pas convertir l’email, le username ou le mot de passe en ASCII. Ils sont restitués exactement tels qu’enregistrés. La forme ASCII peut rester visuellement proche d’un autre nom ASCII : l’autorisation dépend de son égalité avec le nom enregistré, pas d’une promesse générale d’éliminer tous les homographes.

Exemples de règles à tester :

| URL enregistrée | Site demandé | Décision |
| --- | --- | --- |
| `https://paypal.com/login` | `https://paypal.com/account` | Même origine, compte sélectionnable après authentification native. |
| `https://paypal.com` | `https://PAYPAL.COM:443` | Même origine HTTPS canonique. |
| `https://paypal.com` | `https://paypal.com.evil.test` | Refus. |
| `https://paypal.com` | `https://www.paypal.com` | Refus : hôte différent. |
| `https://paypal.com` | `http://paypal.com` ou `https://paypal.com:8443` | Refus. |
| `https://paypal.com` | `https://pаypal.com` avec `а` cyrillique U+0430 | Refus : l’hôte demandé est `xn--pypal-4ve.com`. |
| `https://bücher.de` | `https://xn--bcher-kva.de` | Même hôte IDNA légitime ; pas de translittération en `bucher.de`. |
| `https://faß.de` | `https://fass.de` | Refus : traitement non transitionnel, `xn--fa-hia.de` est différent. |

Conserver ces vecteurs et ceux de conformité URL/IDNA dans les tests TypeScript et Rust. Si les deux parseurs ne produisent pas la même origine ASCII pour un cas, refuser ce cas ; ne pas revenir à une comparaison de texte Unicode. Vérifier l’origine au lancement, après l’authentification native, avant le scellement, puis dans le document ciblé avant l’insertion.

Cibler le `documentId` exact et le frame principal dans le monde isolé. Revérifier l’origine et les champs juste avant insertion ; ne jamais retomber sur le seul `tabId` si le document a disparu. Refuser les iframes, pages internes, protocoles non HTTPS, champs masqués/désactivés/en lecture seule et champs ambigus. Résoudre l’action effective du formulaire et refuser une destination externe dans le premier lot. Distinguer connexion et création d’un nouveau mot de passe, et tester les formulaires en plusieurs étapes.

La popup et la fenêtre d’authentification native affichent le domaine ASCII canonique ; la forme Unicode peut être secondaire, sans masquer l’ASCII. Le titre du site ne peut pas modifier cet affichage. Le choix du compte se fait dans la popup propre à l’extension, séparée du DOM du site, avec emails/usernames rendus comme texte. Le script de contenu ne reçoit jamais la liste et ne peut demander aucun autre compte. Valeurs injectées sans `innerHTML`, sans exécution dans le monde principal et sans soumission automatique. Un site destinataire peut lire son DOM et les événements : le monde isolé ne supprime pas cette limite.

Aucun listener `onMessageExternal`, pont `window.postMessage` ou action « lire un secret » dans le script de contenu. Valider l’ID de l’extension, le type d’expéditeur et le document de chaque message interne. `event.isTrusted` seul ne prouve pas une intention utilisateur au backend.

## Emballage et maintenance

Créer `browser-extension/` pour le TS et ses tests, une crate `autofill-protocol` pour le canal partagé, `src-tauri/src/autofill/` pour les droits et `src-tauri/src/bin/fluxlock-browser-host.rs` pour le relais.

Les installateurs macOS/Windows/Linux gèrent binaire signé et manifestes par navigateur. Tester déplacement, mise à jour, réparation, désinstallation, comptes OS distincts, multi-profils et distributions Linux sandboxées. Refuser les versions incompatibles de l’application et de l’extension. Séparer les profils de données et IDs « FluXlock Test » et production.

Tous les scripts et le WASM sont embarqués. CSP sans code distant, inline ou `eval` ; permettre uniquement `wasm-unsafe-eval` si nécessaire au module compilé, sans `unsafe-eval` JavaScript. [CSP Chrome](https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy).

Dépendances minimales et verrouillées, consultation des avis de sécurité avant choix de version, builds reproductibles et revue du paquet effectif et des permissions. Compte éditeur protégé par MFA avec clé matérielle ; procédure de révocation d’urgence d’une version compromise. Aucun analytics contenant sites, titres, usernames ou secrets.

## Relecture adversariale : failles envisagées et corrections

| Attaque après le premier plan | Correction intégrée | Vérification exigée |
| --- | --- | --- |
| Hôte lancé à la main avec l’ID officiel | Possession de la clé appairée et épinglage mutuel ; l’argument d’ID ne donne aucun droit. | ID correct sans clé : refus. |
| Relais/endpoint remplacé | Canal worker–Tauri de bout en bout ; contrôles OS et paquets signés. | Relais qui observe, modifie ou rejoue des trames : aucun plaintext ni accès autorisé. |
| Handshake valide avec une nouvelle clé | Refus strict d’une clé non épinglée ; pas de réappairage silencieux. | Nouvelle identité cryptographique : refus avant candidats. |
| Appairage imposé par une page | Fenêtre native explicite, comparaison 256 bits, double confirmation et essais limités. | Hors fenêtre, transcript divergent, expiration, concurrence. |
| Jeton de webview réutilisé par le navigateur | Grants dédiés, à usage unique, liés à la génération native. | Jeton général et ancien grant après réouverture : refus. |
| Faux domaine ou URL annoncée par le DOM | Métadonnées navigateur et normalisation exacte d’origine. | Sous-chaînes, IDN, ports, HTTP, userinfo et iframes. |
| Navigation après sélection | Document exact, revalidation et aucune retombée sur un nouvel onglet. | Navigation même origine/autre origine, SPA, BFCache et réutilisation d’onglet. |
| Rejeu ou réponse déplacée | Compteurs de canal, request IDs et consommation atomique liée au document. | Doublons, inversion, déconnexion et réponse tardive. |
| Polling gardant le coffre ouvert | Délai appliqué par Rust, sans activité générée par polling. | Webview suspendue et worker pollant en boucle. |
| Sauvegarde clonant des appairages | Invalidation à la restauration ; credentials non synchronisés. | Archive d’un ancien profil : nouvel appairage obligatoire. |
| Pipe Windows accessible à d’autres utilisateurs/réseau | ACL et refus réseau explicites, plus authentification de bout en bout. | Autre compte, client distant et occupation préalable du nom. |
| Worker redémarré avec vieux nonces/grants | Nouveau handshake et nouvelles clés éphémères ; aucune reprise de grant. | Arrêt forcé à chaque étape. |
| WASM utilisé pour élargir toute la CSP | Exception limitée au WASM embarqué, sans JS évalué ni code distant. | Inspection du manifeste et du paquet. |
| Monde isolé supposé cacher les valeurs au site | Action explicite, origine stricte et limite documentée. | Le site voit les valeurs après remplissage, jamais avant une action autorisée. |
| Coffre déjà ouvert utilisé comme preuve pour plusieurs sites | Authentification native fraîche par demande, liée à son origine et au document ; session temporaire sans ouverture générale. | Session manuelle ouverte, second site et seconde demande : nouvelle preuve obligatoire. |
| Bouton navigateur prétendant valider une authentification | La preuve vient du vérificateur Rust et du dialogue natif lié au nonce, jamais d’un booléen externe. | Faux `authenticated: true`, callback d’une ancienne fenêtre et ancien succès biométrique : refus. |
| Clé de transport inaccessible lorsque le coffre est verrouillé | Identité de transport dans le trousseau OS et registre public authentifié ; aucune clé de coffre récupérable par ce registre. | Démarrage coffre verrouillé : demande native possible, lecture de credential impossible sans preuve. |
| Conversion ASCII qui confond deux domaines | IDNA non transitionnel et égalité de l’origine complète ; pas de translittération/skeleton pour autoriser. | Cyrillic/latin, `ß`/`ss`, accents, punycode, ports, `www` et divergences des deux parseurs. |
| Liste de comptes divulguée avant authentification | Recherche native après preuve, puis seuls les emails/usernames correspondants dans la popup. | Avant preuve : zéro username/email, titre, nombre de comptes ou mot de passe ; compte d’un autre site jamais retourné. |
| Liste de tous les mots de passe d’un site envoyée pour choisir | La popup reçoit uniquement les identités et handles ; le mot de passe choisi est déchiffré à la fin. | Plusieurs comptes du même site : choix explicite ; aucun mot de passe non choisi dans les messages, la vue ou le relais. |
| Handle d’un autre compte/site injecté au moment du choix | Handle lié à la requête, au coffre, au résultat, à la révision et à l’origine ; contrôles répétés côté Rust. | Handle fabriqué, ancien, d’une autre recherche ou fiche modifiée depuis la liste : refus sans élargissement. |
| Plusieurs mots de passe extraits avec une authentification | La première sélection consomme l’autorisation entière et invalide tous les handles de la demande. | Deux sélections concurrentes ou séquentielles : au plus un seul secret remis, puis coffre verrouillé. |
| Liste de la popup divulguée à la page | Liste conservée dans le worker/popup, jamais dans le DOM ou les messages du script de contenu. | Page malveillante : aucun compte non choisi ; après insertion, seul le couple choisi est exposé au document. |
| Chiffrement/WASM présenté comme cachant les valeurs au navigateur | Les emails/usernames affichés sont accessibles au navigateur ; le mot de passe choisi y entre seulement pour le remplissage. | Mot de passe absent pendant la liste ; aucune valeur non choisie dans le formulaire ou le script de contenu. |
| Coffre restant ouvert car l’ACK navigateur n’arrive pas | Sceller la réponse, effacer les clés, confirmer le verrouillage natif, puis seulement émettre. | Relais muet, write bloqué, coupure et ACK absent : coffre déjà verrouillé. |
| Crash/annulation gardant une clé ou une preuve réutilisable | Coordinateur supervisé, effacement des clones, délai natif, aucun renvoi ou reprise de preuve. | Arrêt à chaque étape, demande simultanée, erreur de verrouillage et seconde consommation. |
| Message distant forçant le verrouillage d’une session manuelle | Pas de transition de la session avant acceptation dans la fenêtre native ; limiter les demandes par profil. | Annulation avant consentement : session manuelle conservée ; opération native acceptée puis annulée : coffre verrouillé. |

Ces corrections remplacent notamment les hypothèses insuffisantes « Native Messaging + même compte OS suffit » et « session ouverte = navigateur autorisé ». Il s’agit de corrections du plan ; leur efficacité devra être prouvée par l’implémentation et les tests.

## Lots et critères de passage

1. **Contrat et prototypes** : schémas, vecteurs d’URL, états et politique de session ; `snow` en WASM, aléa et CSP. Passage : vecteurs Noise communs et aucune construction cryptographique implicite restant à inventer.
2. **Session native** : route de demande d’authentification, fenêtre native dédiée, preuve fraîche, transaction temporaire, expiration autonome et verrouillage avant remise. Passage : aucun déverrouillage général, aucune preuve navigateur acceptée et coffre fermé avant tout envoi de credential, y compris sous panne/concurrence.
3. **Canal et appairage** : bibliothèque partagée, relais borné, transport OS, double confirmation, épinglage et révocation. Passage : faux endpoint/relais et client non appairé échouent sans exposer le coffre.
4. **Service autofill** : comparaison exacte IDNA/ASCII dans Rust, liste des seules identités correspondantes après preuve et `select_and_fill` à usage unique. Passage : tests multi-comptes du même site, aucun mot de passe non choisi déchiffré/remis, refus d’un handle hors résultat ou révision, double sélection, vecteurs communs TS/Rust, homographes, zéro métadonnée de fiche avant preuve, mélange de coffres, rejeu, concurrence et révocation.
5. **Extension Chromium** : popup d’attente sans authentification, puis liste d’emails/usernames sans mots de passe et sélection sur clic. Injecter le seul couple choisi dans le document précis. Passage : focus de l’authentification native et réouverture de la même demande, pages HTTPS synthétiques, formulaires multiples et en étapes, événements JS, navigation et DOM hostile ; aucun rendu de liste dans l’application ou dans la page web.
6. **Installation et distribution** : paquets, manifestes officiels et mises à jour. Passage : installations propres et migrations sur macOS/Windows/Linux, sans toucher les coffres personnels pendant les tests.
7. **Revue avant publication** : revue indépendante du bootstrap/protocole, fuzzing des parseurs, avis de dépendances et tests de l’extension réellement chargée. Corriger les constats bloquants avant distribution publique.
8. **Firefox et plateformes suivantes** : conserver les garanties de ciblage et d’appairage ; réduire le périmètre si une API ne les fournit pas. Ne pas ajouter d’exception silencieuse.

La livraison nécessite des résultats enregistrés par OS, uniquement des secrets synthétiques dans les fixtures et aucune régression sur Notes, Fichiers, identifiants, sauvegardes et biométrie. Des mocks ou une capture de popup ne prouvent pas la sécurité du canal natif.

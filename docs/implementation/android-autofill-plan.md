# Autofill Android : intégration proposée

23 novembre 2026. Document de conception après inspection du projet et consultation des API Android officielles. **Aucun service Android d’autofill n’est encore implémenté ou activé.** L’application Android existante conserve ses fonctions actuelles. L’extension MV3 et le relais desktop ne constituent pas une intégration Android.

## Point de départ dans le dépôt

Le manifeste Android déclare `MainActivity`, la biométrie et les fournisseurs de fichiers, mais aucun `AutofillService` ni `CredentialProviderService`. Les classes Kotlin `MainActivity.kt` et `BiometricBridge.kt` fournissent déjà une intégration Keystore/biométrie pour la WebView de l’application. Le coordinateur autofill Rust desktop dépend actuellement de `AppState`, des fenêtres et des événements Tauri : son interface doit être extraite avant de pouvoir le partager proprement avec un service système.

**Choix :** Kotlin pour les composants Android, Rust pour le moteur de coffre, l’authentification par mot de passe, la normalisation des origines et les autorisations à usage unique. Communication interne par JNI/bridge natif typé. Aucun relais externe, serveur HTTP local, accès au presse-papiers ou service d’accessibilité pour remplir les mots de passe.

Deux intégrations complémentaires sont nécessaires : `AutofillService` dès Android 8/API 26, et fournisseur Credential Manager dès Android 14/API 34. Android 7 conserve le coffre mais ne bénéficie pas d’autofill système. Credential Manager fournisseur ne doit pas être confondu avec l’API cliente de connexion utilisable par les applications. Sources : [Autofill](https://developer.android.com/identity/autofill/autofill-services), [fournisseur Credential Manager](https://developer.android.com/identity/sign-in/credential-provider).

## Parcours à conserver

1. Le système propose une entrée générique « Autoriser avec FluXlock ». Avant authentification : aucun username/email, nombre de comptes ou mot de passe.
2. Une activité native FluXlock authentifie l’utilisateur, même si l’application était déjà déverrouillée. Le mot de passe maître ne transite ni dans la WebView du navigateur ni dans une réponse système. La biométrie débloque une opération Keystore avec `CryptoObject`, jamais un simple booléen de succès. [Biométrie cryptographique](https://developer.android.com/identity/sign-in/biometric-auth).
3. Après vérification de la cible, la même activité affiche uniquement les emails/usernames correspondants. Il n’y a pas de seconde fenêtre de sélection. Chaque compte conserve un handle aléatoire lié à la demande.
4. Le choix déchiffre le seul mot de passe sélectionné. Le coordinateur consomme tous les handles, détruit la clé temporaire et verrouille le coffre avant la remise d’un unique `Dataset` ou `PasswordCredential` au système.
5. Annulation, expiration, changement d’application/coffre ou disparition du processus détruisent l’autorisation. Aucun secret dans les sauvegardes d’état, logs, extras d’intents, notifications ou presse-papiers. Les extras transportent seulement des références temporaires ; le résultat final contient nécessairement le seul couple choisi.

Android et l’application/le navigateur destinataires peuvent lire le couple livré au remplissage. Cette limite est identique à celle du desktop. Les mots de passe non choisis ne doivent jamais être déchiffrés pour construire une liste système de plusieurs datasets.

## Cible : application native ou site web

| Cible | Autorisation retenue |
| --- | --- |
| Application native | Association explicite stockée chiffrée : identifiant de package **et** empreintes SHA-256 des certificats de signature. Vérifier les signatures actuelles et la lignée de rotation approuvée ; le nom, l’icône et le package seuls ne suffisent pas. |
| Site dans un navigateur approuvé | Origine HTTPS complète issue d’une API de confiance, après vérification du package et du certificat du navigateur. Comparaison Rust exacte après IDNA/Punycode, avec schéma, hôte complet et port effectif. |
| WebView d’une application | Vérifier l’association domaine/application avec Digital Asset Links et la signature, puis l’origine exacte ; l’association ne donne pas le droit d’élargir aux sous-domaines ni au domaine enregistrable. |
| Origine partielle, contradictoire ou identité inconnue | Refus du remplissage de mot de passe. Aucun repli sur une sous-chaîne, un texte de barre d’adresse ou une confirmation qui supprimerait la vérification. |

Android documente la vérification des certificats des applications et des associations de domaines. Son exemple d’agrégation au domaine enregistrable sert à établir une association ; **il ne sera pas repris comme règle de correspondance des mots de passe FluXlock**. Notre politique reste plus stricte. [Sécurité d’AutofillService](https://developer.android.com/reference/android/service/autofill/AutofillService).

Point bloquant à résoudre dans le prototype : certaines structures Autofill historiques donnent seulement le domaine, et pas une origine fiable avec schéma et port. Elles ne peuvent satisfaire automatiquement notre contrat « site exact ». Ne pas inventer `https:443` lorsque l’information manque. Le prototype doit relever les métadonnées réellement disponibles par navigateur/version et refuser les contextes incomplets. `CallingAppInfo.getOrigin()` de Credential Manager nécessite une liste de navigateurs privilégiés vérifiés par package et certificats ; c’est la voie à examiner pour les origines complètes sur Android 14+. [Origine des appelants privilégiés](https://developer.android.com/identity/sign-in/credential-provider#obtain-an-allowlist-of-privileged-apps).

## Découpage d’implémentation

1. **Moteur commun Rust.** Extraire le coordinateur du rendu Tauri : `begin`, `authenticate`, `list`, `consume`, `cancel`, avec cibles typées `WebOrigin` / `AndroidApp`. Un moteur unique par processus, initialisable sans `MainActivity`, partagé avec Tauri ; mêmes verrous de cycle de vie, base et état de sélection. Aucun deuxième gestionnaire de sessions ou de clés créé dans le service Android. Préserver les commandes desktop existantes derrière cet adaptateur et exécuter leurs tests avant de poursuivre.
2. **Frontière native.** Ajouter des sources Kotlin durables, hors fichiers générés écrasables, et configurer Gradle pour les compiler. Bridge JNI limité à des structures validées et opérations dédiées, sans nom de commande arbitraire. Garder les secrets dans des buffers natifs bornés ; effacer les copies contrôlées. Le bridge WebView biométrique existant n’est pas l’API d’autofill.
3. **Activité d’autorisation.** Composant non exporté, interface native, vérification du nonce et du contexte conservé par le service, biométrie par opération et alternative mot de passe. Ne pas sérialiser le secret dans `savedInstanceState`. `FLAG_SECURE`, protections contre les touches occultées et superpositions selon la version. Le retour tardif d’une biométrie ne réactive jamais une demande annulée.
4. **AutofillService API 26+.** Déclaration protégée par `BIND_AUTOFILL_SERVICE`, métadonnées et activation volontaire dans les paramètres système. Lire le contexte fourni par le framework, vérifier le composant destinataire et les certificats via PackageManager ; l’UID Binder du système ne constitue pas à lui seul l’identité de l’application à remplir. Borner la taille/profondeur de `AssistStructure`, gérer `CancellationSignal` et les formulaires à étapes. Réponse verrouillée générique, puis seulement dataset choisi après le parcours natif. Pas de sauvegarde automatique des mots de passe dans le premier lot.
5. **CredentialProviderService API 34+.** Déclaration protégée par la permission système correspondante ; d’abord les mots de passe existants, sans introduire les passkeys. Réponse initiale d’authentification générique, contrôle de `CallingAppInfo` et de l’origine privilégiée, puis résultat choisi. Adapter les API de résultat selon leur contrat, sans publier une liste de tous les mots de passe après déverrouillage.
6. **Intents et durée de vie.** Intents explicites, identifiants uniques, nonce non prévisible, refus du rejeu et délais natifs (60 s d’authentification, 30 s de choix comme base). `PendingIntent` immuable lorsque l’API le permet ; si le framework doit ajouter des extras et exige de la mutabilité, limiter le composant et les champs modifiables, puis revalider toute donnée reçue. Aucun deep link public ne transporte de preuve d’authentification.
7. **Déploiement progressif.** Prototype sur fixtures, option expérimentale désactivée par défaut, validation sur appareils, puis activation pour les seules combinaisons dont l’identité et l’origine sont vérifiables. Un APK qui compile ne suffit pas à annoncer la prise en charge du remplissage web.

## Tests et critères avant activation

- Réutiliser les vecteurs exacts Rust/TypeScript : IDN, `ß`/`ss`, sous-domaines, `www`, userinfo, ports non standard, HTTP refusé. Kotlin ne doit pas refaire une normalisation IDNA divergente.
- Deux applications de même apparence et signatures différentes ; faux navigateur ; package réinstallé avec un autre certificat ; rotation de certificat reconnue ou refusée explicitement.
- Plusieurs comptes du même site, aucun compte d’un autre site, aucune métadonnée avant preuve ; retour final unique et tous les autres handles invalidés.
- Changement d’application, nouvelle activité, champs remplacés, retour arrière, rotation, verrouillage OS, fermeture ou kill du processus à chaque étape. Aucun mot de passe envoyé à une ancienne cible.
- Touches occultées, tentative d’ouverture externe de l’activité, intents forgés et rejeu d’un `PendingIntent` ; aucune preuve fournie par JavaScript.
- Appareil API 26/28, API 30, API 34 et version courante ; navigateurs et applications réels, certificats de production séparés des clés de test. Tester le mot de passe maître sans biométrie et la biométrie matérielle.
- Régressions : notes et fichiers chiffrés, sauvegarde/restauration, isolation des coffres et absence de clé générale après remplissage. Réduire la compatibilité annoncée si l’origine exacte ne peut être prouvée.

Livrable préalable à toute activation : matrice version/navigateur/API prouvant quelles origines sont disponibles, revue de la frontière JNI et du cycle de vie, résultats instrumentés et tests sur au moins un appareil physique. Cette étape doit précéder la promesse de compatibilité Android globale.

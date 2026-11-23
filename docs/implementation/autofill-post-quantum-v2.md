# Autofill post-quantique : profil v2 et migration

23 novembre 2026. Implémentation locale : extension **0.4.0**, relais **0.2.0**, crate partagé **0.2.0**, version de fil **2**. Ce document remplace les descriptions cryptographiques v1 des premiers rapports. Le parcours d’authentification, l’origine exacte et le verrouillage du coffre restent obligatoires.

## Architecture et choix cryptographiques

Le worker TypeScript et le backend Rust exécutent le même crate `autofill-protocol`, compilé en WASM et nativement. Le relais Native Messaging transporte des trames opaques ; il n’a ni identité cryptographique de pair, ni clé du coffre, ni accès SQL. Le manifeste autorise uniquement l’ID de l’extension enregistré à l’installation.

| Fonction | Algorithme et rôle |
| --- | --- |
| Établissement de secret | **ML-KEM-768** éphémère, combiné aux échanges **X25519** par le mécanisme PSK de Noise. |
| Authentification mutuelle | **ML-DSA-65**, preuves du transcript et du rôle à chaque connexion, clés publiques épinglées lors de l’appairage. |
| Canal | `Noise_XXpsk3_25519_ChaChaPoly_SHA512`, chiffrement authentifié **ChaCha20-Poly1305**, dérivation et transcript **SHA-512** selon Noise. |
| Identité épinglée | SHA-256 avec domaine explicite de la clé publique ML-DSA complète. Cette empreinte de 32 octets n’est pas une clé publique X25519. |
| Comparaison d’appairage | Empreinte de 256 bits du transcript final, huit groupes de huit caractères hexadécimaux, à comparer intégralement dans les deux interfaces. |

Les primitives suivent [FIPS 203, ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) et [FIPS 204, ML-DSA](https://csrc.nist.gov/pubs/fips/204/final). L’intégration utilise le [mécanisme PSK défini par Noise](https://noiseprotocol.org/noise.html#pre-shared-symmetric-keys), avec injection du vrai secret ML-KEM dans le slot 3 de Snow. **L’ensemble constitue un profil applicatif propre à FluXlock**, pas un protocole hybride intégralement standardisé ou un module certifié FIPS. Ce n’est pas X-Wing. Une revue cryptographique indépendante de cette composition reste nécessaire avant diffusion publique.

Les versions RustCrypto sont exactement épinglées : `ml-kem = 0.3.0-rc.2`, `ml-dsa = 0.1.0-rc.8`, avec `zeroize`. Ce sont les versions déjà présentes dans le coffre, encore en préversion ; leur présence et les tests ne constituent pas une preuve d’audit. Snow est épinglé à `0.10.0`. Les lockfiles figent aussi les dépendances transitives.

## Échange et liaison des preuves

Le navigateur est l’initiateur ; FluXlock est le répondeur. Le prologue fixe version, suites et rôles :

```text
fluxlock-autofill-v2/ML-KEM-768/ML-DSA-65/Noise_XXpsk3_25519_ChaChaPoly_SHA512/browser-initiator/desktop-responder
```

Chaque message de handshake contient `FLPQ` (4 octets), version `2` (1), numéro du message (1), longueur du corps Noise (u16 big endian), puis le corps et, pour les messages 2 et 3, une signature ML-DSA détachée de 3309 octets. Rôle, ordre, taille, version et absence d’octets surnuméraires sont vérifiés. Toute erreur détruit l’état utilisable de handshake ; aucune exportation de canal après erreur.

1. **Message 1 :** l’initiateur produit une clé ML-KEM éphémère à partir de 64 octets CSPRNG. La clé publique de 1184 octets est le payload du premier message Noise. Le chiffrement initial propre au pattern PSK ne prouve pas encore une identité.
2. **Message 2 :** le répondeur encapsule vers cette clé avec 32 octets CSPRNG frais et installe le secret de 32 octets dans le slot PSK 3. Le payload Noise contient le ciphertext ML-KEM de 1088 octets et sa clé publique ML-DSA de 1952 octets. Sa signature porte sur `D || 0x02 || h2`, où `D = "fluxlock-autofill-v2/ML-DSA-65/transcript/"` et `h2` est le transcript Noise SHA-512 après ce message. Le navigateur vérifie la signature et décapsule, puis contrôle l’identité épinglée avant d’émettre le message 3.
3. **Message 3 :** le secret ML-KEM est consommé par le token PSK de Noise, avec les contributions X25519 déjà incorporées par la dérivation Noise. Le payload contient la clé publique ML-DSA de l’initiateur. Sa signature porte sur `D || 0x03 || h3 || signature2`. Le backend vérifie cette preuve et le profil appairé avant d’autoriser les commandes applicatives. Aucune donnée applicative n’est autorisée dans les payloads de handshake.
4. **Confirmation :** le backend envoie un message d’accueil chiffré sous les clés hybrides, portant l’empreinte finale. Le navigateur le déchiffre et compare cette empreinte avant toute commande ; cela confirme aussi que le pair possède le secret ML-KEM attendu.

Les signatures utilisent l’API ML-DSA standard avec contexte externe `FluXlock autofill v2`. Le contexte, les domaines et les rôles empêchent de réutiliser une preuve pour une autre fonction. Le transcript Noise couvre les clés éphémères/statiques, la clé ML-KEM et son ciphertext, et les clés publiques ML-DSA des payloads correspondants. Les tests déplacent notamment une signature valide vers un autre échange et vérifient son rejet.

L’engagement final est `SHA512("fluxlock-autofill-v2/complete" || h3 || signature2 || signature3)` (64 octets). L’empreinte affichée est constituée des 32 premiers octets de `SHA512("fluxlock-autofill-pairing-v2" || engagement)`, rendus en hexadécimal majuscule avec tirets, soit **71 caractères**. L’empreinte persistée du pair est `SHA256("fluxlock-autofill-v2/ML-DSA-65/identity" || clé_publique_ML-DSA)`.

Le secret ML-KEM n’est jamais remplacé par un PSK fictif pour commencer l’échange : le slot reste absent jusqu’à sa génération/décapsulation réelle. Un test produit une signature ML-DSA authentique, mais un secret KEM différent, et vérifie l’échec de l’échange. Cela contrôle que le KEM contribue effectivement à la clé de trafic.

Les enveloppes JSON portent également `version: 2`. Limites : 16 Kio par handshake, 64 Kio par enveloppe, 32 Kio par plaintext applicatif. Les bornes, délais, compteurs Noise et authentification AEAD refusent allocations démesurées, attente indéfinie, altérations et rejeux. Il n’y a ni 0-RTT, ni négociation ou repli v1.

## Identités, mémoire et migration

Une identité privée contient **64 octets CSPRNG indépendants du coffre** : 32 pour la clé statique X25519 et 32 pour la graine ML-DSA. La clé ML-KEM est nouvelle à chaque échange et n’est pas persistée. L’aléa provient de l’OS en natif et de `crypto.getRandomValues` dans le worker ; un échec de cette source ferme l’opération.

Le registre natif v2 conserve identité et profils atomiquement dans le trousseau OS, services `com.fluxlock.browser.v2` ou `com.fluxlock.browser.test.v2`. Il n’importe aucune ancienne clé ou autorisation v1. Le chargement d’un registre v2 valide, ou sa création, retire l’ancienne entrée OS ; un échec de retrait bloque l’activation et sera retenté. Les profils conservent uniquement l’empreinte publique de 32 octets ; la limite de quatre profils et les bornes de noms/vaultId préservent la limite de blob Windows, y compris en UTF-16.

Le navigateur utilise une nouvelle base `fluxlock-browser-identity-v2`, une clé AES-GCM-256 non exportable et l’AAD `fluxlock-profile-v2/ML-DSA-65/Noise`. Le champ chiffré fait 80 octets (64 + tag 16). Les identités de 32 octets sont rejetées. La base v1 n’est jamais importée ni consultée pour prendre une décision de confiance ; sa suppression est tentée après ouverture d’une identité v2 valide, sans bloquer si un ancien contexte la garde ouverte. Le stockage protège les données au repos dans les limites du navigateur ; un navigateur compromis peut demander l’usage de sa propre clé.

Les buffers contrôlés sont nettoyés. Un garde natif/WASM détruit puis efface l’allocation complète de la clé ML-DSA développée, car la version épinglée ne nettoie pas toutes ses représentations mises en cache. Le slot PSK est remplacé après dérivation. La pile WASM est fixée à 4 Mio pour les opérations post-quantiques. Cela ne garantit pas l’effacement physique de toutes les copies temporaires Rust, JavaScript, navigateur ou OS.

**Mise à jour locale obligatoire des trois composants :**

1. Fermer l’ancienne application et les opérations d’autofill. Reconstruire/lancer FluXlock depuis ces sources ; un ancien binaire installé ne reçoit pas ces changements.
2. Reconstruire le relais release et remplacer le binaire au chemin enregistré. Si le chemin ou l’ID change, réenregistrer explicitement le manifeste avec l’installateur en simulation par défaut, puis `--install` et les options de remplacement applicables.
3. Recharger `browser-extension/dist` ou décompresser le paquet **0.4.0** au même emplacement puis recharger l’extension.
4. Activer la passerelle dans les réglages du coffre et refaire l’appairage, en comparant les **huit groupes** des deux empreintes avant de confirmer des deux côtés.

La migration invalide volontairement les anciens appairages. Aucun secret du coffre, mot de passe maître, note ou fichier n’est exporté pour migrer le transport. Revenir à un ancien binaire n’est pas une stratégie de compatibilité supportée.

## Autorisation et frontières conservées

Le canal authentifie les pairs appairés ; il ne remplace pas l’authentification fraîche de l’utilisateur. Chaque opération exige une preuve dans FluXlock, jamais le mot de passe maître dans le navigateur. La session native temporaire n’émet aucun jeton général.

Après preuve, seules les fiches de l’origine HTTPS canonique exacte sont listées : nom complet en ASCII IDNA/Punycode, schéma et port effectif ; pas de recherche par sous-chaîne ni de correspondance implicite entre sous-domaines. Les chemins d’une même origine peuvent différer. Les handles sont limités au document, à la connexion, au coffre et à une courte échéance. L’utilisateur choisit son email/username, le backend vérifie que la fiche n’a pas changé, déchiffre le seul mot de passe choisi, scelle la réponse et verrouille le coffre **avant l’envoi**. Annulation, expiration et erreur ferment aussi l’autorisation temporaire.

Le site destinataire et le navigateur peuvent lire le couple choisi après insertion ; le chiffrement du transport ne peut empêcher cela. Les autres secrets ne sont pas transmis. Les permissions minimales et le monde isolé n’autorisent aucun remplissage automatique sans action, aucune soumission de formulaire, ni lecture des notes/fichiers par l’extension.

## Vérification locale et revue des risques

| Contrôle | Résultat et portée |
| --- | --- |
| Coffre Rust | **156 tests réussis**, dont registre/migration, limites Windows, et deux nouveaux tests sur le vrai serveur IPC via flux Tokio et MockRuntime Tauri : aucun accès aux comptes avant preuve native, refus d’une nouvelle identité ML-DSA même avec la même clé X25519. Inclut les régressions Notes et multi-coffres existantes. |
| Protocole Rust | **10 tests réussis** : authentification mutuelle, KEM effectivement requis, signatures altérées/déplacées, rejeux, sens, format/version/ordre/tailles, interdiction du transport prématuré et de données précoces, nouvelles empreintes et vecteurs NIST. |
| Extension Node/WASM | **11 tests réussis** : véritable interopérabilité avec Rust, identité connue NIST en WASM, refus d’une signature altérée, d’une clé v1, d’un aléa défaillant et destruction de l’état après appel ABI hors limite, plus les contrôles d’autorisation du worker et d’origine. |
| Relais | **2 tests réussis**, dont refus explicite de l’enveloppe v1 et bornes avant allocation. |
| Paquet chargé dans Brave | Worker MV3 réel, CSP, WASM, RNG, identité 64 octets stable chiffrée en IndexedDB, clé non exportable ; ancien enregistrement v1 ignoré. Profil jetable, aucun relais enregistré dans le profil personnel. |
| Popup avec empreinte v2 | **100 configurations** ; axe-core sans violation sur les vues contrôlées en clair/sombre ; contraste minimal mesuré 5,83:1. La nouvelle empreinte complète reste lisible. |
| Vraie popup et formulaires | Paquet 0.4.0 ouvert avec `chrome.action.openPopup()` : contexte système POPUP, viewport et contenu **520 × 330**, aucune barre de défilement à l’accueil. Régression Chromium du monde isolé : couple choisi seulement, aucune soumission automatique, refus GET/inscription/origine ou action externe, étapes email/mot de passe. Secrets fictifs uniquement. |
| Builds | Frontend Tauri, TypeScript/WASM et relais macOS release construits. |
| Windows/Linux | Compilation/type check du protocole et du relais pour x64 MSVC/Linux GNU ; vrai code de pipe Windows compilé avec son test. Ce ne sont pas des exécutions sur ces OS. |

Les [vecteurs NIST sélectionnés et leur provenance figée](../../autofill-protocol/test-vectors/README.md) comparent les clés publiques ML-KEM et ML-DSA octet par octet ; ils ne constituent ni une campagne ACVP exhaustive ni une certification. Les journaux locaux `/private/tmp/fluxlock-pq-*.log` sont des traces de travail, pas des artefacts de CI publiés.

Paquet local : [fluxlock-extension-0.4.0.zip](../../browser-extension/fluxlock-extension-0.4.0.zip), 16 fichiers vérifiés octet par octet contre `browser-extension/dist`, 124229 octets ; SHA-256 `d52592efbff32f69255cfac8397d8efc27bce5a85c53f82b6a1003cd605fb608`. L’archive générique `fluxlock-extension.zip` contient la même version. Ces archives générées sont ignorées par Git ; le build et les sources restent la référence reproductible.

La recherche d’avis OSV sur les dépendances du protocole a identifié `block-buffer 0.12.0`. Les deux lockfiles concernés ont été mis à **0.12.1**, correctif de [GHSA-qwgh-2vcv-g2f7 publié par RustCrypto](https://github.com/RustCrypto/utils/security/advisories/GHSA-qwgh-2vcv-g2f7). Après correctif, les 58 couples paquet/version du protocole ne retournent aucun avis connu lors du contrôle OSV du 23 novembre 2026. Le contrôle est ponctuel et circonscrit aux dépendances du protocole ; il ne constitue pas un audit complet du dépôt.

Corrections intégrées lors de la relecture : preuves des deux rôles et du transcript complet, liaison de la signature du serveur dans la preuve du client, confirmation de clé avant commande, pas de PSK de substitution, refus terminal des versions/formats incorrects, identités et registres séparés de v1, aucune migration implicite de confiance, nettoyage des représentations ML-DSA en cache, taille de registre testée sur Windows, et correctif de dépendance cité ci-dessus.

Avant diffusion publique restent nécessaires : revue indépendante du profil cryptographique, fuzzing des états/parseurs, qualification Native Messaging et biométrie réelle sur chaque OS, CI distante sur ces changements locaux, signature des binaires et identité de store définitive. Les tests automatisés actuels ne prouvent pas ces points. Android garde son [plan d’intégration native AutofillService](android-autofill-plan.md) ; la version Chromium desktop ne constitue pas une implémentation Android.

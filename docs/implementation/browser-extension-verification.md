# Vérification de l’implémentation autofill

23 novembre 2026. État : code et paquets de développement construits localement sur macOS Apple Silicon. Aucune publication, aucun enregistrement du relais dans le profil personnel du navigateur.

**Rapport historique de la première version.** Pour la cryptographie et les contrôles actuels, voir [le profil post-quantique v2 et sa vérification](autofill-post-quantum-v2.md) : extension 0.4.0, relais 0.2.0, 156 tests du coffre, 10 du protocole et 11 de l’extension. Les mentions de Noise classique et les anciens résultats ci-dessous ne décrivent pas le canal v2.

Mise à jour : la [refonte 0.2.0 et son rapport multiplateforme](extension-redesign-verification.md) ajoutent l’icône, les vues clair/sombre, huit tests d’extension, la vérification visuelle/accessibilité et les contrôles croisés Windows/Linux. Les résultats ci-dessous documentent la première passe d’implémentation.

## Composants livrés

- `browser-extension` : popup, worker MV3, ciblage par document, formulaires, stockage de l’identité et Noise WASM ; permissions `activeTab`, `scripting`, `nativeMessaging` seulement.
- `autofill-protocol` : Noise XX partagé, `snow` 0.10.0, source aléatoire OS/Web Crypto, enveloppes bornées et interopérabilité native/WASM.
- `native-host` : relais Rust stdio/socket/pipe, sans clé de coffre, SQL, commande système ou API d’authentification.
- `tauri-desktop/src-tauri/src/autofill` : authentification native fraîche, appairage, recherche exacte, autorisation temporaire et sélection unique.
- Fenêtre d’authentification dédiée et réglages d’appairage/révocation dans l’application ; clôture de la session manuelle et purge des vues lors de l’authentification autofill acceptée.
- Installateur de manifeste en simulation par défaut et CI pour les trois OS desktop.

## Résultats locaux

| Vérification | Résultat et portée |
| --- | --- |
| Application Rust, `RUST_MIN_STACK=16777216 cargo test --locked --lib` | **152 réussis**, dont 8 tests du service autofill, authentification sans session générale, avant/après preuve, sélection unique, contexte/document/connexion/révision/compte verrouillé, origine et expiration. Les tests utilisent de vraies bases et le chiffrement réel ; la fenêtre est un `MockRuntime` Tauri. La pile de test par défaut a débordé sur une fixture ; la relance à 16 Mio et la CI utilisent cette configuration. |
| Protocole partagé Rust | Test natif réussi : échange, altération, rejeu et sens du canal. |
| Extension, `npm test` | **7 réussis** : origines et permissions, échange réel Rust/WASM et rejet du rejeu, worker sélectionnant un seul compte, mot de passe absent de la réponse popup, refus après navigation, rejet des messages de page et annulation à la fermeture pendant le choix. Le canal du test worker est simulé, contrairement au test d’interopérabilité cryptographique. |
| Relais Rust | **2 réussis** : bornes avant allocation, encapsulation et conversion des formats de longueur. |
| Interface Tauri et extension | Builds TypeScript/Vite et Rust/WASM réussis ; relais macOS release construit. |
| DOM Chromium isolé | Remplissage du compte choisi, événements DOM, absence de soumission, refus origine/action externe, inscription, GET explicite/implicite ; étape email sans mot de passe, puis étape mot de passe sans email. Aucun secret réel. |
| Paquet MV3 réellement chargé | Worker lancé dans Brave avec un profil temporaire ; CSP, WASM local, aléa Web Crypto et aller-retour de l’identité en IndexedDB sous clé AES-GCM non exportable vérifiés. Pas d’enregistrement Native Messaging ni de dialogue matériel dans ce test. |
| Régression Notes | Parcours Playwright réussi à 390 et 1280 px avec l’interface modifiée. Les tests Rust couvrent aussi Notes, pièces jointes, sauvegardes et transitions de coffres. |
| Régression multi-coffres | Création, verrouillage avant changement, renommage, isolation des sessions et caches vérifiés à 320, 768 et 1280 px. |

Les journaux de travail locaux sont dans `/private/tmp/fluxlock-autofill-*.log` et `/private/tmp/fluxlock-extension-build.log` ; ils ne constituent pas des artefacts de CI durables.

## Relecture de sécurité et corrections intégrées

1. **Authentification falsifiée par le navigateur :** aucun message de succès accepté. Vérification du mot de passe/biométrie dans Rust ; commandes réservées à la fenêtre native portant le nonce et un périmètre IPC réduit. La preuve ne produit pas de jeton général du coffre.
2. **Réponse tardive après révocation :** génération native vérifiée sous verrou de cycle de vie pendant l’émission locale bornée à deux secondes. Annulation, changement de coffre et verrouillage invalident la génération.
3. **Dialogue OS long :** aucun verrou de cycle de vie conservé pendant l’attente biométrique ; revérification du contexte et du délai après son retour. Le superviseur natif expire l’opération même si la popup/webview ne pollent plus.
4. **Déchiffrement excessif :** lecture des URLs et usernames pour la liste seulement ; le mot de passe choisi est déchiffré à la consommation atomique de l’autorisation. Empreinte des champs chiffrés pour refuser une fiche modifiée. Tous les autres handles disparaissent.
5. **Coffre ouvert après remise :** réponse scellée, clés de transaction détruites et nettoyage de session effectué avant sa remise au relais ; aucun ACK attendu.
6. **Domaines ressemblants et navigation :** IDNA/Punycode sans translittération, origine complète égale, document Chromium précis avant récupération et insertion ; aucune retombée vers un simple tabId. Ports, sous-domaines et `www` restent distincts.
7. **Persistance et copie d’une sauvegarde :** identité + registre natifs dans une seule entrée OS atomique ; restauration/réinitialisation retirent les profils concernés avant remplacement des données. Une ancienne sauvegarde de coffre ne peut réactiver un profil. Une restauration complète du trousseau OS n’est pas couverte.
8. **Formulaires et fuite dans une URL :** POST obligatoire lorsqu’un formulaire existe, donc refus du GET par défaut ; pas de soumission, d’iframe, de formulaire ambigu ou d’inscription. L’étape email annule la clé sans récupérer de mot de passe.
9. **Mémoire WASM :** pointeurs récupérés avant de créer la vue du buffer, car l’allocation peut agrandir et détacher la mémoire ; buffers contrôlés effacés, messages et tailles bornés. Pas de promesse d’effacement des copies JS/OS non contrôlées.
10. **Confusion test/production :** nom d’hôte, profil de stockage et ID d’extension distincts ; build test explicite. Le manifeste ne permet qu’un ID fourni par l’installateur.
11. **Changement de coffre pendant une vérification :** les lectures/écritures du vérificateur de mot de passe et le contrôle préalable de biométrie vérifient le coffre et la demande sous garde de cycle de vie ; aucun compteur d’échec ou migration d’email ne doit atteindre une autre base. La garde est libérée pendant le dialogue OS. Le contexte et le délai sont contrôlés à nouveau avant l’admission de la clé et après la recherche des candidats.

## Qualification restant avant une diffusion publique

Faire une installation propre avec extension réellement chargée et relais enregistré sur macOS, Windows et Linux, puis vérifier l’appairage, les reconnexions, la biométrie matérielle, les ACL Windows sous un autre compte/client distant, les blocages du trousseau et les scénarios de panne/navigation/BFCache/concurrence. La CI multiplateforme ajoutée n’a pas été exécutée depuis cette session locale. La branche Windows du nouveau pipe n’a pas été compilée sur ce Mac.

Prévoir une revue indépendante du bootstrap, fuzzing des parseurs/états, audit des dépendances et du paquet distribué, signature des binaires et identité définitive de store. La présence de tests et d’un canal chiffré ne constitue pas une certification du système complet. Le navigateur et un site légitime compromis restent capables de lire le seul mot de passe que l’utilisateur a choisi de remplir.

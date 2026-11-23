# Refonte de l’extension et état multiplateforme

**Actualisation :** l’extension est désormais en **0.4.0**, avec le [canal hybride post-quantique v2](autofill-post-quantum-v2.md). Le présent rapport conserve les mesures de la passe visuelle 0.3.0. La géométrie est conservée ; les 100 configurations et axe-core ont été revérifiés avec l’empreinte d’appairage v2 de 71 caractères. La description « cryptographie inchangée » ci-dessous concerne uniquement la passe visuelle historique. Le nouveau rapport détaille les tests Rust/WASM et les vérifications Windows/Linux relancés pour v2.

23 novembre 2026 — extension **0.3.0**, modifications locales non publiées. Cette révision remplace les proportions trop verticales de la version 0.2.0.

## Design livré

Popup de **520 px de large**, sans hauteur minimale imposée. L’accueil mesure **520 × 330 px dans la vraie popup Brave**, contre un ancien layout de 384 px de large et au moins 512 px de haut. Les cartes ont des coins de 20 px, le cadre et le dialogue de 24 px, les boutons une forme de pilule. Le bloc d’authentification se lit horizontalement ; le grand titre et la rangée d’étapes visuelle ont été retirés. Les étapes restent disponibles pour les lecteurs d’écran.

Identité FluXlock et icônes PNG de l’application dans le manifeste et la barre du navigateur. Palette, espacements et typographie partagés avec `tauri-desktop/src/design-system/tokens.css`, copié au build ; aucun nouveau framework ou style distant. Thème système clair/sombre appliqué avant l’affichage. Le document natif garde une largeur intrinsèque de 520 px, sans plafond `100vw` pendant la mesure initiale du navigateur ; l’aperçu en page ordinaire reste adaptable aux petites largeurs.

Le site exact en ASCII est visible dès l’ouverture à partir des métadonnées navigateur, sans connexion au relais ou recherche de credentials. Une action principale lance le parcours ; attente native, choix des comptes, empreinte d’appairage, succès, absence de compte et erreurs possèdent chacun leur présentation. Lignes de comptes compactes, compteurs alignés au titre, pagination avec précédent/suivant, focus conservé pendant les mises à jour et confirmation avant réinitialisation du profil. L’aide est une vue distincte : son ouverture masque le contenu principal au lieu d’empiler deux écrans verticalement.

Références consultées : [1Password, vue du navigateur](https://support.1password.com/getting-started-browser/), [capture officielle de sa vue d’élément](https://support.1password.com/img/browser-item-view.png), et [refonte Bitwarden, mode compact et largeur réglable](https://bitwarden.com/blog/bringing-intuitive-workflows-and-visual-updates-to-the-bitwarden-browser/). Les choix retenus pour FluXlock sont la densité des lignes, l’utilisation de l’espace horizontal et une action principale claire, en gardant son parcours d’authentification propre.

La sélection ne demande que le handle ; aucun champ de mot de passe maître n’a été ajouté au navigateur. La cryptographie et les règles d’autorisation natives ne changent pas. Aucun favicon de site ou police n’est téléchargé pour le design. Le protocole et ses permissions restent identiques.

Aperçus avec **comptes fictifs** : [accueil clair](../images/extension/idle-light.png), [choix sombre](../images/extension/ready-dark.png). [Capture du vrai conteneur de barre d’outils Brave](../images/extension/actual-toolbar-popup.png), dans un profil jetable sans site autorisé : le message « Ouvrez une page HTTPS » y est donc attendu.

## Vérifications exécutées sur ce Mac

| Contrôle | Résultat |
| --- | --- |
| Build TypeScript + WASM, paquet 0.3.0 | Réussi ; archive contrôlée, 16 fichiers identiques à `dist`. |
| `npm test` | **8 réussis** : tests de sécurité existants et nouveau contrôle qu’ouvrir la popup n’ouvre aucun canal natif ni recherche de credentials. |
| Popup réelle DOM/CSS avec API Chrome simulée | **100 combinaisons** : 10 états × clair/sombre × 320, 375, 520, 768 et 1280 px. Pas de débordement horizontal. Métadonnées hostiles et identifiants longs rendus comme texte. À 520 px, chaque état contrôlé reste sous 500 px de hauteur, l’accueil sous 340 px. |
| Accessibilité | **0 violation axe-core** sur accueil, sélection, appairage et erreur dans les deux thèmes ; contraste minimal mesuré **5,83:1** pour les paires de texte contrôlées. |
| Interactions | Pagination de 23 comptes, choix uniquement sur action, maintien du focus au polling, saisie clavier, Entrée, Escape, confirmation de réinitialisation, reflow à 200 %, mouvement réduit. |
| Paquet chargé dans Brave | Worker MV3, assets, CSP/WASM, Web Crypto et identité IndexedDB sous clé non exportable vérifiés dans un profil jetable. Aucun relais enregistré dans le profil personnel. |
| **Vraie popup de barre d’outils** | `chrome.action.openPopup()` puis vérification du contexte système `POPUP`. Viewport **520 × 330**, contenu **520 × 330**, largeur cliente **520** : aucune barre de défilement à l’accueil. Capture produite depuis son vrai DevTools target. |
| Formulaires Chromium | Régression du monde isolé : seul couple choisi, événements, pas de soumission, refus GET/inscription/action externe et étapes email/mot de passe. |

La fixture de popup simule les messages Chrome pour tester les vues ; elle ne prouve pas une authentification native. Le test de paquet chargé et le test de vraie popup ne constituent pas un parcours matériel biométrique de bout en bout. Les **152 tests applicatifs Rust** du [rapport précédent](browser-extension-verification.md) sont un résultat antérieur à cette passe visuelle ; ils n’ont pas été relancés ici. La révision 0.3.0 ne change aucun code Rust. Le contrôle Windows ci-dessous provient de la passe précédente.

## Windows et Linux : ce qui est réellement prouvé

Les dernières CI distantes consultées sont vertes pour Windows x64, Linux x64, macOS et Android ARM64/ARMv7 au commit `483df783eab08993f862899f53e35f50328e2715`, le **20 novembre**. Elles précèdent les changements locaux Notes, multi-coffres, autofill et cette refonte. [Exécution vérifiée](https://github.com/Tiemtore-dev/fluxlock/actions/runs/44736207616).

Vérifications supplémentaires exécutées le 23 novembre depuis ce Mac avec `scripts/check-autofill-platforms.py` :

| Cible | Contrôle | Résultat |
| --- | --- | --- |
| Windows `x86_64-pc-windows-msvc` | `cargo check --locked` du relais et du protocole | Réussi. |
| Linux `x86_64-unknown-linux-gnu` | `cargo check --locked` du relais et du protocole | Réussi. |
| Windows, vrai code de pipe de l’application | Compilation/type check, y compris test, avec `windows` **0.58.0** et Tokio **1.48.0** comme le desktop | Réussi. |

Le code Windows a été déplacé sans changer son comportement dans `autofill/windows_pipe.rs`, inclus directement par la sonde de compilation : pas de copie divergente. Un test Windows vérifie qu’un client du propriétaire peut s’y connecter et qu’une deuxième création avec `first_pipe_instance` est refusée. Ce test a été **compilé mais pas exécuté sur Windows** pendant cette session.

Ces contrôles n’effectuent ni l’édition de liens d’une application Windows/Linux complète ni son exécution. Aucun Docker Linux n’est actif sur ce Mac. **La compatibilité complète des modifications récentes n’est donc pas encore validée sur Windows/Linux.** Il faut encore reconstruire et tester l’application complète, enregistrer le relais, exercer appairage/authentification/remplissage/révocation, permissions Unix/ACL Windows, trousseau/Secret Service et matériel biométrique sur les OS natifs.

La CI de l’extension a été enrichie pour exécuter les tests de popup/axe, formulaires et chargement du paquet dans Chromium sur les trois OS, avec Playwright et axe-core épinglés, ainsi que pour conserver les aperçus de test. Le workflow desktop existant compile l’application et exécute les tests natifs. **Ces workflows modifiés ne sont pas encore exécutés à distance**, car les modifications restent locales.

## Reproduire

```sh
npm run build --prefix browser-extension
npm test --prefix browser-extension
rustup target add x86_64-pc-windows-msvc x86_64-unknown-linux-gnu
python3 scripts/check-autofill-platforms.py
```

Les tests `browser-extension/tests/popup-ui.mjs`, `browser.mjs` et `extension.mjs` utilisent Playwright. `FLUXLOCK_PLAYWRIGHT` peut indiquer son chemin local ; `FLUXLOCK_AXE` indique `axe-core/axe.min.js` ; `FLUXLOCK_UI_OUTPUT` choisit le dossier d’aperçus. Le test d’extension nécessite Chromium complet ou `FLUXLOCK_BROWSER_EXECUTABLE` pointant vers Brave/Chromium. Les profils sont temporaires et ne contiennent que des données synthétiques.

Journaux de la révision 0.3.0 : `/private/tmp/fluxlock-extension-wide-{build,tests,ui,native}.log`. Journaux de la passe précédente : `/private/tmp/fluxlock-extension-redesign-{loaded,forms}.log` et `/private/tmp/fluxlock-extension-platform-check.log`. Les caches de compilation de la sonde ont été nettoyés après réussite ; les sources, journaux et cibles Rust restent disponibles.

Android fait l’objet d’un [plan natif Kotlin/Rust séparé](android-autofill-plan.md), avec refus des contextes dont l’origine exacte ou l’identité ne peut être vérifiée. Aucun support Android autofill n’est annoncé comme déjà opérationnel.

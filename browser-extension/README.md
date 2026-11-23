# Extension FluXlock — Chromium desktop

Implémentation de développement pour Chrome, Brave et Edge (Chromium 106 minimum). L’application FluXlock issue de **ce dépôt** doit rester ouverte. L’extension n’est pas publiée dans un store ; une ancienne application installée ne contient pas cette passerelle.

La version **0.4.0** utilise le canal hybride **ML-KEM-768 + X25519**, authentifié par **ML-DSA-65**, partagé entre Rust natif et WASM. Il faut mettre à jour **l’application, le relais 0.2.0 et l’extension**, puis refaire l’appairage en comparant les huit groupes de l’empreinte. Aucun repli vers le protocole v1 ni import de sa confiance. Voir [le profil v2, la migration et les résultats](../docs/implementation/autofill-post-quantum-v2.md). Ce profil applicatif nécessite encore une revue indépendante avant diffusion publique.

Le design introduit en **0.3.0** et conservé en **0.4.0** propose une popup large et compacte : **520 × 330 px à l’accueil**, mesurés dans la vraie fenêtre de la barre d’outils Brave. Cartes arrondies, boutons en pilule, liste de comptes compacte, thèmes système clair/sombre ; l’aide remplace le contenu principal au lieu d’allonger la fenêtre. Pour actualiser une installation décompressée, reconstruire `dist` ou remplacer le contenu du même dossier par la nouvelle archive, puis cliquer sur **Recharger** dans la page des extensions. Garder le même chemin préserve l’ID de développement ; une opération d’autofill en cours doit être recommencée. [Aperçus et résultats de vérification](../docs/implementation/extension-redesign-verification.md).

Le navigateur affiche les emails/usernames après une authentification fraîche dans l’application. Le clic sur un compte récupère uniquement son mot de passe, verrouille le coffre avant la transmission, puis remplit le document visé. Aucun mot de passe maître n’est demandé dans l’extension. Les notes et les fichiers ne sont pas accessibles par ce protocole.

## Construire

Prérequis : Node.js 22, Rust stable, dépendances Tauri de la plateforme. Depuis la racine :

```sh
npm ci --prefix tauri-desktop
rustup target add wasm32-unknown-unknown
npm run build --prefix browser-extension
cargo build --locked --release --manifest-path native-host/Cargo.toml
```

Pour lancer l’application contenant la passerelle :

```sh
cd tauri-desktop
npm run tauri -- dev
```

La cryptographie vient du même crate Rust, compilé nativement dans Tauri et en WASM dans le worker : `Noise_XXpsk3_25519_ChaChaPoly_SHA512`, secret ML-KEM-768 dans le slot PSK 3, preuves ML-DSA-65 des transcripts. Le relais Rust ne possède pas de clé de coffre et n’accède pas à sa base. Les dépendances Rust sont verrouillées. Le build utilise le TypeScript déjà verrouillé dans `tauri-desktop/package-lock.json`.

## Installer localement

1. Ouvrir la page des extensions du navigateur (`chrome://extensions`, `brave://extensions` ou `edge://extensions`), activer le mode développeur et charger le dossier **browser-extension/dist** décompressé.
2. Copier l’ID exact affiché par le navigateur. Ne pas utiliser un ID d’exemple. Un déplacement du dossier peut changer cet ID ; `FLUXLOCK_EXTENSION_PUBLIC_KEY` permet de fournir la clé publique d’une identité de développement stable lors du build.
3. Placer le relais compilé à un emplacement durable, accessible uniquement en écriture par le compte attendu. Sous Windows, le nom se termine par `.exe`.
4. Depuis la racine, examiner d’abord la simulation ci-dessous, puis relancer avec `--install` pour enregistrer le manifeste utilisateur. Remplacer les deux valeurs par le chemin absolu du relais et l’ID réel ; choisir `chrome`, `brave` ou `edge`.

```sh
python3 scripts/install-browser-host.py --browser brave --host /chemin/absolu/fluxlock-browser-host --extension-id ID_REEL
python3 scripts/install-browser-host.py --browser brave --host /chemin/absolu/fluxlock-browser-host --extension-id ID_REEL --install
```

Le manifeste autorise ce seul ID. L’installateur n’écrase pas un autre enregistrement sans `--replace`. Le binaire doit rester au chemin enregistré. Windows utilise Python et une entrée HKCU, sans installation administrateur. Aucun enregistrement système n’est effectué par le build.

## Appairer et remplir

1. Dans FluXlock, déverrouiller le coffre voulu et ouvrir **Paramètres → Extension de navigateur**. Activer la passerelle, puis cliquer sur **Connecter un navigateur**.
2. Dans les 60 secondes, sur une page HTTPS, ouvrir l’extension et cliquer sur **Connecter**. Comparer intégralement l’empreinte dans les deux fenêtres et confirmer des deux côtés. Une empreinte différente impose d’annuler.
3. Cliquer sur le remplissage dans l’extension. S’authentifier dans la fenêtre de l’application FluXlock avec le mot de passe maître ou la biométrie disponible. Une session déjà ouverte ne dispense pas de cette authentification.
4. Revenir à la popup si le navigateur l’a fermée lorsque l’application a pris le focus. Choisir explicitement un email/username dans les 30 secondes. Seul ce compte sera rempli, sans soumettre le formulaire.
5. Chaque nouvelle demande exige une authentification. Un changement de document, une expiration ou une déconnexion oblige à recommencer.

Seule l’origine HTTPS exacte correspond : nom complet converti en ASCII par IDNA/Punycode, schéma et port. `www.exemple.com`, `exemple.com`, un sous-domaine et un domaine visuellement similaire sont différents. Enregistrer une URL HTTPS complète dans la fiche. Les chemins de la même origine peuvent différer.

Pour les connexions en deux pages, l’étape email remplit uniquement l’email et détruit l’autorisation sans récupérer de mot de passe. L’étape mot de passe demande une nouvelle authentification. Les iframes, formulaires ambigus, champs masqués, formulaires d’inscription et formulaires GET sont refusés. Les formulaires POST sans champ email sont pris en charge à la seconde étape.

**Révocation :** déverrouiller le coffre et révoquer le profil dans Paramètres. Une restauration ou une réinitialisation révoque aussi ses appairages. Le bouton de réinitialisation du profil de l’extension exige ensuite un nouvel appairage ; il ne contourne pas une révocation native. Limite actuelle : quatre profils au total, et un même profil de navigateur est appairé à un seul coffre à la fois.

## Profils de test

Garder des IDs d’extension distincts et des répertoires distincts pour test et production. Pour le profil isolé « FluXlock Test », compiler l’application et le relais **en debug** avec `FLUXLOCK_TEST_BUILD=1`, construire l’extension avec `FLUXLOCK_EXTENSION_TEST_PROFILE=1` et enregistrer le relais avec `--test-profile`. Le mode test n’est pas activé dans une compilation Rust release. Ne pas mélanger ces trois paramètres avec le coffre habituel.

## Vérification et limites

```sh
cargo test --locked --manifest-path autofill-protocol/Cargo.toml
cargo build --locked --example interop --manifest-path autofill-protocol/Cargo.toml
npm test --prefix browser-extension
cargo test --locked --manifest-path native-host/Cargo.toml
RUST_MIN_STACK=16777216 cargo test --locked --lib --manifest-path tauri-desktop/src-tauri/Cargo.toml
```

`tests/browser.mjs` vérifie le code de formulaire dans un monde isolé Chromium avec Playwright et uniquement des secrets fictifs. Fournir `FLUXLOCK_PLAYWRIGHT` si Playwright n’est pas installé dans le chemin Node habituel.

`tests/extension.mjs` charge le vrai paquet MV3 dans un profil jetable pour vérifier le worker, la CSP, le WASM et l’identité IndexedDB. Il nécessite Chromium complet (pas uniquement `chromium_headless_shell`) ; `FLUXLOCK_BROWSER_EXECUTABLE` permet d’indiquer un exécutable Brave/Chromium. Ce test ne modifie pas le profil personnel et n’enregistre pas de relais.

`tests/popup-native.mjs` ouvre la **vraie action de barre d’outils** avec `chrome.action.openPopup()` et mesure son viewport via DevTools, plutôt qu’un onglet affichant `popup.html`. Le navigateur de test doit supporter `openPopup()` et `runtime.getContexts()`. Ce test vérifie 520 px de largeur, un accueil de 340 px de haut au maximum et l’absence de débordement ; aucune permission supplémentaire n’est ajoutée au produit.

Le site et le navigateur peuvent lire **le couple choisi après insertion** dans le formulaire. Ni WASM ni le canal chiffré ne peuvent cacher au navigateur une valeur qu’il doit insérer. Les autres mots de passe restent dans le coffre. Les chaînes JavaScript et copies internes du navigateur ne permettent pas de garantir l’effacement physique de toute copie ; les buffers contrôlés sont effacés et aucune donnée d’identification n’est persistée par l’extension.

Le trousseau OS conserve l’identité de transport et son registre dans une entrée atomique, indépendante des sauvegardes du coffre. Une restauration complète de l’OS/trousseau ou un poste/navigateur compromis dépasse ces garanties. L’indisponibilité du trousseau bloque la passerelle, sans repli vers un secret en clair.

Les tests automatisés ne remplacent pas la qualification d’une installation propre, de l’extension réellement chargée avec Native Messaging et des dialogues biométriques sur chaque OS. Voir [la vérification détaillée](../docs/implementation/browser-extension-verification.md) et [le plan de sécurité](../docs/implementation/browser-extension-plan.md). Firefox, Safari, Android et la publication/signature des paquets ne font pas partie de cette livraison locale.

État Windows/Linux et contrôles de compilation réalisés : [rapport du 23 novembre](../docs/implementation/extension-redesign-verification.md#windows-et-linux--ce-qui-est-réellement-prouvé). Pour Android, voir [la conception native proposée](../docs/implementation/android-autofill-plan.md).

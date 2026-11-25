# Changelog

Tous les changements notables de FluXlock sont documentés dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0] - 2026-11-25

### Cryptographie Post-Quantique Stable, Clés OpenSSH & Protection AAD

- **Migration vers les crates RustCrypto stables** : mise à niveau de `ml-kem` vers `0.3.4` (FIPS 203), `ml-dsa` vers `0.1.2` (FIPS 204), `pkcs8` vers `0.11.0`, `signature` vers `3.0.0`, et intégration du crate officiel `ssh-key 0.6.7` pour la génération et la sérialisation authentique de paires de clés `ssh-ed25519` (`openssh-key-v1` PEM + empreinte `SHA256:...`), `X25519` (clamping RFC 7748 §5), `ML-DSA-65` et `ML-KEM-768`.
- **Chiffrement authentifié lié par AAD contextuelle (`v2:aad:`) & Lazy Decryption** : chaque colonne sensible SQLite est chiffrée avec `ChaCha20-Poly1305` (RFC 8439) en liant cryptographiquement `(user_id, table, column)` dans l'AAD, empêchant toute attaque par permutation de colonnes ou de lignes. Les secrets critiques (mots de passe, numéros de cartes PAN/CVV, numéros de pièces d'identité, graines TOTP, clés privées) restent chiffrés dans les listes et ne sont déchiffrés qu'unitairement à la demande avec purge mémoire automatique après 60 secondes.
- **Partage de fichiers par clé éphémère HKDF (RFC 5869)** : dérivation d'une clé de partage dédiée par lien via `HKDF-SHA256` sans jamais exposer la clé maître du coffre.

### Authentificateur 2FA (TOTP), Passkeys WebAuthn, Cartes Bancaires & Identité Souveraine

- **Onglet dédié « Codes 2FA (TOTP) » (`/totp`) & Analyseur QR Code 100 % Pur Rust Multiplateforme** : moteur RFC 6238 / RFC 4226 (`HMAC-SHA1`, `HMAC-SHA256`, `HMAC-SHA512`, 6 à 8 chiffres), décodeur Protobuf natif pour l'import groupé depuis Google Authenticator (`otpauth-migration://offline?data=...`), import multi-lignes `otpauth://totp/...` (2FAS, Aegis, Bitwarden, Proton Pass), et analyseur d'images QR Code 100 % pur Rust (`rqrr` + `image`) fonctionnant hors-ligne en mémoire vive sur **macOS, Windows, Linux et Android**.
- **Onglet dédié « Passkeys WebAuthn Level 3 » (`/passkeys`) & Parcours Navigateur 1-Clic** : authentificateur logiciel conforme W3C WebAuthn Level 3 / FIDO2 CTAP2 (clés résidentes COSE `EdDSA -8` `Ed25519`, flags `UP | UV | BE | BS | AT`), relié à l'extension navigateur via le canal post-quantique pour créer une Passkey ou signer une assertion en un geste (Touch ID / Windows Hello / Mot de passe maître) avec vérification anti-phishing stricte du `rp_id`.
- **Onglet dédié « Cartes bancaires » (`/cards`) & Remplissage WHATWG `cc-*`** : validation algorithmique de Luhn (ISO/IEC 7812-1), détection automatique du réseau émetteur et remplissage sécurisé des formulaires de paiement HTTPS (`cc-name`, `cc-number`, `cc-exp`, `cc-exp-month`, `cc-exp-year`, `cc-csc`).
- **Capture de mot de passe à la volée (`ProposeSave`)** : détection des formulaires de création ou de connexion (`new-password` / `current-password`) dans l'extension navigateur et enregistrement chiffré dans le coffre via la fenêtre native de confirmation FluXlock.
- **Onglet dédié « Documents d'identité » (`/identities`) & Preuves IETF SD-JWT** : stockage chiffré des pièces d'identité (CNI, Passeport, Permis, Identité Européenne EUDI Wallet) et émission de justificatifs à divulgation sélective (`draft-ietf-oauth-selective-disclosure-jwt`) salés sur 128 bits CSPRNG et hachés en `SHA-256`.
- **Synchronisation continue P2P multi-appareils (`vault_sync.rs`)** : Horloge Logique Hybride (HLC — Kulkarni et al.) avec garde-fou anti-dérive de 5 minutes, journal d'opérations CRDT LWW-Element-Set signé `ML-DSA-65` et calcul de racine de Merkle `BLAKE3`.

---

## [2.4.2] - 2026-11-24

### Extension Navigateur & Relais Natif Automatique

- **Identifiant d'extension Chromium déterministe (`oifhfkkohaimodaedcjbnfbamhgocndg`)** : épinglage d'une clé publique RSA-2048 SubjectPublicKeyInfo dans `browser-extension/manifest.json` garantissant un identifiant d'extension constant sur Chrome, Brave, Edge et Chromium sous macOS, Windows et Linux.
- **Relais Native Messaging intégré au binaire Desktop** : interception immédiate des invocations `chrome-extension://<id>/` au démarrage de `main()` avant toute initialisation de Tauri, WebView ou SQLite, exécutant un relais `stdio <-> IPC local` isolé avec validation stricte des enveloppes JSON v2 (`MAX = 64 Ko`).
- **Auto-installation et auto-mise à jour des manifestes Native Messaging** : synchronisation automatique de `com.fluxlock.browser.json` (et des clés de registre `HKCU\Software\...\NativeMessagingHosts` sous Windows via FFI Win32 direct) au lancement de FluXlock (`autofill::boot`) et à l'activation de la passerelle (`autofill_enable`), avec écriture atomique en permissions `0600`, protection anti-symlink sur toute l'arborescence, vérification des permissions du binaire et préservation des `allowed_origins` personnalisées.

---

## [2.4.1] - 2026-11-23

### Sécurité & Cryptographie Post-Quantique

- **Handshake P2P hybride (`SPAKE2 + ML-KEM-768`)** : liaison cryptographique du transcript complet (`SPAKE2 A/B || ML-KEM-768 ek || ML-KEM-768 ct`) dans la dérivation `HKDF-SHA3-256` de la clé de session et du `safety_number`.
- **Séparation des clés `Vault v2`** : dérivation de deux sous-clés indépendantes (`fluxlock/vault-v2/aead-key` et `fluxlock/vault-v2/header-mac-key`) via `HKDF-SHA3-256` à partir de la clé maître Argon2id.
- **Durcissement KDF Argon2id (`Vault v2`)** : plafonnement anti-DoS / anti-OOM des paramètres du header non authentifié (`m_cost <= 512 MiB`, `t_cost <= 32`, `p_cost <= 32`).
- **Effacement mémoire PQC (`ML-KEM-768` & `ML-DSA-65`)** : activation de la feature `zeroize` sur `ml-kem`, destruction déterministe via `MaybeUninit` + `drop_in_place` + écritures volatiles (`write_volatile`) et barrière `compiler_fence(SeqCst)`, et retour `Zeroizing<Vec<u8>>` sur les exports de graines et clés PKCS#8 DER.
- **Extension navigateur (`form.ts`, `noise.ts`)** : vérification des attributs HTML5 `formaction` et `formmethod` sur tous les boutons de soumission associés au formulaire, validation de visibilité DOM sur toute la chaîne d'ancêtres (opacité, `pointer-events`, bornes horizontales et verticales), effacement immédiat de la tranche de sortie dans la mémoire linéaire WASM après copie, et encodage Base64 par blocs de 8 Ko.
- **CI / Release** : compilation et empaquetage des relais natifs macOS (`aarch64-apple-darwin` et `x86_64-apple-darwin`) directement au sein des jobs macOS de `build` afin d'éviter la saturation de la file d'attente des runners `macos-latest` lors de la publication vers `fluxlock-releases`.

---

## [2.4.0] - 2026-11-23

### Ajouté

- Notes chiffrées avec pièce jointe, modification, suppression, sauvegarde et restauration.
- Plusieurs coffres locaux avec sessions, clés, caches et sauvegardes isolés ; verrouillage lors du changement de coffre.
- Extension Chromium 0.4.0 et relais natif 0.2.0 pour le remplissage sur l’origine HTTPS exacte. L’authentification reste dans FluXlock ; l’utilisateur choisit un compte, puis le coffre se verrouille avant la remise du seul couple choisi.
- Canal hybride ML-KEM-768/X25519, authentification mutuelle ML-DSA-65 et chiffrement ChaCha20-Poly1305. Les anciens appairages navigateur sont invalidés ; mettre à jour application, relais et extension puis refaire l’appairage.
- Popup compacte de 520 × 330 px à l’accueil, icône FluXlock, cartes arrondies, thèmes clair/sombre et navigation clavier.
- Contrôles CI du coffre, de l’extension et du relais ; publication après validation de main pour une nouvelle version, avec les paquets du relais et de l’extension.

### Corrigé

- Mise à jour de block-buffer 0.12.0 vers 0.12.1 dans le graphe utilisé par le desktop et le protocole d’extension (GHSA-qwgh-2vcv-g2f7).
- Rejet terminal des erreurs de protocole et des appels WASM hors limite ; refus d’établir le canal si l’aléa cryptographique échoue.

### Compatibilité

- L’extension est destinée à Chromium desktop et n’est pas publiée dans un store. Android reçoit l’application, les notes et les coffres ; l’intégration AutofillService Android reste à développer.
- Le profil cryptographique applicatif post-quantique n’a pas encore fait l’objet d’une revue indépendante ; aucune certification FIPS n’est revendiquée.

---

## [2.3.4] - 2026-11-20

### Corrigé

- Windows accepte les connexions de transfert IPv4 et IPv6 sur le même port.
- Les transferts utilisent le port annoncé par l’appareil. L’appairage reste compatible avec la 2.2.23 et les appareils appairés resynchronisent leurs registres signés sur le réseau local.
- Sur macOS, la clé de session reste uniquement en mémoire protégée et est effacée au verrouillage. FluXlock supprime l’ancienne entrée de session du trousseau au démarrage et à la connexion.
- Le mode compatibilité Touch ID est disponible dans les paquets macOS de distribution compilés sans profil Developer ID.

---

## [2.3.1] - 2026-11-20

### Corrigé

- Sur macOS, Touch ID dispose d’un mode compatibilité sans profil Apple. Le Secure Enclave protège le déchiffrement de la clé du coffre.
- Les transferts utilisent le port annoncé par l’appareil et essaient les adresses découvertes jusqu’à authentifier l’offre.
- L’appairage est compatible avec la 2.2.23. Les appareils appairés et visibles resynchronisent leurs registres de confiance signés sur le réseau local.

---

## [2.3.0] - 2026-11-20

### Modifié

- Interface revue sur ordinateur et Android, avec une vue d’ensemble des mots de passe, des fichiers et des clés.
- Pour ouvrir un coffre existant, seul le mot de passe maître est demandé. La biométrie native s’active depuis un coffre déjà déverrouillé. Les anciennes passkeys sont retirées.
- Les transferts valident l’ordre et la taille des blocs. Le registre de confiance est échangé et vérifié lors de l’appairage. Pour utiliser le nouveau protocole de transfert et d’appairage, mettez à jour les deux appareils.
- Les nouveaux fichiers sont chiffrés avec le format SENC v2. FluXlock continue de lire les fichiers SENC v1.

### Corrigé

- La restauration accepte les sauvegardes authentifiées qui contiennent les anciens fichiers de métadonnées. Sur Windows, elle réessaie la publication en cas de verrouillage temporaire.
- L’import de mots de passe prend en charge les exports CSV Brave et Chromium, Firefox, Apple et Bitwarden, en conservant les espaces et les caractères Unicode des mots de passe.

---

## [2.2.23] - 2026-10-18

### Corrigé

- Android : la bannière de mise à jour n'est plus masquée par la barre de navigation du bas.
- Android : les backups sont désormais copiés dans `Documents/FluXlock/` (hors du dossier de l'application) et survivent à une désinstallation. La restauration d'un backup se fait via le sélecteur de fichiers.
- Android : la création et la restauration de backup utilisent le dossier de données réel de l'application.
- Export CSV : le fichier est enregistré dans `Documents/FluXlock/` (Android) ou dans le dossier Téléchargements (bureau), et son emplacement exact est affiché à l'utilisateur.

---

## [2.2.22] - 2026-10-18

### Modifié

- Version de test du mécanisme de mise à jour Android (2.2.20 → 2.2.22). La 2.2.21 n'a jamais été publiée.

---

## [2.2.20] - 2026-10-18

### Modifié

- Android : APK limité aux architectures arm64 et armv7 (taille réduite d'environ 100 Mo)

---

## [2.2.19] - 2026-10-17

### Ajouté

- Android : mise à jour in-app via les releases GitHub (détection, téléchargement en arrière-plan, vérification de l'APK, bouton « Installer »)
- CI : build, signature et publication de l'APK Android avec les autres installeurs

---

## [2.0.0] - 2026-04-10

### Ajouté

- Architecture complète Tauri v2 + Rust + React/TypeScript
- Chiffrement militaire AES-256-GCM et ChaCha20-Poly1305 via la crate `rust-crypto-core`
- Dérivation de clé Argon2id (paramètres adaptatifs desktop/mobile)
- Post-quantum : signatures ML-DSA (CRYSTALS-Dilithium) et échange de clé HKDF/ ML-KEM
- Gestion sécurisée des mots de passe avec SecureMemory (zérotisation automatique)
- Interface graphique desktop cross-platform (macOS, Linux, Windows)
- Système de mise à jour automatique via Tauri Updater (endpoint GitHub Releases)
- Pipeline CI/CD multi-plateforme GitHub Actions (build + release + manifest)
- Support biométrie (SecureEnclave macOS, Windows Hello)
- Module de transfert de coffre-fort (P2P chiffré)
- Système de backup/restauration
- Logs signés et audit trail
- Design system complet (atoms, molecules, organisms)
- Gestion des identités cachées (HiddenStorage)
- Validation de chemins (PathValidator)
- Cache de clés vault (VaultKeyCache)

### Sécurité

- Mémoire protégée avec zérotisation à la libération
- CSP stricte dans Tauri
- Entitlements macOS configurés
- Clé de mise à jour signée (minisign)

---

## [1.0.0] - 2025-01-01

### Ajouté

- Version initiale du projet SecureVault

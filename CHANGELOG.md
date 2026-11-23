# Changelog

Tous les changements notables de FluXlock sont documentés dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

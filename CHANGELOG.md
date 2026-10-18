# Changelog

Tous les changements notables de FluXlock sont documentés dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

# Changelog

Tous les changements notables de FluXlock sont documentés dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/),
et ce projet adhère au [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

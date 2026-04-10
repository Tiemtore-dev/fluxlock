# FluXlock — Secure Vault Next-Gen

> Coffre-fort numérique de nouvelle génération avec cryptographie post-quantique, transfert P2P chiffré et détection de ransomware.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-edition%202021-orange.svg)](https://www.rust-lang.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5.3%2B-blue.svg)](https://www.typescriptlang.org/)
[![Tauri](https://img.shields.io/badge/tauri-v2-purple.svg)](https://v2.tauri.app/)
[![Android](https://img.shields.io/badge/android-API%2024%2B-green.svg)](https://developer.android.com/)

---

## Vue d'ensemble

FluXlock est un gestionnaire de mots de passe et coffre-fort de fichiers desktop et mobile, conçu pour résister aux attaques classiques **et** post-quantiques. Il combine :

- **Chiffrement hybride** : ChaCha20-Poly1305 + ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204)
- **Transfert P2P sécurisé** : SPAKE2 + ML-KEM hybride sur TLS 1.3, sans serveur central
- **Détection de ransomware** : Surveillance temps-réel du système de fichiers avec verrouillage automatique en lecture seule
- **Journal signé** : Chaîne de hachage SHA3-256 + signatures ML-DSA-65 pour l'auditabilité
- **Biométrie** : Touch ID (macOS), Windows Hello, TEE/StrongBox (Android)

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Frontend (React 18)                │
│   TailwindCSS · Zustand · React Query · Vite 5      │
│   13 pages · Design System (atoms/molecules/org.)    │
├──────────────────────────────────────────────────────┤
│                Tauri IPC (65+ commands)               │
├──────────────────────────────────────────────────────┤
│                 Backend Tauri (Rust)                  │
│   Auth · Passwords · Files · Keys · 2FA · Backup     │
│   Transfer P2P · Biometric · Threat Reactor          │
│   Security Monitor · Ransomware Detection            │
│   Signed Log · Auto-lock · Hidden Storage            │
├──────────────────────────────────────────────────────┤
│           rust-crypto-core (bibliothèque)             │
│   ChaCha20 · AES-GCM · Argon2id · ML-KEM-768        │
│   ML-DSA-65 · Ed25519 · X25519 · BLAKE3 · SHA3      │
│   HKDF · Streaming AEAD (SENC v1) · Vault v2        │
│   Zeroize · mlock/munlock · constant-time ops        │
├──────────────────────────────────────────────────────┤
│                     Stockage                         │
│   SQLite (WAL) · OS Keychain · Trust Store chiffré   │
└──────────────────────────────────────────────────────┘
```

### Structure du projet

```
secure-vault-next-gen/
├── rust-crypto-core/          # Bibliothèque cryptographique Rust (25 fichiers)
│   └── src/
│       ├── crypto/            # AEAD (ChaCha20, AES-GCM), vault v2, streaming SENC v1, KDF, KEM
│       ├── hashing/           # SHA3-256/512, BLAKE3
│       ├── key_derivation/    # Argon2id, HKDF
│       ├── key_exchange/      # X25519
│       ├── key_management/    # Gestion clés
│       ├── migration/         # v1 → v2
│       ├── signatures/        # Ed25519, ML-DSA-65
│       ├── secure_memory.rs   # SecureBuffer, mlock/munlock
│       └── errors.rs          # Types d'erreurs
├── tauri-desktop/
│   ├── src/                   # Frontend React/TypeScript (42 fichiers)
│   │   ├── pages/             # 13 pages (Login, Register, Dashboard, Passwords, Files, ...)
│   │   ├── design-system/     # Atoms (Button, Input, Badge, Spinner, Kbd)
│   │   │                      # Molecules (Modal, PasswordField, PasswordStrength, ...)
│   │   │                      # Organisms (Sidebar, Toaster) · Layouts (AppShell)
│   │   ├── lib/               # vault-service.ts (typed API), tauri-api.ts (legacy)
│   │   ├── stores/            # authStore.ts (Zustand + sessionStorage)
│   │   └── hooks/             # useAutoLock, useClipboard, useKeyboardShortcuts
│   └── src-tauri/
│       └── src/               # Backend Rust (35 fichiers)
│           ├── lib.rs         # Point d'entrée (65+ commandes Tauri, AppState)
│           ├── database.rs    # SQLite pool + migrations automatiques
│           ├── crypto.rs      # Logique chiffrement applicatif
│           ├── biometric.rs   # Touch ID / Windows Hello / Android TEE
│           ├── totp.rs        # TOTP 2FA (SHA-256, RFC 6238)
│           ├── transfer/      # P2P (protocol, discovery, handshake, transport, session, trust_store, reencrypt, commands)
│           ├── threat_reactor.rs      # Réaction aux menaces (rate limiting, blocage)
│           ├── security_monitor.rs    # Surveillance sécurité globale
│           ├── filesystem_monitor.rs  # Détection ransomware (50+ extensions)
│           ├── signed_log.rs          # Journal signé ML-DSA-65 + SHA3 hash chain
│           ├── backup_manager.rs      # Backup/restauration chiffrés
│           ├── secure_storage.rs      # Stockage sécurisé OS Keychain
│           ├── hidden_storage.rs      # Répertoires cachés par plateforme
│           ├── path_validator.rs      # Anti-traversal (canonicalize + symlink)
│           ├── notifications.rs       # Email SMTP
│           ├── config.rs              # Configuration .env
│           └── ...
├── docs/                      # Documentation détaillée
├── scripts/                   # Build, test, release, utilitaires
├── infra/                     # Docker, Prometheus, migrations SQL
└── tests/                     # Tests supplémentaires
```

---

## Modèle de sécurité

### Primitives cryptographiques

| Fonction | Algorithme | Standard | Notes |
|---|---|---|---|
| Chiffrement at-rest | ChaCha20-Poly1305 | RFC 8439 | Vault v2, clé 256 bits |
| Chiffrement streaming | SENC v1 (ChaCha20-Poly1305 par chunk) | Propriétaire | Chunks 64 KiB, nonce XOR par index |
| Chiffrement legacy | AES-256-GCM | NIST SP 800-38D | Rétrocompatibilité v1 |
| Dérivation de clé | Argon2id | RFC 9106 | m=64 MiB, t=3, p=4, salt 32 octets |
| KEM post-quantique | ML-KEM-768 | FIPS 203 | Handshake P2P hybride (SPAKE2 + KEM) |
| Signatures PQ | ML-DSA-65 | FIPS 204 | Journal signé, trust store |
| Signatures legacy | Ed25519 | RFC 8032 | Migration progressive vers ML-DSA |
| Échange clés legacy | X25519 | RFC 7748 | Migration progressive vers ML-KEM |
| PAKE | SPAKE2 | RFC 9382 | Wormhole code pour transfer P2P |
| Hash intégrité | BLAKE3 | — | Fingerprints, intégrité fichiers |
| Hash vault | SHA3-256 | FIPS 202 | HMAC vault header, hash chain log |
| Dérivation multi-clés | HKDF-SHA3 | RFC 5869 | Clé hybride SPAKE2 + KEM |

### Architecture de défense

- **Zeroization** : Toutes les clés implémentent `Zeroize` + `ZeroizeOnDrop`. `mlock()` empêche la pagination disque. `MasterKey` est non-`Clone`, non-`Debug`.
- **Constant-time** : Comparaisons MAC/token via `subtle::ConstantTimeEq`.
- **Anti-brute-force** : Backoff exponentiel (0 → 15 → 30 → 60 → 120s), verrouillage compte 30 min si `risk_score ≥ 80`.
- **Anti-ransomware** : 50+ extensions suspectes surveillées, détection modification rapide (>15 événements/10s), chiffrement de masse (>30 fichiers/30s) → bascule automatique en lecture seule.
- **Path traversal** : Canonicalisation + résolution symlinks + vérification base directory.
- **Transfer P2P** : TLS 1.3 (certificats éphémères auto-signés), authentification SPAKE2, chiffrement session ChaCha20-Poly1305 avec nonces incrémentaux 96 bits, messages ≤ 2 MiB, timeout 30s.
- **Biométrie** : Jamais auth primaire. Déverrouillage à froid requiert le mot de passe maître. 3 échecs → fallback mot de passe. Timeout biométrique 15 min.
- **Journal signé** : Append-only (O_APPEND, permissions 0600), chaîne SHA3-256, signature ML-DSA-65 par entrée.
- **Trust store** : Chiffré ChaCha20-Poly1305 (clé dérivée HKDF depuis vault key), signatures ML-DSA-65, fingerprints BLAKE3.

---

## Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| **Gestion mots de passe** | CRUD complet, chiffrement ChaCha20-Poly1305, génération aléatoire, indicateur de force |
| **Coffre-fort fichiers** | Chiffrement streaming (SENC v1) pour fichiers de toute taille, nettoyage sécurisé des temporaires (overwrite zeros) |
| **Clés cryptographiques** | Génération de paires Ed25519/X25519 (classiques) et ML-KEM-768/ML-DSA-65 (post-quantiques) |
| **Partage de fichiers** | Partage chiffré avec révocation |
| **Transfert P2P** | Synchronisation pair-à-pair locale (mDNS + UDP beacon port 52821), wormhole code, re-chiffrement à la volée (zero plaintext on disk) |
| **Authentification 2FA** | TOTP avec QR code, email (configurable : totp / email / both) |
| **Biométrie** | Touch ID (macOS Secure Enclave), Windows Hello, TEE/StrongBox AES-256-GCM (Android) |
| **Détection ransomware** | Surveillance FS temps-réel via `notify`, verrouillage automatique en lecture seule |
| **Journal d'audit** | Entrées signées ML-DSA-65, chaîne SHA3-256, vérification d'intégrité en un clic |
| **Backup/Restauration** | Sauvegardes chiffrées, recherche automatique dans les emplacements standard |
| **Auto-lock** | Verrouillage automatique configurable, double couche JS timer + backend heartbeat |
| **Migration automatique** | v1 → v2 transparente lors de l'accès aux données |
| **Auto-update** | Mise à jour signée (minisign v1) via GitHub Releases |

---

## Prérequis

### Desktop

- **macOS** 11+ (Big Sur), **Windows** 10+, ou **Linux** (glibc 2.31+)
- **Rust** ≥ 1.77 (edition 2021)
- **Node.js** ≥ 18 LTS
- **npm**

```bash
# macOS
xcode-select --install
brew install rust node

# Linux (Ubuntu/Debian)
sudo apt install libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Windows : Visual Studio Build Tools (C++ workload) + rustup-init.exe
```

### Android

- **JDK 17** (Temurin) — `brew install --cask temurin@17`
- **Android SDK** (API 24+) — via Android Studio ou `sdkmanager`
- **Android NDK** r29+ — `sdkmanager "ndk;29.0.13846066"`
- **Cibles Rust ARM** — `rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android`

---

## Installation & Build

```bash
# Cloner le dépôt
git clone <repository-url>
cd secure-vault-next-gen

# Installer les dépendances frontend
cd tauri-desktop
npm install

# Build de développement (hot-reload)
npm run tauri:dev

# Build de production
npm run tauri:build
```

### Build Android

```bash
cd tauri-desktop
npx tauri android dev       # Développement (hot-reload sur émulateur)
npx tauri android build --apk   # Production APK
```

### Profil release optimisé

Le profil release est configuré dans `.cargo/config.toml` :

| Option | Valeur | Effet |
|---|---|---|
| `opt-level` | 3 | Optimisation maximale |
| `lto` | fat | Link-Time Optimization complète |
| `codegen-units` | 1 | Compilation mono-unité (taille min) |
| `strip` | true | Suppression symboles debug |
| `panic` | abort | Pas de stack unwinding |

---

## Usage

### Première utilisation

1. Lancer FluXlock (`npm run tauri:dev` ou l'exécutable compilé)
2. Créer un compte avec un mot de passe maître fort
3. Le vault est initialisé automatiquement (format v2, Argon2id)

### Transfert P2P

1. **Émetteur** : Créer une offre → un code wormhole est généré
2. **Récepteur** : Saisir le code wormhole pour se connecter
3. Le handshake SPAKE2 + ML-KEM établit une session chiffrée
4. Vérifier le numéro de sécurité affiché (`BLAKE3(session_key || id_a || id_b)[0:8]` hex)
5. Les données sont re-chiffrées à la volée (zero plaintext on disk)

### CLI (optionnel)

```bash
# securevault-cli (bin séparé, nécessite compilation)
securevault login
securevault add-password --site example.com --username user
securevault list-passwords
securevault encrypt-file /path/to/file
securevault decrypt-file /path/to/encrypted
```

---

## Configuration

### Variables d'environnement (.env)

| Variable | Défaut | Description |
|---|---|---|
| `DATABASE_PATH` | Plateforme-dépendant | Chemin SQLite |
| `DATABASE_WAL_MODE` | `true` | Write-Ahead Logging |
| `THREAT_CRITICAL_THRESHOLD` | `80` | Seuil score pour blocage compte |
| `THREAT_CRITICAL_BLOCK_MINUTES` | `30` | Durée blocage (min) |
| `THREAT_MEDIUM_RATE_LIMIT` | `0.2` | 1 action / 5s |
| `THREAT_HIGH_RATE_LIMIT` | `0.1` | 1 action / 10s |
| `AUTH_2FA_METHOD` | `both` | `totp`, `email`, ou `both` |
| `AUTH_2FA_MAX_ATTEMPTS` | `5` | Tentatives 2FA max |
| `AUTH_2FA_LOCKOUT_MINUTES` | `15` | Verrouillage 2FA (min) |

### Stockage par plateforme

| OS | Répertoire données | Keychain |
|---|---|---|
| macOS | `~/Library/Application Support/SecureVault` | macOS Keychain (Secure Enclave) |
| Windows | `%LOCALAPPDATA%/SecureVault` | Windows Credential Manager |
| Linux | `~/.local/share/SecureVault` | Secret Service (D-Bus) |
| Android | `app_data_dir()` (privé) | Android Keystore (TEE/StrongBox) |

### Tauri CSP

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self' data:;
connect-src 'self' ipc: http://ipc.localhost https://tauri.localhost
```

---

## Tests

```bash
# Tests unitaires du core crypto (~70+ tests)
cd rust-crypto-core
cargo test --all-features

# Tests backend Tauri (intégration + sécurité)
cd tauri-desktop/src-tauri
cargo test

# Tests spécifiques
cargo test --test integration_tests   # 6 tests (DB, users, passwords, config)
cargo test --test security_tests      # 9 tests (zeroize, brute-force, SQL injection, ransomware)
cargo test --test transfer_tests      # Tests transfer P2P

# Scripts de test
./scripts/test/test-all.sh            # Suite complète
./scripts/test/test-security.sh       # Tests sécurité
./scripts/test/test_memory_security.sh # Tests mémoire
```

### Tests notables

| Test | Module | Vérifie |
|---|---|---|
| `test_encrypt_decrypt_vault` | vault.rs | Round-trip chiffrement vault v2 |
| `test_stream_encrypt_large` | stream_cipher.rs | Streaming AEAD multi-chunks |
| `test_tamper_detection` | stream_cipher.rs | Détection modification chunks |
| `test_kem_encapsulate_decapsulate` | kem.rs | ML-KEM-768 round-trip |
| `test_sign_verify` | ml_dsa.rs | ML-DSA-65 sign/verify |
| `test_argon2id_kdf` | kdf.rs | Dérivation Argon2id |
| `test_brute_force_protection` | security_tests.rs | Backoff exponentiel |
| `test_ransomware_detection` | security_tests.rs | Détection extensions suspectes |
| `test_sql_injection_prevention` | security_tests.rs | Protection SQLi paramétrisée |

---

## Dépendances

### Crate `secure-vault-crypto-core` v1.0.0

| Catégorie | Crates |
|---|---|
| Chiffrement | `chacha20poly1305` 0.10, `aes-gcm` 0.10 |
| KDF | `argon2` 0.5 |
| PQC | `ml-kem` =0.3.0-rc.2, `ml-dsa` =0.1.0-rc.8 |
| Hash | `sha3` 0.10, `sha2` 0.10, `blake3` 1.5, `hmac` 0.12, `hkdf` 0.12 |
| Signatures | `ed25519-dalek` 2.1, `x25519-dalek` 2.0 |
| Mémoire | `zeroize` 1.7, `subtle` 2.5 |
| Sérialisation | `serde` 1.0, `rmp-serde` 1.3, `bincode` 1.3 |

### Application `fluxlock` v2.0.0

| Catégorie | Crates |
|---|---|
| Framework | `tauri` 2, plugins (fs, dialog, shell, clipboard, updater) |
| Base de données | `sqlx` 0.7 (SQLite, tokio-rustls) |
| Async | `tokio` 1 (rt-multi-thread) |
| Transfer P2P | `spake2` 0.4, `chacha20poly1305` 0.10, `mdns-sd` 0.11, `tokio-rustls` 0.25, `rcgen` 0.12 |
| Auth | `totp-rs` 5.5, `keyring` 2.0 |
| Sécurité | `zeroize` 1.8.2, `secrecy` 0.10.3, `subtle` 2.5, `argon2` 0.5 |
| Monitoring | `notify` 6.1 |
| Email | `lettre` 0.11 |

### Frontend

| Package | Version |
|---|---|
| `react` / `react-dom` | ^18.2.0 |
| `@tauri-apps/api` | ^2.10.1 |
| `@tanstack/react-query` | ^5.17.9 |
| `zustand` | ^4.4.7 |
| `react-router-dom` | ^6.21.1 |
| `tailwindcss` | ^3.4.1 |
| `vite` | ^5.0.11 |
| `typescript` | ^5.3.3 |

---

## Scripts

| Script | Description |
|---|---|
| `scripts/build/build-all-platforms.sh` | Build multi-plateforme (macOS/Windows/Linux) |
| `scripts/build/build.sh` | Build rapide |
| `scripts/build/create-dmg.sh` | Création DMG macOS |
| `scripts/release/release.sh` | Publication release |
| `scripts/release/build-signed.sh` | Build avec signature |
| `scripts/test/test-all.sh` | Suite complète de tests |

---

## Documentation

- [**Guides**](docs/guides/) — Manuel utilisateur, build Windows, chiffrement backup, partage fichiers, mise à jour
- [**Sécurité**](docs/security/) — Architecture crypto, audits, corrections, red team report
- [**Rapports**](docs/reports/) — Rapports de nettoyage, corrections, audit complet

---

## Licence

MIT — Copyright © 2024 Tiemtore Rafahim — voir [LICENSE](LICENSE)

---

## Contact

**Auteur :** Tiemtore Rafahim  
**GitHub :** [@Tiemtore-dev](https://github.com/Tiemtore-dev)

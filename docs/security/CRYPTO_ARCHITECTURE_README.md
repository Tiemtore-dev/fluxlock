# FluXlock 2.0 — Architecture Cryptographique Détaillée

> **Document exhaustif** — Ce README décrit en détail chaque mécanisme cryptographique de FluXlock 2.0 : quelles données sont en clair, quelles données sont chiffrées, quel algorithme est appliqué, quand, et comment. Chaque workflow interne est documenté avec les fonctions Rust exactes, les paramètres, et les formats binaires.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Stack Technique](#2-stack-technique)
3. [Primitives & Algorithmes](#3-primitives--algorithmes-cryptographiques)
4. [Architecture des Modules](#4-architecture-des-modules)
5. [Schéma de Base de Données — Clair vs Chiffré](#5-schéma-de-base-de-données--clair-vs-chiffré)
6. [Flux de Login & Protection Brute Force](#6-flux-de-login--protection-brute-force)
7. [Dérivation de Clé — Comment la Clé Maître est Créée](#7-dérivation-de-clé--comment-la-clé-maître-est-créée)
8. [Chiffrement des Mots de Passe — Étape par Étape](#8-chiffrement-des-mots-de-passe--étape-par-étape)
9. [Génération de Mots de Passe — Algorithme Interne](#9-génération-de-mots-de-passe--algorithme-interne)
10. [Chiffrement des Fichiers — Comment un Fichier est Protégé](#10-chiffrement-des-fichiers--comment-un-fichier-est-protégé)
11. [Stockage de Clés (SSH/API) — Fonctionnement Interne](#11-stockage-de-clés-sshapi--fonctionnement-interne)
12. [Format Vault v2 — Structure Binaire Complète](#12-format-vault-v2--structure-binaire-complète)
13. [2FA TOTP — Fonctionnement Interne](#13-2fa-totp--fonctionnement-interne)
14. [Backup / Restauration — Format et Chiffrement](#14-backup--restauration--format-et-chiffrement)
15. [Transfert P2P — Protocole Cryptographique Complet](#15-transfert-p2p--protocole-cryptographique-complet)
16. [Trust Store — Stockage de Confiance entre Appareils](#16-trust-store--stockage-de-confiance-entre-appareils)
17. [Session & Auto-lock — Gestion des Tokens](#17-session--auto-lock--gestion-des-tokens)
18. [Gestion des Secrets en Mémoire](#18-gestion-des-secrets-en-mémoire)
19. [Gestion des Erreurs Cryptographiques](#19-gestion-des-erreurs-cryptographiques)
20. [Surface d'Attaque](#20-surface-dattaque)

---

## 1. Vue d'ensemble

FluXlock est un gestionnaire de mots de passe local-first avec transfert P2P serverless. L'architecture cryptographique repose sur 5 couches de défense en profondeur, avec support post-quantique via ML-KEM-768 (FIPS 203) et ML-DSA-65 (FIPS 204).

**Principes fondamentaux :**

- Aucun serveur central : toute la synchronisation est P2P (mDNS / UDP beacon / IPv6 link-local)
- Zero-knowledge : le mot de passe maître ne quitte jamais la RAM
- Plaintext jamais sur disque : re-chiffrement en mémoire lors des transferts
- Post-quantique : handshake hybride SPAKE2 + ML-KEM-768, signatures ML-DSA-65

---

## 2. Stack Technique

| Composant             | Technologie                    | Version               |
| --------------------- | ------------------------------ | --------------------- |
| **Langage backend**   | Rust                           | Edition 2021          |
| **Framework desktop** | Tauri                          | v2                    |
| **Frontend**          | React + TypeScript + Vite      | —                     |
| **Runtime async**     | Tokio                          | 1.x (rt-multi-thread) |
| **Base de données**   | SQLite (sqlx)                  | 0.7                   |
| **TLS**               | tokio-rustls                   | 0.25                  |
| **Certs éphémères**   | rcgen                          | 0.12                  |
| **Platforms**         | macOS, Windows, Linux, Android | —                     |

---

## 3. Primitives & Algorithmes Cryptographiques

### 3.1 Tableau des primitives

| Primitive             | Algorithme              | Paramètres                                   | Bibliothèque (version)   | Usage                                    |
| --------------------- | ----------------------- | -------------------------------------------- | ------------------------ | ---------------------------------------- |
| AEAD (primaire)       | ChaCha20-Poly1305       | Clé: 256 bits, Nonce: 96 bits, Tag: 128 bits | chacha20poly1305 0.10    | Vault v2, session transfer, trust store  |
| AEAD (legacy)         | AES-256-GCM             | Clé: 256 bits, Nonce: 96 bits, Tag: 128 bits | aes-gcm 0.10             | Rétrocompatibilité vault v1              |
| KDF (mot de passe)    | Argon2id                | m=65536 KiB, t=3, p=4, output=32 bytes       | argon2 0.5               | Dérivation de clé maître                 |
| KDF (sous-clés)       | HKDF-SHA3-256           | RFC 5869                                     | hkdf 0.12 + sha3 0.10    | Trust store sub-key, session key hybride |
| MAC                   | HMAC-SHA3-256           | Clé: 256 bits, Tag: 256 bits                 | hmac 0.12 + sha3 0.10    | Intégrité header vault, metadata backup  |
| Hash (intégrité)      | BLAKE3                  | 256 bits output                              | blake3 1.5               | Vérification fichiers transfert          |
| Hash (legacy)         | SHA-256                 | 256 bits output                              | sha2 0.10                | TOTP (HMAC-SHA256)                       |
| Hash (moderne)        | SHA3-256                | 256 bits output                              | sha3 0.10                | HMAC, HKDF                               |
| KEM (PQC)             | ML-KEM-768              | FIPS 203, niveau 3, PK: 1184B, CT: 1088B     | ml-kem 0.3.0-rc.2        | Handshake P2P post-quantique             |
| Signature (PQC)       | ML-DSA-65               | FIPS 204, niveau 3, Sig: 3309B               | ml-dsa 0.1.0-rc.8        | Trust store, sync pair verification      |
| PAKE                  | SPAKE2                  | Ed25519Group, password-authenticated         | spake2 0.4               | Handshake wormhole code                  |
| Signature (legacy)    | Ed25519                 | RFC 8032, 64B signature                      | ed25519-dalek 2.1        | Rétrocompatibilité                       |
| Key exchange (legacy) | X25519                  | RFC 7748, ECDH                               | x25519-dalek 2.0         | Rétrocompatibilité                       |
| CSPRNG                | OsRng                   | getrandom 0.4 (OS-backed)                    | rand 0.8 / rand_core 0.6 | Tous les nonces, sels, clés              |
| TOTP                  | HMAC-SHA256 (RFC 6238)  | 6 digits, 30s period                         | totp-rs 5.5              | Authentification 2FA                     |
| Timing-safe compare   | ConstantTimeEq          | Volatile writes                              | subtle 2.5               | Comparaisons MAC, mots de passe          |
| Memory wipe           | Zeroize + ZeroizeOnDrop | —                                            | zeroize 1.7/1.8.2        | Toute mémoire sensible                   |

### 3.2 Bibliothèques crypto distinctes (versions exactes)

**rust-crypto-core/Cargo.toml :**

```
chacha20poly1305 = "0.10"
aes-gcm = "0.10"
argon2 = "0.5"
ml-kem = "0.3.0-rc.2"
ml-dsa = "0.1.0-rc.8"
sha3 = "0.10"
sha2 = "0.10"
hmac = "0.12"
blake3 = "1.5"
hkdf = "0.12"
ed25519-dalek = "2.1"
x25519-dalek = "2.0"
zeroize = "1.7"
subtle = "2.5"
getrandom = "0.4"
rand = "0.8"
rand_core = "0.6"
```

**tauri-desktop/src-tauri/Cargo.toml :**

```
spake2 = "0.4"
chacha20poly1305 = "0.10"
argon2 = "0.5"
zeroize = "1.8.2"
secrecy = "0.10.3"
subtle = "2.5"
keyring = "2.0"
tokio-rustls = "0.25"
rcgen = "0.12"
totp-rs = "5.5"
libc = "0.2"
```

---

## 4. Architecture des Modules

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND (React/TS)                       │
│  LoginPage → vault-service.ts → @tauri-apps/api/core → IPC     │
│  PasswordsPage → generatePassword() → crypto.getRandomValues   │
└────────────────────────────┬────────────────────────────────────┘
                             │ Tauri IPC (invoke)
┌────────────────────────────▼────────────────────────────────────┐
│                      BACKEND (Rust/Tauri v2)                     │
│                                                                  │
│  lib.rs ─── Commandes Tauri (local_login, biometric_login, ...) │
│  │                                                               │
│  ├── crypto.rs ──────── Chiffrement vault, vérification mdp     │
│  ├── secure_key.rs ──── SecureKey (mlock + ZeroizeOnDrop)       │
│  ├── secure_storage.rs ─ Keychain/Credential Manager (OS)       │
│  ├── biometric.rs ────── Touch ID / Face ID / Android Biometric │
│  ├── database.rs ──────── SQLite (sqlx) pour users + entries     │
│  ├── totp.rs ───────────── 2FA TOTP generation & validation     │
│  ├── backup_manager.rs ── Backup/restore chiffré                │
│  │                                                               │
│  ├── transfer/ ──────────── Module de transfert P2P              │
│  │   ├── discovery.rs ─── mDNS + UDP beacon + IPv6 link-local  │
│  │   ├── handshake.rs ─── SPAKE2 + ML-KEM-768 hybride          │
│  │   ├── session.rs ───── ChaCha20-Poly1305 par message         │
│  │   ├── transport.rs ─── TLS éphémère (rcgen + tokio-rustls)  │
│  │   ├── protocol.rs ──── Wire format (MessagePack)             │
│  │   ├── reencrypt.rs ─── Re-chiffrement en mémoire             │
│  │   ├── trust_store.rs ─ TrustStore chiffré + ML-DSA-65        │
│  │   └── commands.rs ──── TransferManager + commandes Tauri     │
│  │                                                               │
│  ├── security_monitor.rs ── Détection ransomware temps réel     │
│  ├── threat_reactor.rs ──── Réponse automatique aux menaces     │
│  ├── filesystem_monitor.rs ─ Surveillance FS (notify crate)     │
│  └── platform_security.rs ── Marquage antivirus (ADS, xattr)   │
│                                                                  │
└────────────────────────────┬────────────────────────────────────┘
                             │ (local crate path)
┌────────────────────────────▼────────────────────────────────────┐
│               rust-crypto-core (bibliothèque)                    │
│                                                                  │
│  crypto/                                                         │
│  ├── cipher.rs ──── ChaCha20-Poly1305 EncryptedBlob             │
│  ├── chacha.rs ──── ChaCha20 encrypt/decrypt + AAD              │
│  ├── aes_gcm.rs ─── AES-256-GCM (legacy v1)                    │
│  ├── kdf.rs ──────── Argon2id MasterKey derivation              │
│  ├── kem.rs ──────── ML-KEM-768 encapsulate/decapsulate         │
│  ├── integrity.rs ── HMAC-SHA3-256 (vault header)               │
│  └── vault.rs ────── Format vault v2 (serialize + seal)         │
│                                                                  │
│  hashing/mod.rs ──── BLAKE3, SHA-256, SHA3-256                  │
│  key_derivation/ ─── Argon2 + HKDF-SHA3-256                    │
│  key_exchange/ ───── X25519 (legacy)                            │
│  signatures/ ─────── Ed25519 (legacy) + ML-DSA-65 (PQC)        │
│  migration/ ──────── Vault v1 → v2 migration atomique           │
│  secure_memory.rs ── SecretBytes, CryptoKey (Zeroize)           │
│  key_management/ ─── KeyManager (HashMap gardé)                 │
│  errors.rs ──────── CryptoError enum (thiserror)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. Schéma de Base de Données — Clair vs Chiffré

### 5.1 Vue globale : quelles colonnes sont chiffrées ?

> Le chiffrement est appliqué **au niveau des champs individuels**, pas au niveau de la base entière. SQLite lui-même n'est pas chiffré (pas de SQLCipher). Les données sensibles sont chiffrées avec ChaCha20-Poly1305 avant insertion.

### 5.2 Table `users`

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    crypto_salt TEXT NOT NULL,
    totp_secret TEXT,
    totp_enabled BOOLEAN DEFAULT 0,
    totp_verified_at DATETIME,
    backup_codes TEXT,
    account_locked BOOLEAN DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
```

| Colonne            | État                     | Détail                                                                                                            |
| ------------------ | ------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| `id`               | 🔓 **Clair**             | Entier auto-incrémenté                                                                                            |
| `username`         | 🔓 **Clair**             | Texte, indexé UNIQUE                                                                                              |
| `email`            | 🔓 **Clair**             | Texte, indexé UNIQUE                                                                                              |
| `password_hash`    | 🔒 **Hash irréversible** | Argon2id hash — ne peut pas être déchiffré, sert uniquement à la vérification                                     |
| `crypto_salt`      | 🔓 **Clair** (base64)    | Sel unique par utilisateur, 32 bytes, stocké en base64. Nécessaire pour re-dériver la clé                         |
| `totp_secret`      | 🔒 **Chiffré**           | Secret TOTP chiffré avec ChaCha20-Poly1305 (clé vault de l'utilisateur), format `v2:base64(nonce‖ciphertext+tag)` |
| `totp_enabled`     | 🔓 **Clair**             | Booléen                                                                                                           |
| `totp_verified_at` | 🔓 **Clair**             | Date-heure                                                                                                        |
| `backup_codes`     | 🔒 **Chiffré**           | Tableau JSON de codes de secours, chiffré avec ChaCha20-Poly1305                                                  |
| `account_locked`   | 🔓 **Clair**             | Booléen de verrouillage brute force                                                                               |
| `locked_until`     | 🔓 **Clair**             | Date-heure de fin de verrouillage                                                                                 |
| `created_at`       | 🔓 **Clair**             | Date de création                                                                                                  |

### 5.3 Table `passwords`

```sql
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    username TEXT,
    password TEXT NOT NULL,
    url TEXT,
    notes TEXT,
    category TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
```

| Colonne      | État           | Détail                                                                                       |
| ------------ | -------------- | -------------------------------------------------------------------------------------------- |
| `id`         | 🔓 **Clair**   | Entier auto-incrémenté                                                                       |
| `user_id`    | 🔓 **Clair**   | FK vers `users.id`                                                                           |
| `title`      | 🔓 **Clair**   | ⚠️ Le titre de l'entrée (ex: "Gmail", "GitHub") est en clair dans la base                    |
| `username`   | 🔓 **Clair**   | ⚠️ Le nom d'utilisateur associé est en clair                                                 |
| `password`   | 🔒 **Chiffré** | Le mot de passe est chiffré avec ChaCha20-Poly1305, format `v2:base64(nonce‖ciphertext+tag)` |
| `url`        | 🔓 **Clair**   | ⚠️ L'URL du site est en clair                                                                |
| `notes`      | 🔓 **Clair**   | ⚠️ Les notes sont en clair                                                                   |
| `category`   | 🔓 **Clair**   | Catégorie en clair                                                                           |
| `created_at` | 🔓 **Clair**   | Date de création                                                                             |
| `updated_at` | 🔓 **Clair**   | Date de mise à jour                                                                          |

> **⚠️ Note de sécurité :** Seule la colonne `password` est chiffrée. Les métadonnées (`title`, `username`, `url`, `notes`, `category`) sont stockées en clair dans SQLite. Un attaquant ayant accès au fichier de base de données peut voir quels sites et comptes sont enregistrés, mais **pas les mots de passe**.

### 5.4 Table `secure_files`

```sql
CREATE TABLE IF NOT EXISTS secure_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT,
    integrity_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
```

| Colonne          | État         | Détail                                                         |
| ---------------- | ------------ | -------------------------------------------------------------- |
| `id`             | 🔓 **Clair** |                                                                |
| `user_id`        | 🔓 **Clair** |                                                                |
| `filename`       | 🔓 **Clair** | ⚠️ Le nom du fichier original est en clair                     |
| `file_path`      | 🔓 **Clair** | Chemin vers le fichier chiffré sur disque                      |
| `file_size`      | 🔓 **Clair** | Taille du fichier original                                     |
| `mime_type`      | 🔓 **Clair** | Type MIME (ex: "application/pdf")                              |
| `integrity_hash` | 🔓 **Clair** | Hash BLAKE3 du contenu original, pour vérification d'intégrité |
| `created_at`     | 🔓 **Clair** |                                                                |

> **Le contenu du fichier** est stocké sur disque dans un fichier séparé, **entièrement chiffré** avec ChaCha20-Poly1305. Seules les métadonnées sont dans SQLite.

### 5.5 Table `secure_keys`

```sql
CREATE TABLE IF NOT EXISTS secure_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_name TEXT NOT NULL,
    key_type TEXT NOT NULL,
    key_data TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
```

| Colonne     | État           | Détail                                                          |
| ----------- | -------------- | --------------------------------------------------------------- |
| `key_name`  | 🔓 **Clair**   | ⚠️ Le nom de la clé (ex: "serveur-production-ssh") est en clair |
| `key_type`  | 🔓 **Clair**   | Type de clé (ex: "SSH", "API")                                  |
| `key_data`  | 🔒 **Chiffré** | Contenu de la clé chiffré avec ChaCha20-Poly1305                |
| `algorithm` | 🔓 **Clair**   | Algorithme de la clé (ex: "RSA-4096", "Ed25519")                |

### 5.6 Table `file_shares`

| Colonne         | État                  | Détail                                                         |
| --------------- | --------------------- | -------------------------------------------------------------- |
| `share_token`   | 🔓 **Clair** (UNIQUE) | Token de partage                                               |
| `encrypted_key` | 🔒 **Chiffré**        | Clé de déchiffrement du fichier, chiffrée pour le destinataire |

### 5.7 Table `audit_logs`

Toutes les colonnes sont en **clair** : `action`, `resource_type`, `resource_id`, `ip_address`, `user_agent`, `created_at`.

---

## 6. Flux de Login & Protection Brute Force

### 6.1 Flux détaillé de `local_login`

Le login est géré par la commande Tauri `local_login` dans `lib.rs` :

```
Utilisateur saisit username + password
    │
    ▼
1. Récupérer l'utilisateur par username (SELECT * FROM users WHERE username = ?)
    │
    ▼
2. Vérifier si le compte est verrouillé (SecurityMonitor.is_user_locked)
   └─ Si verrouillé → Retourner "Compte temporairement verrouillé. Réessayez dans X secondes."
    │
    ▼
3. Compter les tentatives échouées dans les 2 dernières minutes
   (SELECT COUNT(*) FROM audit_logs WHERE user_id=? AND action='LOGIN_FAILED' AND created_at > ?)
    │
    ▼
4. Appliquer le délai progressif :
   ┌────────────────────────────────────┐
   │ Tentatives échouées │ Délai (sec)  │
   │ 0-2                 │ 0            │
   │ 3-4                 │ 15           │
   │ 5-7                 │ 30           │
   │ 8-10                │ 60           │
   │ > 10                │ 120          │
   └────────────────────────────────────┘
   └─ Si délai actif → "Trop de tentatives. Patientez X secondes."
    │
    ▼
5. Vérifier le mot de passe :
   a. Récupérer crypto_salt de l'utilisateur (base64 → bytes)
   b. Argon2id(password, salt, m=64MiB, t=3, p=4) → derived_key[32 bytes]
   c. Comparer derived_key avec password_hash stocké (constant-time)
   └─ Si échec → log audit "LOGIN_FAILED", incrémenter compteur
    │
    ▼
6. Succès :
   a. Stocker la vault key (derived_key) dans SecureKey (mlock + ZeroizeOnDrop)
   b. Stocker la vault key dans Keychain OS (macOS: Keychain, Windows: DPAPI, Linux: libsecret)
   c. Générer session token : OsRng → 32 bytes → base64url_no_pad
   d. Stocker session token en mémoire (Mutex<Option<String>>)
   e. Mettre à jour last_activity timestamp
   f. Déverrouiller trust store + démarrer mDNS discovery
   g. Retourner LoginResponse { success: true, token, user_id, email }
```

### 6.2 Génération du token de session

```rust
fn generate_session_token() -> String {
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes)
}
```

- **Source d'aléa** : `OsRng` (CSPRNG du système d'exploitation)
- **Taille** : 32 bytes = 256 bits d'entropie
- **Encodage** : Base64 URL-safe sans padding
- **Stockage** : En mémoire uniquement (`Mutex<Option<String>>` dans `AppState`)
- **Aucune persistence** : le token est perdu au redémarrage de l'application

---

## 7. Dérivation de Clé — Comment la Clé Maître est Créée

### 7.1 Processus complet

```
Mot de passe maître (ex: "MonSuperM0tDePasse!")
    │
    ▼
┌──────────────────────────────────────────────────────────┐
│ Argon2id                                                  │
│                                                          │
│  Paramètres :                                            │
│  ├── Variante      : Argon2id (hybride i+d)             │
│  ├── memory_cost   : 65536 KiB = 64 MiB                 │
│  ├── time_cost     : 3 itérations                        │
│  ├── parallelism   : 4 threads                           │
│  ├── output_length : 32 bytes (256 bits)                 │
│  └── salt          : 32 bytes aléatoires (OsRng)         │
│                                                          │
│  Input  : password.as_bytes() + salt[32B]                │
│  Output : SecretBytes[32B] = clé de chiffrement vault    │
└────────────────────┬─────────────────────────────────────┘
                     │
     ┌───────────────┼────────────────┬──────────────────┐
     ▼               ▼                ▼                  ▼
 Vault key       Trust store       Vérification      Keychain OS
 (chiffre les    sub-key           (hash stocké      (sauvegarde
  données en     (HKDF dérivé)     dans users.        la vault key
  base)                            password_hash)     pour biométrie)
```

### 7.2 Configurations Argon2id disponibles

| Profil        | m_cost (KiB)     | t_cost | p_cost | output | Cas d'usage      |
| ------------- | ---------------- | ------ | ------ | ------ | ---------------- |
| Default       | 65536 (64 MiB)   | 3      | 4      | 32B    | Desktop standard |
| High Security | 131072 (128 MiB) | 4      | 8      | 32B    | Profil renforcé  |
| Mobile        | 32768 (32 MiB)   | 2      | 2      | 32B    | Android/iOS      |
| Test          | 8192 (8 MiB)     | 1      | 1      | 32B    | Tests unitaires  |

### 7.3 Code Rust exact

```rust
// rust-crypto-core/src/key_derivation/argon2.rs
const DEFAULT_M_COST: u32 = 65536;   // 64 MiB
const DEFAULT_T_COST: u32 = 3;
const DEFAULT_P_COST: u32 = 4;
const OUTPUT_LEN: usize = 32;        // 256 bits

pub fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<SecretBytes> {
    derive_key_from_password_with_config(password, salt, &Argon2Config::default())
}

pub fn generate_salt() -> Vec<u8> {
    // 32 bytes aléatoires via OsRng
}
```

### 7.4 Sel utilisateur

- **Taille** : 32 bytes
- **Génération** : `OsRng` lors de la création du compte
- **Stockage** : `users.crypto_salt` en base64 (clair dans la base)
- **Unicité** : Chaque utilisateur a son propre sel
- **Objectif** : Empêcher les attaques par tables arc-en-ciel (rainbow tables)

---

## 8. Chiffrement des Mots de Passe — Étape par Étape

### 8.1 Quand un mot de passe est sauvegardé

```
1. L'utilisateur saisit un mot de passe (ex: "s3cretP@ss!")
    │
    ▼
2. Le frontend envoie le mot de passe en clair via Tauri IPC
   invoke("create_password", { password: "s3cretP@ss!", title: "Gmail", ... })
    │
    ▼
3. Le backend récupère la vault key depuis SecureKey (mlock'd en RAM)
   key.use_key(|k| encrypt_data(password, k))
    │
    ▼
4. encrypt_data() dans crypto.rs :
   a. Vérifier que la clé fait 32 bytes
   b. Appeler encrypt_chacha(key, password.as_bytes())
      └─ Interne :
         i.   Générer nonce aléatoire de 12 bytes (OsRng)
         ii.  ChaCha20-Poly1305.encrypt(key[32B], nonce[12B], plaintext)
         iii. Retourne EncryptedBlob { nonce[12B] || ciphertext || tag[16B] }
   c. Base64-encode le blob
   d. Préfixer avec "v2:"
   e. Résultat : "v2:SGVsbG8gV29ybGQ..." (string)
    │
    ▼
5. INSERT INTO passwords (password, title, ...) VALUES ("v2:SGVs...", "Gmail", ...)
```

### 8.2 Format exact d'un mot de passe chiffré en base

```
"v2:" + base64( nonce[12 bytes] || ciphertext[N bytes] || Poly1305_tag[16 bytes] )
```

Exemple concret pour "s3cretP@ss!" (11 bytes de plaintext) :

```
Nonce    : [12 bytes aléatoires]
Ciphertext: [11 bytes chiffrés]
Tag      : [16 bytes Poly1305]
Total    : 39 bytes → base64 → 52 chars
Résultat : "v2:dGhpcyBpcyBhIG5vbmNlABCDEFGHIJKLMNOPQRSTU..."
```

### 8.3 Quand un mot de passe est lu

```
1. SELECT password FROM passwords WHERE id = ?
   Retourne : "v2:SGVsbG8gV29ybGQ..."
    │
    ▼
2. decrypt_data(encrypted_base64, key) dans crypto.rs :
   a. Détecter le préfixe "v2:" → mode ChaCha20-Poly1305
   b. Strip "v2:", puis base64-decode → bytes
   c. EncryptedBlob::from_bytes(bytes) → séparer nonce[12B] + ciphertext+tag
   d. decrypt_chacha(key, blob)
      └─ ChaCha20-Poly1305.decrypt(key, nonce, ciphertext+tag)
      └─ Vérification du tag Poly1305 (128 bits) → si altéré → CryptoError::DecryptionError
   e. UTF-8 decode → "s3cretP@ss!"
```

### 8.4 Rétrocompatibilité v1 (AES-256-GCM)

Si le mot de passe stocké **ne commence pas par "v2:"**, il est traité comme v1 :

```
1. base64-decode le tout → bytes
2. Séparer : nonce = bytes[0..12], ciphertext+tag = bytes[12..]
3. AES-256-GCM.decrypt(key, nonce, ciphertext+tag)
4. UTF-8 decode
```

> Il n'y a pas de migration automatique de v1 vers v2. Les anciens mots de passe restent en AES-256-GCM jusqu'à modification.

### 8.5 Code Rust exact

```rust
// tauri-desktop/src-tauri/src/crypto.rs

const V2_PREFIX: &str = "v2:";

pub fn encrypt_data(data: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 { return Err(CryptoError::InvalidKey); }
    let key_arr: &[u8; 32] = key.try_into().map_err(|_| CryptoError::InvalidKey)?;
    let blob = encrypt_chacha(key_arr, data.as_bytes())?;
    let encoded = general_purpose::STANDARD.encode(blob.to_bytes());
    Ok(format!("{}{}", V2_PREFIX, encoded))
}

pub fn decrypt_data(encrypted_base64: &str, key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 { return Err(CryptoError::InvalidKey); }
    if let Some(v2_data) = encrypted_base64.strip_prefix(V2_PREFIX) {
        // v2: ChaCha20-Poly1305
        let combined = general_purpose::STANDARD.decode(v2_data)?;
        let key_arr: &[u8; 32] = key.try_into()?;
        let blob = EncryptedBlob::from_bytes(&combined)?;
        let plaintext = decrypt_chacha(key_arr, &blob)?;
        String::from_utf8(plaintext.to_vec())
    } else {
        // v1: AES-256-GCM (legacy fallback)
        let combined = general_purpose::STANDARD.decode(encrypted_base64)?;
        let nonce = combined[..12].to_vec();
        let ciphertext = combined[12..].to_vec();
        decrypt_aes_gcm(&EncryptedData::new("AES-256-GCM".into(), nonce, ciphertext), key)
    }
}

// Version avec SecureKey (clé protégée par mlock)
pub fn encrypt_data_secure(data: &str, key: &SecureKey) -> Result<String, CryptoError> {
    key.use_key(|k| encrypt_data(data, k))
}
```

---

## 9. Génération de Mots de Passe — Algorithme Interne

### 9.1 Implémentation (frontend TypeScript)

La génération de mots de passe est effectuée côté **frontend** dans `PasswordsPage.tsx` :

```typescript
const generatePassword = () => {
  const len = 16;
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=";
  const rnd = (max: number) => {
    const a = new Uint32Array(1);
    crypto.getRandomValues(a); // CSPRNG du navigateur (Web Crypto API)
    return a[0] % max;
  };

  // Garantir au moins 1 caractère de chaque catégorie
  let pw =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[rnd(26)] + // 1 majuscule
    "abcdefghijklmnopqrstuvwxyz"[rnd(26)] + // 1 minuscule
    "0123456789"[rnd(10)] + // 1 chiffre
    "!@#$%^&*()_+-="[rnd(14)]; // 1 symbole

  // Remplir les 12 caractères restants
  for (let i = pw.length; i < len; i++) pw += charset[rnd(charset.length)];

  // Mélanger (Fisher-Yates shuffle)
  const chars = pw.split("");
  for (let i = chars.length - 1; i > 0; i--) {
    const j = rnd(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }

  setPassword(chars.join(""));
};
```

### 9.2 Caractéristiques détaillées

| Propriété              | Valeur                                                                                |
| ---------------------- | ------------------------------------------------------------------------------------- |
| **Longueur**           | 16 caractères (fixe)                                                                  |
| **Jeu de caractères**  | 74 caractères au total                                                                |
| **Minuscules**         | `abcdefghijklmnopqrstuvwxyz` (26)                                                     |
| **Majuscules**         | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` (26)                                                     |
| **Chiffres**           | `0123456789` (10)                                                                     |
| **Symboles**           | `!@#$%^&*()_+-=` (14)                                                                 |
| **Source d'aléa**      | `crypto.getRandomValues()` (Web Crypto API, CSPRNG)                                   |
| **Entropie théorique** | $16 \times \log_2(74) \approx 99.2$ bits                                              |
| **Garanties**          | Au moins 1 majuscule, 1 minuscule, 1 chiffre, 1 symbole                               |
| **Mélange**            | Fisher-Yates shuffle (les 4 caractères garantis ne sont pas toujours en position 0-3) |

### 9.3 Biais potentiel

La fonction `rnd(max)` utilise `Uint32Array[0] % max`. Le biais de modulo est présent mais négligeable : pour `max=74`, le biais est de $74 / 2^{32} \approx 1.7 \times 10^{-8}$, soit < 0.000002%. Non exploitable en pratique.

---

## 10. Chiffrement des Fichiers — Comment un Fichier est Protégé

### 10.1 Flux complet d'ajout de fichier

```
1. L'utilisateur sélectionne un fichier (ex: "contrat.pdf", 2.3 MB)
    │
    ▼
2. Le fichier est lu depuis le disque en mémoire (Vec<u8>)
    │
    ▼
3. Calcul du hash d'intégrité : BLAKE3(file_bytes) → 32 bytes → hex string
    │
    ▼
4. Encodage base64 du contenu : base64::encode(file_bytes) → string
    │
    ▼
5. Chiffrement avec la vault key :
   encrypt_data_secure(base64_content, &vault_key)
   └─ ChaCha20-Poly1305(key[32B], nonce[12B], base64_content.as_bytes())
   └─ Résultat : "v2:" + base64(nonce || ciphertext || tag)
    │
    ▼
6. Écriture du fichier chiffré sur disque
   └─ Chemin : {app_data}/files/{user_id}/{uuid}.enc
    │
    ▼
7. Insertion des métadonnées en base (tout en clair sauf le contenu) :
   INSERT INTO secure_files (filename, file_path, file_size, mime_type, integrity_hash)
   VALUES ("contrat.pdf", "/path/to/uuid.enc", 2300000, "application/pdf", "a1b2c3...")
```

### 10.2 Format du fichier chiffré sur disque

```
Fichier .enc sur disque :
"v2:" + base64(
    nonce[12 bytes]
    || ciphertext[base64(original_file_bytes).len() bytes]
    || Poly1305_tag[16 bytes]
)
```

> **Important** : Le fichier est d'abord encodé en base64, puis le résultat base64 est chiffré comme un string. Cela augmente la taille d'environ 33% (overhead base64) + 28 bytes (nonce + tag).

### 10.3 Lecture d'un fichier chiffré

```
1. Lecture du fichier .enc depuis le disque
2. decrypt_data_secure(encrypted_content, &vault_key)
   └─ ChaCha20-Poly1305.decrypt → base64_string
3. base64::decode(base64_string) → bytes originaux
4. Vérification BLAKE3 : hash(bytes) == integrity_hash stocké en base
   └─ Comparaison constant-time
5. Écriture en fichier temporaire pour visualisation
   └─ Fichier temporaire nettoyé au verrouillage (secure_cleanup_decrypted_files)
```

### 10.4 Ce qui est en clair vs chiffré pour les fichiers

| Donnée                    | État           | Où                                   |
| ------------------------- | -------------- | ------------------------------------ |
| Nom du fichier original   | 🔓 Clair       | SQLite `secure_files.filename`       |
| Chemin du fichier chiffré | 🔓 Clair       | SQLite `secure_files.file_path`      |
| Taille originale          | 🔓 Clair       | SQLite `secure_files.file_size`      |
| Type MIME                 | 🔓 Clair       | SQLite `secure_files.mime_type`      |
| Hash BLAKE3               | 🔓 Clair       | SQLite `secure_files.integrity_hash` |
| **Contenu du fichier**    | 🔒 **Chiffré** | Fichier .enc sur disque              |

---

## 11. Stockage de Clés (SSH/API) — Fonctionnement Interne

### 11.1 Flux de stockage

```
1. L'utilisateur colle une clé (ex: clé privée SSH RSA-4096)
    │
    ▼
2. Chiffrement avec la vault key :
   encrypt_data_secure(key_content, &vault_key)
   └─ "v2:" + base64(nonce[12B] || ciphertext || tag[16B])
    │
    ▼
3. INSERT INTO secure_keys (key_name, key_type, key_data, algorithm)
   VALUES ("prod-server", "SSH", "v2:...", "RSA-4096")
```

### 11.2 Ce qui est en clair vs chiffré

| Donnée                | État                               |
| --------------------- | ---------------------------------- |
| Nom de la clé         | 🔓 Clair                           |
| Type (SSH/API/...)    | 🔓 Clair                           |
| Algorithme            | 🔓 Clair                           |
| **Contenu de la clé** | 🔒 **Chiffré** (ChaCha20-Poly1305) |

---

## 12. Format Vault v2 — Structure Binaire Complète

### 12.1 Layout binaire

```
Offset  Taille   Champ                   Description
──────  ──────   ─────                   ───────────
0       6        magic                   Constante : b"VAULT\x02"
6       1        version                 Constante : 2
7       1        algo                    CipherAlgo enum (0=AES-256-GCM, 1=ChaCha20-Poly1305)
8       4        kdf_m_cost              Little-endian u32 (ex: 65536)
12      4        kdf_t_cost              Little-endian u32 (ex: 3)
16      4        kdf_p_cost              Little-endian u32 (ex: 4)
20      32       salt                    Sel Argon2id (32 bytes)
──────  ──────   ─── HEADER_SIZE = 52 ───
52      12       nonce                   Nonce ChaCha20-Poly1305
64      4        ciphertext_len          Little-endian u32 (taille du ciphertext)
68      N        ciphertext              Données chiffrées + Poly1305 tag (16B)
68+N    32       header_mac              HMAC-SHA3-256 calculé sur les 52 bytes du header
```

### 12.2 Structures Rust

```rust
pub const VAULT_MAGIC: &[u8; 6] = b"VAULT\x02";
pub const VAULT_VERSION: u8 = 2;
pub const HEADER_SIZE: usize = 52;

#[repr(u8)]
pub enum CipherAlgo {
    Aes256Gcm = 0,
    ChaCha20Poly1305 = 1,
}

pub struct VaultHeader {
    pub version: u8,
    pub algo: CipherAlgo,
    pub kdf_params: KdfParams,    // m_cost, t_cost, p_cost
    pub salt: [u8; 32],
}

pub struct SealedVault {
    pub header: VaultHeader,
    pub encrypted_payload: EncryptedBlob,  // nonce + ciphertext + tag
    pub header_mac: [u8; 32],              // HMAC-SHA3-256
}
```

### 12.3 Données internes du vault (après déchiffrement)

Le payload chiffré contient un `VaultData` sérialisé en MessagePack :

```rust
pub struct VaultData {
    pub entries: Vec<VaultEntry>,
    pub metadata: VaultMeta,
}

pub struct VaultEntry {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: String,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct VaultMeta {
    pub created_at: i64,
    pub updated_at: i64,
    pub entry_count: usize,
    pub format_version: u8,
    pub sequence: u64,          // Anti-rollback counter
}
```

### 12.4 Protection anti-rollback

`VaultMeta.sequence` est un compteur incrémenté à chaque sauvegarde. Lors de l'ouverture, si la séquence est inférieure à la dernière valeur connue, le vault est rejeté (détection de restauration d'une ancienne version).

---

## 13. 2FA TOTP — Fonctionnement Interne

### 13.1 Activation du TOTP

```
1. Générer le secret : OsRng → 32 bytes (256 bits)
    │
    ▼
2. Encoder en base32 :
   Secret::Raw(secret_bytes).to_encoded().to_string()
   Ex: "JBSWY3DPEHPK3PXP..."
    │
    ▼
3. Construire l'URI otpauth :
   otpauth://totp/FluXlock:{username}?secret={base32}&issuer=FluXlock&algorithm=SHA256&digits=6&period=30
    │
    ▼
4. Générer QR code :
   qrcode crate → PNG → base64 → envoyé au frontend pour affichage
    │
    ▼
5. L'utilisateur scanne le QR et entre un code TOTP pour vérification
    │
    ▼
6. Générer 10 codes de secours (backup codes)
    │
    ▼
7. Chiffrer le secret TOTP et les backup codes avec la vault key :
   encrypt_data_secure(totp_secret, &vault_key)
   encrypt_data_secure(json_backup_codes, &vault_key)
    │
    ▼
8. UPDATE users SET totp_secret = "v2:...", backup_codes = "v2:...",
                    totp_enabled = 1, totp_verified_at = NOW()
```

### 13.2 Vérification TOTP

```
1. Utilisateur saisit le code à 6 chiffres
2. Déchiffrer totp_secret depuis la base : decrypt_data_secure → base32 string
3. TOTP::new(algorithm=SHA256, digits=6, skew=1, step=30, secret) → vérification
   └─ skew=1 : accepte le code de la période précédente (±30s de tolérance)
4. Si valide → login autorisé
5. Si invalide → vérifier contre les backup codes (un code ne peut être utilisé qu'une fois)
```

### 13.3 Génération des codes de secours

```rust
fn generate_backup_codes(count: usize) -> Vec<String> {
    let chars = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    // Note : exclut I, O, 0, 1 pour éviter les confusions visuelles
    // 32 caractères possibles = 5 bits par caractère
    // 8 caractères = 40 bits d'entropie par code

    for each code (10 codes) {
        OsRng → 8 bytes aléatoires
        Chaque byte % 32 → index dans chars
        Insertion d'un tiret après le 4ème caractère
        Résultat : "ABCD-EFGH"
    }
}
```

**Format** : `XXXX-XXXX` (8 caractères + tiret)
**Jeu de caractères** : `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` (32 chars, sans I/O/0/1)
**Entropie par code** : $8 \times \log_2(32) = 40$ bits
**Nombre de codes** : 10
**Stockage** : Tableau JSON chiffré dans `users.backup_codes`

---

## 14. Backup / Restauration — Format et Chiffrement

### 14.1 Structure du fichier de backup

Le backup est un fichier JSON avec la structure suivante :

```json
{
  "metadata": {
    "version": "2.0",
    "created_at": "2024-01-15T10:30:00Z",
    "username": "john",
    "device_name": "MacBook-Pro",
    "file_count": 5,
    "password_count": 42
  },
  "metadata_mac": "base64(HMAC-SHA3-256(metadata, backup_key))",
  "backup_salt": "base64(32 bytes aléatoires)",
  "database_encrypted": "v2:base64(nonce || encrypted_db_dump || tag)",
  "files_encrypted": [
    {
      "filename": "contrat.pdf",
      "encrypted_content": "v2:base64(nonce || encrypted_file || tag)",
      "size": 2300000
    }
  ]
}
```

### 14.2 Processus de création du backup

```
1. L'utilisateur fournit un mot de passe de backup (peut être différent du mot de passe maître)
    │
    ▼
2. Générer un sel unique : OsRng → 32 bytes
    │
    ▼
3. Dériver la clé de backup :
   Argon2id(backup_password, backup_salt, m=64MiB, t=3, p=4) → backup_key[32B]
    │
    ▼
4. Exporter le dump complet de la base de données → JSON string
    │
    ▼
5. Chiffrer le dump :
   encrypt_data_secure(db_dump_json, &backup_key)
   → "v2:base64(nonce || ciphertext || tag)"
    │
    ▼
6. Pour chaque fichier sécurisé :
   a. Lire le fichier chiffré depuis le disque
   b. Re-chiffrer avec la backup_key (pas la vault_key)
    │
    ▼
7. Assembler les métadonnées (version, date, username, compteurs)
    │
    ▼
8. Calculer le MAC des métadonnées :
   HMAC-SHA3-256(key=backup_key, data=serialize(metadata)) → 32 bytes → base64
    │
    ▼
9. Sérialiser le tout en JSON et écrire le fichier .fluxlock-backup
```

### 14.3 Processus de restauration

```
1. L'utilisateur fournit le fichier de backup + mot de passe de backup
    │
    ▼
2. Parser le JSON, extraire backup_salt
    │
    ▼
3. Dériver la clé : Argon2id(password, backup_salt) → backup_key
    │
    ▼
4. Vérifier le MAC des métadonnées :
   HMAC-SHA3-256(backup_key, metadata) == metadata_mac ?
   └─ Si non → "Mot de passe incorrect ou backup corrompu"
    │
    ▼
5. Déchiffrer le dump de base de données
6. Restaurer les entrées dans SQLite
7. Pour chaque fichier : déchiffrer et re-chiffrer avec la vault_key locale
```

---

## 15. Transfert P2P — Protocole Cryptographique Complet

### 15.1 Découverte des pairs

```
1. mDNS : annonce _fluxlock-transfer._tcp.local. sur le réseau local
2. UDP beacon : port 52821 (broadcast 255.255.255.255 + multicast 239.255.77.77)
3. Résultat : liste des IP + ports des pairs FluXlock sur le réseau
```

### 15.2 Handshake — Établissement de la session chiffrée

Le handshake combine 3 mécanismes pour une sécurité hybride classique + post-quantique :

```
    Appareil A (expéditeur)                     Appareil B (destinataire)
    ─────────────────────                       ─────────────────────────

    ① L'utilisateur génère un wormhole code (ex: "7-guitar-purple")
       et le communique verbalement à B

    ② SPAKE2 Phase :
    Spake2::<Ed25519Group>::start_a(            Spake2::<Ed25519Group>::start_b(
        password = wormhole_code.as_bytes(),        password = wormhole_code.as_bytes(),
        identity_a = b"fluxlock-sender",            identity_b = b"fluxlock-receiver"
    ) → (spake_state_A, msg_A)                  ) → (spake_state_B, msg_B)

    ─── msg_A ──────────────────────────────►
    ◄── msg_B ──────────────────────────────

    spake_state_A.finish(msg_B)                 spake_state_B.finish(msg_A)
    → spake_key_A[32B]                          → spake_key_B[32B]
                        (spake_key_A == spake_key_B si même wormhole code)

    ③ ML-KEM-768 Phase (post-quantique) :
    (kem_pk, kem_sk) = generate_recipient_keypair()

    ◄── kem_pk (1184 bytes) ────────────────

    (shared_secret, ciphertext) =
        encapsulate(&kem_pk)
    → shared_secret[32B]

    ─── ciphertext (1088 bytes) ────────────►

                                                shared_secret = decapsulate(&kem_sk, &ct)
                                                → shared_secret[32B]

    ④ Dérivation de la clé de session hybride :
    ikm = spake_key || kem_shared_secret       (concaténation, 64 bytes)
    session_key = HKDF-SHA3-256(
        input = ikm,
        salt  = b"fluxlock-transfer-v1",
        info  = b"session-key",
        len   = 32
    )
    → session_key[32B] identique des deux côtés

    ⑤ Calcul du safety number :
    safety = BLAKE3(session_key || id_A || id_B)[0..6]
    → Affiché en hex (24 bits = 6 hex chars)
    → L'utilisateur vérifie visuellement que les deux appareils affichent le même code
```

### 15.3 Session chiffrée — Messages individuels

Chaque message est chiffré avec ChaCha20-Poly1305 et un nonce basé sur un **compteur** :

```rust
fn nonce_from_counter(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    // Bytes 0-3 : zéros
    // Bytes 4-11 : compteur big-endian
    *Nonce::from_slice(&nonce)
}
```

**AAD (Additional Authenticated Data)** : `"fluxlock-v1:send:{counter}"` — lie chaque message à son numéro de séquence pour empêcher le réordonnancement.

### 15.4 Re-chiffrement en transit (zero-disk plaintext)

Lors du transfert d'un mot de passe :

```
Appareil A (expéditeur) :
1. Déchiffrer le mot de passe avec la vault_key_A :
   decrypt_data_secure(encrypted_password, &vault_key_A) → plaintext (Zeroizing<String>)
2. Le plaintext existe uniquement en RAM (Zeroizing = auto-zéroisation)
3. Chiffrer avec la session_key pour l'envoi :
   encrypt(session_key, nonce_counter, plaintext.as_bytes(), aad) → ciphertext
4. Envoyer le ciphertext par TLS

Appareil B (destinataire) :
1. Déchiffrer avec la session_key :
   decrypt(session_key, nonce, ciphertext, aad) → plaintext (Zeroizing<Vec<u8>>)
2. Le plaintext existe uniquement en RAM (Zeroizing)
3. Re-chiffrer avec la vault_key_B :
   encrypt_data_secure(plaintext, &vault_key_B) → "v2:..."
4. Stocker dans la base locale
```

> **À aucun moment le mot de passe en clair n'est écrit sur disque.** Le buffer `Zeroizing` est zéroïsé automatiquement quand il sort du scope Rust.

### 15.5 Re-chiffrement des fichiers en transit

Pour les fichiers volumineux, le transfert utilise des **chunks de 64 KiB** :

```rust
const CHUNK_SIZE: usize = 64 * 1024;  // 64 KiB

pub fn prepare_file_chunks(file_path: &Path) -> Result<Vec<FileChunk>> {
    // Lire le fichier chiffré depuis le disque
    // Découper en chunks de 64 KiB
    // Chaque chunk est envoyé individuellement via la session chiffrée
}
```

Intégrité vérifiée par BLAKE3 :

```rust
let hash = blake3::hash(&original_data);
// Comparaison constant-time à la réception
```

---

## 16. Trust Store — Stockage de Confiance entre Appareils

### 16.1 Dérivation de la sous-clé trust store

La clé du trust store est dérivée de la vault key, jamais stockée directement :

```rust
let trust_key = HKDF-SHA3-256(
    input = vault_key,
    salt  = b"fluxlock-v1",
    info  = b"fluxlock-trust-store-v1",
    len   = 32
)
```

### 16.2 Contenu du trust store

Le trust store est un fichier JSON chiffré contenant :

- Liste des appareils de confiance (device_id, device_name, ...)
- Clé publique ML-DSA-65 de chaque appareil (pour vérifier les signatures)
- Seed de signature ML-DSA-65 local (chiffré)
- Historique des pairings

### 16.3 Format sur disque

```
Fichier : trust_store.enc
Contenu : "v2:" + base64(nonce[12B] || encrypted_json || tag[16B])
Permissions : chmod 0o600 (lecture/écriture propriétaire seulement)
```

### 16.4 Signatures ML-DSA-65

Chaque appareil possède une paire de clés ML-DSA-65 :

```rust
pub struct MlDsaKeyPair {
    signing_key: ml_dsa::SigningKey<MlDsa65>,
}

impl MlDsaKeyPair {
    pub fn generate() -> Result<Self>;          // Génère nouvelle paire
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;  // Signe (3309 bytes)
    pub fn verifying_key_bytes(&self) -> Result<Vec<u8>>;    // Clé publique
    pub fn signing_seed_bytes(&self) -> Vec<u8>;             // Seed (pour backup)
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>>;           // Sérialisation
    pub fn from_pkcs8_der(der_bytes: &[u8]) -> Result<Self>; // Désérialisation
}

pub fn verify_ml_dsa(
    vk_der: &[u8],        // Clé publique du signataire
    message: &[u8],       // Message signé
    signature_bytes: &[u8] // Signature (3309 bytes)
) -> Result<bool>;
```

### 16.5 ML-KEM-768 — Détails de l'implémentation

```rust
// rust-crypto-core/src/crypto/kem.rs

// Tailles :
// Clé publique  : 1184 bytes
// Clé privée    : ~2400 bytes (zéroïsée on Drop via unsafe mémoire brute)
// Ciphertext    : 1088 bytes
// Secret partagé: 32 bytes (Zeroizing<[u8; 32]>)

pub fn generate_recipient_keypair() -> Result<(KemPublicKey, KemPrivateKey)> {
    let (dk, ek) = MlKem768::generate_keypair();
    Ok((KemPublicKey { key: ek }, KemPrivateKey { key: dk }))
}

pub fn encapsulate(recipient_pubkey: &KemPublicKey) -> Result<(SharedSecret, KemCiphertext)> {
    let (ct, shared_key) = recipient_pubkey.key.encapsulate();
    // shared_key → premiers 32 bytes → Zeroizing<[u8; 32]>
    Ok((SharedSecret { secret }, KemCiphertext { data: ct.as_ref().to_vec() }))
}

pub fn decapsulate(privkey: &KemPrivateKey, ciphertext: &KemCiphertext) -> Result<SharedSecret> {
    let ct = Ciphertext::<MlKem768>::try_from(ciphertext.as_bytes())?;
    let shared_key = privkey.key.decapsulate(&ct);
    Ok(SharedSecret { secret: shared_key[..32] })
}

// Sécurité de la clé privée :
impl Drop for KemPrivateKey {
    fn drop(&mut self) {
        // Zéroïsation mémoire brute via unsafe
        let ptr = &mut self.key as *mut _ as *mut u8;
        let size = std::mem::size_of::<DecapsulationKey<MlKem768>>();
        let bytes = unsafe { std::slice::from_raw_parts_mut(ptr, size) };
        bytes.zeroize();  // Écriture volatile de zéros
    }
}
```

---

## 17. Session & Auto-lock — Gestion des Tokens

### 17.1 Auto-lock

Le mécanisme d'auto-lock protège contre les sessions laissées ouvertes :

```rust
#[tauri::command]
async fn check_auto_lock(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    // 1. Vérifier si un utilisateur est authentifié
    // 2. Calculer le temps écoulé depuis last_activity
    // 3. Si elapsed >= timeout_minutes * 60 :
    //    a. Nettoyer les fichiers temporaires déchiffrés (secure_cleanup_decrypted_files)
    //    b. Supprimer la clé de chiffrement du Keychain OS
    //    c. Effacer le session token en mémoire
    //    d. Effacer le current_user_id
    //    e. Logger "AUTO_LOCK" dans audit_logs
    //    f. Retourner { locked: true, reason: "inactivity" }
}
```

| Paramètre          | Valeur                                                   |
| ------------------ | -------------------------------------------------------- |
| Timeout par défaut | 5 minutes                                                |
| Configurable       | Oui (`set_auto_lock_timeout(minutes)`)                   |
| Valeur 0           | Désactive l'auto-lock                                    |
| Actions au lock    | Suppression clé Keychain + token mémoire + fichiers temp |

### 17.2 Ce qui se passe au lock/logout

```
1. secure_cleanup_decrypted_files() — supprime tous les fichiers temporaires déchiffrés
2. secure_storage::delete_encryption_key(user_id) — supprime la vault key du Keychain OS
3. session_token = None — efface le token de mémoire
4. current_user_id = None — déconnecte l'utilisateur
5. La vault key en RAM (SecureKey) → ZeroizeOnDrop → bytes écrasés par des zéros + munlock
```

---

## 18. Gestion des Secrets en Mémoire

### 18.1 Types sécurisés

| Type              | Module           | Protection                                                                          |
| ----------------- | ---------------- | ----------------------------------------------------------------------------------- |
| `SecureKey`       | secure_key.rs    | `Vec<u8>` + mlock + ZeroizeOnDrop + munlock on Drop, no Clone/Serialize/Debug(full) |
| `SecretBytes`     | secure_memory.rs | `Vec<u8>` + ZeroizeOnDrop, no Debug/Clone                                           |
| `SecretString`    | secure_memory.rs | `String` + ZeroizeOnDrop, no Debug/Clone                                            |
| `CryptoKey`       | secure_memory.rs | `Vec<u8>` + ZeroizeOnDrop, generate() via OsRng                                     |
| `MasterKey`       | kdf.rs           | `Zeroizing<[u8; 32]>`, no Debug/Clone                                               |
| `SessionKeyGuard` | session.rs       | Wrapper zeroized at session end                                                     |
| `KemPrivateKey`   | kem.rs           | Explicit Drop with unsafe zeroize on raw memory (~2400 bytes)                       |
| `MlDsaKeyPair`    | ml_dsa.rs        | Explicit Drop with zeroize()                                                        |

### 18.2 SecureKey — Fonctionnement détaillé

```rust
pub struct SecureKey {
    key: Vec<u8>,    // 32 bytes, verrouillés en RAM
}

impl SecureKey {
    pub fn new(key: Vec<u8>) -> Result<Self, String> {
        // 1. Allouer le Vec<u8>
        // 2. libc::mlock(ptr, len) — empêche le swap disque
        //    (la clé ne sera JAMAIS écrite dans un fichier de swap)
        // 3. Retourner SecureKey
    }

    pub fn use_key<F, R>(&self, f: F) -> R where F: FnOnce(&[u8]) -> R {
        // Pattern callback : la clé n'est jamais retournée directement
        // Elle n'existe que dans le scope du callback
        f(&self.key)
    }
}

impl Drop for SecureKey {
    fn drop(&mut self) {
        // 1. ZeroizeOnDrop : écrire des zéros sur self.key (volatile write)
        // 2. libc::munlock(ptr, len) — permet au système de réutiliser la page
    }
}
```

### 18.3 Invariants de sécurité

- Aucun `println!` / `dbg!` / `log!` sur des données sensibles
- `Debug` implémenté manuellement : affiche seulement `SecureKey(len=32)`, jamais le contenu
- `Clone` / `Serialize` / `Deserialize` non implémentés sur les types secrets
- `to_vec()` retourne `Zeroizing<Vec<u8>>` (auto-nettoyage automatique)
- Toutes les comparaisons de secrets utilisent `subtle::ConstantTimeEq` (temps constant)

---

## 19. Gestion des Erreurs Cryptographiques

| Module           | Pattern                  | Détails                                                                                         |
| ---------------- | ------------------------ | ----------------------------------------------------------------------------------------------- |
| rust-crypto-core | `Result<T, CryptoError>` | Enum thiserror avec 13 variantes (EncryptionError, DecryptionError, AuthenticationFailed, etc.) |
| crypto.rs        | `Result<T, String>`      | Messages descriptifs, propagation via `?`                                                       |
| secure_key.rs    | `Result<T, String>`      | Échec Argon2 → erreur retournée, pas de panic                                                   |
| transfer/\*      | `Result<T, String>`      | Chaque étape du handshake retourne une erreur en cas d'échec                                    |
| biometric.rs     | `Result<T, String>`      | 3 échecs → fallback mot de passe                                                                |

**Aucun `unwrap()` sur des opérations crypto** — tout est propagé via `Result` ou `?`.  
**Aucun `panic!()` dans les chemins crypto** — sauf `OsRng` failure (par design : pas d'entropie = pas de sécurité).

---

## 20. Surface d'Attaque

### 20.1 Entrées utilisateur

- Mot de passe maître → Argon2id (rate-limited : 0/15/30/60/120s backoff progressif selon tentatives)
- Code wormhole → SPAKE2 (42 bits d'entropie, ~4 trillion combinaisons)
- Code TOTP → 6 digits (validation avec fenêtre ±1 période)

### 20.2 Données persistées

| Fichier/Table            | Contenu en clair                                       | Contenu chiffré/hashé                                                     |
| ------------------------ | ------------------------------------------------------ | ------------------------------------------------------------------------- |
| `sv.db` → `users`        | username, email, salt, flags                           | password_hash (Argon2id), totp_secret (ChaCha20), backup_codes (ChaCha20) |
| `sv.db` → `passwords`    | title, username, url, notes, category                  | password (ChaCha20)                                                       |
| `sv.db` → `secure_files` | filename, file_path, file_size, mime_type, blake3_hash | — (contenu chiffré sur disque)                                            |
| `sv.db` → `secure_keys`  | key_name, key_type, algorithm                          | key_data (ChaCha20)                                                       |
| `sv.db` → `audit_logs`   | action, resource_type, ip_address, user_agent          | —                                                                         |
| `trust_store.enc`        | —                                                      | Tout chiffré (ChaCha20, clé HKDF)                                         |
| `files/*.enc`            | —                                                      | Tout chiffré (ChaCha20)                                                   |

### 20.3 Interfaces réseau / IPC

- **mDNS** : `_fluxlock-transfer._tcp.local.` / `_fluxlock-recv._tcp.local.`
- **UDP beacon** : Port 52821 (broadcast + multicast 239.255.77.77)
- **TCP transfer** : Port 52820 (TLS éphémère + SPAKE2 + ML-KEM-768 + ChaCha20)
- **Tauri IPC** : Commandes avec capabilities (migrated.json, desktop.json, android.json)

### 20.4 Points d'exposition des clés

| Point                  | Protection                            | Risque résiduel                               |
| ---------------------- | ------------------------------------- | --------------------------------------------- |
| RAM (vault key)        | mlock + zeroize                       | Cold boot attack (physique)                   |
| Keychain OS            | Secure Enclave (macOS), DPAPI (Win)   | Accès admin local                             |
| Trust store sur disque | ChaCha20 + HKDF sub-key + chmod 0o600 | Compromission vault key → trust store lisible |
| TLS self-signed        | Pas de vérification PKI               | MITM résolu par SPAKE2 + safety number        |
| Biometric key          | OS keystore                           | Jailbreak / root device                       |
| Session token          | Mémoire uniquement, non persisté      | Accès mémoire processus                       |

### 20.5 Résumé : ce qu'un attaquant peut voir avec accès au disque

| Accès                        | Ce qu'il voit                                                                                                  | Ce qu'il ne voit PAS                                                              |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Fichier SQLite seul          | Noms d'utilisateur, emails, titres des entrées, URLs, notes, noms de fichiers, tailles, types MIME, audit logs | Mots de passe, contenus de fichiers, clés SSH/API, secrets TOTP, codes de secours |
| Fichier SQLite + vault key   | Tout                                                                                                           | —                                                                                 |
| Backup sans mot de passe     | metadata (username, compteurs, date)                                                                           | Dump DB, fichiers                                                                 |
| Trust store sans vault key   | Rien (entièrement chiffré)                                                                                     | —                                                                                 |
| Fichiers .enc sans vault key | Rien (entièrement chiffré)                                                                                     | —                                                                                 |

---

## Annexe A — Lacunes documentaires

| Élément                                                                             | Statut                                                                              |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| Métadonnées en clair dans `passwords` (title, username, url, notes)                 | `[PAR DESIGN]` — compromis performance/sécurité, seul le mot de passe est secret    |
| Configuration mobile Argon2 (32 MiB) : seuil de sécurité sur appareils bas de gamme | `[À ÉVALUER]`                                                                       |
| ML-KEM 0.3.0-rc.2 / ML-DSA 0.1.0-rc.8 : versions release candidate                  | `[À SURVEILLER]` — mise à jour vers versions stables prévue                         |
| Safety number 24 bits : collision théorique 1/16M                                   | `[ACCEPTABLE]` — compromis UX/sécurité, confirmation manuelle                       |
| Rotation automatique des clés ML-DSA-65                                             | `[NON TROUVÉ]` — pas de mécanisme de rotation périodique                            |
| Audit formel du protocole de sync P2P                                               | `[NON TROUVÉ]` — protocole custom, pas de vérification formelle (ProVerif, Tamarin) |
| Test de résistance aux side-channels (timing, cache)                                | `[NON TROUVÉ]` — dépend de RustCrypto impls (réputées constant-time)                |
| Migration automatique v1→v2 des mots de passe existants                             | `[NON TROUVÉ]` — les anciens mots de passe restent en AES-256-GCM                   |

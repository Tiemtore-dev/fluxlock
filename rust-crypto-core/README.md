# 🔐 Rust Crypto Core

Core cryptographique de niveau militaire pour SecureVault Next-Gen.

## 🚀 Compilation

```bash
cargo build --release
```

## 🧪 Tests

```bash
# Tous les tests
cargo test

# Tests avec output
cargo test -- --nocapture

# Tests d'un module spécifique
cargo test crypto::aes_gcm

# Benchmarks
cargo bench
```

## 📖 Documentation

```bash
cargo doc --open
```

## 🔧 Utilisation

```rust
use secure_vault_crypto::*;

// Dériver une clé depuis un mot de passe
let password = "super_secret";
let salt = key_derivation::generate_salt();
let key = derive_key_from_password(password, &salt)?;

// Chiffrer des données
let data = b"Donnees ultra secretes";
let encrypted = encrypt_aes_gcm(data, key.expose_secret())?;

// Déchiffrer
let decrypted = decrypt_aes_gcm(&encrypted, key.expose_secret())?;
```

## 🔒 Fonctionnalités

- ✅ AES-256-GCM (chiffrement authentifié)
- ✅ ChaCha20-Poly1305 (alternative légère)
- ✅ Argon2id (dérivation de clés résistante GPU)
- ✅ Ed25519 (signatures numériques)
- ✅ X25519 (échange de clés Diffie-Hellman)
- ✅ BLAKE3, SHA-256, SHA3-256 (hachage)
- ✅ HKDF (dérivation de clés multiples)
- ✅ Zeroize (effacement sécurisé de la mémoire)

## ⚡ Performance

Benchmarks sur Apple M1:

- AES-GCM encrypt 1MB: ~2ms
- ChaCha20 encrypt 1MB: ~1.5ms
- Argon2id derivation: ~250ms (config par défaut)
- Ed25519 signature: <0.5ms

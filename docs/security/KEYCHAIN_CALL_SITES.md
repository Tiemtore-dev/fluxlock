# Cartographie des appels Keychain / Secure Enclave

> **Dernière mise à jour** : Juin 2025
> **Contexte** : Toutes les opérations cryptographiques du coffre-fort passent par le Keychain macOS (ou Android Keystore / Windows Credential Manager) via la crate `keyring`. Ce document répertorie **chaque point d'accès** au Keychain.

---

## 1. Fonctions d'accès Keychain (définitions)

Les trois fonctions bas-niveau sont définies dans `src/secure_storage.rs` :

| Fonction                                  | Ligne | Rôle                                                                                                  |
| ----------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------- |
| `store_encryption_key(user_id, key)`      | L67   | Encode la clé en Base64, la stocke dans le Keychain via `keyring::Entry::set_password`                |
| `retrieve_encryption_key_secure(user_id)` | L324  | Lit le Keychain, décode Base64, zeroize le buffer B64, retourne `SecureKey` (mlock + Zeroize on Drop) |
| `delete_encryption_key(user_id)`          | L355  | Supprime l'entrée Keychain via `keyring::Entry::delete_credential`                                    |

---

## 2. Helper centralisé — `get_or_fetch_vault_key()`

**Fichier** : `src/lib.rs` (L99)

Toutes les commandes qui ont besoin de **lire** la clé passent par ce helper unique :

```
get_or_fetch_vault_key(state, user_id)
    ├─ si UTILISATION_CACHE=false → retrieve_encryption_key_secure() [accès direct Keychain]
    └─ si UTILISATION_CACHE=true (défaut)
         ├─ Cache hit   → retourne la clé depuis le cache XOR-masked (aucun accès Keychain)
         └─ Cache miss  → retrieve_encryption_key_secure() → stocke en cache → retourne
```

**Variable d'environnement** : `UTILISATION_CACHE` (`.env`, section 8)

- `true` (défaut) : cache actif — TTL 3 min, XOR-masking, mlock, rotation masque 30s
- `false` : ancien comportement, accès direct Keychain à chaque opération

---

## 3. Appels indirects — via `get_or_fetch_vault_key()` (20 sites)

Chaque appel déclenche au maximum **un** accès Keychain (en cas de cache miss).

### 3.1 Mots de passe (`commands/passwords.rs`)

| Ligne | Commande Tauri     | Opération                                             |
| ----- | ------------------ | ----------------------------------------------------- |
| L22   | `create_password`  | Chiffrer et stocker un nouveau mot de passe           |
| L88   | `get_passwords`    | Lister les mots de passe (+ auto-migration v1→v2)     |
| L212  | `decrypt_password` | Déchiffrer un mot de passe spécifique                 |
| L241  | `update_password`  | Re-chiffrer et mettre à jour un mot de passe existant |

### 3.2 Fichiers (`commands/files.rs`)

| Ligne | Commande Tauri                 | Opération                                                       |
| ----- | ------------------------------ | --------------------------------------------------------------- |
| L53   | `create_secure_file`           | Chiffrer un fichier (Base64) et stocker dans le coffre          |
| L221  | `create_secure_file_from_path` | Chiffrer un fichier depuis un chemin disque (SENC v1 streaming) |
| L369  | `get_secure_files`             | Lister les fichiers avec noms déchiffrés                        |
| L409  | `decrypt_file`                 | Déchiffrer un fichier en mémoire (Base64)                       |
| L486  | `decrypt_file_to_path`         | Déchiffrer un fichier en streaming vers le disque               |

### 3.3 Clés cryptographiques (`commands/keys.rs`)

| Ligne | Commande Tauri        | Opération                                              |
| ----- | --------------------- | ------------------------------------------------------ |
| L58   | `generate_secure_key` | Générer une nouvelle clé crypto et la stocker chiffrée |
| L101  | `import_secure_key`   | Importer une clé externe, la chiffrer et la stocker    |
| L145  | `get_secure_keys`     | Lister les clés avec noms déchiffrés                   |
| L180  | `decrypt_key`         | Déchiffrer les données d'une clé par ID                |

### 3.4 Partage (`commands/sharing.rs`)

| Ligne | Commande Tauri | Opération                                            |
| ----- | -------------- | ---------------------------------------------------- |
| L33   | `share_file`   | Générer un token de partage sécurisé pour un fichier |

### 3.5 Biométrie (`commands/biometric_cmds.rs`)

| Ligne | Commande Tauri     | Opération                                                                    |
| ----- | ------------------ | ---------------------------------------------------------------------------- |
| L33   | `enable_biometric` | Lire la clé vault pour l'enregistrer dans le Keychain biométrique (Touch ID) |

### 3.6 TOTP / 2FA (`commands/totp_2fa.rs`)

| Ligne | Commande Tauri          | Opération                                                      |
| ----- | ----------------------- | -------------------------------------------------------------- |
| L35   | `setup_2fa`             | Générer le secret TOTP et le QR code                           |
| L85   | `verify_and_enable_2fa` | Vérifier le code TOTP, chiffrer le secret et activer le 2FA    |
| L194  | `verify_2fa_login`      | Déchiffrer le secret TOTP pour vérifier le code à la connexion |

### 3.7 Transfert P2P (`transfer/commands.rs`)

| Ligne | Commande Tauri                 | Opération                                                                    |
| ----- | ------------------------------ | ---------------------------------------------------------------------------- |
| L876  | `transfer_confirm_and_execute` | **Récepteur** : obtenir la clé vault pour re-chiffrer les données reçues     |
| L1156 | `transfer_confirm_and_execute` | **Émetteur** : obtenir la clé vault pour déchiffrer les éléments avant envoi |

---

## 4. Appels directs — `store_encryption_key()` (4 sites)

Ces appels **écrivent** dans le Keychain (pas de passage par le cache).

### 4.1 Inscription & Connexion (`commands/auth.rs`)

| Ligne | Commande Tauri   | Opération                                                        |
| ----- | ---------------- | ---------------------------------------------------------------- |
| L184  | `local_register` | Stocker la clé dérivée dans le Keychain après création du compte |
| L353  | `local_login`    | Stocker la clé dérivée dans le Keychain après authentification   |

> **Note** : Ces deux appels peuplent aussi le cache (`vault_key_cache.store()`) immédiatement après (L195 et L366).

### 4.2 Connexion biométrique (`commands/biometric_cmds.rs`)

| Ligne | Commande Tauri             | Opération                                                                               |
| ----- | -------------------------- | --------------------------------------------------------------------------------------- |
| L106  | `biometric_login`          | Restaurer la clé dans le Keychain après authentification biométrique (macOS)            |
| L192  | `biometric_login_with_key` | Restaurer la clé dans le Keychain après authentification biométrique (Android Keystore) |

---

## 5. Appels directs — `delete_encryption_key()` (2 sites)

Ces appels **suppriment** l'entrée Keychain et **invalident** le cache.

### 5.1 Session (`commands/session.rs`)

| Ligne | Commande Tauri    | Opération                                                                     |
| ----- | ----------------- | ----------------------------------------------------------------------------- |
| L20   | `local_logout`    | Supprimer la clé du Keychain + invalider le cache à la déconnexion            |
| L81   | `check_auto_lock` | Supprimer la clé du Keychain + invalider le cache au verrouillage automatique |

> **Note** : `vault_key_cache.invalidate()` est appelé **avant** `delete_encryption_key()` dans les deux cas (L18 et L79).

---

## 6. Tests unitaires (`secure_storage.rs`)

| Ligne | Fonction de test                     | Appels Keychain                            |
| ----- | ------------------------------------ | ------------------------------------------ |
| L466  | `test_keyring_store_retrieve_delete` | `delete` → `store` → `retrieve` → `delete` |

---

## 7. Résumé quantitatif

| Catégorie                                     | Nombre de sites | Fichiers concernés  |
| --------------------------------------------- | --------------- | ------------------- |
| Lecture via cache (`get_or_fetch_vault_key`)  | **20**          | 7 fichiers          |
| Écriture directe (`store_encryption_key`)     | **4**           | 2 fichiers          |
| Suppression directe (`delete_encryption_key`) | **2**           | 1 fichier           |
| **Total sites d'appel**                       | **26**          | **8 fichiers**      |
| Définitions de fonctions                      | 3               | `secure_storage.rs` |
| Tests                                         | 1               | `secure_storage.rs` |

---

## 8. Flux de vie de la clé dans le Keychain

```
Inscription / Connexion
    └─ store_encryption_key()       ← Écriture Keychain
    └─ vault_key_cache.store()      ← Peuplement cache

Opérations CRUD (mots de passe, fichiers, clés, TOTP, transfert, partage)
    └─ get_or_fetch_vault_key()
         ├─ Cache hit  → pas d'accès Keychain
         └─ Cache miss → retrieve_encryption_key_secure()  ← Lecture Keychain
                         └─ cache.store()                  ← Peuplement cache

Déconnexion / Auto-lock
    └─ vault_key_cache.invalidate() ← Zeroize + munlock cache
    └─ delete_encryption_key()      ← Suppression Keychain
```

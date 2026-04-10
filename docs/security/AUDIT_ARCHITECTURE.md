# VAULT — ARCHITECTURE ET CONFORMITÉ AUX MEILLEURES PRATIQUES

## Audit de sécurité profond — Livrable 2

**Date**: 2025  
**Cible**: FluXlock v2.0.0 (Rust/Tauri + React/TypeScript)

---

## Section 2.1 — Architecture réelle de l'application

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          FRONTEND (WebView Tauri)                       │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ ┌───────────────┐  │
│  │ LoginPage   │ │ PasswordsPage│ │ TransferPage │ │ SettingsPage  │  │
│  │ RegisterPage│ │ FilesPage    │ │ SecurityPage │ │ BackupRestore │  │
│  │ ResetVault  │ │ KeysPage     │ │ SharesPage   │ │ SystemSecurity│  │
│  └──────┬──────┘ └──────┬───────┘ └──────┬───────┘ └───────┬───────┘  │
│         │               │                │                  │          │
│  ┌──────┴───────────────┴────────────────┴──────────────────┴───────┐  │
│  │                    vault-service.ts (IPC abstraction)            │  │
│  │                    tauri-api.ts (legacy duplicate)               │  │
│  │                    authStore.ts (Zustand persist → localStorage) │  │
│  └──────────────────────────────┬───────────────────────────────────┘  │
│                                 │ invoke() / IPC Tauri                 │
└─────────────────────────────────┼─────────────────────────────────────┘
                                  │
══════════════════════════════════╪═══════════════════ FRONTIÈRE IPC ═════
                                  │
┌─────────────────────────────────┼─────────────────────────────────────┐
│                      BACKEND RUST (lib.rs — God Object)               │
│  ┌──────────────────────────────┴──────────────────────────────────┐  │
│  │              42 #[tauri::command] dans un seul fichier           │  │
│  │              AppState { db, user_id, session, config, ... }     │  │
│  └────┬──────────┬──────────┬──────────┬──────────┬───────────────┘  │
│       │          │          │          │          │                    │
│  ┌────┴───┐ ┌───┴────┐ ┌──┴───┐ ┌───┴────┐ ┌──┴──────────────┐    │
│  │database│ │crypto  │ │secure│ │backup  │ │transfer/        │    │
│  │.rs     │ │.rs     │ │_key  │ │_manager│ │  commands.rs    │    │
│  │        │ │        │ │.rs   │ │.rs     │ │  handshake.rs   │    │
│  │SQLite  │ │Argon2id│ │mlock │ │HMAC    │ │  transport.rs   │    │
│  │sqlx    │ │ChaCha20│ │Zeroize││Backup  │ │  session.rs     │    │
│  └────┬───┘ └───┬────┘ └──┬───┘ └───┬───┘ │  discovery.rs   │    │
│       │         │         │         │      │  protocol.rs    │    │
│       │         │         │         │      │  trust_store.rs │    │
│       │         │         │         │      └──┬──────────────┘    │
│       │         │         │         │         │                    │
│  ═════╪═════════╪═════════╪═════════╪═════════╪══ FRONTIÈRE OS ═══│
│       │         │         │         │         │                    │
│  ┌────┴───┐ ┌───┴────────┴──┐ ┌───┴───┐ ┌──┴──────────┐         │
│  │SQLite  │ │secure_storage │ │FS disk│ │ Network     │         │
│  │fichier │ │.rs            │ │       │ │ UDP :52821  │         │
│  │.db     │ │┌─────────────┐│ │Backup │ │ TCP :52820  │         │
│  └────────┘ ││  Keychain   ││ │JSON   │ │ mDNS       │         │
│             ││  (macOS)    ││ └───────┘ │ TLS ephem  │         │
│             │├─────────────┤│           └─────────────┘         │
│             ││  Secret Svc ││                                    │
│             ││  (Linux)    ││                                    │
│             │├─────────────┤│                                    │
│             ││  Cred Mgr   ││                                    │
│             ││  (Windows)  ││                                    │
│             │├─────────────┤│                                    │
│             ││  File-based ││                                    │
│             ││  (Android)  ││                                    │
│             │└─────────────┘│                                    │
│             └───────────────┘                                    │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│                    rust-crypto-core (bibliothèque)                │
│  ┌───────────────┐ ┌──────────────┐ ┌──────────────────────┐    │
│  │ crypto/       │ │ signatures/  │ │ key_exchange/        │    │
│  │  cipher.rs    │ │  ml_dsa.rs   │ │  x25519.rs           │    │
│  │  chacha.rs    │ │  ed25519.rs  │ ├──────────────────────┤    │
│  │  aes_gcm.rs   │ ├──────────────┤ │ key_derivation/      │    │
│  │  vault.rs     │ │ hashing/     │ │  kdf.rs (v2 Argon2id)│    │
│  │  kem.rs       │ │  blake3      │ │  argon2.rs (v1)      │    │
│  │  kdf.rs       │ │  sha3-256    │ │  hkdf.rs (SHA3-256)  │    │
│  │  integrity.rs │ │  sha-256     │ ├──────────────────────┤    │
│  └───────────────┘ └──────────────┘ │ secure_memory.rs     │    │
│                                      │ migration/migrate.rs │    │
│                                      └──────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

### Observations architecturales

**God Object — lib.rs** : Le fichier lib.rs contient ~3060 lignes avec 42 commandes Tauri, toute la logique métier,
et la gestion d'état. Il n'existe pas de couche service intermédiaire. C'est un couplage fort qui rend l'isolation
et le test unitaire difficiles.

**Double abstraction IPC** : vault-service.ts et tauri-api.ts sont deux couches d'abstraction IPC parallèles pour
les mêmes commandes backend. Risque d'incohérence et de maintenance.

**Frontière de confiance IPC** : La seule frontière de confiance est le canal IPC Tauri (intra-processus). Il n'y a
pas de validation de token de session côté backend — l'authentification repose sur la présence d'un user_id dans
l'AppState Mutex.

---

## Section 2.2 — Flux de données sensibles

### Mot de passe maître

```
Saisie utilisateur (LoginPage.tsx)
  → useState (React state, non zéroïsable)
  → invoke("local_login", { password })  [IPC Tauri, intra-processus]
  → Argon2id(pw, salt) → hash de comparaison
  → Argon2id(pw, crypto_salt) → K_vault (SecureKey, mlock+ZeroizeOnDrop)
  → K_vault stocké dans Keychain OS (keyring crate)
  → mot de passe en mémoire JS non zéroïsé (limitation JS)
Évaluation: ⚠️ INSUFFISANT — JS ne peut pas zéroïser. Backend correct.
```

### K_vault (clé de chiffrement du vault)

```
Dérivation : Argon2id(master_pw, crypto_salt, 64MiB, 3 iter, 4 threads) → 32 octets
Stockage   : keyring → OS Keychain (macOS/Linux/Windows) ou fichier chiffré (Android)
Usage      : SecureKey.use_key(|k| encrypt_data_secure(data, k))
Suppression: local_logout → delete_encryption_key → keyring.delete_password()
             + SecureKey::drop() → zeroize() + munlock()
Évaluation: ✅ CORRECT — cycle de vie bien géré avec mlock et ZeroizeOnDrop.
            ⚠️ PARTIEL sur macOS — Keychain sans paramètres restrictifs (CFG-001).
```

### Entrées vault en clair

```
Déchiffrement: get_passwords → decrypt_data_secure(encrypted_field, K_vault) → String
Transit IPC  : Retour JSON avec tous les champs en clair
Frontend     : Stockage dans React Query cache (staleTime 5min)
Destruction  : Cache invalidation à la navigation / timeout
Évaluation: ⚠️ INSUFFISANT — Données en clair dans le React Query cache (EXP-007).
            Les String Rust ne sont pas Zeroizing — résidus mémoire côté backend.
```

### Clés de session de transfert

```
Dérivation : HKDF-SHA256(salt="fluxlock-transfer-v1", ikm=K_spake||K_kem, info="session-key") → 32 octets
Usage      : SecureSession::new(key) → ChaCha20Poly1305 cipher + compteur nonce
Suppression: SecureSession::drop() → unsafe scrub mémoire du cipher + zero compteurs
             SessionKeyGuard::drop() → zeroize [u8; 32]
Évaluation: ✅ CORRECT — Zéroïsation défensive, scrub mémoire du cipher struct.
```

### Clés PQC (ML-KEM-768, ML-DSA-65)

```
Génération ML-KEM: generate_recipient_keypair() → (KemPublicKey, KemPrivateKey)
   KemPrivateKey::drop() → unsafe zeroize raw bytes (UB technique mais fonctionnel)
Génération ML-DSA: MlDsaKeyPair::generate() via SysRng
   MlDsaKeyPair::drop() → unsafe zeroize raw bytes (UB technique mais fonctionnel)
Stockage ML-DSA  : PKCS#8 DER dans trust_store.enc (chiffré ChaCha20-Poly1305)
Évaluation: ⚠️ PARTIEL — signing_seed_bytes() retourne Vec<u8> non Zeroizing (CFG-016).
            Les unsafe Drop sont techniquement UB mais pragmatiquement efficaces.
```

### Codes wormhole

```
Génération : generate_wormhole_code() → "N-mot1-mot2-mot3-mot4" (4 mots × 256 = 2^32)
Partage    : Retourné au frontend via IPC → affiché à l'utilisateur
Invalidation: WORMHOLE_TTL_SECS = 300s (5 minutes)
              HandshakeInitiator::drop() → zeroize wormhole_code via unsafe as_bytes_mut()
Évaluation: ⚠️ PARTIEL — Code loggé en clair dans eprintln (EXP-009).
            Code copié dans clipboard sans auto-clear (contrairement aux mots de passe).
```

### Données biométriques

```
Délégation: OS biometric API (Touch ID, Face ID, Windows Hello)
Retour    : Succès/Échec (bool) — pas de données biométriques dans le processus
Évaluation: ✅ CORRECT — Aucune donnée biométrique ne transite par l'application.
```

---

## Section 2.3 — Conformité aux meilleures pratiques par domaine

### Domaine 1 — Architecture

```
Pratique                                    Statut      Commentaire
───────────────────────────────────────────────────────────────────────
Séparation des responsabilités              ⚠️ PARTIEL  lib.rs = God Object (3060 lines)
Couche service intermédiaire                ❌ NON       Logique métier directement dans commands
Validation à la frontière IPC               ⚠️ PARTIEL  Auth check OK, input validation inégale
Couplage faible entre composants            ⚠️ PARTIEL  crypto-core bien isolé, lib.rs monolithique
Abstractions cryptographiques cohérentes    ✅ OUI       crypto-core → SecureKey → commandes
```

### Domaine 2 — Cryptographie au repos

```
Pratique                                    Statut      Commentaire
───────────────────────────────────────────────────────────────────────
ChaCha20-Poly1305 (AEAD)                   ✅ OUI       RFC 8439, clé 256 bits
Nonces via CSPRNG (OsRng)                  ✅ OUI       12 octets, try_fill_bytes
Argon2id conforme OWASP 2024               ✅ OUI       64MiB, t=3, p=4, sortie 32B
Paramètres minimum KDF enforcés (v2)       ✅ OUI       m_cost≥65536, t_cost≥3 dans kdf.rs
Salt 256 bits par utilisateur              ✅ OUI       32 octets CSPRNG
Header vault authentifié (HMAC-SHA3-256)   ✅ OUI       MAC vérifié AVANT déchiffrement
Anti-rollback (séquence monotone)          ✅ OUI       decrypt_vault_checked()
Protection OOM (MAX_CIPHERTEXT 256MiB)     ✅ OUI       vault.rs
Migration v1→v2 automatique                ✅ OUI       AES-GCM → ChaCha20 on-read
ZeroizeOnDrop sur K_vault (SecureKey)      ✅ OUI       mlock + zeroize + no Clone/Serialize
ZeroizeOnDrop sur VaultData                ❌ NON       VaultEntry.password = Option<String>
Comparaison constante-temps                ✅ OUI       subtle::ConstantTimeEq partout
```

### Domaine 2b — Cryptographie en transit

```
Pratique                                    Statut      Commentaire
───────────────────────────────────────────────────────────────────────
Construction hybride PQC correcte          ✅ OUI       SPAKE2 + ML-KEM-768 → HKDF
Domain separator dans HKDF                 ✅ OUI       salt="fluxlock-transfer-v1"
Secrets intermédiaires zéroïsés            ✅ OUI       Zeroizing<Vec> pour IKM concat
ChaCha20 session avec nonce compteur       ✅ OUI       Bytes 4..12 = counter BE
AAD incluant direction + compteur          ✅ OUI       "fluxlock-v1:send:{N}"
BLAKE3 intégrité par chunk                 ✅ OUI       constant-time verification
Session key zéroïsée au drop               ✅ OUI       SessionKeyGuard + unsafe scrub
```

### Domaine 2c — Gestion mémoire

```
Pratique                                    Statut      Commentaire
───────────────────────────────────────────────────────────────────────
SecureKey avec mlock()                     ✅ OUI       Pages verrouillées en RAM
Warning si mlock() échoue                  ✅ OUI       last_os_error() loggé
SecureKey : no Clone, no Serialize         ✅ OUI       Prévient copies accidentelles
Debug/Display redacted                     ✅ OUI       <REDACTED> sur K_vault
MasterKey (kdf.rs) : no Debug, no Clone    ✅ OUI       Strict minimum
Core dumps désactivés                      ❌ NON       Pas de PR_SET_DUMPABLE/PT_DENY_ATTACH
RLIMIT_MEMLOCK configuré                   ❌ NON       Pas de configuration au démarrage
```

---

## Section 2.4 — Évaluation de chaque enclave par plateforme

```
Plateforme  Enclave utilisée           Niveau     Paramètres               Statut
──────────────────────────────────────────────────────────────────────────────────
macOS       Keychain via keyring       Software   Défaut (aucun kSecAttr   ⚠️ PARTIEL
                                                   configuré, sync iCloud
                                                   possible, pas de SE)
Linux       Secret Service (D-Bus)     Software   Défaut (secret-service   ⚠️ PARTIEL
            via keyring                            backend, pas de kernel
                                                   keyring, pas de TPM)
Windows     Credential Manager         Software   Défaut (DPAPI implicite  ⚠️ PARTIEL
            via keyring                            via WCM, pas de Windows
                                                   Hello binding, pas de
                                                   TPM explicit)
Android     Fichier chiffré via        Software   ChaCha20 + HMAC-SHA256   ⚠️ PARTIEL
            ChaCha20-Poly1305                      device wrapping key,
                                                   permissions 0600,
                                                   PAS d'Android Keystore
```

**Analyse** : Toutes les plateformes utilisent la crate `keyring` sans personnalisation. La crate keyring fournit un
accès de base au magasin d'identifiants OS mais ne permet pas de configurer les paramètres de sécurité avancés
(kSecAttrAccessible, SecAccessControl, DPAPI flags, etc.). Le niveau de protection est "software" sur toutes
les plateformes — aucune liaison hardware (Secure Enclave, TPM, StrongBox) n'est implémentée.

**macOS** : `keyring` crée une entrée dans le Keychain "login" avec les paramètres par défaut. Cela signifie :

- `kSecAttrSynchronizable` = par défaut (peut être synchronisé via iCloud)
- Pas de `SecAccessControl` → accessible sans Touch ID/Face ID supplémentaire
- Pas d'usage du Secure Enclave

**Linux** : `keyring` utilise le backend `secret-service` (D-Bus). Sur GNOME cela cible gnome-keyring, sur KDE
kwallet. Le kernel keyring Linux et le TPM 2.0 ne sont pas utilisés.

**Windows** : `keyring` utilise le Windows Credential Manager qui est implicitement protégé par DPAPI (CURRENT_USER).
Pas d'intégration Windows Hello, pas d'usage explicite du TPM 2.0.

**Android** : Aucun usage d'Android Keystore. Un stockage fichier avec chiffrement symétrique est utilisé à la place,
ce qui est significativement moins sécurisé (pas de protection hardware, clé de wrapping derivable par tout processus
connaissant le sel).

---

## Section 2.5 — Évaluation des protocoles

### Protocole de transfert

```
Propriété                           Satisfaite      Commentaire
──────────────────────────────────────────────────────────────────────────
Authentification mutuelle           ✅ OUI           SPAKE2 bilatéral + Safety Number
Forward secrecy                     ✅ OUI           Clés éphémères (SPAKE2 + ML-KEM)
                                                     détruites après handshake
Résistance post-quantique           ✅ OUI           ML-KEM-768 hybride (SPAKE2 classique
                                                     + KEM PQC), sécurité composite
Résistance MITM                     ✅ OUI           Safety Number dérivé de K_session
                                                     qui inclut K_spake + K_kem
Relay aveugle aux données           N/A              Pas de relay implémenté (direct P2P)
Anti-replay                         ✅ OUI           Nonce compteur monotone, AAD unique
Plaintext zéroïsé après transit     ⚠️ PARTIEL      Sender : data.zeroize() OK
                                                     Receiver : serde_json copies non zéroïsées
Timeouts sur messages               ❌ NON           recv_message sans timeout → connexion zombie
Safety Number lie l'identité        ⚠️ PARTIEL      Lie au K_session mais pas à l'identité
                                                     des pairs (id_a/id_b = "initiator"/"responder")
```

### Protocole de synchronisation

```
Propriété                           Satisfaite      Commentaire
──────────────────────────────────────────────────────────────────────────
Authentification mutuelle           ⚠️ PARTIEL      SPAKE2+ML-KEM effectué mais Safety Number
                                                     NON présenté à l'utilisateur (C16/C17)
Identités ML-DSA liées              ✅ OUI           ML-DSA-65 keys exchanged pendant pairing
Révocation d'appareils              ✅ OUI           transfer_remove_sync_device
Révocation immédiate                ❌ NON           Différée — prend effet au prochain sync
Données signées ML-DSA              ✅ OUI           Entrées trust_store signées canoniquement
Résolution de conflits              ⚠️ PARTIEL      transfer_count seulement — overflow exploitable
                                                     par appareil compromis
Atomicité de la synchronisation     ❌ NON           Pas de transaction / rollback si interrompu
Gestion CRDTs / horloges vect.      ❌ NON           Non implémenté — last-write-wins basique
```

---

## Section 2.6 — Évaluation de la découverte réseau

```
Composant   Fonctionne    Failles                        Commentaire
──────────────────────────────────────────────────────────────────────────
mDNS        ✅ OUI        - Annonce unauthentifiée       Nom d'appareil visible
                           - Pas de rate-limit réception  Spoofable mais mitigé
                           - Active même vault verrouillé  par handshake crypto
                           - Nom appareil exposé

UDP Beacon  ✅ OUI        - Plaintext broadcast           FLUXLOCK|name|port|fp
                           - Spoofable, rejouable          fp = BLAKE3(ML-DSA vk)
                           - Pas de rate-limit             vérifié côté réception
                           - Flood → croissance mémoire

IPv6        ✅ OUI        - get_public_ipv6_address()      Filtre fe80::/10 OK
                           - Privacy extensions non         Adresses stables
                             préférées                      potentiellement
                                                            liées au MAC
```

---

## Section 2.7 — Évaluation des logs

```
Critère                           Statut      Commentaire
──────────────────────────────────────────────────────────────────────────
Aucune donnée sensible logguée    ❌ NON      Wormhole codes en clair (commands.rs:511,1764)
                                              Titres mots de passe (commands.rs:900,1069)
                                              Mots de passe dans console.log (vault-service.ts)
Logs signés cryptographiquement   ❌ NON      Aucune signature — INSERT SQL brut
Hash chain implémenté             ❌ NON      Entrées indépendantes dans audit_logs
Append-only (O_APPEND)            ❌ NON      SQLite standard, pas de fichier append
Désactivation depuis paramètres   ❌ NON      Pas d'option UI
Vérification intégrité dispo      ❌ NON      Pas de mécanisme de vérification
Mode isolation implémenté         ❌ NON      Aucune implémentation trouvée
Variables d'env pour les ports    ❌ NON      Ports hardcodés (52820, 52821)
                                              Config.rs ne couvre pas les ports réseau
```

---

## Section 2.8 — Score global

```
Domaine                      Score    Niveau
─────────────────────────────────────────────────────
Chiffrement au repos         88/100   EXCELLENT
  Algorithmes, KDF, format vault, nonces, intégrité
  — tous conformes. Points perdus : VaultEntry
  sans Zeroize, migration v1 silencieuse.

Gestion mémoire              75/100   BON
  SecureKey exemplaire. Points perdus : pas de
  core dump protection, VaultEntry/Ed25519/ChaCha
  sans ZeroizeOnDrop, serde copies non zéroïsées.

Enclaves sécurisées          35/100   INSUFFISANT
  Toutes plateformes utilisent keyring defaults.
  Pas de Secure Enclave/TPM/Keystore binding.
  Android = fichier chiffré seulement.

Protocole de transfert       78/100   BON
  Handshake hybride PQC exemplaire. Points perdus :
  pas de timeout, safety number non lié à l'identité,
  plaintext receiver non zéroïsé.

Protocole de sync            45/100   INSUFFISANT
  Pairing sans Safety Number UI, auto-accept,
  pas d'atomicité, résolution conflits basique,
  révocation non immédiate.

Découverte réseau            55/100   PASSABLE
  Fonctionnel avec fingerprint vérification.
  Points perdus : beacon unauthentifié, pas de
  rate-limit, annonce même vault verrouillé.

Logs et audit trail          15/100   CRITIQUE
  Pas de signature, pas de hash chain, données
  sensibles dans les logs, pas de contrôle
  utilisateur, pas d'immuabilité.

Mode isolation               0/100    ABSENT
  Fonctionnalité non implémentée.

Configuration et env vars    40/100   INSUFFISANT
  Config.rs existe et couvre ML/email/DB/logs.
  Mais ports réseau, timeouts transfert, Argon2id
  params absents. Pas de validation au démarrage.

IPC et frontend              50/100   PASSABLE
  Auth checks cohérents, CSP correct, capabilities
  bien scoped. Points perdus : vulnérabilités
  critiques (user_id hardcodé, IDOR, token previsible),
  secrets dans React cache et console.log.
─────────────────────────────────────────────────────
SCORE GLOBAL                 48/100   INSUFFISANT
─────────────────────────────────────────────────────
```

**Note** : Le score global est pondéré en fonction de l'impact sécurité de chaque domaine.
La cryptographie de base est excellente, mais les lacunes dans les logs, l'isolation,
les enclaves et les vulnérabilités applicatives tirent le score vers le bas.

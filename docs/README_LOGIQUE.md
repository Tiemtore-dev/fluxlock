# FluXlock 2.0 — Logique des Grandes Parties

> Explication détaillée des trois piliers : **chiffrement au repos**, **transfert P2P** et **communication réseau**.

---

## Table des matières

1. [Chiffrement au repos](#1-chiffrement-au-repos)
2. [Transfert P2P chiffré](#2-transfert-p2p-chiffré)
3. [Communication réseau](#3-communication-réseau)

---

## 1. Chiffrement au repos

### Objectif

Protéger toutes les données stockées localement (mots de passe, fichiers, clés) de sorte qu'elles soient inaccessibles sans le mot de passe maître, même si le disque est copié.

### Architecture

```
Mot de passe maître (utilisateur)
        │
        ▼
┌──────────────────────────┐
│  Argon2id (m=64 MiB,     │   ← Dérivation de clé résistante au brute-force
│  t=3, p=1, salt=16 oct.) │     GPU/ASIC-resistant grâce au coût mémoire
└──────────┬───────────────┘
           │ master_key (32 octets)
           ▼
┌──────────────────────────┐
│  HKDF-SHA256             │   ← Dérivation de sous-clés par contexte
│  salt = "fluxlock-v1"   │
│  info = "vault-key"     │
└──────────┬───────────────┘
           │ vault_key (32 octets)
           ▼
┌──────────────────────────┐
│  ChaCha20-Poly1305       │   ← Chiffrement AEAD de chaque entrée
│  nonce = 12 oct. random  │     Authentifié : toute altération = rejet
│  AAD = contexte           │
└──────────────────────────┘
```

### Flux détaillé

1. **Inscription** :
   - L'utilisateur choisit un mot de passe maître.
   - Argon2id génère `master_key` depuis le mot de passe + un sel aléatoire de 16 octets.
   - Le sel est stocké en clair dans la base SQLite (il n'est pas secret).
   - `master_key` est gardée en mémoire uniquement pendant la session (zeroize au logout).
   - La clé est également sauvegardée dans le **keychain OS** (macOS Keychain / Android Keystore) pour le déverrouillage biométrique.

2. **Ajout d'un mot de passe** :
   - Le plaintext est sérialisé en JSON.
   - HKDF dérive une `vault_key` depuis `master_key`.
   - ChaCha20-Poly1305 chiffre le JSON avec un nonce aléatoire de 12 octets.
   - Le ciphertext (nonce ∥ ciphertext ∥ tag) est stocké en base SQLite.
   - Le plaintext est immédiatement `zeroize()` en mémoire.

3. **Lecture d'un mot de passe** :
   - Le ciphertext est lu depuis SQLite.
   - ChaCha20-Poly1305 déchiffre avec la `vault_key` en mémoire.
   - Le plaintext est affiché à l'utilisateur puis `zeroize()` après usage.

4. **Vérification d'intégrité** :
   - BLAKE3 calcule un hash du ciphertext stocké.
   - À chaque lecture, le hash est re-calculé et comparé (constant-time).
   - Toute altération est détectée avant le déchiffrement.

### Primitives utilisées

| Primitif          | Crate Rust         | Rôle                                  |
| ----------------- | ------------------ | ------------------------------------- |
| Argon2id          | `argon2`           | Dérivation de clé depuis mot de passe |
| HKDF-SHA256       | `hkdf` + `sha2`    | Dérivation de sous-clés               |
| ChaCha20-Poly1305 | `chacha20poly1305` | Chiffrement AEAD                      |
| BLAKE3            | `blake3`           | Hachage rapide + intégrité            |

### Fichiers sources

- [rust-crypto-core/src/key_derivation/argon2.rs](../rust-crypto-core/src/key_derivation/argon2.rs) — Argon2id
- [rust-crypto-core/src/key_derivation/hkdf.rs](../rust-crypto-core/src/key_derivation/hkdf.rs) — HKDF-SHA256
- [rust-crypto-core/src/crypto/chacha.rs](../rust-crypto-core/src/crypto/chacha.rs) — ChaCha20-Poly1305
- [rust-crypto-core/src/crypto/vault.rs](../rust-crypto-core/src/crypto/vault.rs) — Format Vault
- [tauri-desktop/src-tauri/src/crypto.rs](../tauri-desktop/src-tauri/src/crypto.rs) — Bridge crypto Tauri
- [tauri-desktop/src-tauri/src/secure_key.rs](../tauri-desktop/src-tauri/src/secure_key.rs) — Gestion des clés dérivées
- [tauri-desktop/src-tauri/src/database.rs](../tauri-desktop/src-tauri/src/database.rs) — Stockage SQLite chiffré

---

## 2. Transfert P2P chiffré

### Objectif

Transférer des mots de passe entre deux appareils FluXlock sans serveur intermédiaire, avec chiffrement de bout en bout post-quantique. Le plaintext ne touche jamais le disque du réseau.

### Architecture du handshake

```
  Émetteur (Sender)                           Récepteur (Receiver)
  ─────────────────                           ────────────────────

  1. Génère un code wormhole :
     "427-alpha-storm-eagle-cobalt"
     (canal 0-999 + 4 mots × 256 = ~2⁴² combinaisons)
                                    ────→ Code partagé hors-bande
                                              (voix, SMS, QR)

  2. SPAKE2 (mot de passe = code wormhole)
     ┌────────────────────┐
     │ A envoie msg_a     │ ────────────────→
     │                     │ ←──────────────── B envoie msg_b
     │ Calcul de la clé   │
     │ partagée SPAKE2    │                   Calcul identique
     └────────────────────┘

  3. ML-KEM-768 (post-quantique)
     ┌────────────────────┐
     │ Génère (ek, dk)    │
     │ Envoie ek           │ ────────────────→
     │                     │ ←──────────────── Envoie ciphertext (ct)
     │ Décapsule ct → kem_key │               Encapsule ek → (ct, kem_key)
     └────────────────────┘

  4. Dérivation hybride de la clé de session
     session_key = HKDF-SHA256(
       IKM = spake2_key ∥ kem_key,
       salt = "fluxlock-transfer-v1",
       info = "session-key"
     )  → 32 octets

  5. Vérification du Safety Number
     safety_number = BLAKE3("fluxlock-safety-v1:" ∥ session_key ∥ id_a ∥ id_b)
     → Affiché : "A1B2 C3D4 E5F6"
     → Les deux utilisateurs comparent visuellement
```

### Flux de transfert des données

```
  Émetteur                                    Récepteur
  ────────                                    ─────────

  Pour chaque mot de passe :
  ┌──────────────────────────────────────────────────────────────┐
  │ 1. Déchiffre le mot de passe depuis le vault local          │
  │ 2. Sérialise en JSON ({site, username, password, ...})      │
  │ 3. Découpe en chunks de 512 KiB si > 512 KiB (streaming)   │
  │ 4. Pour chaque chunk :                                      │
  │    a. BLAKE3(chunk_data) → integrity_hash                   │
  │    b. ChaCha20-Poly1305 chiffre le DataChunk                │
  │       - nonce = compteur incrémental                        │
  │       - AAD = "fluxlock-v1:send:{counter}"                  │
  │    c. Envoie le frame chiffré sur TCP                       │
  │ 5. Attend ACK du récepteur (un ACK par item complet)        │
  └─────────────────────────────────┬────────────────────────────┘
                                    │
                                    ▼
  ┌──────────────────────────────────────────────────────────────┐
  │ 1. Reçoit le frame chiffré                                  │
  │ 2. ChaCha20-Poly1305 déchiffre (même nonce counter + AAD)   │
  │ 3. Vérifie BLAKE3 integrity_hash (constant-time)            │
  │ 4. Accumule les chunks par item_index                       │
  │ 5. Quand is_last_chunk = true :                             │
  │    a. Désérialise le JSON complet                           │
  │    b. Re-chiffre avec la vault_key locale (Argon2id)        │
  │    c. Insère dans la base SQLite locale                     │
  │    d. Zeroize le plaintext en mémoire                       │
  │    e. Envoie ACK                                            │
  └──────────────────────────────────────────────────────────────┘
```

### Sécurité du canal

| Propriété       | Mécanisme                                                        |
| --------------- | ---------------------------------------------------------------- |
| Confidentialité | ChaCha20-Poly1305 avec clé de session 256 bits                   |
| Intégrité       | Poly1305 MAC (AEAD) + BLAKE3 par chunk                           |
| Authenticité    | SPAKE2 (code wormhole) + Safety Number visuel                    |
| Post-quantique  | ML-KEM-768 hybride (résiste à Shor's algorithm)                  |
| Forward secrecy | Clé éphémère par session (SPAKE2 + KEM)                          |
| Anti-replay     | Nonce compteur monotone + AAD unique par message                 |
| Anti-MITM       | Safety Number + Trust Store (TOFU)                               |
| Streaming       | Chunking 512 KiB pour fichiers > 1 MiB, limité à 2 MiB par frame |

### Trust Store (TOFU — Trust On First Use)

```
Premier transfert entre A et B :
  1. A et B comparent le Safety Number
  2. Si OK → B clique "Faire confiance"
  3. L'empreinte BLAKE3 de la clé publique de A est sauvegardée
  4. Fichier trust_store.json (permissions 0600)

Transferts suivants :
  1. A et B font le handshake
  2. B vérifie l'empreinte contre le Trust Store
  3. Si match → transfert automatique (pas de re-confirmation)
  4. Si mismatch → ⚠️ ALERTE : possible MITM
```

### Fichiers sources

- [tauri-desktop/src-tauri/src/transfer/protocol.rs](../tauri-desktop/src-tauri/src/transfer/protocol.rs) — Messages wire (DataChunk, Ack, Hello, Offer...)
- [tauri-desktop/src-tauri/src/transfer/handshake.rs](../tauri-desktop/src-tauri/src/transfer/handshake.rs) — SPAKE2 + ML-KEM-768 + Safety Number
- [tauri-desktop/src-tauri/src/transfer/session.rs](../tauri-desktop/src-tauri/src/transfer/session.rs) — Session ChaCha20-Poly1305 (AAD, nonce counter)
- [tauri-desktop/src-tauri/src/transfer/commands.rs](../tauri-desktop/src-tauri/src/transfer/commands.rs) — Commandes Tauri (chunking sender/receiver)
- [tauri-desktop/src-tauri/src/transfer/trust_store.rs](../tauri-desktop/src-tauri/src/transfer/trust_store.rs) — Trust Store TOFU
- [tauri-desktop/src-tauri/src/transfer/reencrypt.rs](../tauri-desktop/src-tauri/src/transfer/reencrypt.rs) — Re-chiffrement vault-à-vault

---

## 3. Communication réseau

### Objectif

Permettre aux appareils FluXlock de se découvrir mutuellement sur le réseau local et d'établir une connexion directe, sans configuration manuelle.

### Stratégie de découverte (par ordre de priorité)

```
┌────────────────────────────────────────────────────────────────┐
│                                                                │
│  1. UDP Broadcast Beacon (primaire, le plus fiable)            │
│     Port : 52820 (UDP)                                         │
│     Format : "FLUXLOCK|{username}|{port}"                     │
│     Fréquence : toutes les 3 secondes                         │
│     Condition : seulement si visibilité activée (E-01)        │
│                                                                │
│  2. mDNS/DNS-SD (secondaire, bonus)                           │
│     Service : _fluxlock-transfer._tcp.local.                  │
│     Enregistrement : seulement si visibilité activée (E-01)   │
│     Avantage : fonctionne sur les réseaux avec isolation L2   │
│                                                                │
│  3. IPv6 Link-Local (scan direct)                             │
│     Scan des interfaces réseau pour trouver des pairs         │
│     Avantage : fonctionne sans infrastructure réseau          │
│                                                                │
│  4. Code Wormhole (cross-réseau)                              │
│     Saisie manuelle du code pour réseaux différents           │
│     Avantage : fonctionne même sans LAN partagé               │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Flux de connexion

```
┌──────────────┐                              ┌──────────────────┐
│  Appareil A  │                              │   Appareil B     │
│  (Émetteur)  │                              │   (Récepteur)    │
└──────┬───────┘                              └────────┬─────────┘
       │                                               │
       │  1. Crée une offre de transfert               │
       │     → Génère un code wormhole                 │
       │     → Démarre un listener TCP:52820           │
       │     → Active la visibilité (beacon + mDNS)    │
       │                                               │
       │  2. ──── Code wormhole partagé hors-bande ───→│
       │                                               │
       │                   3. Saisit le code wormhole  │
       │                      → Résolution de l'adresse│
       │                         a. Scan beacon UDP    │
       │                         b. Query mDNS         │
       │                         c. IPv6 link-local    │
       │                         d. Connexion directe  │
       │                            si adresse dans    │
       │                            le code            │
       │                                               │
       │  ←────────── Connexion TCP établie ──────────→│
       │                                               │
       │  4. Handshake SPAKE2 + ML-KEM-768             │
       │     (voir section 2 pour le détail)           │
       │                                               │
       │  5. Session chiffrée établie                  │
       │     → Échange de Hello (nom, version)         │
       │     → Offre : liste des items à transférer    │
       │     → Accept/Reject par le récepteur          │
       │                                               │
       │  6. Transfert des données (DataChunks)        │
       │     → Streaming par chunks de 512 KiB         │
       │     → ACK par item complet                    │
       │                                               │
       │  7. TransferComplete                          │
       │     → Désactive la visibilité                 │
       │     → Ferme le listener TCP                   │
       │                                               │
```

### Gestion de la visibilité (E-01)

La visibilité réseau est contrôlée par l'utilisateur :

| État                       | Beacon UDP                 | mDNS Register           | mDNS Browse      | Listen Beacon    |
| -------------------------- | -------------------------- | ----------------------- | ---------------- | ---------------- |
| **Visible = OFF** (défaut) | ❌ Pas de broadcast        | ❌ Pas d'enregistrement | ✅ Écoute active | ✅ Écoute active |
| **Visible = ON**           | ✅ Broadcast toutes les 3s | ✅ Enregistré           | ✅ Écoute active | ✅ Écoute active |

> Le device écoute **toujours** les beacons et les annonces mDNS des autres, mais ne s'annonce que quand l'utilisateur l'active explicitement.

### Transport

```
┌─────────────────────────────────────────────┐
│            Couche Transport                  │
│                                              │
│  TCP direct (port 52820)                     │
│  ├── Rate limiting (1 KiB/s min, 10 MiB/s   │
│  │   max, anti-flood)                        │
│  ├── Timeout connexion : 30 secondes         │
│  └── MAX_MESSAGE_SIZE : 2 MiB par frame      │
│                                              │
│  TLS fallback (si TCP direct échoue)         │
│  └── rustls avec certificat auto-signé       │
│                                              │
└─────────────────────────────────────────────┘
```

### Protocole de messages (MessagePack)

Tous les messages sont sérialisés en **MessagePack** (binaire compact) puis chiffrés avec ChaCha20-Poly1305 :

```
Trame sur le fil :
┌───────────┬──────────────────────────────────────┐
│ 4 octets  │ N octets (max 2 MiB)                 │
│ taille    │ payload chiffré ChaCha20-Poly1305     │
│ (u32 BE)  │ (nonce ∥ ciphertext ∥ tag)            │
└───────────┴──────────────────────────────────────┘
```

Types de messages :

| Message            | Direction            | Rôle                                                                       |
| ------------------ | -------------------- | -------------------------------------------------------------------------- |
| `Hello`            | Bidirectionnel       | Échange de noms et versions                                                |
| `Offer`            | Émetteur → Récepteur | Propose la liste des items avec métadonnées                                |
| `Accept`           | Récepteur → Émetteur | Accepte le transfert                                                       |
| `Reject`           | Récepteur → Émetteur | Refuse le transfert                                                        |
| `DataChunk`        | Émetteur → Récepteur | Données chiffrées (item_index, chunk_index, is_last_chunk, integrity_hash) |
| `Ack`              | Récepteur → Émetteur | Confirmation de réception (integrity_ok)                                   |
| `TransferComplete` | Émetteur → Récepteur | Fin du transfert                                                           |
| `Error`            | Bidirectionnel       | Erreur fatale, fermeture du canal                                          |

### Fichiers sources

- [tauri-desktop/src-tauri/src/transfer/discovery.rs](../tauri-desktop/src-tauri/src/transfer/discovery.rs) — mDNS + UDP beacon + IPv6 link-local
- [tauri-desktop/src-tauri/src/transfer/transport.rs](../tauri-desktop/src-tauri/src/transfer/transport.rs) — TCP/TLS + rate limiting
- [tauri-desktop/src-tauri/src/transfer/protocol.rs](../tauri-desktop/src-tauri/src/transfer/protocol.rs) — Définition des messages (MessagePack)
- [tauri-desktop/src-tauri/src/transfer/mod.rs](../tauri-desktop/src-tauri/src/transfer/mod.rs) — Types partagés, constantes (WORMHOLE_TTL_SECS)
- [tauri-desktop/src/pages/TransferPage.tsx](../tauri-desktop/src/pages/TransferPage.tsx) — Interface utilisateur de transfert

---

## Résumé des algorithmes

| Domaine                  | Algorithme            | Taille de clé  | Usage                                        |
| ------------------------ | --------------------- | -------------- | -------------------------------------------- |
| Dérivation mot de passe  | Argon2id              | 256 bits       | Master password → master_key                 |
| Dérivation sous-clés     | HKDF-SHA256           | 256 bits       | master_key → vault_key, session_key          |
| Chiffrement au repos     | ChaCha20-Poly1305     | 256 bits       | Chiffrement AEAD des entrées                 |
| Chiffrement transfert    | ChaCha20-Poly1305     | 256 bits       | Session E2E chiffrée                         |
| Échange de clé classique | SPAKE2 (Ristretto255) | 256 bits       | Wormhole PAKE                                |
| Échange de clé PQC       | ML-KEM-768            | 2400 bits (ek) | Post-quantique hybride                       |
| Hachage                  | BLAKE3                | 256 bits       | Intégrité, empreintes, safety number         |
| Signature                | Ed25519               | 256 bits       | Authentification des mises à jour            |
| Échange de clé (legacy)  | X25519                | 256 bits       | DH classique (non utilisé dans le transfert) |

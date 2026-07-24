# Rapport d'Architecture Cryptographique Avancée : FluXlock

Ce document détaille rigoureusement l'architecture cryptographique du coffre-fort FluXlock. Il couvre les fondements mathématiques de chaque primitive utilisée et décrit **exactement** comment elles sont implémentées dans le code source Rust, avec une traçabilité précise des variables.

---

## 1. Cryptographie Symétrique Authentifiée (AEAD)

### ChaCha20-Poly1305 (RFC 8439)

**Fondements Mathématiques :**
- **ChaCha20 (Chiffrement de Flux) :** Repose sur une fonction pseudo-aléatoire (PRF) basée sur des opérations ARX (Addition modulo 2^32, Rotation, XOR). Il prend une clé K de 256 bits et un nonce N de 96 bits. La matrice d'état de 4x4 mots de 32 bits est mélangée par 20 itérations ("rounds") pour produire un flux binaire (Keystream) S. Le chiffré C est obtenu par : C = P XOR S.
- **Poly1305 (Code d'Authentification de Message) :** Fonctionne dans le corps fini premier F_p où p = (2^130) - 5. Le message C est découpé en blocs c_i de 16 octets. Le tag d'authentification T est généré par l'évaluation du polynôme avec une clé jetable (r, s) générée par ChaCha20 :
```math
T = \left( \sum_{i=1}^{n} c_i \cdot r^{n-i+1} \right) \pmod{2^{130}-5} + s \pmod{2^{128}}
```
- **Propriété Mathématique (Intégrité Inconditionnelle) :** Si l'attaquant modifie le texte chiffré sans connaître $r$, la probabilité qu'il devine le tag valide $T'$ est bornée par la taille du message $L$ divisée par $2^{106}$.

**Limites :**
Si un couple (K, N) est utilisé pour chiffrer deux messages différents (réutilisation de Nonce), le Keystream S s'annule lors d'un XOR (C1 XOR C2 = P1 XOR P2). L'attaquant récupère le texte clair.

**Utilisation Détaillée dans l'Application :**
Dans FluXlock, ChaCha20-Poly1305 (implémenté via le crate `chacha20poly1305`) est **le cœur du chiffrement**. 
1. **Chiffrement du coffre global :** Utilisé pour chiffrer tous les mots de passe de la base de données SQLite.
2. **Double-Wrapping (Fichier `passkey.rs`, Fonction `wrap_with_key`) :** 
   - La fonction `wrap_with_key(plaintext, key)` instancie `ChaCha20Poly1305::new(&key)`. 
   - Elle génère un nonce aléatoire de 12 octets via `rand::rngs::OsRng`.
   - Elle renvoie un blob binaire contenant le `nonce` concaténé au `ciphertext`.

---

## 2. Dérivation de Clé à partir d'un Mot de Passe (KDF)

### Argon2id (RFC 9106)

**Fondements Mathématiques :**
- Argon2 est une fonction de hachage lourde en mémoire. Argon2id combine l'adressage dépendant des données (pour résister aux GPU) et indépendant des données (contre les attaques par canaux cachés).
- L'algorithme alloue une matrice mémoire B de m blocs. Chaque bloc B[i] est calculé en appliquant la fonction de compression G (basée sur Blake2b) sur deux blocs précédents :
```math
B[i] = G(B[i-1], B[\text{ref}])
```
- L'index de référence $\text{ref}$ est déterminé de manière déterministe (Argon2i) dans la première passe, puis aléatoirement (Argon2d) dans les passes suivantes.

**Utilisation Détaillée dans l'Application :**
- **Fichiers concernés :** `crypto.rs` / `auth.rs`.
- Lorsqu'un utilisateur tape son mot de passe maître (par exemple "MonSuperSecret"), ce mot de passe est passé à Argon2id avec un sel (Salt) unique à l'utilisateur (généré lors de la création du compte).
- **Variable Résultante :** Cela génère `encryption_key` (également appelée `master_key` dans les commentaires), un tableau de 32 octets (`[u8; 32]`). Cette clé est ensuite utilisée par ChaCha20-Poly1305 pour déchiffrer la base de données.

---

## 3. Cryptographie Asymétrique Classique (Signatures)

### Ed25519 (EdDSA sur Curve25519)

**Fondements Mathématiques :**
- Basé sur la courbe de Twisted Edwards définie sur le corps fini premier F_p avec p = (2^255) - 19 :
```math
-x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2
```
- **Problème Mathématique (ECDLP) :** Trouver le scalaire *a* tel que A = a * B (où B est le point de base de la courbe) est un problème intordable classiquement en un temps raisonnable (complexité exponentielle).
- **Création de Signature :** Pour signer un message M avec la clé privée *a*, on génère un point R = r * B. La signature est le couple (R, S) où S = r + H(R, A, M) * a (modulo q).

**Limites :**
L'algorithme de Shor (sur un ordinateur quantique fonctionnel) résout l'ECDLP en un temps polynomial. Cela réduirait la sécurité d'Ed25519 à 0.

**Utilisation Détaillée dans l'Application :**
- **Lieu :** `passkey.rs` (fonction `register_passkey`).
- **Génération :** `Ed25519KeyPair::generate()` produit `ed25519_privkey_bytes` (32 octets) et `ed25519_pubkey_bytes` (32 octets).
- **Ancrage Matériel (Hardware-backed) :** 
  - Sous macOS : la clé privée `ed25519_privkey_bytes` est stockée dans la **Secure Enclave**.
  - Sous Android : la clé est encodée en Base64, renvoyée au front-end (`SettingsPage.tsx`) qui la stocke dans le **TEE/StrongBox** via `androidKeystoreStore`.
- **Authentification (`authenticate_passkey`) :** Le backend génère un `challenge` aléatoire (32 octets). Le frontend/Secure Enclave signe ce challenge avec la clé privée. Le backend vérifie la signature avec `ed25519_pubkey_b64` (stockée en base SQLite locale).

---

## 4. Cryptographie Post-Quantique (KEM)

### ML-KEM-768 (Module Learning With Errors / FIPS 203)

**Fondements Mathématiques :**
- Repose sur le problème des réseaux euclidiens (Lattice-based cryptography), spécifiquement le M-LWE.
- Soit un anneau de polynômes R_q = Z_q[X] / (X^256 + 1) avec q = 3329.
- **Génération de Clé :** On génère une matrice aléatoire publique A (3x3 pour ML-KEM-768). Le secret est un vecteur s, et on ajoute un vecteur de bruit (erreur) e. La clé publique est t = A * s + e.
- **Propriété Mathématique :** Résoudre s à partir de (A, t) est prouvé être au moins aussi difficile que de trouver le vecteur le plus court (SVP - Shortest Vector Problem) dans un réseau de haute dimension. Il n'existe pas d'algorithme quantique efficace pour cela.
- **Encapsulation :** Le destinataire utilise la clé publique t pour encapsuler un secret aléatoire *ss* (Shared Secret) en ajoutant de nouveau du bruit, produisant un chiffré *c* (Ciphertext).

**Utilisation Détaillée dans l'Application :**
- **Lieu :** `passkey.rs` (fonction `register_passkey`).
- **Génération :** `generate_recipient_keypair()` produit `kem_privkey` et `kem_pubkey`. `kem_privkey` est sauvegardée dans le Trousseau OS classique (Logiciel).
- **Encapsulation :** L'appel à `encapsulate(&kem_pubkey)` crée :
  - `shared_secret` (32 octets).
  - `kem_ciphertext` (1088 octets), qui est sauvegardé sur le disque (`kem_ciphertext_b64` dans `PasskeyEnrollment`).
- **Lors de l'authentification (`authenticate_passkey`) :** Le backend charge `kem_ciphertext` du disque, récupère la `kem_privkey` du trousseau OS, et appelle `decapsulate(kem_ciphertext, kem_privkey)` pour régénérer le **même** `shared_secret` (32 octets).

---

## 5. Fonction de Dérivation de Clé HKDF (RFC 5869)

### HKDF-SHA3-256

**Fondements Mathématiques :**
- HKDF utilise le paradigme *Extract-then-Expand*.
- **Extract :** PRK = HMAC-Hash(salt, IKM). Cela compresse l'Input Keying Material (IKM) qui peut avoir une entropie non-uniforme en une clé pseudo-aléatoire (PRK) uniforme.
- **Expand :** OKM = HMAC-Hash(PRK, info || 0x01). Cela étend la PRK à la longueur désirée (32 octets).
- **Propriété Mathématique :** L'ajout de la constante `info` garantit la séparation des domaines : HKDF(K, "A") et HKDF(K, "B") sont mathématiquement indépendants et ne partagent aucune corrélation exploitable.

**Utilisation Détaillée dans l'Application (Le "Double-Wrapping") :**
C'est ici que l'hybridation (Classique + PQC) s'opère dans `passkey.rs`. Le but est d'envelopper la `encryption_key` de l'utilisateur (32 octets).

1. **Première couche (L'enveloppe Classique/Biométrique) :**
   - **Extract/Expand :** `derive_wrapping_key(&ed25519_privkey_bytes, "passkey-wrap-1")`
   - **Résultat :** `wrapping_key_1` (32 octets purs).
   - **Chiffrement :** `blob_1 = wrap_with_key(encryption_key, &wrapping_key_1)`. `blob_1` contient donc le `master_key` chiffré par ChaCha20-Poly1305.
2. **Deuxième couche (L'enveloppe Post-Quantique) :**
   - **Extract/Expand :** `derive_wrapping_key(shared_secret.as_bytes(), "passkey-wrap-2")` (où `shared_secret` vient de ML-KEM).
   - **Résultat :** `wrapping_key_2` (32 octets purs).
   - **Chiffrement :** `blob_2 = wrap_with_key(&blob_1, &wrapping_key_2)`. 
3. **Persistance :** `blob_2` est sauvegardé sous forme de base64 (`wrapped_master_key_b64`) dans le fichier d'enrôlement SQLite.

**Pour déverrouiller le coffre, le backend fait exactement l'inverse (`authenticate_passkey`) :**
1. Décapsulation de ML-KEM pour retrouver le `shared_secret`.
2. `HKDF(shared_secret, "passkey-wrap-2")` donne `wrapping_key_2`.
3. Déchiffrement de `blob_2` avec `wrapping_key_2` pour récupérer `blob_1`.
4. Récupération de `ed25519_privkey_bytes` (via le Secure Enclave ou le TEE Android).
5. `HKDF(ed25519_privkey, "passkey-wrap-1")` donne `wrapping_key_1`.
6. Déchiffrement de `blob_1` pour récupérer la `encryption_key` (Master Key) d'origine !

---

## 6. Cryptographie des Sauvegardes (Backup)

L'export et la restauration des données (module `backup_manager.rs`) nécessitent une stratégie cryptographique spécifique pour garantir que les données au repos sur un disque dur externe ou un cloud (Google Drive, etc.) soient inaccessibles.

**Fondements Cryptographiques & Mécanisme :**
1. **Dérivation de Clé Indépendante :** Lors de la création d'un backup, un nouveau sel (Salt) cryptographique aléatoire de 32 octets (CSPRNG) est généré. La clé de chiffrement du backup est dérivée via `Argon2id(MotDePasse, NouveauSel)`.
2. **Chiffrement Authentifié :** La base de données SQLite et les fichiers joints sont chiffrés avec `ChaCha20-Poly1305`.
3. **Double MAC (HMAC-SHA3-256) contre les Oracles :**
   - **MAC des Métadonnées :** Un HMAC est calculé sur les métadonnées (version, compteurs de fichiers) pour empêcher toute falsification (tampering) avant même le déchiffrement.
   - **MAC du Contenu :** Un HMAC global `HMAC-SHA3-256(Clé, CiphertextDB || CiphertextFiles)` est calculé. 
   - *Propriété Mathématique :* C'est le principe "Encrypt-then-MAC". Lors de la restauration, l'application vérifie ce MAC global *avant* de tenter le moindre déchiffrement. Cela neutralise totalement les attaques par Oracle de Déchiffrement (Padding/Decryption Oracles) où un attaquant soumettrait des fichiers corrompus pour observer le comportement de l'algorithme.

**Limites :**
Les sauvegardes ne sont pas compatibles avec la Passkey. Étant donné que la Passkey (Ed25519) est verrouillée dans le matériel de l'appareil courant (Secure Enclave / TEE Android), un backup chiffré par Passkey serait irrécupérable sur un nouvel appareil. Le mot de passe maître est donc obligatoirement requis pour le backup.

---

## 7. Cryptographie des Transferts P2P (Wormhole)

Pour transférer des données entre deux appareils (ex: de PC vers Android) sur un réseau local (module `transfer`), FluXlock implémente un protocole "Wormhole" hybride extrêmement sécurisé.

**Architecture de Transport et Défense en Profondeur :**
1. **Couche Transport (TLS Éphémère) :** Une connexion TLS 1.3 avec un certificat auto-signé généré à la volée est établie (`transport.rs`). 
2. **Couche Authentification (SPAKE2 + PQC) :** 
   - **PAKE (Password-Authenticated Key Exchange) :** Les deux appareils partagent un code éphémère de 4 mots (ex: "42-alpha-beacon-drift"). Ils utilisent le protocole SPAKE2 sur le groupe Ed25519. SPAKE2 garantit que sans connaître le code exact, un attaquant (Mitm) ne peut faire qu'une seule tentative mathématique par connexion.
   - **Hybridation ML-KEM-768 :** L'appareil A génère une paire de clés ML-KEM-768 et l'envoie. B encapsule un secret aléatoire.
   - **Secret Final (HKDF) :** Le secret commun de la session TLS applicative est calculé par `HKDF(spake2_secret || kem_shared_secret)`.
3. **Safety Number (BLAKE3) :** Une empreinte (Safety Number) est calculé via `BLAKE3(SessionKey)` affichée sur les deux écrans, vérifiable humainement pour contrer l'attaque de l'homme du milieu (MITM).
4. **Couche Session :** Les données transférées dans ce tunnel sont rechiffrées par paquets avec une session `ChaCha20-Poly1305`.

Cette architecture hybride garantit que même si un attaquant quantique enregistre le flux WiFi local aujourd'hui, il ne pourra pas le déchiffrer dans 10 ans, et que même s'il attaque le réseau en temps réel, l'authentification PAKE le bloquera.

---

## Synthèse Pédagogique : Le Flux de la Passkey FluXlock

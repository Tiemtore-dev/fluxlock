<div align="center">

<img src="docs/images/logo-256.png" width="120" alt="FluXlock Logo">

# FluXlock

**Coffre-fort numérique de nouvelle génération**

Gérez vos mots de passe, chiffrez vos fichiers et transférez vos données en toute sécurité — même face aux futures menaces quantiques.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-Edition%202021-E57324?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Tauri](https://img.shields.io/badge/Tauri-v2-FFC131?logo=tauri&logoColor=white)](https://v2.tauri.app/)
[![Platform](https://img.shields.io/badge/Platform-macOS%20·%20Windows%20·%20Linux%20·%20Android-888888)](#plateformes-supportées)

<br>

[Fonctionnalités](#-fonctionnalités) · [Aperçu](#-aperçu) · [Installation](#-installation) · [Sécurité](#-sécurité) · [Contribuer](#-contribuer)

</div>

<br>

## 📸 Aperçu

<div align="center">

<img src="docs/images/dashboard-screenshot.png" width="900" alt="FluXlock — Tableau de bord" style="border-radius: 12px;">

<sub>Tableau de bord FluXlock — Vue d'ensemble de votre coffre-fort avec accès rapide à toutes les fonctionnalités</sub>

</div>

<br>

## ✨ Fonctionnalités

### 🔐 Gestion des mots de passe
Stockez, organisez et générez des mots de passe forts en un clic. Chaque mot de passe est chiffré individuellement avant d'être enregistré. Un indicateur de force vous aide à éviter les mots de passe trop faibles.

### 📁 Coffre-fort de fichiers
Chiffrez n'importe quel fichier, quelle que soit sa taille, grâce au chiffrement par flux (streaming). Vos fichiers originaux sont nettoyés en mémoire après chiffrement — aucune trace en clair ne subsiste.

### 🔑 Clés cryptographiques
Générez et gérez des paires de clés de chiffrement classiques et post-quantiques. Parfait pour sécuriser vos échanges ou signer des documents.

### 🔄 Transfert pair-à-pair (P2P)
Transférez votre coffre-fort vers un autre appareil sur le même réseau local, sans passer par un serveur distant. La connexion s'établit par un code simple (« wormhole code »), et les données sont re-chiffrées à la volée — jamais en clair sur le disque.

### 🛡️ Détection de ransomware
FluXlock surveille votre système de fichiers en temps réel. Si un comportement suspect est détecté (chiffrement massif, extensions douteuses), votre coffre-fort bascule automatiquement en lecture seule pour protéger vos données.

### 📱 Biométrie
Déverrouillez votre coffre-fort avec Touch ID (macOS), Windows Hello, ou le capteur biométrique de votre téléphone Android. La biométrie n'est jamais l'unique méthode — un mot de passe maître reste toujours requis au premier démarrage.

### 🔒 Authentification 2FA
Ajoutez une couche de sécurité supplémentaire avec l'authentification à deux facteurs : TOTP (compatible avec les apps d'authentification) ou par email.

### 📋 Journal d'audit signé
Chaque action sensible est enregistrée dans un journal inviolable. Les entrées sont signées numériquement et liées entre elles par une chaîne de hachage — toute altération est immédiatement détectable.

### 💾 Backup & Restauration
Sauvegardez l'intégralité de votre coffre-fort dans un fichier chiffré. Restaurez-le en un clic sur n'importe quel appareil.

### 🔄 Mise à jour automatique
FluXlock vérifie et installe automatiquement les nouvelles versions via les releases GitHub, avec vérification de signature.

<br>

## 🏗️ Construit avec

<div align="center">

| Couche | Technologies |
|:---:|:---|
| **Frontend** | React 18 · TypeScript · TailwindCSS · Zustand · React Query · Vite 5 |
| **Backend** | Rust · Tauri v2 · SQLite (WAL) · Tokio |
| **Cryptographie** | ChaCha20-Poly1305 · Argon2id · ML-KEM-768 · ML-DSA-65 · BLAKE3 · SHA3 |
| **Plateformes** | macOS · Windows · Linux · Android |

</div>

<br>

## 🖥️ Plateformes supportées

| Plateforme | Version minimum | Biométrie |
|:---|:---|:---|
| 🍎 **macOS** | Big Sur (11+) | Touch ID (Secure Enclave) |
| 🪟 **Windows** | Windows 10+ | Windows Hello |
| 🐧 **Linux** | glibc 2.31+ | — |
| 🤖 **Android** | API 24+ | TEE / StrongBox |

<br>

## 📦 Installation

### Prérequis

- **Rust** ≥ 1.77
- **Node.js** ≥ 18 LTS

### Démarrage rapide

```bash
# Cloner le dépôt
git clone https://github.com/Tiemtore-dev/fluxlock.git
cd fluxlock

# Installer les dépendances frontend
cd tauri-desktop
npm install

# Lancer en mode développement (hot-reload)
npm run tauri:dev
```

### Build de production

```bash
npm run tauri:build
```

### Build Android

```bash
npx tauri android dev         # Développement sur émulateur
npx tauri android build --apk # APK de production
```

> **Prérequis Android :** JDK 17, Android SDK (API 24+), Android NDK r29+, et les cibles Rust ARM (`rustup target add aarch64-linux-android armv7-linux-androideabi`).

<br>

## 🔒 Sécurité

FluXlock est conçu pour protéger vos données aujourd'hui **et** demain. Voici les principes qui guident notre approche :

### Protection post-quantique

Les ordinateurs quantiques menaceront un jour les algorithmes de chiffrement classiques. FluXlock intègre dès maintenant les standards post-quantiques du NIST :
- **ML-KEM-768** (FIPS 203) pour l'échange de clés
- **ML-DSA-65** (FIPS 204) pour les signatures numériques

### Chiffrement de bout en bout

Vos données ne sont jamais stockées en clair. Le mot de passe maître est dérivé via **Argon2id** (fonction lente par conception, résistante aux attaques GPU), puis utilisé pour chiffrer chaque élément avec **ChaCha20-Poly1305**.

### Zéro confiance, zéro trace

- Les clés sont effacées de la mémoire dès qu'elles ne sont plus utilisées (`zeroize`)
- La mémoire sensible est verrouillée pour ne jamais être écrite sur le disque (`mlock`)
- Les comparaisons de secrets s'effectuent en temps constant (protection contre les attaques temporelles)
- Pas de serveur central — vos données restent sur votre appareil

### Défense active

- **Anti-brute-force** : délai exponentiel entre les tentatives (jusqu'à 2 minutes), verrouillage du compte après trop d'échecs
- **Anti-ransomware** : surveillance de 50+ extensions suspectes, détection de chiffrement massif → bascule automatique en lecture seule
- **Anti-traversée de chemin** : validation stricte de tous les chemins de fichiers

<br>

## 📚 Documentation

| Rubrique | Description |
|:---|:---|
| [📖 Guides utilisateur](docs/guides/) | Manuel d'utilisation, configuration, premiers pas |
| [🔐 Architecture sécurité](docs/security/) | Modèle de menaces, choix cryptographiques, audit |
| [📊 Rapports](docs/reports/) | Résultats de tests, nettoyages, corrections |

<br>

## 🧪 Tests

```bash
# Tests du cœur cryptographique (~70+ tests)
cd rust-crypto-core && cargo test --all-features

# Tests d'intégration et de sécurité
cd tauri-desktop/src-tauri && cargo test

# Suite complète
./scripts/test/test-all.sh
```

<br>

## 🤝 Contribuer

Les contributions sont les bienvenues ! Que ce soit un bug report, une suggestion, un audit de sécurité ou une pull request :

1. **Fork** le projet
2. Créez votre branche (`git checkout -b feature/ma-fonctionnalite`)
3. **Committez** vos changements (`git commit -m 'Ajout de ma fonctionnalité'`)
4. **Push** sur votre branche (`git push origin feature/ma-fonctionnalite`)
5. Ouvrez une **Pull Request**

<br>

## 📄 Licence

Distribué sous licence **MIT** — voir le fichier [LICENSE](LICENSE) pour plus de détails.

<br>

---

<div align="center">

<img src="docs/images/logo-256.png" width="40" alt="FluXlock">

**FluXlock** — Sécurité redéfinie.

Conçu par [Tiemtore Fahim](https://github.com/Tiemtore-dev)

</div>

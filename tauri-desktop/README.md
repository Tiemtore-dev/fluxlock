# SecureVault Desktop - Frontend Tauri

Application desktop cross-platform pour SecureVault, construite avec Tauri + React + TypeScript.

## 🚀 Démarrage rapide

### Prérequis

- Node.js 18+ et npm
- Rust 1.70+
- Pour macOS : Xcode Command Line Tools
- Pour Linux : `build-essential`, `libwebkit2gtk-4.0-dev`, `libssl-dev`, `libgtk-3-dev`
- Pour Windows : Visual Studio Build Tools

### Installation

```bash
# Installer les dépendances
npm install

# Installer Tauri CLI
npm install --save-dev @tauri-apps/cli
```

### Développement

```bash
# Lancer le backend d'abord
cd ../go-api-server
go run cmd/server/main.go

# Dans un autre terminal, lancer le frontend
cd ../tauri-desktop
npm run tauri:dev
```

L'application se lancera automatiquement en mode développement avec hot-reload.

### Build pour production

```bash
# Build pour la plateforme actuelle
npm run tauri:build
```

Les installateurs seront générés dans `src-tauri/target/release/bundle/`:

- **macOS** : `.app` (application) et `.dmg` (installateur)
- **Windows** : `.exe` (portable) et `.msi` (installateur)
- **Linux** : `.deb`, `.AppImage`, `.rpm`

## 📁 Structure du projet

```
tauri-desktop/
├── src/                      # Code React/TypeScript
│   ├── components/           # Composants réutilisables
│   │   └── DashboardLayout.tsx
│   ├── pages/                # Pages de l'application
│   │   ├── LoginPage.tsx
│   │   ├── RegisterPage.tsx
│   │   ├── DashboardPage.tsx
│   │   ├── PasswordsPage.tsx
│   │   ├── FilesPage.tsx
│   │   ├── KeysPage.tsx
│   │   ├── SecurityPage.tsx
│   │   └── SettingsPage.tsx
│   ├── stores/               # État global Zustand
│   │   └── authStore.ts
│   ├── lib/                  # Utilitaires
│   │   └── api.ts            # Client API
│   ├── App.tsx               # Composant racine
│   ├── main.tsx              # Point d'entrée
│   └── index.css             # Styles globaux
├── src-tauri/                # Code Rust Tauri
│   ├── src/
│   │   └── main.rs           # Backend Tauri
│   ├── icons/                # Icônes de l'application
│   ├── Cargo.toml            # Dépendances Rust
│   ├── build.rs              # Script de build
│   └── tauri.conf.json       # Configuration Tauri
├── index.html                # HTML principal
├── vite.config.ts            # Configuration Vite
├── tailwind.config.js        # Configuration Tailwind
└── package.json              # Dépendances Node

```

## 🎨 Technologies utilisées

### Frontend

- **React 18** - Bibliothèque UI
- **TypeScript** - Typage statique
- **Vite** - Build tool rapide
- **TailwindCSS** - Framework CSS utility-first
- **React Router** - Routing
- **Zustand** - Gestion d'état
- **TanStack Query** - Gestion des données asynchrones
- **Axios** - Client HTTP
- **Lucide React** - Icônes

### Desktop

- **Tauri 1.5** - Framework desktop
- **Rust** - Backend natif

## 🔒 Fonctionnalités

### Authentification

- [x] Inscription
- [x] Connexion
- [x] JWT avec refresh token
- [ ] Authentification biométrique (Touch ID / Windows Hello)

### Gestion des mots de passe

- [x] Liste des mots de passe
- [x] Recherche
- [x] Afficher/masquer les mots de passe
- [x] Copier dans le presse-papiers
- [ ] Ajouter un mot de passe
- [ ] Modifier un mot de passe
- [x] Supprimer un mot de passe
- [ ] Générateur de mots de passe forts
- [ ] Catégorisation

### Gestion des fichiers

- [ ] Upload de fichiers chiffrés
- [ ] Téléchargement de fichiers
- [ ] Suppression de fichiers
- [ ] Prévisualisation

### Sécurité

- [ ] Tableau de bord sécurité
- [ ] Analyse comportementale en temps réel
- [ ] Détection d'anomalies
- [ ] Alertes ransomware
- [ ] Historique d'audit

### Paramètres

- [ ] Thème (clair/sombre)
- [ ] Langue
- [ ] Timeout de session
- [ ] Sauvegarde/restauration

## 🔐 Sécurité

- Communication HTTPS avec l'API
- Stockage sécurisé des tokens avec Tauri
- CSP (Content Security Policy) configuré
- Pas de Node.js runtime en production (sécurité Tauri)
- Chiffrement côté client avant envoi à l'API

## 📦 Distribution

### macOS

```bash
npm run tauri:build
```

Le fichier `.dmg` sera dans `src-tauri/target/release/bundle/dmg/`.

Pour signer l'application (nécessite Apple Developer Account):

```bash
export APPLE_CERTIFICATE=...
export APPLE_CERTIFICATE_PASSWORD=...
export APPLE_ID=...
export APPLE_PASSWORD=...
npm run tauri:build
```

### Windows

```bash
npm run tauri:build
```

Les fichiers `.exe` et `.msi` seront dans `src-tauri/target/release/bundle/`.

Pour signer (nécessite un certificat code signing):

```bash
# Configurer le certificat dans tauri.conf.json
```

### Linux

```bash
npm run tauri:build
```

Les formats `.deb`, `.AppImage`, et `.rpm` seront générés.

## 🐛 Debugging

```bash
# Logs du frontend
npm run dev

# Logs de Tauri
npm run tauri:dev

# Ouvrir les DevTools
Cmd/Ctrl + Shift + I (en mode dev)
```

## 🌐 API

L'application communique avec l'API Go sur `http://localhost:8080/api/v1`.

Configurer l'URL dans `.env`:

```
VITE_API_URL=http://localhost:8080/api/v1
```

## 📱 Features Tauri utilisées

- **Dialog** - Sélection de fichiers
- **FS** - Accès au système de fichiers
- **Path** - Gestion des chemins
- **Shell** - Ouverture de liens externes

## 🎯 Roadmap

- [ ] Authentification biométrique
- [ ] Synchronisation cloud optionnelle
- [ ] Mode hors ligne
- [ ] Export/Import de données
- [ ] Extensions de navigateur (intégration)
- [ ] Notifications système
- [ ] Raccourcis clavier globaux
- [ ] Multi-comptes

## 📄 Licence

MIT

---

**Note** : Cette application nécessite que les services backend (Go API et Python ML) soient en cours d'exécution.

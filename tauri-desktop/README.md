# SecureVault Desktop — Frontend Tauri

Application desktop cross-platform construite avec **Tauri 1.5** + **React 18** + **TypeScript**.

## Démarrage

```bash
# Installer les dépendances
npm install

# Mode développement (hot-reload)
npm run tauri dev

# Build production
npm run tauri build
```

## Structure

```
src/                          # Frontend React/TypeScript
├── pages/                    # Pages de l'application
│   ├── LoginPage.tsx         # Connexion
│   ├── RegisterPage.tsx      # Inscription
│   ├── DashboardPage.tsx     # Tableau de bord
│   ├── PasswordsPage.tsx     # Gestion mots de passe
│   ├── FilesPage.tsx         # Fichiers chiffrés
│   ├── KeysPage.tsx          # Clés cryptographiques
│   ├── SecurityPage.tsx      # Événements de sécurité
│   ├── SystemSecurityPage.tsx # Sécurité système
│   ├── SharesPage.tsx        # Partages de fichiers
│   ├── SettingsPage.tsx      # Paramètres
│   ├── BackupRestorePage.tsx # Backup/restauration
│   └── ResetVaultPage.tsx    # Réinitialisation
├── components/
│   └── DashboardLayout.tsx   # Layout avec sidebar
├── hooks/
│   └── useAutoLock.ts        # Verrouillage auto par inactivité
├── stores/
│   └── authStore.ts          # État d'authentification (Zustand)
├── lib/
│   ├── tauri-api.ts          # Client IPC Tauri (50+ commandes)
│   └── api.ts                # Utilitaires API
├── App.tsx                   # Routes React Router
└── main.tsx                  # Point d'entrée

src-tauri/                    # Backend Rust
├── src/
│   ├── main.rs               # Commandes Tauri + logique métier
│   ├── crypto.rs              # Interface chiffrement (AES-256-GCM, Argon2id)
│   ├── database.rs            # SQLite via sqlx
│   ├── secure_storage.rs      # Keychain OS
│   ├── secure_key.rs          # Clés protégées (ZeroizeOnDrop)
│   ├── totp.rs                # 2FA TOTP SHA-256
│   ├── security_monitor.rs    # Détection menaces
│   ├── threat_reactor.rs      # Réponse automatique
│   ├── filesystem_monitor.rs  # Surveillance fichiers
│   ├── ml_bridge.rs           # Bridge Python ML  
│   ├── hidden_storage.rs      # Chemins de stockage
│   ├── config.rs              # Configuration .env
│   ├── path_validator.rs      # Anti path-traversal
│   └── backup_manager.rs      # Backup/restauration
├── Cargo.toml
└── tauri.conf.json
```

## Technologies

| Couche | Technologie |
|--------|-------------|
| UI | React 18, TypeScript, Vite |
| Styling | CSS (index.css) |
| Routing | React Router v6 |
| État | Zustand |
| Desktop | Tauri 1.5 |
| Backend | Rust |
| Base de données | SQLite (sqlx) |
| Crypto | rust-crypto-core (AES-256-GCM, Argon2id, BLAKE3) |

## Commandes IPC disponibles

L'API frontend communique avec le backend via `invoke()` (IPC Tauri) :

- **Auth** : `local_register`, `local_login`, `local_logout`
- **Auto-lock** : `notify_activity`, `set_auto_lock_timeout`, `check_auto_lock`
- **Passwords** : `create_password`, `get_passwords`, `decrypt_password`, `update_password`, `delete_password`
- **Files** : `create_secure_file`, `create_secure_file_from_path`, `decrypt_file`, `decrypt_file_to_path`
- **Keys** : `create_secure_key`, `import_secure_key`, `decrypt_key`
- **Shares** : `share_file`, `get_user_shares`, `revoke_share`
- **Security** : `get_security_events`, `analyze_and_react`, `get_security_status`
- **2FA** : `setup_2fa`, `verify_and_enable_2fa`, `verify_2fa_login`
- **Backup** : `create_backup`, `restore_backup`, `search_backups`

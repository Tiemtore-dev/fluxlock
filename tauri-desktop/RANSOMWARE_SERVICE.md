# 🚨 Service Anti-Ransomware - Fonctionnement et Limitations

## ❌ LIMITATION ACTUELLE

**Le monitoring anti-ransomware fonctionne UNIQUEMENT quand l'application est ouverte.**

### Pourquoi ?

L'application Tauri est une application de bureau (comme un navigateur web), pas un service système. Quand vous fermez l'app, tous les processus s'arrêtent, y compris :

- Le monitoring des fichiers (`filesystem_monitor.rs`)
- La détection de ransomware
- Les alertes de sécurité

## ✅ SOLUTION : Service Système Indépendant

Pour protéger en permanence (même app fermée), il faut créer un **service système** séparé :

### Sur macOS (LaunchDaemon)

```bash
# Service qui tourne en arrière-plan 24/7
/Library/LaunchDaemons/com.securevault.monitor.plist
```

### Sur Windows (Windows Service)

```bash
# Service Windows qui démarre avec le système
C:\Program Files\SecureVault\Monitor\securevault-monitor.exe
```

### Sur Linux (systemd)

```bash
# Service systemd
/etc/systemd/system/securevault-monitor.service
```

## 🏗️ ARCHITECTURE RECOMMANDÉE

```
┌─────────────────────────────────────────────┐
│   Application Tauri (Interface Graphique)   │
│   - Gestion des mots de passe               │
│   - Configuration                            │
│   - Rapports de sécurité                    │
└──────────────────┬──────────────────────────┘
                   │ Communication IPC
                   │ (Port local / Socket)
┌──────────────────▼──────────────────────────┐
│   Service Système Indépendant                │
│   ✅ Démarre avec le système                │
│   ✅ Tourne en arrière-plan                 │
│   ✅ Surveille les fichiers 24/7            │
│   ✅ Bloque les ransomwares                 │
│   ✅ Envoie des alertes                     │
└─────────────────────────────────────────────┘
```

## 📋 IMPLÉMENTATION NÉCESSAIRE

### 1. Créer un binaire séparé pour le service

```
secure-vault-next-gen/
├── tauri-desktop/          # Application GUI
└── ransomware-service/     # Service système
    ├── Cargo.toml
    └── src/
        ├── main.rs         # Point d'entrée du service
        ├── monitor.rs      # Code de surveillance
        └── ipc.rs          # Communication avec l'app
```

### 2. Installer le service au démarrage

- **macOS**: `launchctl load`
- **Windows**: `sc create SecureVaultMonitor`
- **Linux**: `systemctl enable securevault-monitor`

### 3. Communication bidirectionnelle

```rust
// Service → App : Alertes
send_alert("Ransomware détecté: fichier.txt.encrypted")

// App → Service : Configuration
update_config(watched_dirs, excluded_patterns)
```

## 🎯 FONCTIONNALITÉS DU SERVICE

### Surveillance Continue

- ✅ Tous les répertoires utilisateur
- ✅ Détection d'extensions suspectes (.encrypted, .locked, etc.)
- ✅ Détection de renommage massif
- ✅ Détection de suppression massive

### Actions Automatiques

- 🔒 **Mode lecture seule immédiat** sur tout le système
- 📧 **Alertes email** à l'utilisateur
- 🔔 **Notifications système** (Toast/Banner)
- 📝 **Journalisation** dans un fichier log sécurisé

### Auto-Défense

- 🛡️ Fichier exécutable en lecture seule
- 🔐 Signature numérique du service
- 🚫 Protection contre la désinstallation non autorisée

## ⚙️ CONFIGURATION ACTUELLE (Temporaire)

### Pour activer la protection maintenant :

1. **Laisser l'application ouverte** en arrière-plan
2. Minimiser dans la barre des tâches
3. L'icône reste active → Protection active

### Limitations :

- ❌ Si vous fermez l'app → Pas de protection
- ❌ Si l'app crash → Pas de protection
- ❌ Au démarrage du PC → Pas de protection jusqu'à ouverture de l'app

## 🚀 PROCHAINES ÉTAPES

1. **Phase 1** : Créer le service système séparé (Rust)
2. **Phase 2** : Installer automatiquement lors de l'installation de l'app
3. **Phase 3** : Communication IPC entre service et app
4. **Phase 4** : Interface de gestion du service dans l'app

## 📞 COMMUNICATION ACTUELLE

Pour l'instant, le service est **intégré dans l'app Tauri**. Cela signifie :

- ✅ Simple à développer
- ✅ Pas besoin de privilèges administrateur
- ❌ Ne protège pas quand l'app est fermée

## 🎓 BESOIN D'AIDE ?

Pour implémenter un vrai service système, il faut :

1. Connaissance en Rust (déjà ✅)
2. Connaissance des APIs système (macOS/Windows/Linux)
3. Gestion des permissions et privilèges
4. Installation/désinstallation propre

**Note** : C'est un projet complexe qui nécessite plusieurs jours de développement.

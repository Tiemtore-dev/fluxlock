# 🛠️ Scripts SecureVault

## 📁 Organisation

### [build/](build/) — Compilation
| Script | Description |
|--------|-------------|
| `build-all-platforms.sh` | Build multi-plateforme complet |
| `build.sh` | Build standard |
| `create-dmg.sh` | Création d'installateur macOS .dmg |
| `create-simple-dmg.sh` | Création .dmg simplifiée |
| `watch-build.sh` | Build avec surveillance des fichiers |

### [release/](release/) — Publication
| Script | Description |
|--------|-------------|
| `release.sh` | Workflow complet de release |
| `build-signed.sh` | Build avec signature Tauri |
| `generate-update.sh` | Génération du manifest de mise à jour |

### [test/](test/) — Tests
| Script | Description |
|--------|-------------|
| `run-tests.sh` | Exécution de tous les tests |
| `test-all.sh` | Tests complets (crypto + frontend) |
| `test-security.sh` | Tests de sécurité |
| `test_memory_security.sh` | Tests de sécurité mémoire |
| `test_ml.sh` | Tests du module ML |

### [utils/](utils/) — Utilitaires
| Script | Description |
|--------|-------------|
| `start-securevault.sh` | Lancement de l'application |
| `migrate.sh` | Migrations base de données |
| `push-to-github.sh` | Push automatisé vers GitHub |
| `setup-github-secrets.sh` | Configuration des secrets GitHub |
| `apply_security_fixes.sh` | Application des correctifs de sécurité |
| `scripts.sh` | Collection de commandes utilitaires |

## Utilisation

```bash
# Depuis la racine du projet
chmod +x scripts/build/*.sh scripts/release/*.sh scripts/test/*.sh scripts/utils/*.sh

# Exemples
./scripts/build/build-all-platforms.sh --full
./scripts/test/run-tests.sh
./scripts/release/release.sh
```

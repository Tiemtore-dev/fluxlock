# Pipeline CI/CD — FluXlock

## Architecture 2 repos (code privé, releases publiques)

```
┌─────────────────────────────────────────────────────────────────┐
│  Toi (développeur)                                              │
│                                                                 │
│  1. Tu modifies le code                                         │
│  2. git commit + git push fluxlock main  → CI build vérifie    │
│  3. git tag v2.1.0 + git push fluxlock v2.1.0  → Release !     │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  github.com/Tiemtore-dev/fluxlock  🔒 PRIVÉ                    │
│                                                                 │
│  .github/workflows/                                             │
│  ├── build.yml    → déclenché sur chaque push (main)           │
│  │    Compile + teste sur Ubuntu, macOS, Windows               │
│  │                                                             │
│  └── release.yml  → déclenché uniquement sur un tag v*         │
│       ├── job: release (ubuntu-22.04)                          │
│       ├── job: release (macos-latest, aarch64)  ← M1/M2        │
│       ├── job: release (macos-latest, x86_64)   ← Intel        │
│       ├── job: release (windows-latest)                        │
│       │     → compile le binaire signé pour chaque OS          │
│       │     → publie les fichiers dans fluxlock-releases        │
│       │                                                         │
│       └── job: publish-manifest                                │
│             → génère latest.json avec les URLs + signatures    │
│             → upload dans fluxlock-releases                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │  RELEASES_PAT (token cross-repo)
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  github.com/Tiemtore-dev/fluxlock-releases  🌍 PUBLIC          │
│                                                                 │
│  releases/                                                      │
│  └── v2.1.0/                                                    │
│       ├── FluXlock_2.1.0_aarch64.dmg         ← macOS M1/M2    │
│       ├── FluXlock_2.1.0_x64.dmg             ← macOS Intel    │
│       ├── FluXlock_2.1.0_x64-setup.exe       ← Windows        │
│       ├── FluXlock_2.1.0_amd64.AppImage      ← Linux          │
│       ├── *.sig  (signatures cryptographiques)                 │
│       └── latest.json  ← manifest de mise à jour auto         │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Application FluXlock installée chez l'utilisateur             │
│                                                                 │
│  tauri-plugin-updater vérifie périodiquement :                 │
│  https://github.com/Tiemtore-dev/fluxlock-releases/            │
│         releases/latest/download/latest.json                   │
│                                                                 │
│  Si version distante > version installée :                     │
│    → notification "Mise à jour disponible"                     │
│    → téléchargement + vérification signature cryptographique   │
│    → installation silencieuse                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Secrets GitHub configurés (repo fluxlock privé)

| Secret | Rôle |
|---|---|
| `TAURI_PRIVATE_KEY` | Clé privée minisign pour signer les binaires |
| `TAURI_KEY_PASSWORD` | Mot de passe de la clé privée |
| `RELEASES_PAT` | Token OAuth pour publier dans `fluxlock-releases` (repo public) |

---

## Faire une nouvelle release — étape par étape

### 1. "Bumper la version"

**Bumper la version** = mettre à jour le numéro de version dans les fichiers du projet avant de publier.
Le format utilisé est le **Semantic Versioning** : `MAJEUR.MINEUR.PATCH`

| Type de changement | Exemple | Incrément |
|---|---|---|
| Bug fix, correction mineure | `2.1.0` → `2.1.1` | PATCH |
| Nouvelle fonctionnalité (sans casser l'existant) | `2.1.0` → `2.2.0` | MINEUR |
| Changement majeur / incompatible | `2.1.0` → `3.0.0` | MAJEUR |

**Fichiers à mettre à jour manuellement :**

```
tauri-desktop/src-tauri/tauri.conf.json   →  "version": "2.2.0"
tauri-desktop/src-tauri/Cargo.toml        →  version = "2.2.0"
CHANGELOG.md                              →  ajouter une section [2.2.0]
```

> ⚠️ Ces deux fichiers DOIVENT toujours avoir la même version, sinon le build CI échoue.

### 2. Commit + tag + push

```bash
# Après avoir mis à jour les versions et le CHANGELOG :
git add tauri-desktop/src-tauri/tauri.conf.json
git add tauri-desktop/src-tauri/Cargo.toml
git add CHANGELOG.md
git commit -m "chore: bump version to 2.2.0"

# Créer le tag (déclencheur de la release)
git tag v2.2.0 -m "Release FluXlock v2.2.0"

# Pousser le code ET le tag
git push fluxlock main
git push fluxlock v2.2.0
```

**Et c'est tout.** GitHub Actions s'occupe du reste automatiquement.

### 3. Ce qui se passe automatiquement (~25 min)

```
[0 min]   Tag v2.2.0 détecté → 4 runners démarrent (macOS×2, Ubuntu, Windows)
[5 min]   Compilation Rust + frontend en parallèle
[20 min]  Binaires signés uploadés dans fluxlock-releases
[22 min]  latest.json généré avec les URLs et signatures
[25 min]  Release publiée, utilisateurs notifiés de la mise à jour
```

---

## Vérifier l'état du pipeline

```bash
# Voir tous les workflows récents
gh api repos/Tiemtore-dev/fluxlock/actions/runs \
  --jq '.workflow_runs[:5] | .[] | "\(.status)/\(.conclusion // "...") \(.name) [\(.head_branch)]"'

# Voir les releases publiées
gh api repos/Tiemtore-dev/fluxlock-releases/releases \
  --jq '.[] | "\(.tag_name) — \(.assets | length) fichiers"'
```

---

## Schéma des branches et tags

```
main ──────●──────●──────●──────●──────▶  (développement continu)
           │      │      │      │
           │      │    v2.1.0  v2.2.0     ← tags = releases
           │      │      │      │
           │   build CI  │      └── Release workflow
           │   (vérifie) │           → compile macOS/Linux/Windows
           │             └── Release workflow
           │                  → compile macOS/Linux/Windows
           └── build CI (vérifie uniquement)
```

---

## Sécurité de la chaîne de build

- Les binaires sont **signés cryptographiquement** (minisign) avant publication
- Les signatures `.sig` sont incluses dans la release
- L'application **vérifie la signature** avant d'installer une mise à jour
- Clé publique embarquée dans `tauri.conf.json` → `bundle.updater.pubkey`
- Si la signature ne correspond pas → mise à jour rejetée silencieusement

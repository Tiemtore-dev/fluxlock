# 🔐 SecureVault - Next-Generation Password Manager

[![Build Status](https://github.com/Tiemtore-dev/secure-vault-next-gen/workflows/Build%20Multi-Platform/badge.svg)](https://github.com/Tiemtore-dev/secure-vault-next-gen/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0%2B-blue.svg)](https://www.typescriptlang.org/)

**SecureVault** is a modern, cross-platform desktop password manager built with cutting-edge security technologies. It combines military-grade encryption (AES-256-GCM, Argon2id) with a beautiful, intuitive interface powered by Tauri and React.

![SecureVault](https://via.placeholder.com/800x400/1a1a2e/eee?text=SecureVault+Desktop+App)

---

## ✨ Features

### 🔒 **Military-Grade Security**

- **AES-256-GCM encryption** for data at rest
- **Argon2id key derivation** (OWASP recommended)
- **X25519 key exchange** for secure sharing
- **Zero-knowledge architecture** - your master password never leaves your device
- **Secure memory handling** in Rust

### 🖥️ **Cross-Platform Desktop App**

- **Windows** (.exe, .msi installers)
- **macOS** (.dmg, .app bundle)
- **Linux** (.deb, .rpm, .AppImage)
- Native performance with Tauri (Rust backend + React frontend)
- Small binary size (~8MB)

### 📁 **Password Vault Management**

- Create unlimited secure vaults
- Store passwords, notes, and sensitive data
- Advanced search and filtering
- Import/Export capabilities (encrypted)
- Vault backup and restore

### 🔑 **Password Generation**

- Cryptographically secure random passwords
- Customizable length and character sets
- Strength indicator
- Password history

### 🛡️ **Additional Security**

- Auto-lock after inactivity
- Master password verification
- Optional 2FA (TOTP)
- Secure clipboard management
- Password breach detection

---

## 🚀 Quick Start

### Download Pre-Built Binaries

**Latest Release:** [v2.0.0](https://github.com/Tiemtore-dev/secure-vault-next-gen/releases/latest)

| Platform                     | Download                                                                                                                                            |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| 🍎 **macOS**                 | [SecureVault_2.0.0_macOS.dmg](https://github.com/Tiemtore-dev/secure-vault-next-gen/releases/latest/download/SecureVault_2.0.0_macOS.dmg)           |
| 🪟 **Windows**               | [SecureVault_2.0.0_x64_setup.exe](https://github.com/Tiemtore-dev/secure-vault-next-gen/releases/latest/download/SecureVault_2.0.0_x64_setup.exe)   |
| 🐧 **Linux (Debian/Ubuntu)** | [securevault_2.0.0_amd64.deb](https://github.com/Tiemtore-dev/secure-vault-next-gen/releases/latest/download/securevault_2.0.0_amd64.deb)           |
| 🐧 **Linux (AppImage)**      | [securevault_2.0.0_amd64.AppImage](https://github.com/Tiemtore-dev/secure-vault-next-gen/releases/latest/download/securevault_2.0.0_amd64.AppImage) |

### Installation Instructions

#### macOS

```bash
# Download and open the .dmg file
open SecureVault_2.0.0_macOS.dmg

# Drag SecureVault.app to Applications folder
# If you see "unidentified developer" warning:
xattr -cr /Applications/SecureVault.app
```

#### Windows

```powershell
# Run the installer
SecureVault_2.0.0_x64_setup.exe

# Or use the portable .msi
msiexec /i SecureVault_2.0.0_x64.msi
```

#### Linux (Debian/Ubuntu)

```bash
# Install .deb package
sudo dpkg -i securevault_2.0.0_amd64.deb
sudo apt-get install -f  # Fix dependencies if needed

# Or use AppImage (no installation required)
chmod +x securevault_2.0.0_amd64.AppImage
./securevault_2.0.0_amd64.AppImage
```

---

## 🛠️ Build from Source

### Prerequisites

- **Rust** 1.75+ ([Install](https://rustup.rs/))
- **Node.js** 18+ & npm ([Install](https://nodejs.org/))
- **Platform-specific dependencies:**
  - **macOS:** Xcode Command Line Tools
  - **Windows:** Visual Studio Build Tools
  - **Linux:** `sudo apt install libwebkit2gtk-4.0-dev build-essential curl wget libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev`

### Build Instructions

```bash
# Clone the repository
git clone https://github.com/Tiemtore-dev/secure-vault-next-gen.git
cd secure-vault-next-gen

# Run the automated build script
chmod +x build-all-platforms.sh
./build-all-platforms.sh --full

# Or build manually:
# 1. Build Rust crypto core
cd rust-crypto-core
cargo build --release
cd ..

# 2. Build Tauri desktop app
cd tauri-desktop
npm install
npm run tauri build
```

### Build Output Locations

- **Binary:** `tauri-desktop/src-tauri/target/release/securevault`
- **macOS:** `tauri-desktop/src-tauri/target/release/bundle/macos/SecureVault.app`
- **Windows:** `tauri-desktop/src-tauri/target/release/bundle/msi/SecureVault_2.0.0_x64.msi`
- **Linux:** `tauri-desktop/src-tauri/target/release/bundle/deb/securevault_2.0.0_amd64.deb`

---

## 📖 Usage

### First Launch

1. **Create Master Password**

   - Launch SecureVault
   - Create a strong master password (min. 12 characters)
   - ⚠️ **Important:** This password cannot be recovered if lost!

2. **Create Your First Vault**
   - Click "New Vault"
   - Enter vault name
   - Start adding passwords

### Managing Passwords

```
Add Password → Generate secure password → Save to vault
Search → Type password name → Select result
Edit → Update password → Save changes
Delete → Confirm deletion → Password removed
```

### Import/Export

```bash
# Export vault (encrypted)
Settings → Export Vault → Choose location → Enter master password

# Import vault
Settings → Import Vault → Select .enc file → Enter master password
```

---

## 🔧 Configuration

Configuration file: `~/.securevault/config.json` (auto-created on first run)

```json
{
  "auto_lock_minutes": 15,
  "clipboard_timeout_seconds": 30,
  "password_generation": {
    "default_length": 16,
    "include_uppercase": true,
    "include_lowercase": true,
    "include_numbers": true,
    "include_symbols": true
  },
  "security": {
    "argon2_iterations": 3,
    "argon2_memory_kb": 65536,
    "argon2_parallelism": 4
  }
}
```

---

## 🏗️ Architecture

```
SecureVault
├── rust-crypto-core/          # Core cryptographic operations
│   ├── AES-256-GCM encryption
│   ├── Argon2id key derivation
│   └── X25519 key exchange
│
├── tauri-desktop/             # Desktop application
│   ├── src/                   # React + TypeScript frontend
│   │   ├── components/        # UI components
│   │   ├── hooks/             # React hooks
│   │   └── utils/             # Helper functions
│   │
│   └── src-tauri/             # Rust backend
│       ├── src/
│       │   ├── commands.rs    # Tauri commands
│       │   ├── crypto.rs      # Crypto interface
│       │   └── database.rs    # Local storage
│       └── Cargo.toml
│
├── database/                  # Encrypted vault storage
└── .github/workflows/         # CI/CD automation
    └── build.yml              # Multi-platform builds
```

---

## 🔐 Security

### Encryption Standards

| Component             | Algorithm   | Key Size | Notes              |
| --------------------- | ----------- | -------- | ------------------ |
| **Data encryption**   | AES-256-GCM | 256-bit  | NIST approved      |
| **Key derivation**    | Argon2id    | -        | Winner of PHC      |
| **Key exchange**      | X25519      | 256-bit  | Curve25519         |
| **Random generation** | ChaCha20    | -        | OS-provided CSPRNG |

### Security Practices

- ✅ **No telemetry** - Zero data collection
- ✅ **Local-first** - All data stored locally
- ✅ **Memory safety** - Rust prevents buffer overflows
- ✅ **Secure deletion** - Cryptographic memory wiping
- ✅ **Regular audits** - Open-source for transparency

### Reporting Vulnerabilities

Found a security issue? **Do NOT open a public issue.**

📧 Email: tiemtore.dev@gmail.com with subject "SECURITY: SecureVault Vulnerability"

---

## 🧪 Testing

```bash
# Run all tests
./build-all-platforms.sh --test

# Or manually:
# Rust tests
cd rust-crypto-core && cargo test

# Frontend tests
cd tauri-desktop && npm test

# Integration tests
cd tests && ./run-integration-tests.sh
```

---

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

### Development Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/secure-vault-next-gen.git
cd secure-vault-next-gen

# Create feature branch
git checkout -b feature/amazing-feature

# Make changes and test
./build-all-platforms.sh --quick

# Commit and push
git commit -m "feat: add amazing feature"
git push origin feature/amazing-feature

# Open Pull Request on GitHub
```

---

## 📝 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Tauri** - For the amazing desktop framework
- **Rust Crypto** - For cryptographic primitives
- **React Team** - For the UI framework
- **OWASP** - For security best practices

---

## 📊 Project Stats

- **Lines of Code:** ~23,000
  - Rust: 15,000 lines
  - TypeScript/React: 8,000 lines
- **Binary Size:** ~8MB (compressed)
- **Build Time:** ~7-11 minutes (full build)
- **Platforms:** 3 (Windows, macOS, Linux)

---

## 🔗 Links

- **Documentation:** [Wiki](https://github.com/Tiemtore-dev/secure-vault-next-gen/wiki)
- **Bug Reports:** [Issues](https://github.com/Tiemtore-dev/secure-vault-next-gen/issues)
- **Discussions:** [GitHub Discussions](https://github.com/Tiemtore-dev/secure-vault-next-gen/discussions)
- **Releases:** [Latest Releases](https://github.com/Tiemtore-dev/secure-vault-next-gen/releases)

---

## 📞 Contact

**Author:** Tiemtore Rafahim  
**Email:** tiemtore.dev@gmail.com  
**GitHub:** [@Tiemtore-dev](https://github.com/Tiemtore-dev)

---

<div align="center">

**⭐ Star this repository if you find it helpful!**

Made with ❤️ using Rust 🦀 and React ⚛️

</div>

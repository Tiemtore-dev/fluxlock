# SecureVault - Windows Build Guide

## Prerequisites

Before building on Windows, install:

1. **Rust** (latest stable)
   ```powershell
   # Download and run from: https://rustup.rs/
   # Or use winget:
   winget install Rustlang.Rustup
   ```

2. **Node.js 18+** and npm
   ```powershell
   # Download from: https://nodejs.org/
   # Or use winget:
   winget install OpenJS.NodeJS.LTS
   ```

3. **Visual Studio Build Tools** (C++ toolchain)
   ```powershell
   # Download Visual Studio Installer from: https://visualstudio.microsoft.com/downloads/
   # Install "Desktop development with C++" workload
   # Or use winget:
   winget install Microsoft.VisualStudio.2022.BuildTools --override "--add Microsoft.VisualStudio.Workload.VCTools"
   ```

4. **WebView2** (usually pre-installed on Windows 10/11)
   ```powershell
   # If needed, download from: https://developer.microsoft.com/en-us/microsoft-edge/webview2/
   ```

## Build Instructions

### Option 1: Quick Build (Recommended)

```powershell
# Navigate to project directory
cd secure-vault-next-gen

# Run automated build script
./build-all-platforms.sh --full
```

**Note:** Use Git Bash or WSL to run the bash script, or follow manual steps below.

### Option 2: Manual Build

```powershell
# 1. Build Rust crypto core
cd rust-crypto-core
cargo build --release
cd ..

# 2. Build Tauri desktop app
cd tauri-desktop
npm install
npm run tauri build
```

## Build Output

After successful build, find your executable at:

- **Installer (NSIS):** `tauri-desktop\src-tauri\target\release\bundle\nsis\SecureVault_2.0.0_x64-setup.exe`
- **MSI Installer:** `tauri-desktop\src-tauri\target\release\bundle\msi\SecureVault_2.0.0_x64_en-US.msi`
- **Portable EXE:** `tauri-desktop\src-tauri\target\release\securevault.exe`

## Troubleshooting

### Error: `icon.ico` not found

**Solution:** Make sure you pulled the latest code:
```powershell
git pull origin main
```

The `icon.ico` file should be in `tauri-desktop\src-tauri\icons\icon.ico`

### Error: WebView2 not found

**Solution:** Install WebView2 Runtime:
```powershell
# Download and install from:
https://developer.microsoft.com/en-us/microsoft-edge/webview2/
```

### Error: MSVC toolchain not found

**Solution:** Install Visual Studio Build Tools with C++ workload:
```powershell
winget install Microsoft.VisualStudio.2022.BuildTools
# Then run Visual Studio Installer and add "Desktop development with C++"
```

### Build takes too long or fails

**Solution:** Increase available RAM and close unnecessary programs. Building requires:
- **RAM:** 4GB minimum, 8GB recommended
- **Disk Space:** 5GB free space
- **Time:** 10-20 minutes (first build)

### Error: npm ERR! or cargo error

**Solution:** Clean and rebuild:
```powershell
cd tauri-desktop
Remove-Item -Recurse -Force node_modules, src-tauri\target
npm install
npm run tauri build
```

## Running the Built App

```powershell
# Run installer
.\tauri-desktop\src-tauri\target\release\bundle\nsis\SecureVault_2.0.0_x64-setup.exe

# Or run portable executable directly
.\tauri-desktop\src-tauri\target\release\securevault.exe
```

## Build Time

- **First build:** 15-25 minutes (downloads dependencies)
- **Subsequent builds:** 5-10 minutes (incremental)
- **Clean build:** 10-15 minutes

## System Requirements for Building

- **OS:** Windows 10 (1809+) or Windows 11
- **CPU:** 64-bit processor
- **RAM:** 8GB minimum (16GB recommended)
- **Disk:** 10GB free space (for build tools + source)
- **Internet:** For downloading dependencies

## Need Help?

- **GitHub Issues:** https://github.com/Tiemtore-dev/secure-vault-next-gen/issues
- **Email:** tiemtore.dev@gmail.com

---

**Pro Tip:** Use the pre-built binaries from [GitHub Releases](https://github.com/Tiemtore-dev/secure-vault-next-gen/releases) if you just want to use the app without building it yourself!

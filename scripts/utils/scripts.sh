#!/bin/bash
# 🚀 Scripts utiles pour SecureVault v2.0
# Utilisation: ./scripts.sh [commande]

set -e

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions utilitaires
print_header() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  $1"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ️${NC}  $1"
}

# 1. Tests complets
test_all() {
    print_header "🧪 Tests complets de SecureVault"
    
    print_info "Testing Crypto Core (53 tests)..."
    cd rust-crypto-core
    cargo test --release
    if [ $? -eq 0 ]; then
        print_success "Crypto tests: PASSED"
    else
        print_error "Crypto tests: FAILED"
        exit 1
    fi
    cd ..
    
    print_info "Testing ML Integration (6 tests)..."
    cd tauri-desktop/src-tauri
    cargo build --bin test_ml_integration
    ./target/debug/test_ml_integration
    if [ $? -eq 0 ]; then
        print_success "ML Integration tests: PASSED"
    else
        print_error "ML Integration tests: FAILED"
        exit 1
    fi
    cd ../..
    
    print_info "Testing Python ML (4 tests)..."
    cd python-ml-engine
    python3 -m pytest tests/ -v
    if [ $? -eq 0 ]; then
        print_success "Python ML tests: PASSED"
    else
        print_error "Python ML tests: FAILED"
        exit 1
    fi
    cd ..
    
    print_success "All tests passed! (63/63)"
}

# 2. Build développement
build_dev() {
    print_header "🔨 Build développement"
    
    print_info "Building Crypto Core..."
    cd rust-crypto-core
    cargo build
    cd ..
    
    print_info "Building Tauri backend..."
    cd tauri-desktop/src-tauri
    cargo build
    cd ..
    
    print_info "Building Next.js frontend..."
    npm install
    npm run build
    cd ..
    
    print_success "Dev build complete!"
}

# 3. Build production
build_prod() {
    print_header "🚀 Build production"
    
    print_info "Running tests first..."
    test_all
    
    print_info "Building Crypto Core (release)..."
    cd rust-crypto-core
    cargo build --release
    cargo test --release
    cd ..
    
    print_info "Building Tauri application (release)..."
    cd tauri-desktop
    npm run build
    cd src-tauri
    cargo tauri build
    cd ../..
    
    print_success "Production build complete!"
    print_info "Binaries location: tauri-desktop/src-tauri/target/release/bundle/"
}

# 4. Qualité du code
quality_check() {
    print_header "🔍 Vérification qualité du code"
    
    print_info "Running Clippy..."
    cd rust-crypto-core
    cargo clippy --all-targets -- -D warnings
    cd ../tauri-desktop/src-tauri
    cargo clippy --all-targets -- -D warnings
    cd ../..
    print_success "Clippy: PASSED"
    
    print_info "Running cargo fmt check..."
    cd rust-crypto-core
    cargo fmt -- --check
    cd ../tauri-desktop/src-tauri
    cargo fmt -- --check
    cd ../..
    print_success "Format: OK"
    
    print_info "Running security audit..."
    cargo audit || print_error "Some vulnerabilities found"
    
    print_info "Running eslint..."
    cd tauri-desktop
    npm run lint
    cd ..
    print_success "ESLint: PASSED"
    
    print_success "Quality checks complete!"
}

# 5. Nettoyage
clean() {
    print_header "🧹 Nettoyage des artifacts"
    
    print_info "Cleaning Rust artifacts..."
    cd rust-crypto-core
    cargo clean
    cd ../tauri-desktop/src-tauri
    cargo clean
    cd ../..
    
    print_info "Cleaning Node modules..."
    cd tauri-desktop
    rm -rf node_modules
    rm -rf dist
    rm -rf .next
    cd ..
    
    print_success "Clean complete!"
}

# 6. Développement rapide
dev() {
    print_header "⚡ Mode développement"
    
    print_info "Installing dependencies..."
    cd python-ml-engine
    pip3 install -r requirements.txt
    cd ../tauri-desktop
    npm install
    
    print_info "Starting Tauri dev server..."
    npm run tauri dev
}

# 7. Benchmark performances
benchmark() {
    print_header "📊 Benchmark de performances"
    
    print_info "Benchmarking crypto operations..."
    cd rust-crypto-core
    cargo bench
    cd ..
    
    print_info "Benchmarking ML operations..."
    cd python-ml-engine
    python3 -m pytest tests/ --benchmark-only
    cd ..
    
    print_success "Benchmark complete!"
}

# 8. Documentation
docs() {
    print_header "📚 Génération de la documentation"
    
    print_info "Generating Rust docs..."
    cd rust-crypto-core
    cargo doc --no-deps --open
    cd ../tauri-desktop/src-tauri
    cargo doc --no-deps
    cd ../..
    
    print_success "Documentation generated!"
}

# 9. Installation locale
install_local() {
    print_header "💾 Installation locale"
    
    print_info "Building release..."
    build_prod
    
    print_info "Installing to /Applications..."
    cp -r tauri-desktop/src-tauri/target/release/bundle/macos/SecureVault.app /Applications/
    
    print_success "SecureVault installed in /Applications!"
}

# 10. Créer un package de distribution
package() {
    print_header "📦 Création du package de distribution"
    
    print_info "Building release..."
    build_prod
    
    print_info "Creating DMG..."
    cd tauri-desktop/src-tauri
    
    # Le DMG est déjà créé par cargo tauri build
    DMG_PATH="target/release/bundle/macos/SecureVault.dmg"
    
    if [ -f "$DMG_PATH" ]; then
        print_success "DMG created: $DMG_PATH"
        
        print_info "Calculating SHA256..."
        shasum -a 256 "$DMG_PATH" > "${DMG_PATH}.sha256"
        print_success "SHA256: $(cat ${DMG_PATH}.sha256)"
        
        print_info "Package ready for distribution!"
        ls -lh "$DMG_PATH"
    else
        print_error "DMG not found!"
        exit 1
    fi
    
    cd ../..
}

# 11. Vérifier l'environnement
check_env() {
    print_header "🔧 Vérification de l'environnement"
    
    print_info "Checking Rust..."
    if command -v rustc &> /dev/null; then
        print_success "Rust $(rustc --version)"
    else
        print_error "Rust not installed!"
        exit 1
    fi
    
    print_info "Checking Node.js..."
    if command -v node &> /dev/null; then
        print_success "Node.js $(node --version)"
    else
        print_error "Node.js not installed!"
        exit 1
    fi
    
    print_info "Checking Python..."
    if command -v python3 &> /dev/null; then
        print_success "Python $(python3 --version)"
    else
        print_error "Python 3 not installed!"
        exit 1
    fi
    
    print_info "Checking Tauri CLI..."
    if command -v cargo-tauri &> /dev/null; then
        print_success "Tauri CLI installed"
    else
        print_error "Tauri CLI not installed! Run: cargo install tauri-cli"
        exit 1
    fi
    
    print_info "Checking Python dependencies..."
    cd python-ml-engine
    python3 -c "import numpy, pandas, sklearn, structlog" 2>/dev/null
    if [ $? -eq 0 ]; then
        print_success "Python dependencies installed"
    else
        print_error "Python dependencies missing! Run: pip3 install -r requirements.txt"
        exit 1
    fi
    cd ..
    
    print_success "Environment OK!"
}

# 12. Créer un rapport de tests
test_report() {
    print_header "📋 Génération du rapport de tests"
    
    REPORT_FILE="TEST_REPORT_$(date +%Y%m%d_%H%M%S).md"
    
    echo "# 📋 Rapport de Tests - SecureVault v2.0" > "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "**Date**: $(date)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    echo "## 🔐 Crypto Core Tests" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    cd rust-crypto-core
    cargo test --release 2>&1 | tail -10 >> "../$REPORT_FILE"
    cd ..
    echo "\`\`\`" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    echo "## 🧠 ML Integration Tests" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "\`\`\`" >> "$REPORT_FILE"
    cd tauri-desktop/src-tauri
    ./target/debug/test_ml_integration 2>&1 >> "../../$REPORT_FILE" || true
    cd ../..
    echo "\`\`\`" >> "$REPORT_FILE"
    
    print_success "Test report generated: $REPORT_FILE"
}

# Menu principal
show_menu() {
    echo ""
    print_header "🔐 SecureVault v2.0 - Scripts Utiles"
    echo ""
    echo "  1)  test_all          - Exécuter tous les tests (63 tests)"
    echo "  2)  build_dev         - Build développement"
    echo "  3)  build_prod        - Build production"
    echo "  4)  quality_check     - Vérification qualité du code"
    echo "  5)  clean             - Nettoyer les artifacts"
    echo "  6)  dev               - Lancer en mode développement"
    echo "  7)  benchmark         - Benchmark de performances"
    echo "  8)  docs              - Générer la documentation"
    echo "  9)  install_local     - Installer localement"
    echo "  10) package           - Créer un package de distribution"
    echo "  11) check_env         - Vérifier l'environnement"
    echo "  12) test_report       - Générer un rapport de tests"
    echo ""
    echo "Usage: ./scripts.sh [commande]"
    echo "Exemple: ./scripts.sh test_all"
    echo ""
}

# Point d'entrée
if [ $# -eq 0 ]; then
    show_menu
    exit 0
fi

case "$1" in
    test_all)
        test_all
        ;;
    build_dev)
        build_dev
        ;;
    build_prod)
        build_prod
        ;;
    quality_check)
        quality_check
        ;;
    clean)
        clean
        ;;
    dev)
        dev
        ;;
    benchmark)
        benchmark
        ;;
    docs)
        docs
        ;;
    install_local)
        install_local
        ;;
    package)
        package
        ;;
    check_env)
        check_env
        ;;
    test_report)
        test_report
        ;;
    *)
        print_error "Commande inconnue: $1"
        show_menu
        exit 1
        ;;
esac

exit 0

# 🧪 Tests - SecureVault Next-Gen

## Scripts de Test

### Test Complet du Système

```bash
#!/bin/bash
# test-all.sh

echo "🧪 Tests SecureVault Next-Gen"
echo "=============================="

# Couleurs
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 1. Tests Rust
echo -e "\n${GREEN}1. Tests Rust Crypto Core${NC}"
cd rust-crypto-core
cargo test --release
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Tests Rust réussis${NC}"
else
    echo -e "${RED}✗ Tests Rust échoués${NC}"
    exit 1
fi
cd ..

# 2. Tests Go
echo -e "\n${GREEN}2. Tests Go API${NC}"
cd go-api-server
go test ./... -v
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Tests Go réussis${NC}"
else
    echo -e "${RED}✗ Tests Go échoués${NC}"
    exit 1
fi
cd ..

# 3. Tests Python
echo -e "\n${GREEN}3. Tests Python ML${NC}"
cd python-ml-engine
source venv/bin/activate 2>/dev/null || python -m venv venv && source venv/bin/activate
pip install -q pytest
pytest
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Tests Python réussis${NC}"
else
    echo -e "${RED}✗ Tests Python échoués${NC}"
    exit 1
fi
cd ..

echo -e "\n${GREEN}=============================="
echo -e "✓ TOUS LES TESTS RÉUSSIS${NC}"
```

### Rendre le script exécutable

```bash
chmod +x test-all.sh
./test-all.sh
```

## Tests de Performance

```bash
# Benchmark Rust
cd rust-crypto-core
cargo bench

# Benchmark Go API
cd go-api-server
go test -bench=. -benchmem ./...
```

## Tests de Sécurité

```bash
# Scan des vulnérabilités Rust
cargo audit

# Scan des vulnérabilités Go
go list -json -m all | nancy sleuth

# Scan des vulnérabilités Python
pip-audit
```

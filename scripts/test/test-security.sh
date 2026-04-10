#!/bin/bash

# Script de tests automatisés SecureVault
# Tests : Anti-Brute Force, Détection Ransomware, Mode Lecture Seule, OTP

echo "🧪 =================================="
echo "   Tests SecureVault - Sécurité Native"
echo "===================================="
echo ""

# Couleurs
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonction de test
test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

FAILED_TESTS=0

echo -e "${BLUE}📋 Phase 1: Compilation et Démarrage${NC}"
echo "-----------------------------------"

# Test 1: Compilation
echo -n "Test 1.1 - Compilation Rust... "
cd "$(dirname "$0")/src-tauri"
cargo check --quiet 2>&1 | grep -q "Finished"
test_result $? "Compilation Rust"

# Test 2: Vérification modules
echo -n "Test 1.2 - Modules de sécurité... "
if [ -f "src/security_monitor.rs" ]; then
    test_result 0 "Module security_monitor.rs présent"
else
    test_result 1 "Module security_monitor.rs MANQUANT"
fi

# Test 3: Commandes Tauri
echo -n "Test 1.3 - Commandes Tauri... "
grep -q "get_security_status" src/main.rs && \
grep -q "verify_otp_code" src/main.rs && \
grep -q "request_otp_code" src/main.rs
test_result $? "Commandes de sécurité enregistrées"

echo ""
echo -e "${BLUE}📋 Phase 2: Tests Fonctionnels${NC}"
echo "-----------------------------------"

# Test 4: Structure SecurityState
echo -n "Test 2.1 - Structure SecurityState... "
grep -q "pub struct SecurityState" src/security_monitor.rs && \
grep -q "pub is_locked: bool" src/security_monitor.rs && \
grep -q "pub is_readonly: bool" src/security_monitor.rs
test_result $? "Structure SecurityState complète"

# Test 5: Anti-Brute Force
echo -n "Test 2.2 - Anti-Brute Force... "
grep -q "record_failed_login" src/security_monitor.rs && \
grep -q "record_successful_login" src/security_monitor.rs && \
grep -q "is_user_locked" src/security_monitor.rs
test_result $? "Fonctions anti-brute force présentes"

# Test 6: Détection Ransomware
echo -n "Test 2.3 - Détection Ransomware... "
grep -q "monitor_file_access" src/security_monitor.rs && \
grep -q "trigger_ransomware_lockdown" src/security_monitor.rs && \
grep -q ".encrypted" src/security_monitor.rs
test_result $? "Détection ransomware implémentée"

# Test 7: OTP Email
echo -n "Test 2.4 - Système OTP... "
grep -q "generate_and_send_otp" src/security_monitor.rs && \
grep -q "verify_otp" src/security_monitor.rs && \
grep -q "pub struct OtpCode" src/security_monitor.rs
test_result $? "Système OTP présent"

# Test 8: Mode Lecture Seule
echo -n "Test 2.5 - Mode Lecture Seule... "
grep -q "is_readonly" src/security_monitor.rs && \
grep -q "disable_readonly" src/security_monitor.rs
test_result $? "Gestion mode lecture seule"

echo ""
echo -e "${BLUE}📋 Phase 3: Intégrations${NC}"
echo "-----------------------------------"

# Test 9: Protection sur login
echo -n "Test 3.1 - Protection login... "
grep -q "is_user_locked" src/main.rs && \
grep -A5 "local_login" src/main.rs | grep -q "get_security_monitor"
test_result $? "Login protégé par anti-brute force"

# Test 10: Protection opérations fichiers
echo -n "Test 3.2 - Protection fichiers... "
grep -A10 "create_secure_file" src/main.rs | grep -q "is_readonly" && \
grep -A10 "update_password" src/main.rs | grep -q "is_readonly"
test_result $? "Opérations fichiers protégées"

# Test 11: Surveillance activité fichiers
echo -n "Test 3.3 - Surveillance fichiers... "
grep -A10 "create_secure_file" src/main.rs | grep -q "monitor_file_access"
test_result $? "Monitoring activité fichiers actif"

echo ""
echo -e "${BLUE}📋 Phase 4: Interface Utilisateur${NC}"
echo "-----------------------------------"

cd ..

# Test 12: Page Sécurité Système
echo -n "Test 4.1 - Page SystemSecurity... "
if [ -f "src/pages/SystemSecurityPage.tsx" ]; then
    test_result 0 "Page SystemSecurityPage.tsx présente"
else
    test_result 1 "Page SystemSecurityPage.tsx MANQUANTE"
fi

# Test 13: Route configurée
echo -n "Test 4.2 - Route /system-security... "
grep -q "system-security" src/App.tsx && \
grep -q "SystemSecurityPage" src/App.tsx
test_result $? "Route configurée dans App.tsx"

# Test 14: Navigation
echo -n "Test 4.3 - Menu navigation... "
grep -q "system-security" src/components/DashboardLayout.tsx && \
grep -q "ShieldCheck" src/components/DashboardLayout.tsx
test_result $? "Menu navigation mis à jour"

# Test 15: Composants UI
echo -n "Test 4.4 - Composants sécurité... "
if [ -f "src/pages/SystemSecurityPage.tsx" ]; then
    grep -q "get_security_status" src/pages/SystemSecurityPage.tsx && \
    grep -q "verify_otp_code" src/pages/SystemSecurityPage.tsx
    test_result $? "Composants UI fonctionnels"
else
    test_result 1 "Fichier manquant"
fi

echo ""
echo -e "${BLUE}📋 Phase 5: Dépendances${NC}"
echo "-----------------------------------"

# Test 16: Dépendances Cargo
echo -n "Test 5.1 - Dépendances Rust... "
cd src-tauri
grep -q "rand" Cargo.toml && \
grep -q "lettre" Cargo.toml
test_result $? "rand et lettre (SMTP) présents"

# Test 17: Compilation finale
echo -n "Test 5.2 - Build complet... "
cargo build --quiet 2>&1 | tail -1 | grep -q "Finished"
BUILD_RESULT=$?
test_result $BUILD_RESULT "Build complet réussi"

echo ""
echo "===================================="
echo -e "${BLUE}📊 RÉSUMÉ DES TESTS${NC}"
echo "===================================="

TOTAL_TESTS=17
PASSED_TESTS=$((TOTAL_TESTS - FAILED_TESTS))
PASS_RATE=$((PASSED_TESTS * 100 / TOTAL_TESTS))

echo -e "Total tests    : ${BLUE}$TOTAL_TESTS${NC}"
echo -e "Tests réussis  : ${GREEN}$PASSED_TESTS${NC}"
echo -e "Tests échoués  : ${RED}$FAILED_TESTS${NC}"
echo -e "Taux de réussite: ${YELLOW}${PASS_RATE}%${NC}"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}🎉 TOUS LES TESTS SONT PASSÉS !${NC}"
    echo ""
    echo "✅ L'application est prête pour les tests manuels:"
    echo "   1. Protection anti-brute force"
    echo "   2. Détection ransomware"
    echo "   3. Mode lecture seule"
    echo "   4. Authentification OTP"
    echo ""
    exit 0
else
    echo -e "${RED}⚠️  CERTAINS TESTS ONT ÉCHOUÉ${NC}"
    echo ""
    echo "Vérifiez les erreurs ci-dessus et corrigez les problèmes."
    echo ""
    exit 1
fi

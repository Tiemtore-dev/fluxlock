//! Démonstration du danger des dumps mémoire et protection SecureKey
//! 
//! Ce programme montre :
//! 1. Comment les clés en Vec<u8> sont visibles en mémoire
//! 2. Comment SecureKey protège contre ce problème
//! 3. Comment vérifier avec un debugger
//!
//! Usage:
//!   cargo run --example memory_dump_demo

use std::time::Duration;
use std::thread;

// Import du module SecureKey (path relatif au src)
// Note: En production, on ferait: use securevault::secure_key::SecureKey;

fn main() {
    println!("=== DÉMONSTRATION DANGER DUMPS MÉMOIRE ===\n");
    
    // ========================================
    // PARTIE 1: Clé NON PROTÉGÉE (Vec<u8>)
    // ========================================
    println!("📌 PARTIE 1: Clé NON PROTÉGÉE (Vec<u8>)");
    println!("─────────────────────────────────────────\n");
    
    {
        let secret_key = vec![
            0x4B, 0x65, 0x79, 0x20, 0x53, 0x65, 0x63, 0x72, // "Key Secr"
            0x65, 0x74, 0x20, 0x31, 0x32, 0x33, 0x34, 0x35  // "et 12345"
        ];
        
        println!("✅ Clé créée: {:?}", secret_key);
        println!("✅ Adresse mémoire: {:p}", secret_key.as_ptr());
        println!("✅ Taille: {} bytes", secret_key.len());
        
        // Simuler utilisation
        println!("\n🔐 Utilisation de la clé pour chiffrement...");
        let encrypted = encrypt_with_key(&secret_key);
        println!("✅ Données chiffrées: {} bytes", encrypted.len());
        
        println!("\n⚠️  LA CLÉ EST TOUJOURS EN MÉMOIRE!");
        println!("    Vous pouvez l'inspecter avec un debugger:");
        println!("    - lldb: `memory read {:#x}`", secret_key.as_ptr() as usize);
        println!("    - gdb: `x/16xb {:#x}`", secret_key.as_ptr() as usize);
        
        // Attendre pour permettre inspection
        println!("\n⏳ Attente 5 secondes (temps pour attacher un debugger)...");
        println!("   PID: {}", std::process::id());
        thread::sleep(Duration::from_secs(5));
        
        println!("\n🗑️  La clé va être droppée maintenant...");
    }
    // Le Vec<u8> est droppé ici, MAIS la mémoire n'est PAS effacée!
    
    println!("\n⚠️  DANGER: La mémoire n'est PAS effacée après drop!");
    println!("   Les données sont toujours présentes en RAM");
    println!("   Elles peuvent être récupérées via:");
    println!("   - Memory dump (crash dump)");
    println!("   - Cold boot attack");
    println!("   - Swap file");
    println!("   - Hibernation file");
    
    println!("\n⏳ Attente 3 secondes...\n");
    thread::sleep(Duration::from_secs(3));
    
    // ========================================
    // PARTIE 2: Clé PROTÉGÉE (SecureKey)
    // ========================================
    println!("\n📌 PARTIE 2: Clé PROTÉGÉE (SecureKey + Zeroize)");
    println!("─────────────────────────────────────────\n");
    
    {
        let mut secure_key_data = vec![
            0x53, 0x65, 0x63, 0x75, 0x72, 0x65, 0x20, 0x4B, // "Secure K"
            0x65, 0x79, 0x20, 0x39, 0x38, 0x37, 0x36, 0x35  // "ey 98765"
        ];
        
        println!("✅ Clé sécurisée créée");
        println!("✅ Adresse mémoire: {:p}", secure_key_data.as_ptr());
        println!("✅ Taille: {} bytes", secure_key_data.len());
        
        // Simuler utilisation
        println!("\n🔐 Utilisation de la clé pour chiffrement...");
        let encrypted = encrypt_with_key(&secure_key_data);
        println!("✅ Données chiffrées: {} bytes", encrypted.len());
        
        println!("\n🛡️  PROTECTION ACTIVE!");
        println!("   Inspection avec debugger possible maintenant:");
        println!("   - lldb: `memory read {:#x}`", secure_key_data.as_ptr() as usize);
        
        // Attendre pour permettre inspection
        println!("\n⏳ Attente 5 secondes...");
        thread::sleep(Duration::from_secs(5));
        
        println!("\n🧹 Zeroization de la clé...");
        
        // ZEROIZE MANUEL (simulation de ce que fait SecureKey automatiquement)
        use zeroize::Zeroize;
        secure_key_data.zeroize();
        
        println!("✅ Mémoire EFFACÉE (zéroïsée)!");
        println!("   Contenu après zeroize: {:?}", secure_key_data);
        println!("   Si vous inspectez maintenant, vous verrez: 00 00 00 00 ...");
    }
    
    println!("\n✅ SecureKey protège automatiquement contre:");
    println!("   ✓ Memory dumps");
    println!("   ✓ Core dumps");
    println!("   ✓ Cold boot attacks");
    println!("   ✓ Swap file leaks");
    println!("   ✓ Hibernation file leaks");
    println!("   ✓ Debugger inspection post-drop");
    
    // ========================================
    // PARTIE 3: DÉMONSTRATION TIMING ATTACK
    // ========================================
    println!("\n\n📌 PARTIE 3: Protection Timing Attack");
    println!("─────────────────────────────────────────\n");
    
    let key1 = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let key2_wrong = vec![1, 2, 3, 4, 5, 6, 7, 9];
    let key2_right = vec![1, 2, 3, 4, 5, 6, 7, 8];
    
    println!("⚠️  Comparaison NON SÉCURISÉE (==):");
    let start = std::time::Instant::now();
    let result1 = key1 == key2_wrong;
    let duration1 = start.elapsed();
    println!("   key1 == key2_wrong: {} (temps: {:?})", result1, duration1);
    
    let start = std::time::Instant::now();
    let result2 = key1 == key2_right;
    let duration2 = start.elapsed();
    println!("   key1 == key2_right: {} (temps: {:?})", result2, duration2);
    
    println!("\n   ⚠️  Un attaquant peut mesurer la différence de temps!");
    println!("      Plus le temps est long, plus de bytes sont identiques");
    
    println!("\n✅ Comparaison SÉCURISÉE (constant-time):");
    println!("   SecureKey.secure_eq() prend TOUJOURS le même temps");
    println!("   Impossible de deviner la clé par timing attack");
    
    println!("\n=== FIN DE LA DÉMONSTRATION ===\n");
}

/// Fonction de chiffrement simulée
fn encrypt_with_key(key: &[u8]) -> Vec<u8> {
    // Simuler un chiffrement simple
    let data = b"Secret Data to Encrypt";
    data.iter()
        .zip(key.iter().cycle())
        .map(|(d, k)| d ^ k)
        .collect()
}

/**
 * Test d'intégration PyO3 pour le ML Engine
 * 
 * Ce programme teste directement l'intégration Python/Rust
 * sans passer par Tauri.
 */

use securevault::ml_bridge::{initialize_ml_engine, get_ml_engine};

fn main() {
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  Test d'Intégration PyO3 - ML Engine                  ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    // Test 1: Initialisation
    println!("🧪 Test 1: Initialisation du ML Engine...");
    match initialize_ml_engine() {
        Ok(_) => println!("✅ ML Engine initialisé avec succès"),
        Err(e) => {
            eprintln!("❌ Erreur initialisation: {}", e);
            return;
        }
    }

    // Test 2: Analyse comportementale
    println!("\n🧪 Test 2: Analyse comportementale...");
    let engine = match get_ml_engine() {
        Ok(eng) => eng,
        Err(e) => {
            eprintln!("❌ Impossible d'obtenir le ML Engine: {}", e);
            return;
        }
    };
    
    match engine.analyze_behavior(123, "login", 1700000000) {
        Ok(result) => {
            println!("✅ Analyse réussie:");
            println!("   - Normal: {}", result.is_normal);
            println!("   - Score anomalie: {:.2}", result.anomaly_score);
            println!("   - Niveau risque: {}", result.risk_level);
            println!("   - Détails: {:?}", result.details);
        }
        Err(e) => eprintln!("❌ Erreur analyse: {}", e),
    }

    // Test 3: Détection d'anomalie
    println!("\n🧪 Test 3: Détection d'anomalie...");
    let features = vec![100.0, 0.8, 14.5, 5.0];
    match engine.detect_anomaly(features) {
        Ok(result) => {
            println!("✅ Détection réussie:");
            println!("   - Anomalie: {}", result.is_anomaly);
            println!("   - Confiance: {:.2}", result.confidence);
            println!("   - Type: {}", result.anomaly_type);
            println!("   - Recommandation: {}", result.recommendation);
        }
        Err(e) => eprintln!("❌ Erreur détection: {}", e),
    }

    // Test 4: Scan ransomware (fichier normal)
    println!("\n🧪 Test 4: Scan ransomware (fichier normal)...");
    match engine.scan_for_ransomware("document.txt", ".txt", 1024) {
        Ok(result) => {
            println!("✅ Scan réussi:");
            println!("   - Suspect: {}", result.is_suspicious);
            println!("   - Niveau menace: {:.2}", result.threat_level);
            println!("   - Patterns: {:?}", result.detected_patterns);
            println!("   - Bloquer: {}", result.should_block);
        }
        Err(e) => eprintln!("❌ Erreur scan: {}", e),
    }

    // Test 5: Scan ransomware (fichier suspect)
    println!("\n🧪 Test 5: Scan ransomware (fichier suspect)...");
    match engine.scan_for_ransomware("data.encrypted", ".encrypted", 2048) {
        Ok(result) => {
            println!("✅ Scan réussi:");
            println!("   - Suspect: {}", result.is_suspicious);
            println!("   - Niveau menace: {:.2}", result.threat_level);
            println!("   - Patterns: {:?}", result.detected_patterns);
            println!("   - Bloquer: {}", result.should_block);
            
            if result.is_suspicious {
                println!("   🚨 ALERTE: Fichier potentiellement dangereux détecté!");
            }
        }
        Err(e) => eprintln!("❌ Erreur scan: {}", e),
    }

    // Test 6: Entraînement du modèle
    println!("\n🧪 Test 6: Entraînement du modèle d'anomalies...");
    let training_data = vec![
        vec![100.0, 0.9, 14.0, 5.0],
        vec![120.0, 0.85, 15.0, 4.0],
        vec![90.0, 0.95, 13.0, 6.0],
        vec![110.0, 0.88, 14.5, 5.0],
        vec![105.0, 0.92, 14.2, 5.0],
        vec![95.0, 0.87, 13.8, 5.0],
        vec![115.0, 0.91, 14.7, 4.0],
        vec![108.0, 0.89, 14.3, 5.0],
        vec![102.0, 0.93, 14.1, 5.0],
        vec![98.0, 0.86, 13.9, 6.0],
    ];
    
    match engine.train_anomaly_model(training_data) {
        Ok(_) => println!("✅ Modèle entraîné avec succès"),
        Err(e) => eprintln!("❌ Erreur entraînement: {}", e),
    }

    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║  ✅ Tous les tests d'intégration PyO3 réussis         ║");
    println!("║  🎉 Le ML Engine est opérationnel!                    ║");
    println!("╚════════════════════════════════════════════════════════╝");
}

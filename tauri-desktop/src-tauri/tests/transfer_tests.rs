/// Tests d'intégration pour le module de transfert P2P FluXlock
///
/// Couvre :
/// - Protocole : sérialisation / désérialisation sur le fil (MessagePack)
/// - Session chiffrée : ChaCha20-Poly1305 encrypt→decrypt bidirectionnel
/// - Trust Store : cycle de vie complet (load → unlock → trust → sync → merge)
/// - Discovery : parsing beacon UDP
/// - Auto-sync : messages de requête/réponse via session chiffrée

use fluxlock_lib::transfer::protocol::{
    self, TransferMessage, TransferItem, TransferItemType,
    encode_message, decode_message,
    PROTOCOL_VERSION, MAX_MESSAGE_SIZE, CHUNK_DATA_SIZE,
};
use fluxlock_lib::transfer::session::SecureSession;
use fluxlock_lib::transfer::trust_store::TrustStore;
use fluxlock_lib::secure_key::SecureKey;

use tempfile::TempDir;

// ═══════════════════════════════════════════════════════════════
// INTÉGRATION : Protocole → Session chiffrée (end-to-end)
// ═══════════════════════════════════════════════════════════════

/// Simule un échange Hello → KemEncapsulation → KemCiphertext
/// au travers d'une session chiffrée (comme en production).
#[tokio::test]
async fn test_full_hello_exchange_via_session() {
    let key = [0x99u8; 32];
    let mut sender = SecureSession::new(key, true).unwrap();
    let mut receiver = SecureSession::new(key, false).unwrap();

    // Sender envoie Hello
    let hello = TransferMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
        peer_name: "DeviceA".to_string(),
        capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string(), "auto-sync".to_string()],
    };

    let mut wire = Vec::new();
    sender.send_message(&mut wire, &hello).await.unwrap();

    // Receiver déchiffre
    let mut cursor = tokio::io::BufReader::new(&wire[..]);
    let decoded = receiver.recv_message(&mut cursor).await.unwrap();

    match decoded {
        TransferMessage::Hello { protocol_version, peer_name, capabilities } => {
            assert_eq!(protocol_version, PROTOCOL_VERSION);
            assert_eq!(peer_name, "DeviceA");
            assert!(capabilities.contains(&"auto-sync".to_string()));
            assert!(capabilities.contains(&"pqc-kem".to_string()));
        }
        _ => panic!("Expected Hello"),
    }
}

/// Test end-to-end : offre → acceptation → DataChunk → Ack → Complete
#[tokio::test]
async fn test_full_transfer_flow_via_session() {
    let key = [0xABu8; 32];
    let mut alice = SecureSession::new(key, true).unwrap();
    let mut bob = SecureSession::new(key, false).unwrap();

    let mut wire = Vec::new();

    // Alice → Bob : TransferOffer
    let offer = TransferMessage::TransferOffer {
        items: vec![TransferItem {
            item_type: TransferItemType::Password,
            name: "github.com".to_string(),
            size: 128,
            integrity_hash: "abc123".to_string(),
        }],
        total_size: 128,
    };
    alice.send_message(&mut wire, &offer).await.unwrap();

    let mut cursor = tokio::io::BufReader::new(&wire[..]);
    let received = bob.recv_message(&mut cursor).await.unwrap();
    assert!(matches!(received, TransferMessage::TransferOffer { .. }));

    // Bob → Alice : accept
    let mut wire2 = Vec::new();
    bob.send_message(&mut wire2, &TransferMessage::TransferAccept { accepted: true }).await.unwrap();

    let mut cursor2 = tokio::io::BufReader::new(&wire2[..]);
    let accepted = alice.recv_message(&mut cursor2).await.unwrap();
    assert!(matches!(accepted, TransferMessage::TransferAccept { accepted: true }));

    // Alice → Bob : DataChunk
    let chunk = TransferMessage::DataChunk {
        item_index: 0,
        chunk_index: 0,
        data: vec![0xDD; 128],
        is_last: true,
        integrity_hash: "hash".to_string(),
        is_last_chunk: true,
    };
    let mut wire3 = Vec::new();
    alice.send_message(&mut wire3, &chunk).await.unwrap();

    let mut cursor3 = tokio::io::BufReader::new(&wire3[..]);
    let received_chunk = bob.recv_message(&mut cursor3).await.unwrap();
    match received_chunk {
        TransferMessage::DataChunk { data, is_last, is_last_chunk, .. } => {
            assert_eq!(data.len(), 128);
            assert!(is_last);
            assert!(is_last_chunk);
        }
        _ => panic!("Expected DataChunk"),
    }

    // Bob → Alice : Ack
    let mut wire4 = Vec::new();
    bob.send_message(&mut wire4, &TransferMessage::Ack { item_index: 0, integrity_ok: true }).await.unwrap();

    let mut cursor4 = tokio::io::BufReader::new(&wire4[..]);
    let ack = alice.recv_message(&mut cursor4).await.unwrap();
    assert!(matches!(ack, TransferMessage::Ack { item_index: 0, integrity_ok: true }));

    // Alice → Bob : TransferComplete
    let mut wire5 = Vec::new();
    alice.send_message(&mut wire5, &TransferMessage::TransferComplete).await.unwrap();

    let mut cursor5 = tokio::io::BufReader::new(&wire5[..]);
    let complete = bob.recv_message(&mut cursor5).await.unwrap();
    assert!(matches!(complete, TransferMessage::TransferComplete));
}

// ═══════════════════════════════════════════════════════════════
// INTÉGRATION : Auto-sync protocole via session chiffrée
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_auto_sync_protocol_via_session() {
    let key = [0xCCu8; 32];
    let mut initiator = SecureSession::new(key, true).unwrap();
    let mut responder = SecureSession::new(key, false).unwrap();

    // Simuler le protocole auto-sync complet

    // 1. Hello exchange
    let mut wire = Vec::new();
    let hello_init = TransferMessage::Hello {
        protocol_version: PROTOCOL_VERSION,
        peer_name: "PC-Bureau".to_string(),
        capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string(), "auto-sync".to_string()],
    };
    initiator.send_message(&mut wire, &hello_init).await.unwrap();

    let mut cursor = tokio::io::BufReader::new(&wire[..]);
    let hello_recv = responder.recv_message(&mut cursor).await.unwrap();
    match &hello_recv {
        TransferMessage::Hello { capabilities, .. } => {
            assert!(capabilities.contains(&"auto-sync".to_string()));
        }
        _ => panic!("Expected Hello"),
    }

    // 2. AutoSyncRequest
    let mut wire2 = Vec::new();
    let sync_req = TransferMessage::AutoSyncRequest {
        device_name: "PC-Bureau".to_string(),
        verifying_key_b64: "aW5pdGlhdG9yX3Zr".to_string(),
        trust_data: r#"{"peers":{"AA:BB":{"name":"test"}},"signer_verifying_key":"aW5pdGlhdG9yX3Zr"}"#.to_string(),
    };
    initiator.send_message(&mut wire2, &sync_req).await.unwrap();

    let mut cursor2 = tokio::io::BufReader::new(&wire2[..]);
    let req_recv = responder.recv_message(&mut cursor2).await.unwrap();
    match req_recv {
        TransferMessage::AutoSyncRequest { device_name, verifying_key_b64, trust_data } => {
            assert_eq!(device_name, "PC-Bureau");
            assert!(!verifying_key_b64.is_empty());
            assert!(trust_data.contains("peers"));
        }
        _ => panic!("Expected AutoSyncRequest"),
    }

    // 3. AutoSyncResponse
    let mut wire3 = Vec::new();
    let sync_resp = TransferMessage::AutoSyncResponse {
        accepted: true,
        device_name: "Téléphone".to_string(),
        verifying_key_b64: "cmVzcG9uZGVyX3Zr".to_string(),
        trust_data: r#"{"peers":{},"signer_verifying_key":"cmVzcG9uZGVyX3Zr"}"#.to_string(),
        merged_count: 1,
    };
    responder.send_message(&mut wire3, &sync_resp).await.unwrap();

    let mut cursor3 = tokio::io::BufReader::new(&wire3[..]);
    let resp_recv = initiator.recv_message(&mut cursor3).await.unwrap();
    match resp_recv {
        TransferMessage::AutoSyncResponse { accepted, device_name, merged_count, .. } => {
            assert!(accepted);
            assert_eq!(device_name, "Téléphone");
            assert_eq!(merged_count, 1);
        }
        _ => panic!("Expected AutoSyncResponse"),
    }
}

// ═══════════════════════════════════════════════════════════════
// INTÉGRATION : Trust Store — cycle complet avec ML-DSA-65
// ═══════════════════════════════════════════════════════════════

/// Crée un TrustStore déverrouillé dans un dossier temporaire
fn create_unlocked_store(key_byte: u8) -> (TrustStore, TempDir) {
    let tmp = TempDir::new().unwrap();
    let mut store = TrustStore::load(tmp.path()).unwrap();
    let key = SecureKey::from_slice(&[key_byte; 32]);
    store.unlock(&key).unwrap();
    (store, tmp)
}

#[test]
fn test_trust_store_full_lifecycle() {
    let (mut store, _tmp) = create_unlocked_store(0x42);

    // 1. Ajouter des pairs
    store.trust_peer("Alice", "AA:BB:CC:DD:EE:FF:00:11").unwrap();
    store.trust_peer("Bob", "11:22:33:44:55:66:77:88").unwrap();
    assert_eq!(store.list_trusted().len(), 2);

    // 2. Enregistrer des transferts
    store.record_transfer("AA:BB:CC:DD:EE:FF:00:11").unwrap();
    store.record_transfer("AA:BB:CC:DD:EE:FF:00:11").unwrap();
    store.record_transfer("11:22:33:44:55:66:77:88").unwrap();

    // 3. Configurer la synchronisation
    store.set_sync_enabled(true).unwrap();
    let vk = store.device_verifying_key_b64().unwrap();
    store.add_sync_device("Self", &vk).unwrap();

    // 4. Exporter pour sync (signé ML-DSA)
    let export = store.export_for_sync().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&export).unwrap();
    assert_eq!(parsed["signer_verifying_key"].as_str().unwrap(), &vk);

    // 5. Révoquer un pair
    store.revoke_trust("11:22:33:44:55:66:77:88").unwrap();
    assert_eq!(store.list_trusted().len(), 1);
    assert!(!store.is_trusted("11:22:33:44:55:66:77:88"));

    // 6. Supprimer un sync device
    store.remove_sync_device(&vk).unwrap();
    assert_eq!(store.list_sync_devices().len(), 0);
}

/// Test la synchronisation bidirectionnelle entre deux stores
#[test]
fn test_bidirectional_sync_between_stores() {
    let (mut store_a, _tmp_a) = create_unlocked_store(0x60);
    let (mut store_b, _tmp_b) = create_unlocked_store(0x61);

    let vk_a = store_a.device_verifying_key_b64().unwrap();
    let vk_b = store_b.device_verifying_key_b64().unwrap();

    // Activer sync et s'autoriser mutuellement
    store_a.set_sync_enabled(true).unwrap();
    store_b.set_sync_enabled(true).unwrap();
    store_a.add_sync_device("StoreB", &vk_b).unwrap();
    store_b.add_sync_device("StoreA", &vk_a).unwrap();

    // A a des peers que B n'a pas
    store_a.trust_peer("PeerFromA", "AA:AA:AA:AA:AA:AA:AA:AA").unwrap();
    // B a des peers que A n'a pas
    store_b.trust_peer("PeerFromB", "BB:BB:BB:BB:BB:BB:BB:BB").unwrap();

    // A → B
    let export_a = store_a.export_for_sync().unwrap();
    let merged_into_b = store_b.merge_from_sync(&export_a).unwrap();
    assert_eq!(merged_into_b, 1);
    assert!(store_b.is_trusted("AA:AA:AA:AA:AA:AA:AA:AA"));

    // B → A
    let export_b = store_b.export_for_sync().unwrap();
    let merged_into_a = store_a.merge_from_sync(&export_b).unwrap();
    assert_eq!(merged_into_a, 1);
    assert!(store_a.is_trusted("BB:BB:BB:BB:BB:BB:BB:BB"));

    // Les deux stores ont maintenant les mêmes peers
    assert_eq!(store_a.list_trusted().len(), 2);
    assert_eq!(store_b.list_trusted().len(), 2);
}

/// Test que la fusion respecte le transfer_count
#[test]
fn test_sync_merge_conflict_resolution() {
    let (mut store_a, _tmp_a) = create_unlocked_store(0x70);
    let (mut store_b, _tmp_b) = create_unlocked_store(0x71);

    let vk_a = store_a.device_verifying_key_b64().unwrap();
    let vk_b = store_b.device_verifying_key_b64().unwrap();

    store_a.set_sync_enabled(true).unwrap();
    store_b.set_sync_enabled(true).unwrap();
    store_a.add_sync_device("B", &vk_b).unwrap();
    store_b.add_sync_device("A", &vk_a).unwrap();

    // Les deux ont le même peer, mais A a plus de transfers
    store_a.trust_peer("SharedPeer", "CC:CC:CC:CC:CC:CC:CC:CC").unwrap();
    for _ in 0..10 { store_a.record_transfer("CC:CC:CC:CC:CC:CC:CC:CC").unwrap(); }

    store_b.trust_peer("SharedPeer", "CC:CC:CC:CC:CC:CC:CC:CC").unwrap();
    for _ in 0..3 { store_b.record_transfer("CC:CC:CC:CC:CC:CC:CC:CC").unwrap(); }

    // B exporte (count=3) → merge dans A (count=10) → A garde le sien
    let export_b = store_b.export_for_sync().unwrap();
    let merged = store_a.merge_from_sync(&export_b).unwrap();
    assert_eq!(merged, 0); // A a plus de transfers, rien ne change
    let peer_a = store_a.list_trusted().into_iter()
        .find(|p| p.fingerprint == "CC:CC:CC:CC:CC:CC:CC:CC").unwrap();
    assert_eq!(peer_a.transfer_count, 10);

    // A exporte (count=10) → merge dans B (count=3) → B prend celui de A
    let export_a = store_a.export_for_sync().unwrap();
    let merged = store_b.merge_from_sync(&export_a).unwrap();
    assert_eq!(merged, 1);
    let peer_b = store_b.list_trusted().into_iter()
        .find(|p| p.fingerprint == "CC:CC:CC:CC:CC:CC:CC:CC").unwrap();
    assert_eq!(peer_b.transfer_count, 10);
}

// ═══════════════════════════════════════════════════════════════
// INTÉGRATION : Session chiffrée — sécurité
// ═══════════════════════════════════════════════════════════════

/// Vérifie qu'un attaquant qui altère le ciphertext provoque un rejet
#[tokio::test]
async fn test_session_tampered_ciphertext_rejected() {
    let key = [0xEEu8; 32];
    let mut sender = SecureSession::new(key, true).unwrap();
    let mut receiver = SecureSession::new(key, false).unwrap();

    let msg = TransferMessage::TransferComplete;
    let mut buf = Vec::new();
    sender.send_message(&mut buf, &msg).await.unwrap();

    // Altérer un byte dans le ciphertext (après le header)
    if buf.len() > 5 {
        buf[5] ^= 0xFF;
    }

    let mut cursor = tokio::io::BufReader::new(&buf[..]);
    let result = receiver.recv_message(&mut cursor).await;
    assert!(result.is_err());
}

/// Vérifie qu'un replay d'un ancien message est rejeté (nonce counter out-of-order)
#[tokio::test]
async fn test_session_replay_detection() {
    let key = [0xFFu8; 32];
    let mut sender = SecureSession::new(key, true).unwrap();
    let mut receiver = SecureSession::new(key, false).unwrap();

    // Envoyer 2 messages
    let mut buf1 = Vec::new();
    sender.send_message(&mut buf1, &TransferMessage::TransferComplete).await.unwrap();
    let mut buf2 = Vec::new();
    sender.send_message(&mut buf2, &TransferMessage::TransferAccept { accepted: true }).await.unwrap();

    // Receiver décrypte le premier normalement
    let mut cursor1 = tokio::io::BufReader::new(&buf1[..]);
    let _ = receiver.recv_message(&mut cursor1).await.unwrap();

    // Si on rejoue le premier message au lieu du second → erreur de déchiffrement
    let mut cursor_replay = tokio::io::BufReader::new(&buf1[..]);
    let result = receiver.recv_message(&mut cursor_replay).await;
    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════
// INTÉGRATION : Protocole frame robustesse
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_encode_decode_all_message_types() {
    let messages: Vec<TransferMessage> = vec![
        TransferMessage::Hello {
            protocol_version: 1,
            peer_name: "Test".to_string(),
            capabilities: vec![],
        },
        TransferMessage::SpakeMessage { body: vec![0x01, 0x02, 0x03] },
        TransferMessage::KemEncapsulation { ek_bytes: vec![0xAA; 32] },
        TransferMessage::KemCiphertext { ct_bytes: vec![0xBB; 32] },
        TransferMessage::SafetyNumberConfirm { confirmed: true },
        TransferMessage::TransferOffer {
            items: vec![],
            total_size: 0,
        },
        TransferMessage::TransferAccept { accepted: false },
        TransferMessage::DataChunk {
            item_index: 0,
            chunk_index: 0,
            data: vec![],
            is_last: true,
            integrity_hash: String::new(),
            is_last_chunk: true,
        },
        TransferMessage::Ack { item_index: 0, integrity_ok: true },
        TransferMessage::TransferComplete,
        TransferMessage::TrustStoreSync { trust_data: "{}".to_string() },
        TransferMessage::TrustStoreSyncAck { merged_count: 5 },
        TransferMessage::SyncPairRequest {
            device_name: "D".to_string(),
            verifying_key_b64: "vk".to_string(),
        },
        TransferMessage::SyncPairResponse {
            device_name: "D".to_string(),
            verifying_key_b64: "vk".to_string(),
            accepted: true,
        },
        TransferMessage::AutoSyncRequest {
            device_name: "A".to_string(),
            verifying_key_b64: "k".to_string(),
            trust_data: "d".to_string(),
        },
        TransferMessage::AutoSyncResponse {
            accepted: true,
            device_name: "B".to_string(),
            verifying_key_b64: "k".to_string(),
            trust_data: "d".to_string(),
            merged_count: 0,
        },
        TransferMessage::Error { code: 500, message: "test".to_string() },
    ];

    for msg in &messages {
        let frame = encode_message(msg)
            .unwrap_or_else(|e| panic!("Encode failed for {:?}: {}", msg, e));
        let decoded = decode_message(&frame)
            .unwrap_or_else(|e| panic!("Decode failed for {:?}: {}", msg, e));
        // Vérifier que le type correspond (pattern match)
        let original_type = std::mem::discriminant(msg);
        let decoded_type = std::mem::discriminant(&decoded);
        assert_eq!(original_type, decoded_type, "Type mismatch for {:?}", msg);
    }
}

// ═══════════════════════════════════════════════════════════════
// INTÉGRATION : Trust Store persistence
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_trust_store_persistence_across_unlock_cycles() {
    let tmp = TempDir::new().unwrap();
    let key = SecureKey::from_slice(&[0x88u8; 32]);

    // Cycle 1: créer et peupler
    {
        let mut store = TrustStore::load(tmp.path()).unwrap();
        store.unlock(&key).unwrap();
        store.trust_peer("PersistentPeer", "PP:PP:PP:PP:PP:PP:PP:PP").unwrap();
        store.set_sync_enabled(true).unwrap();
        store.add_sync_device("MySyncDevice", "c3luY19kZXZpY2U=").unwrap();
        store.record_transfer("PP:PP:PP:PP:PP:PP:PP:PP").unwrap();
    }

    // Cycle 2: recharger et vérifier
    {
        let mut store = TrustStore::load(tmp.path()).unwrap();
        store.unlock(&key).unwrap();
        
        assert!(store.is_trusted("PP:PP:PP:PP:PP:PP:PP:PP"));
        assert!(store.is_sync_enabled());
        assert_eq!(store.list_sync_devices().len(), 1);
        assert_eq!(store.list_sync_devices()[0].name, "MySyncDevice");
        
        let peers = store.list_trusted();
        let peer = peers.iter().find(|p| p.name == "PersistentPeer").unwrap();
        assert_eq!(peer.transfer_count, 1);
    }

    // Cycle 3: mauvaise clé → erreur signalée (VULN-006: pas de réinitialisation silencieuse)
    {
        let mut store = TrustStore::load(tmp.path()).unwrap();
        let bad_key = SecureKey::from_slice(&[0x99u8; 32]);
        let result = store.unlock(&bad_key);
        assert!(result.is_err(), "unlock with wrong key must return an error");
        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("corrompu ou clé changée"),
            "Error message should mention corruption or key change: {}", err_msg
        );
        // L'ancien fichier est sauvegardé en .bak
        assert!(tmp.path().join("trust_store.enc.bak").exists());
    }
}

// ═══════════════════════════════════════════════════════════════
// INTÉGRATION : Fingerprint
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_fingerprint_format_and_consistency() {
    let fp = TrustStore::compute_fingerprint(b"some-public-key-bytes");
    // Format XX:XX:XX:XX:XX:XX:XX:XX
    let parts: Vec<&str> = fp.split(':').collect();
    assert_eq!(parts.len(), 8);
    for part in &parts {
        assert_eq!(part.len(), 2);
        assert!(part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // Même entrée → même sortie
    assert_eq!(fp, TrustStore::compute_fingerprint(b"some-public-key-bytes"));
    // Entrée différente → sortie différente
    assert_ne!(fp, TrustStore::compute_fingerprint(b"different-key"));
}

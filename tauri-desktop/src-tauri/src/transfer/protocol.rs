//! Protocol — Types de messages sur le fil (MessagePack).
//!
//! Chaque message est sérialisé en MessagePack, chiffré par la session
//! ChaCha20-Poly1305, puis envoyé sous forme de frame length-prefixed.

use serde::{Serialize, Deserialize};

/// Version du protocole
pub const PROTOCOL_VERSION: u8 = 1;

/// Taille maximale d'un message sur le fil (2 MiB — inclut chunk + overhead AEAD)
pub const MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024;

/// Taille maximale d'un chunk de données (512 KiB).
/// Les payloads plus grands sont découpés en plusieurs DataChunks.
pub const CHUNK_DATA_SIZE: usize = 512 * 1024;

/// Taille du header de frame (4 bytes big-endian length)
pub const FRAME_HEADER_SIZE: usize = 4;

/// Identifiant du service mDNS
pub const MDNS_SERVICE_TYPE: &str = "_fluxlock-transfer._tcp.local.";

/// Port par défaut pour le transfert direct
pub const DEFAULT_TRANSFER_PORT: u16 = 52_820;

/// Messages du protocole de transfert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferMessage {
    /// Phase 1 : Hello — annonce les capacités
    Hello {
        protocol_version: u8,
        peer_name: String,
        capabilities: Vec<String>,
    },

    /// Phase 2 : SPAKE2 — message A ou B
    SpakeMessage {
        body: Vec<u8>,
    },

    /// Phase 3 : ML-KEM encapsulation
    KemEncapsulation {
        /// Clé publique ML-KEM-768 (1184 bytes)
        ek_bytes: Vec<u8>,
    },

    /// Phase 3b : ML-KEM ciphertext
    KemCiphertext {
        /// Ciphertext (1088 bytes)
        ct_bytes: Vec<u8>,
    },

    /// Phase 4 : Safety number confirmation
    SafetyNumberConfirm {
        confirmed: bool,
    },

    /// Phase 5 : Offre de transfert — liste des items à envoyer
    TransferOffer {
        items: Vec<TransferItem>,
        total_size: u64,
    },

    /// Phase 5b : Réponse à l'offre
    TransferAccept {
        accepted: bool,
    },

    /// Phase 6 : Chunk de données chiffré
    DataChunk {
        item_index: u32,
        chunk_index: u32,
        data: Vec<u8>,
        is_last: bool,
        /// BLAKE3 hash of `data` for end-to-end integrity verification
        #[serde(default)]
        integrity_hash: String,
        /// Dernier chunk de cet item (true = item complet, prêt à traiter).
        /// Default true pour rétro-compatibilité avec les messages pré-streaming.
        #[serde(default = "bool_true")]
        is_last_chunk: bool,
    },

    /// Phase 7 : Accusé de réception
    Ack {
        item_index: u32,
        integrity_ok: bool,
    },

    /// Fin du transfert
    TransferComplete,

    /// Synchronisation du trust store entre pairs (serverless P2P sync)
    TrustStoreSync {
        /// JSON chiffré par la session (déjà dans SecureSession, double protection)
        trust_data: String,
    },

    /// Accusé de sync trust store
    TrustStoreSyncAck {
        /// Nombre de pairs fusionnés
        merged_count: u32,
    },

    /// Demande d'appairage sync : envoie le nom et la clé publique ML-DSA-65
    SyncPairRequest {
        device_name: String,
        verifying_key_b64: String,
    },

    /// Réponse d'appairage sync : accepte/refuse et renvoie sa propre clé ML-DSA-65
    SyncPairResponse {
        device_name: String,
        verifying_key_b64: String,
        accepted: bool,
    },

    /// Demande de sync automatique : un appareil appairé envoie sa VK + trust store signé
    AutoSyncRequest {
        device_name: String,
        verifying_key_b64: String,
        /// Trust store signé ML-DSA-65
        trust_data: String,
    },

    /// Réponse de sync automatique : l'autre appareil renvoie son trust store signé
    AutoSyncResponse {
        accepted: bool,
        device_name: String,
        verifying_key_b64: String,
        trust_data: String,
        merged_count: u32,
    },

    /// Erreur
    Error {
        code: u16,
        message: String,
    },
}

/// Item à transférer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferItem {
    pub item_type: TransferItemType,
    pub name: String,
    pub size: u64,
    /// BLAKE3 hash du contenu chiffré
    pub integrity_hash: String,
}

/// Types d'items transférables
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransferItemType {
    Password,
    SecureFile,
    SecureKey,
    VaultBackup,
}

/// Encode un message en frame length-prefixed MessagePack
pub fn encode_message(msg: &TransferMessage) -> Result<Vec<u8>, String> {
    let payload = rmp_serde::to_vec(msg).map_err(|e| format!("Sérialisation échouée: {}", e))?;
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(format!("Message trop grand: {} > {}", payload.len(), MAX_MESSAGE_SIZE));
    }
    let len = (payload.len() as u32).to_be_bytes();
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len());
    frame.extend_from_slice(&len);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Décode un frame length-prefixed MessagePack
pub fn decode_message(frame: &[u8]) -> Result<TransferMessage, String> {
    if frame.len() < FRAME_HEADER_SIZE {
        return Err("Frame trop courte".to_string());
    }
    let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(format!("Frame trop grande: {}", len));
    }
    if frame.len() < FRAME_HEADER_SIZE + len {
        return Err("Frame incomplète".to_string());
    }
    rmp_serde::from_slice(&frame[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + len])
        .map_err(|e| format!("Désérialisation échouée: {}", e))
}

/// Lit exactement un message depuis un flux async
/// CFG-005: Timeout de 30s pour éviter le blocage indéfini (DoS)
pub async fn read_message<R: tokio::io::AsyncReadExt + Unpin>(reader: &mut R) -> Result<TransferMessage, String> {
    use tokio::time::{timeout, Duration};
    const READ_TIMEOUT: Duration = Duration::from_secs(30);

    let mut len_buf = [0u8; FRAME_HEADER_SIZE];
    timeout(READ_TIMEOUT, reader.read_exact(&mut len_buf))
        .await
        .map_err(|_| "Timeout lecture header (30s)".to_string())?
        .map_err(|e| format!("Lecture header: {}", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(format!("Message trop grand: {}", len));
    }
    let mut payload = vec![0u8; len];
    timeout(READ_TIMEOUT, reader.read_exact(&mut payload))
        .await
        .map_err(|_| "Timeout lecture payload (30s)".to_string())?
        .map_err(|e| format!("Lecture payload: {}", e))?;
    rmp_serde::from_slice(&payload).map_err(|e| format!("Désérialisation: {}", e))
}

/// Écrit un message sur un flux async
pub async fn write_message<W: tokio::io::AsyncWriteExt + Unpin>(writer: &mut W, msg: &TransferMessage) -> Result<(), String> {
    let payload = rmp_serde::to_vec(msg).map_err(|e| format!("Sérialisation: {}", e))?;
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(format!("Message trop grand: {}", payload.len()));
    }
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await.map_err(|e| format!("Écriture header: {}", e))?;
    writer.write_all(&payload).await.map_err(|e| format!("Écriture payload: {}", e))?;
    writer.flush().await.map_err(|e| format!("Flush: {}", e))?;
    Ok(())
}

/// Helper pour serde: valeur par défaut `true` (rétro-compatibilité streaming).
fn bool_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ═══ encode_message / decode_message round-trip ═══

    #[test]
    fn test_hello_roundtrip() {
        let msg = TransferMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            peer_name: "TestDevice".to_string(),
            capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string()],
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::Hello { protocol_version, peer_name, capabilities } => {
                assert_eq!(protocol_version, PROTOCOL_VERSION);
                assert_eq!(peer_name, "TestDevice");
                assert_eq!(capabilities.len(), 2);
            }
            _ => panic!("Expected Hello message"),
        }
    }

    #[test]
    fn test_error_roundtrip() {
        let msg = TransferMessage::Error {
            code: 404,
            message: "Pair non trouvé".to_string(),
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::Error { code, message } => {
                assert_eq!(code, 404);
                assert_eq!(message, "Pair non trouvé");
            }
            _ => panic!("Expected Error message"),
        }
    }

    #[test]
    fn test_transfer_offer_roundtrip() {
        let items = vec![
            TransferItem {
                item_type: TransferItemType::Password,
                name: "github.com".to_string(),
                size: 256,
                integrity_hash: "abc123".to_string(),
            },
            TransferItem {
                item_type: TransferItemType::SecureFile,
                name: "backup.zip".to_string(),
                size: 1024 * 1024,
                integrity_hash: "def456".to_string(),
            },
        ];
        let msg = TransferMessage::TransferOffer {
            items: items.clone(),
            total_size: 1024 * 1024 + 256,
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::TransferOffer { items: decoded_items, total_size } => {
                assert_eq!(total_size, 1024 * 1024 + 256);
                assert_eq!(decoded_items.len(), 2);
                assert_eq!(decoded_items[0].name, "github.com");
                assert_eq!(decoded_items[1].item_type, TransferItemType::SecureFile);
            }
            _ => panic!("Expected TransferOffer message"),
        }
    }

    #[test]
    fn test_auto_sync_request_roundtrip() {
        let msg = TransferMessage::AutoSyncRequest {
            device_name: "MonPC".to_string(),
            verifying_key_b64: "dGVzdC1rZXk=".to_string(),
            trust_data: r#"{"peers":{}}"#.to_string(),
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::AutoSyncRequest { device_name, verifying_key_b64, trust_data } => {
                assert_eq!(device_name, "MonPC");
                assert_eq!(verifying_key_b64, "dGVzdC1rZXk=");
                assert!(trust_data.contains("peers"));
            }
            _ => panic!("Expected AutoSyncRequest message"),
        }
    }

    #[test]
    fn test_auto_sync_response_roundtrip() {
        let msg = TransferMessage::AutoSyncResponse {
            accepted: true,
            device_name: "Téléphone".to_string(),
            verifying_key_b64: "a2V5".to_string(),
            trust_data: "{}".to_string(),
            merged_count: 3,
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::AutoSyncResponse { accepted, device_name, merged_count, .. } => {
                assert!(accepted);
                assert_eq!(device_name, "Téléphone");
                assert_eq!(merged_count, 3);
            }
            _ => panic!("Expected AutoSyncResponse message"),
        }
    }

    #[test]
    fn test_kem_encapsulation_roundtrip() {
        let msg = TransferMessage::KemEncapsulation {
            ek_bytes: vec![0xAA; 1184], // ML-KEM-768 public key size
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::KemEncapsulation { ek_bytes } => {
                assert_eq!(ek_bytes.len(), 1184);
                assert!(ek_bytes.iter().all(|&b| b == 0xAA));
            }
            _ => panic!("Expected KemEncapsulation message"),
        }
    }

    #[test]
    fn test_kem_ciphertext_roundtrip() {
        let msg = TransferMessage::KemCiphertext {
            ct_bytes: vec![0xBB; 1088], // ML-KEM-768 ciphertext size
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::KemCiphertext { ct_bytes } => {
                assert_eq!(ct_bytes.len(), 1088);
            }
            _ => panic!("Expected KemCiphertext message"),
        }
    }

    #[test]
    fn test_sync_pair_request_roundtrip() {
        let msg = TransferMessage::SyncPairRequest {
            device_name: "Desktop".to_string(),
            verifying_key_b64: "dmVyaWZ5aW5nX2tleQ==".to_string(),
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::SyncPairRequest { device_name, verifying_key_b64 } => {
                assert_eq!(device_name, "Desktop");
                assert_eq!(verifying_key_b64, "dmVyaWZ5aW5nX2tleQ==");
            }
            _ => panic!("Expected SyncPairRequest message"),
        }
    }

    #[test]
    fn test_data_chunk_roundtrip() {
        let msg = TransferMessage::DataChunk {
            item_index: 0,
            chunk_index: 5,
            data: vec![0x42; CHUNK_DATA_SIZE],
            is_last: false,
            integrity_hash: "blake3hash".to_string(),
            is_last_chunk: false,
        };
        let frame = encode_message(&msg).unwrap();
        let decoded = decode_message(&frame).unwrap();
        match decoded {
            TransferMessage::DataChunk { item_index, chunk_index, data, is_last, is_last_chunk, .. } => {
                assert_eq!(item_index, 0);
                assert_eq!(chunk_index, 5);
                assert_eq!(data.len(), CHUNK_DATA_SIZE);
                assert!(!is_last);
                assert!(!is_last_chunk);
            }
            _ => panic!("Expected DataChunk message"),
        }
    }

    // ═══ Frame format validation ═══

    #[test]
    fn test_frame_header_is_big_endian_length() {
        let msg = TransferMessage::TransferComplete;
        let frame = encode_message(&msg).unwrap();
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(len, frame.len() - FRAME_HEADER_SIZE);
    }

    #[test]
    fn test_decode_frame_too_short() {
        let result = decode_message(&[0, 0]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("trop courte"));
    }

    #[test]
    fn test_decode_frame_incomplete() {
        // Header says 100 bytes but only 4 bytes of payload
        let mut frame = vec![0, 0, 0, 100, 1, 2, 3, 4];
        let result = decode_message(&frame);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("incomplète"));
    }

    #[test]
    fn test_encode_oversized_message_rejected() {
        // Create a message larger than MAX_MESSAGE_SIZE
        let msg = TransferMessage::DataChunk {
            item_index: 0,
            chunk_index: 0,
            data: vec![0xFF; MAX_MESSAGE_SIZE + 1],
            is_last: true,
            integrity_hash: String::new(),
            is_last_chunk: true,
        };
        let result = encode_message(&msg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("trop grand"));
    }

    // ═══ Async read/write round-trip ═══

    #[tokio::test]
    async fn test_async_write_read_roundtrip() {
        let msg = TransferMessage::SafetyNumberConfirm { confirmed: true };
        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = tokio::io::BufReader::new(&buf[..]);
        let decoded = read_message(&mut cursor).await.unwrap();
        match decoded {
            TransferMessage::SafetyNumberConfirm { confirmed } => assert!(confirmed),
            _ => panic!("Expected SafetyNumberConfirm"),
        }
    }

    #[tokio::test]
    async fn test_async_multiple_messages() {
        let messages = vec![
            TransferMessage::Hello {
                protocol_version: 1,
                peer_name: "A".to_string(),
                capabilities: vec![],
            },
            TransferMessage::TransferAccept { accepted: true },
            TransferMessage::TransferComplete,
        ];

        let mut buf = Vec::new();
        for msg in &messages {
            write_message(&mut buf, msg).await.unwrap();
        }

        let mut cursor = tokio::io::BufReader::new(&buf[..]);
        // Read back all 3 messages
        let m1 = read_message(&mut cursor).await.unwrap();
        assert!(matches!(m1, TransferMessage::Hello { .. }));
        let m2 = read_message(&mut cursor).await.unwrap();
        assert!(matches!(m2, TransferMessage::TransferAccept { accepted: true }));
        let m3 = read_message(&mut cursor).await.unwrap();
        assert!(matches!(m3, TransferMessage::TransferComplete));
    }

    // ═══ TransferItemType ═══

    #[test]
    fn test_transfer_item_types() {
        assert_eq!(TransferItemType::Password, TransferItemType::Password);
        assert_ne!(TransferItemType::Password, TransferItemType::SecureFile);
        assert_ne!(TransferItemType::SecureKey, TransferItemType::VaultBackup);
    }
}

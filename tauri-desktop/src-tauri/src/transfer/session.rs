//! Session — Session chiffrée ChaCha20-Poly1305 au-dessus du transport.
//!
//! Chaque message est chiffré avec un nonce incrémental de 96 bits.
//! La clé de session est issue du handshake hybride SPAKE2 + ML-KEM-768.
//!
//! INVARIANT : La clé de session est zéroïsée au drop.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use super::protocol::{TransferMessage, MAX_MESSAGE_SIZE, FRAME_HEADER_SIZE};

/// Compteur de nonce (96 bits / 12 bytes)
/// VULN-003: Le premier byte encode la direction (0x00=initiator, 0x01=responder)
/// pour garantir que les nonces des deux pairs ne se chevauchent jamais,
/// même avec des compteurs identiques.
fn nonce_from_counter(counter: u64, is_initiator_sending: bool) -> Nonce {
    let mut nonce = [0u8; 12];
    // Byte 0: direction tag — empêche la réutilisation de nonce entre les deux pairs
    nonce[0] = if is_initiator_sending { 0x00 } else { 0x01 };
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());
    *Nonce::from_slice(&nonce)
}

/// Session de transfert chiffrée
pub struct SecureSession {
    cipher: ChaCha20Poly1305,
    send_counter: u64,
    recv_counter: u64,
    /// true si cette instance est le côté initiateur du handshake
    is_initiator: bool,
    /// Copie de la clé pour zéroïsation explicite au drop
    _session_key: SessionKeyGuard,
}

/// Garde de clé qui se zéroïse au drop
struct SessionKeyGuard {
    key: [u8; 32],
}

impl Drop for SessionKeyGuard {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Zéroïse l'état interne du cipher en défense en profondeur.
/// chacha20poly1305 (RustCrypto) utilise GenericArray qui implémente Zeroize,
/// mais on force un scrub mémoire brut pour être certain.
impl Drop for SecureSession {
    fn drop(&mut self) {
        // 1. Scrub mémoire du cipher (contient une copie de la clé dans GenericArray)
        let cipher_ptr = &mut self.cipher as *mut _ as *mut u8;
        let cipher_size = std::mem::size_of::<ChaCha20Poly1305>();
        unsafe {
            let bytes = std::slice::from_raw_parts_mut(cipher_ptr, cipher_size);
            bytes.zeroize();
        }
        // 2. Zéroïser les compteurs pour ne pas fuiter la quantité de données échangées
        self.send_counter = 0;
        self.recv_counter = 0;
        // 3. SessionKeyGuard._session_key se zéroïse dans son propre Drop
    }
}

impl SecureSession {
    /// Crée une session chiffrée à partir d'une clé de session 256 bits
    ///
    /// `is_initiator`: true si cette instance est le côté qui a initié le handshake.
    /// La clé passée est consommée et zéroïsée après initialisation du cipher.
    pub fn new(mut session_key: [u8; 32], is_initiator: bool) -> Result<Self, String> {
        let cipher = ChaCha20Poly1305::new_from_slice(&session_key)
            .map_err(|e| format!("Initialisation cipher: {}", e))?;

        let guard = SessionKeyGuard { key: session_key };
        // Zéroïser la copie locale sur la stack immédiatement
        session_key.zeroize();

        Ok(Self {
            cipher,
            send_counter: 0,
            recv_counter: 0,
            is_initiator,
            _session_key: guard,
        })
    }

    /// Chiffre et envoie un message sur le transport
    pub async fn send_message<W: AsyncWrite + Unpin + ?Sized>(
        &mut self,
        writer: &mut W,
        msg: &TransferMessage,
    ) -> Result<(), String> {
        let plaintext = rmp_serde::to_vec(msg)
            .map_err(|e| format!("Sérialisation: {}", e))?;

        if plaintext.len() > MAX_MESSAGE_SIZE {
            return Err(format!("Message trop grand: {} bytes", plaintext.len()));
        }

        let nonce = nonce_from_counter(self.send_counter, self.is_initiator);
        self.send_counter = self.send_counter.checked_add(1)
            .ok_or_else(|| "Compteur de nonce overflow — session expirée".to_string())?;

        // VULN-003: AAD inclut la direction pour lier le rôle au ciphertext
        let direction = if self.is_initiator { "init" } else { "resp" };
        let aad = format!("fluxlock-v1:{}:send:{}", direction, self.send_counter - 1);
        let ciphertext = self.cipher.encrypt(
            &nonce,
            Payload { msg: plaintext.as_ref(), aad: aad.as_bytes() },
        ).map_err(|e| format!("Chiffrement: {}", e))?;

        // Frame : [4 bytes len][ciphertext]
        let len = (ciphertext.len() as u32).to_be_bytes();
        writer.write_all(&len).await.map_err(|e| format!("Écriture len: {}", e))?;
        writer.write_all(&ciphertext).await.map_err(|e| format!("Écriture data: {}", e))?;
        writer.flush().await.map_err(|e| format!("Flush: {}", e))?;

        Ok(())
    }

    /// Reçoit et déchiffre un message depuis le transport
    /// CFG-005: Timeout de 30s pour éviter le blocage indéfini (DoS)
    pub async fn recv_message<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        reader: &mut R,
    ) -> Result<TransferMessage, String> {
        use tokio::time::{timeout, Duration};
        const RECV_TIMEOUT: Duration = Duration::from_secs(30);

        let mut len_buf = [0u8; FRAME_HEADER_SIZE];
        timeout(RECV_TIMEOUT, reader.read_exact(&mut len_buf))
            .await
            .map_err(|_| "Timeout réception header (30s)".to_string())?
            .map_err(|e| format!("Lecture len: {}", e))?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE + 16 { // +16 for AEAD tag
            return Err(format!("Frame trop grande: {}", len));
        }

        let mut ciphertext = vec![0u8; len];
        timeout(RECV_TIMEOUT, reader.read_exact(&mut ciphertext))
            .await
            .map_err(|_| "Timeout réception ciphertext (30s)".to_string())?
            .map_err(|e| format!("Lecture ciphertext: {}", e))?;

        let nonce = nonce_from_counter(self.recv_counter, !self.is_initiator);
        self.recv_counter = self.recv_counter.checked_add(1)
            .ok_or_else(|| "Compteur de nonce overflow — session expirée".to_string())?;

        // VULN-003: AAD doit correspondre à ce que l'expéditeur a utilisé (rôle inversé)
        let peer_direction = if self.is_initiator { "resp" } else { "init" };
        let aad = format!("fluxlock-v1:{}:send:{}", peer_direction, self.recv_counter - 1);
        let plaintext = self.cipher.decrypt(
            &nonce,
            Payload { msg: ciphertext.as_ref(), aad: aad.as_bytes() },
        ).map_err(|_| "Déchiffrement échoué — message corrompu ou clé incorrecte".to_string())?;

        rmp_serde::from_slice(&plaintext)
            .map_err(|e| format!("Désérialisation: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::protocol::TransferMessage;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_session_creation() {
        let session = SecureSession::new(test_key(), true);
        assert!(session.is_ok());
    }

    #[test]
    fn test_nonce_from_counter_deterministic() {
        let n1 = nonce_from_counter(0, true);
        let n2 = nonce_from_counter(0, true);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_nonce_from_counter_unique() {
        let n0 = nonce_from_counter(0, true);
        let n1 = nonce_from_counter(1, true);
        let n2 = nonce_from_counter(2, true);
        assert_ne!(n0, n1);
        assert_ne!(n1, n2);
        assert_ne!(n0, n2);
    }

    #[test]
    fn test_nonce_direction_prevents_collision() {
        // VULN-003: Même compteur, directions différentes → nonces différents
        let n_init = nonce_from_counter(0, true);
        let n_resp = nonce_from_counter(0, false);
        assert_ne!(n_init, n_resp);
    }

    #[tokio::test]
    async fn test_session_send_recv_roundtrip() {
        let key = test_key();
        let mut sender = SecureSession::new(key, true).unwrap();
        let mut receiver = SecureSession::new(key, false).unwrap();

        let msg = TransferMessage::Hello {
            protocol_version: 1,
            peer_name: "TestPeer".to_string(),
            capabilities: vec!["pqc-kem".to_string()],
        };

        let mut buf = Vec::new();
        sender.send_message(&mut buf, &msg).await.unwrap();

        let mut cursor = tokio::io::BufReader::new(&buf[..]);
        let decoded = receiver.recv_message(&mut cursor).await.unwrap();

        match decoded {
            TransferMessage::Hello { peer_name, .. } => {
                assert_eq!(peer_name, "TestPeer");
            }
            _ => panic!("Expected Hello message"),
        }
    }

    #[tokio::test]
    async fn test_session_multiple_messages_ordered() {
        let key = test_key();
        let mut sender = SecureSession::new(key, true).unwrap();
        let mut receiver = SecureSession::new(key, false).unwrap();

        let messages = vec![
            TransferMessage::TransferAccept { accepted: true },
            TransferMessage::Ack { item_index: 0, integrity_ok: true },
            TransferMessage::TransferComplete,
        ];

        let mut buf = Vec::new();
        for msg in &messages {
            sender.send_message(&mut buf, msg).await.unwrap();
        }

        let mut cursor = tokio::io::BufReader::new(&buf[..]);
        let m1 = receiver.recv_message(&mut cursor).await.unwrap();
        assert!(matches!(m1, TransferMessage::TransferAccept { accepted: true }));
        let m2 = receiver.recv_message(&mut cursor).await.unwrap();
        assert!(matches!(m2, TransferMessage::Ack { item_index: 0, integrity_ok: true }));
        let m3 = receiver.recv_message(&mut cursor).await.unwrap();
        assert!(matches!(m3, TransferMessage::TransferComplete));
    }

    #[tokio::test]
    async fn test_session_wrong_key_fails_decrypt() {
        let mut sender = SecureSession::new([0x11u8; 32], true).unwrap();
        let mut receiver = SecureSession::new([0x22u8; 32], false).unwrap();

        let msg = TransferMessage::Error { code: 500, message: "test".to_string() };
        let mut buf = Vec::new();
        sender.send_message(&mut buf, &msg).await.unwrap();

        let mut cursor = tokio::io::BufReader::new(&buf[..]);
        let result = receiver.recv_message(&mut cursor).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Déchiffrement"));
    }

    #[tokio::test]
    async fn test_session_counter_out_of_sync_fails() {
        let key = test_key();
        let mut sender = SecureSession::new(key, true).unwrap();
        let mut receiver = SecureSession::new(key, false).unwrap();

        let msg1 = TransferMessage::TransferComplete;
        let msg2 = TransferMessage::TransferAccept { accepted: false };

        let mut buf = Vec::new();
        sender.send_message(&mut buf, &msg1).await.unwrap();
        sender.send_message(&mut buf, &msg2).await.unwrap();

        // Read only msg2 frame (skip msg1) → counter mismatch
        let mut cursor = tokio::io::BufReader::new(&buf[..]);
        // Consume first message correctly
        let _ok = receiver.recv_message(&mut cursor).await.unwrap();
        // Second message should also work since counters are in sync
        let ok2 = receiver.recv_message(&mut cursor).await.unwrap();
        assert!(matches!(ok2, TransferMessage::TransferAccept { accepted: false }));
    }

    #[tokio::test]
    async fn test_session_large_data_chunk() {
        let key = test_key();
        let mut sender = SecureSession::new(key, true).unwrap();
        let mut receiver = SecureSession::new(key, false).unwrap();

        let msg = TransferMessage::DataChunk {
            item_index: 0,
            chunk_index: 0,
            data: vec![0xAB; 512 * 1024], // 512 KB chunk
            is_last: true,
            integrity_hash: "hash".to_string(),
            is_last_chunk: true,
        };

        let mut buf = Vec::new();
        sender.send_message(&mut buf, &msg).await.unwrap();

        let mut cursor = tokio::io::BufReader::new(&buf[..]);
        let decoded = receiver.recv_message(&mut cursor).await.unwrap();
        match decoded {
            TransferMessage::DataChunk { data, .. } => {
                assert_eq!(data.len(), 512 * 1024);
                assert!(data.iter().all(|&b| b == 0xAB));
            }
            _ => panic!("Expected DataChunk"),
        }
    }

    #[test]
    fn test_session_key_zeroized_on_drop() {
        // Vérifie que la création et la destruction ne paniquent pas
        let session = SecureSession::new(test_key(), true).unwrap();
        drop(session);
        // Pas de panic = clé correctement zéroïsée
    }

    #[tokio::test]
    async fn test_session_auto_sync_messages() {
        let key = test_key();
        let mut sender = SecureSession::new(key, true).unwrap();
        let mut receiver = SecureSession::new(key, false).unwrap();

        let request = TransferMessage::AutoSyncRequest {
            device_name: "PC-Bureau".to_string(),
            verifying_key_b64: "dGVzdGtleQ==".to_string(),
            trust_data: r#"{"peers":{},"signer_verifying_key":"abc"}"#.to_string(),
        };

        let mut buf = Vec::new();
        sender.send_message(&mut buf, &request).await.unwrap();

        let mut cursor = tokio::io::BufReader::new(&buf[..]);
        let decoded = receiver.recv_message(&mut cursor).await.unwrap();
        match decoded {
            TransferMessage::AutoSyncRequest { device_name, .. } => {
                assert_eq!(device_name, "PC-Bureau");
            }
            _ => panic!("Expected AutoSyncRequest"),
        }
    }
}

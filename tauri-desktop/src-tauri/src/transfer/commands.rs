//! Commands — Commandes Tauri exposées au frontend.
//!
//! C1: transfer_create_offer       — Crée une offre (sender): TCP/TLS listener + mDNS + wormhole
//! C2: transfer_connect             — Connecte et handshake (receiver)
//! C3: transfer_confirm_and_execute — Confirme safety number + transfère (sender ou receiver)
//! C4: transfer_scan_local_network  — Scan mDNS + IPv6
//! C5: transfer_get_trusted_peers   — Liste les pairs de confiance
//! C6: transfer_revoke_trust        — Révoque un pair
//! C7: transfer_get_status          — Statut d'un transfert en cours
//! C8: transfer_cancel              — Annule un transfert
//! C16: transfer_start_sync_pairing — Démarre l'appairage sync (initiateur, background)
//! C17: transfer_join_sync_pairing  — Rejoint l'appairage sync (joiner, bloquant)
//!
//! ## Architecture de sécurité
//! Toutes les connexions passent par TLS (transport.rs) + SecureSession
//! (ChaCha20-Poly1305) pour les messages post-handshake.

use serde::{Serialize, Deserialize};
use tokio::sync::Mutex;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::sync::Arc;
use zeroize::Zeroize;

use super::discovery::{DiscoveryService, DiscoveredPeer};
use super::handshake;
use super::trust_store::TrustStore;
use super::transport::{TransportListener, TransportConnection, connect_to_peer};
use super::protocol::{self, TransferMessage, TransferItem, TransferItemType, DEFAULT_TRANSFER_PORT, CHUNK_DATA_SIZE};
use super::session::SecureSession;
use super::{ConnectionMethod, TransferState, TransferInfo, WORMHOLE_TTL_SECS};

use crate::crypto::{encrypt_data_secure, decrypt_data_secure};

/// Données d'un mot de passe sérialisées pour le transfert (plaintext transitoire)
#[derive(Debug, Serialize, Deserialize)]
struct TransferPasswordPayload {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub category: Option<String>,
}

impl Drop for TransferPasswordPayload {
    fn drop(&mut self) {
        self.title.zeroize();
        self.password.zeroize();
        if let Some(ref mut u) = self.username { u.zeroize(); }
        if let Some(ref mut u) = self.url { u.zeroize(); }
        if let Some(ref mut n) = self.notes { n.zeroize(); }
        if let Some(ref mut c) = self.category { c.zeroize(); }
    }
}

/// Métadonnées d'un fichier sérialisées en tête du flux de transfert
#[derive(Debug, Serialize, Deserialize)]
struct TransferFileMetadata {
    pub filename: String,       // nom chiffré (on le re-chiffrera côté receiver)
    pub original_size: i64,
    pub mime_type: Option<String>,
    pub integrity_hash: Option<String>,
}

impl Drop for TransferFileMetadata {
    fn drop(&mut self) {
        self.filename.zeroize();
        if let Some(ref mut m) = self.mime_type { m.zeroize(); }
        if let Some(ref mut h) = self.integrity_hash { h.zeroize(); }
    }
}

/// Rôle dans le transfert
#[derive(Debug, Clone, PartialEq)]
pub enum TransferRole {
    Sender,
    Receiver,
}

/// État global du module de transfert
pub struct TransferManager {
    pub discovery: DiscoveryService,
    pub trust_store: Arc<Mutex<TrustStore>>,
    pub active_transfers: Arc<Mutex<HashMap<String, TransferInfo>>>,
    /// Only one local offer can own the advertised endpoint.
    active_offer: Arc<Mutex<Option<(String, tokio::task::JoinHandle<()>)>>>,
    registry_sync_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Active transport connections keyed by transfer_id
    pub active_connections: Arc<Mutex<HashMap<String, TransportConnection>>>,
    /// Active secure sessions keyed by transfer_id (post-handshake)
    pub active_sessions: Arc<Mutex<HashMap<String, SecureSession>>>,
    /// Transfer roles keyed by transfer_id
    pub transfer_roles: Arc<Mutex<HashMap<String, TransferRole>>>,
    /// Pending items to transfer keyed by transfer_id → (item_type, item_ids)
    pub pending_items: Arc<Mutex<HashMap<String, (String, Vec<i64>)>>>,
    /// Whether this device is visible on the network (mDNS discoverable)
    pub visible: Arc<Mutex<bool>>,
    pub peer_name: String,
}

impl TransferManager {
    pub fn new(app_data_dir: &std::path::Path, peer_name: &str) -> Result<Self, String> {
        let trust_store = TrustStore::load(app_data_dir)?;
        let visible = Arc::new(Mutex::new(false));
        let discovery = DiscoveryService::new(peer_name, visible.clone());

        Ok(Self {
            discovery,
            trust_store: Arc::new(Mutex::new(trust_store)),
            active_transfers: Arc::new(Mutex::new(HashMap::new())),
            active_offer: Arc::new(Mutex::new(None)),
            registry_sync_task: Mutex::new(None),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
            transfer_roles: Arc::new(Mutex::new(HashMap::new())),
            pending_items: Arc::new(Mutex::new(HashMap::new())),
            visible,
            peer_name: peer_name.to_string(),
        })
    }

    async fn start_registry_sync(&self, state: &crate::AppState) -> Result<(), String> {
        let mut task = self.registry_sync_task.lock().await;
        if task.as_ref().is_some_and(|task| !task.is_finished()) {
            return Ok(());
        }
        let token = state.session_token.lock().await.clone().ok_or("Session inactive")?;
        let fingerprint = self.trust_store.lock().await.local_sync_fingerprint()?;
        self.discovery.set_trust_info(Some(fingerprint), Vec::new()).await;
        let listener = TransportListener::bind(0).await?;
        let worker = super::registry_sync::RegistrySync {
            trust_store: self.trust_store.clone(),
            session_token: state.session_token.clone(),
            isolation: state.isolation_mode.clone(),
            token,
        };
        *task = Some(tokio::spawn(worker.run(listener, self.discovery.clone())));
        Ok(())
    }

    pub(crate) async fn stop_registry_sync(&self) {
        if let Some(task) = self.registry_sync_task.lock().await.take() {
            task.abort();
            let _ = task.await;
        }
        self.discovery.advertise_registry_sync(0).await;
    }

    pub(crate) async fn stop_offers(&self) {
        let mut offer = self.active_offer.lock().await;
        if let Some((id, task)) = offer.take() {
            task.abort();
            let _ = task.await;
            if let Some(info) = self.active_transfers.lock().await.get_mut(&id) {
                info.state = TransferState::Failed { reason: "Offre annulée".into() };
            }
        }
        self.discovery.clear_offer().await;
    }

}

const NEGOTIATION_TIMEOUT: Duration = Duration::from_secs(12);
const DIRECT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OfferKind {
    Transfer,
    Pairing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PairingProtocol {
    Legacy,
    SignedRegistry,
}

const OFFER_ACK_CAPABILITY: &str = "offer-ready-v1";

struct PeerHello {
    name: String,
    pairing_protocol: PairingProtocol,
    acknowledge_offer: bool,
}

fn capabilities(kind: OfferKind) -> Vec<String> {
    let mut capabilities = vec!["pqc-kem".into(), "chacha20".into()];
    if kind == OfferKind::Pairing {
        capabilities.extend(["sync-pair-v2".into(), "sync-pair".into()]);
    } else {
        capabilities.push(OFFER_ACK_CAPABILITY.into());
    }
    capabilities
}

fn read_hello(message: TransferMessage, kind: OfferKind) -> Result<PeerHello, String> {
    let TransferMessage::Hello { peer_name, protocol_version, capabilities } = message else {
        return Err("Le pair n’a pas envoyé de message Hello".into());
    };
    if protocol_version != protocol::PROTOCOL_VERSION {
        return Err("Version du protocole incompatible. Mettez à jour les deux appareils.".into());
    }
    let pairing = if capabilities.iter().any(|capability| capability == "sync-pair-v2") {
        Some(PairingProtocol::SignedRegistry)
    } else if capabilities.iter().any(|capability| capability == "sync-pair") {
        Some(PairingProtocol::Legacy)
    } else {
        None
    };
    let pairing_protocol = match (kind, pairing) {
        (OfferKind::Pairing, Some(pairing)) => pairing,
        (OfferKind::Transfer, None) => PairingProtocol::Legacy,
        _ => return Err("Le code correspond à un autre type d’offre (transfert ou appairage).".into()),
    };
    Ok(PeerHello {
        name: peer_name,
        pairing_protocol,
        acknowledge_offer: capabilities.iter().any(|capability| capability == OFFER_ACK_CAPABILITY),
    })
}

fn parse_access_code(raw_code: &str) -> Result<(&str, Option<DiscoveredPeer>), String> {
    let raw_code = raw_code.trim();
    let Some((code, endpoint)) = raw_code.split_once('@') else {
        return Ok((raw_code, None));
    };
    let address: std::net::SocketAddr = endpoint.parse()
        .map_err(|_| "Adresse ou port invalide dans le code temporaire")?;
    if address.port() == 0 {
        return Err("Port invalide dans le code temporaire".into());
    }
    let addr = match address {
        std::net::SocketAddr::V6(v6) if v6.scope_id() != 0 => format!("{}%{}", v6.ip(), v6.scope_id()),
        _ => address.ip().to_string(),
    };
    Ok((code, Some(DiscoveredPeer {
        name: "Adresse du code".into(),
        addr,
        port: address.port(),
        method: "Direct".into(),
        verified: false,
    })))
}

async fn listen_for_offer(
    listener: &TransportListener,
    deadline: tokio::time::Instant,
) -> Result<TransportConnection, String> {
    let reverse = async {
        loop {
            if let Ok(peer) = super::discovery::discover_receiver_peer(10).await {
                if let Ok(connection) = connect_to_peer(&peer).await {
                    return connection;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    tokio::time::timeout_at(deadline, async {
        tokio::select! {
            result = listener.accept() => result,
            result = reverse => Ok(result),
        }
    }).await.map_err(|_| "Le code temporaire a expiré".to_string())?
}

struct NegotiatedOffer {
    connection: TransportConnection,
    session: SecureSession,
    safety_number: String,
    peer_name: String,
    pairing_protocol: PairingProtocol,
    first_message: TransferMessage,
}

async fn negotiate_offer(
    mut connection: TransportConnection, code: &str, name: &str, kind: OfferKind,
) -> Result<NegotiatedOffer, String> {
    let stream = &mut connection.stream;
    protocol::write_message(stream, &TransferMessage::Hello {
        protocol_version: protocol::PROTOCOL_VERSION,
        peer_name: name.to_owned(),
        capabilities: capabilities(kind),
    }).await?;
    let peer = read_hello(protocol::read_message(stream).await?, kind)?;

    let responder = handshake::HandshakeResponder::new(code)?;
    protocol::write_message(stream, &TransferMessage::SpakeMessage {
        body: responder.spake_message().to_vec(),
    }).await?;
    let TransferMessage::SpakeMessage { body } = protocol::read_message(stream).await? else {
        return Err("Protocole invalide : message SPAKE2 attendu".into());
    };
    let TransferMessage::KemEncapsulation { ek_bytes } = protocol::read_message(stream).await? else {
        return Err("Protocole invalide : encapsulation KEM attendue".into());
    };
    let (result, ct_bytes) = responder.complete_handshake(&body, &ek_bytes)?;
    protocol::write_message(stream, &TransferMessage::KemCiphertext { ct_bytes }).await?;
    let mut session = SecureSession::new(result.session_key, false)?;
    let first_message = session.recv_message(stream).await?;
    let valid = matches!(
        (kind, &first_message),
        (OfferKind::Transfer, TransferMessage::TransferOffer { .. })
            | (OfferKind::Pairing, TransferMessage::SyncPairRequest { .. })
    );
    if !valid {
        return Err("Le pair n’a pas transmis l’offre attendue".into());
    }
    if kind == OfferKind::Transfer && peer.acknowledge_offer {
        session.send_message(stream, &TransferMessage::OfferReady).await?;
    }
    Ok(NegotiatedOffer {
        connection, session, safety_number: result.safety_number.clone(),
        peer_name: peer.name, pairing_protocol: peer.pairing_protocol, first_message,
    })
}

async fn initiate_offer(
    stream: &mut Box<dyn super::transport::AsyncReadWrite>, code: &str, name: &str, kind: OfferKind,
) -> Result<(PeerHello, SecureSession, String), String> {
    let peer = read_hello(protocol::read_message(stream).await?, kind)?;
    protocol::write_message(stream, &TransferMessage::Hello {
        protocol_version: protocol::PROTOCOL_VERSION,
        peer_name: name.to_owned(),
        capabilities: capabilities(kind),
    }).await?;
    let TransferMessage::SpakeMessage { body } = protocol::read_message(stream).await? else {
        return Err("Protocole invalide : message SPAKE2 attendu".into());
    };
    let initiator = handshake::HandshakeInitiator::new(code)?;
    protocol::write_message(stream, &TransferMessage::SpakeMessage {
        body: initiator.spake_message().to_vec(),
    }).await?;
    let spake = initiator.complete_spake2(&body)?;
    protocol::write_message(stream, &TransferMessage::KemEncapsulation {
        ek_bytes: spake.ek_bytes.clone(),
    }).await?;
    let TransferMessage::KemCiphertext { ct_bytes } = protocol::read_message(stream).await? else {
        return Err("Protocole invalide : encapsulation KEM attendue".into());
    };
    let result = spake.finalize_with_kem(&ct_bytes)?;
    let session = SecureSession::new(result.session_key, true)?;
    Ok((peer, session, result.safety_number.clone()))
}

async fn send_transfer_offer(
    stream: &mut Box<dyn super::transport::AsyncReadWrite>,
    session: &mut SecureSession,
    items: Vec<TransferItem>,
    total_size: u64,
    acknowledge_offer: bool,
) -> Result<(), String> {
    session.send_message(stream, &TransferMessage::TransferOffer { items, total_size }).await?;
    if acknowledge_offer && !matches!(session.recv_message(stream).await?, TransferMessage::OfferReady) {
        return Err("Le destinataire n’a pas confirmé l’offre de transfert".into());
    }
    Ok(())
}

async fn receive_offer(
    discovery: &DiscoveryService,
    code: &str,
    name: &str,
    kind: OfferKind,
    direct_peers: Vec<DiscoveredPeer>,
) -> Result<NegotiatedOffer, String> {
    // Validate the code even when there is no network candidate.
    handshake::HandshakeResponder::new(code)?;
    if let Err(error) = discovery.start_mdns_discovery().await {
        eprintln!("[TRANSFER] Démarrage de la découverte : {error}");
    }
    let deadline = tokio::time::Instant::now() + DIRECT_DISCOVERY_TIMEOUT;
    let mut attempted = HashSet::new();
    let mut last_error = None;
    loop {
        let mut peers = direct_peers.clone();
        peers.extend(discovery.get_discovered_peers().await);
        for peer in peers {
            if peer.port == 0 || !attempted.insert((peer.addr.clone(), peer.port)) {
                continue;
            }
            let result = tokio::time::timeout(NEGOTIATION_TIMEOUT, async {
                let conn = connect_to_peer(&peer).await?;
                negotiate_offer(conn, code, name, kind).await
            }).await.unwrap_or_else(|_| Err("Délai de négociation avec le pair dépassé".into()));
            match result {
                Ok(offer) => return Ok(offer),
                Err(error) => last_error = Some(error),
            }
            if attempted.len() >= 8 {
                break;
            }
        }
        if tokio::time::Instant::now() >= deadline || attempted.len() >= 8 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let listener = TransportListener::bind(0).await?;
    let port = listener.local_port;
    if let Err(error) = discovery.register_receiver_mdns(port).await {
        return Err(last_error.unwrap_or(error));
    }
    let reverse_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let result = loop {
        let Ok(connection) = tokio::time::timeout_at(reverse_deadline, listener.accept()).await else {
            break Err(last_error.unwrap_or_else(|| {
                "Aucune offre joignable. Vérifiez que l’autre appareil attend la connexion.".into()
            }));
        };
        let connection = match connection {
            Ok(connection) => connection,
            Err(error) => break Err(error),
        };
        let deadline = reverse_deadline.min(tokio::time::Instant::now() + NEGOTIATION_TIMEOUT);
        match tokio::time::timeout_at(deadline, negotiate_offer(connection, code, name, kind)).await {
            Ok(Ok(offer)) => break Ok(offer),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => last_error = Some("Délai de négociation inverse dépassé".into()),
        }
    };
    discovery.unregister_receiver_mdns(port).await;
    result

}

const MAX_TRANSFER_ITEM_BYTES: usize = 32 * 1024 * 1024;
const MAX_TRANSFER_METADATA_BYTES: usize = 8 * 1024;

#[derive(Default)]
struct LimitedTransferBuffer {
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl std::io::Write for LimitedTransferBuffer {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > MAX_TRANSFER_ITEM_BYTES.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("Fichier trop volumineux pour le transfert"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn validate_transfer_chunk(
    expected_item: u32, expected_chunk: u32, accumulated: usize,
    item: u32, chunk: u32, size: usize, finished: bool, last: bool, last_chunk: bool,
) -> Result<(), String> {
    if finished || item != expected_item || chunk != expected_chunk
        || size == 0 || size > CHUNK_DATA_SIZE || (last && !last_chunk)
        || accumulated.saturating_add(size) > MAX_TRANSFER_ITEM_BYTES + MAX_TRANSFER_METADATA_BYTES
    {
        return Err("Séquence de blocs ou taille de transfert invalide".into());
    }
    Ok(())
}

#[cfg(test)]
mod transfer_limits_tests {
    use super::*;

    #[tokio::test]
    async fn tcp_offer_requires_the_receiver_to_authenticate_before_confirming() {
        let listener = TransportListener::bind(0).await.unwrap();
        let peer = DiscoveredPeer {
            name: "instance de test".into(),
            addr: "127.0.0.1".into(),
            port: listener.local_port,
            method: "Direct".into(),
            verified: false,
        };
        let code = handshake::generate_wormhole_code();
        let wrong_code = loop {
            let candidate = handshake::generate_wormhole_code();
            if candidate != code { break candidate; }
        };
        for (receiver_code, should_connect) in [(&wrong_code, false), (&code, true)] {
            let (sender, receiver) = tokio::time::timeout(Duration::from_secs(5), async {
                let (sender, receiver) = tokio::join!(listener.accept(), connect_to_peer(&peer));
                let mut sender = sender.unwrap();
                let receiver = receiver.unwrap();
                assert_eq!(sender.channel_binding, receiver.channel_binding);
                let outgoing = async {
                    let (hello, mut session, number) =
                        initiate_offer(&mut sender.stream, &code, "sender", OfferKind::Transfer).await?;
                    send_transfer_offer(&mut sender.stream, &mut session, vec![TransferItem {
                        item_type: TransferItemType::Password, name: "fixture".into(),
                        size: 12, integrity_hash: String::new(),
                    }], 12, hello.acknowledge_offer).await?;
                    let confirmation = session.recv_message(&mut sender.stream).await?;
                    assert!(matches!(confirmation, TransferMessage::SafetyNumberConfirm { confirmed: true }));
                    Ok::<_, String>(number)
                };
                let incoming = async {
                    let mut offer = negotiate_offer(receiver, receiver_code, "receiver", OfferKind::Transfer).await?;
                    assert!(matches!(offer.first_message, TransferMessage::TransferOffer { total_size: 12, .. }));
                    offer.session.send_message(&mut offer.connection.stream,
                        &TransferMessage::SafetyNumberConfirm { confirmed: true }).await?;
                    Ok::<_, String>(offer.safety_number)
                };
                tokio::join!(outgoing, incoming)
            }).await.unwrap();
            if should_connect {
                assert_eq!(sender.unwrap(), receiver.unwrap());
            } else {
                assert!(sender.is_err());
                assert!(receiver.is_err());
            }
        }
    }

    #[test]
    fn chunks_must_be_ordered_bounded_and_end_on_item_boundary() {
        assert!(validate_transfer_chunk(1, 2, 12, 1, 2, 10, false, true, true).is_ok());
        assert!(validate_transfer_chunk(1, 2, 12, 1, 3, 10, false, false, true).is_err());
        assert!(validate_transfer_chunk(1, 2, 12, 0, 2, 10, false, false, true).is_err());
        assert!(validate_transfer_chunk(1, 2, 12, 1, 2, 10, false, true, false).is_err());
        assert!(validate_transfer_chunk(1, 2, 12, 1, 2, 10, true, false, true).is_err());
        assert!(validate_transfer_chunk(1, 2, MAX_TRANSFER_ITEM_BYTES + MAX_TRANSFER_METADATA_BYTES,
            1, 2, 10, false, false, true).is_err());
    }
}

/// Requête de création d'offre
#[derive(Debug, Deserialize)]
pub struct CreateOfferRequest {
    pub item_type: String,
    pub item_ids: Vec<i64>,
    /// If true, embed the public IPv6 address in the wormhole code for cross-network transfers
    #[serde(default)]
    pub cross_network: bool,
}

/// Réponse de création d'offre
#[derive(Debug, Serialize)]
pub struct CreateOfferResponse {
    pub transfer_id: String,
    pub wormhole_code: String,
    pub connection_method: String,
}

/// Requête de connexion
#[derive(Debug, Deserialize)]
pub struct ConnectRequest {
    pub wormhole_code: String,
    /// Optional: direct peer address from mDNS discovery (Peers tab click-to-connect)
    pub peer_addr: Option<String>,
    /// Optional: direct peer port from mDNS discovery
    pub peer_port: Option<u16>,
}

/// Réponse de connexion
#[derive(Debug, Serialize)]
pub struct ConnectResponse {
    pub transfer_id: String,
    pub safety_number: String,
    pub peer_name: String,
    pub connection_method: String,
    pub items: Vec<TransferItemInfo>,
    pub total_size: u64,
}

/// Info d'item pour le frontend
#[derive(Debug, Clone, Serialize)]
pub struct TransferItemInfo {
    pub name: String,
    pub item_type: String,
    pub size: u64,
}

/// C1 : Crée une offre de transfert (côté sender)
///
/// 1. Génère un code wormhole
/// 2. Lance un TCP/TLS listener
/// 3. Enregistre le service mDNS
/// 4. Spawne un background task qui accepte la connexion, fait le handshake
///    sender-side (SPAKE2 initiator + ML-KEM), et prépare la session.
#[tauri::command]
pub async fn transfer_create_offer(
    request: CreateOfferRequest,
    state: tauri::State<'_, crate::AppState>,
) -> Result<CreateOfferResponse, String> {
    // Vérifier le mode isolation réseau
    if *state.isolation_mode.lock().await {
        return Err("Mode isolation activé — transferts réseau désactivés".to_string());
    }
    // Vérifier l'authentification
    crate::validate_session(&state).await?;

    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié")?;

    // Fetch items from DB to build real TransferOffer
    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let transfer_items = match request.item_type.as_str() {
        "passwords" => {
            let all_passwords = db.get_passwords(user_id).await
                .map_err(|e| format!("Erreur DB: {}", e))?;
            all_passwords.into_iter()
                .filter(|p| request.item_ids.contains(&p.id))
                .map(|p| TransferItem {
                    item_type: TransferItemType::Password,
                    name: p.title.clone(),
                    size: p.password.len() as u64,
                    integrity_hash: String::new(),
                })
                .collect::<Vec<_>>()
        }
        "files" => {
            let all_files = db.get_secure_files(user_id).await
                .map_err(|e| format!("Erreur DB fichiers: {}", e))?;
            all_files.into_iter()
                .filter(|f| request.item_ids.contains(&f.id))
                .map(|f| TransferItem {
                    item_type: TransferItemType::SecureFile,
                    name: f.filename.clone(),
                    size: f.file_size as u64,
                    integrity_hash: f.integrity_hash.clone().unwrap_or_default(),
                })
                .collect::<Vec<_>>()
        }
        _ => vec![],
    };
    let total_size: u64 = transfer_items.iter().map(|i| i.size).sum();

    // Log l'action
    let _ = db.log_action(user_id, "TRANSFER_OFFER_CREATE", "transfer", None).await;
    drop(db_guard);

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    // Générer le code wormhole
    let base_wormhole_code = handshake::generate_wormhole_code();
    let transfer_id = uuid::Uuid::new_v4().to_string();

    let mut active_offer = tm.active_offer.lock().await;
    if active_offer.is_some() {
        return Err("Une offre est déjà en attente sur cet appareil.".into());
    }

    // Start TCP/TLS listener
    let listener = match TransportListener::bind(DEFAULT_TRANSFER_PORT).await {
        Ok(l) => l,
        Err(_) => TransportListener::bind(0).await
            .map_err(|e| format!("Erreur listener : {}", e))?,
    };
    let actual_port = listener.local_port;
    eprintln!("[TRANSFER] Sender listener bound on port {}", actual_port);

    // Start mDNS discovery + register this device on the ACTUAL port
    if let Err(e) = tm.discovery.start_mdns_discovery().await {
        eprintln!("[TRANSFER] start_mdns_discovery failed: {}", e);
    }
    if let Err(e) = tm.discovery.advertise_offer(actual_port).await {
        eprintln!("[TRANSFER] register_mdns_service_on_port({}) failed: {}", actual_port, e);
    }

    // Wormhole code: clean code for same-network, IPv6 appended only for cross-network
    let wormhole_code = if request.cross_network {
        if let Some(v6) = super::discovery::get_public_ipv6_address() {
            eprintln!("[TRANSFER] Cross-network: public IPv6 = {}", v6);
            format!("{}@[{}]:{}", base_wormhole_code, v6, actual_port)
        } else {
            eprintln!("[TRANSFER] Cross-network requested but no public IPv6 found");
            base_wormhole_code.clone()
        }
    } else {
        eprintln!("[TRANSFER] Same-network: clean wormhole code");
        base_wormhole_code.clone()
    };

    // Store pending items for C3
    tm.pending_items.lock().await.insert(
        transfer_id.clone(),
        (request.item_type.clone(), request.item_ids.clone()),
    );

    // Store listener for accept phase
    let listener = Arc::new(listener);

    // Enregistrer le transfert
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    tm.active_transfers.lock().await.insert(transfer_id.clone(), TransferInfo {
        transfer_id: transfer_id.clone(),
        state: TransferState::WaitingForPeer,
        connection_method: ConnectionMethod::MdnsLocal,
        safety_number: None,
        peer_name: None,
        created_at: now_epoch,
    });

    // Mark as sender
    tm.transfer_roles.lock().await.insert(transfer_id.clone(), TransferRole::Sender);

    // Clone shared state for background task
    let active_transfers = tm.active_transfers.clone();
    let active_connections = tm.active_connections.clone();
    let active_sessions = tm.active_sessions.clone();
    let tid = transfer_id.clone();
    let wc = base_wormhole_code.clone(); // SPAKE2 uses base code only (without #ip:port)
    let peer_name_clone = tm.peer_name.clone();
    let offer_items = transfer_items.clone();
    let offer_total_size = total_size;

    // Spawn background task: accept incoming connection OR discover receiver + connect out
    let discovery = tm.discovery.clone();
    let active_slot = tm.active_offer.clone();
    let task = tokio::spawn(async move {
        let result: Result<(), String> = async {
            // ═══ V-03 SPAKE2 rate-limiting ═══
            // Retry loop with exponential backoff to throttle brute-force attempts.
            // An attacker trying random wormhole codes will be delayed exponentially
            // and locked out after MAX_HANDSHAKE_ATTEMPTS failures.
            const MAX_HANDSHAKE_ATTEMPTS: u32 = 5;
            const BASE_BACKOFF_MS: u64 = 1000; // 1s → 2s → 4s → 8s → 16s
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(WORMHOLE_TTL_SECS);
            let mut handshake_failures: u32 = 0;

            loop {
                // Check global deadline
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    return Err(format!(
                        "Code wormhole expiré après {} secondes",
                        WORMHOLE_TTL_SECS
                    ));
                }
                let remaining = deadline - now;

                eprintln!(
                    "[TRANSFER] Sender background: waiting for connection (failures={}/{}, remaining={:?})",
                    handshake_failures, MAX_HANDSHAKE_ATTEMPTS, remaining
                );

                let conn = match listen_for_offer(&listener, deadline).await {
                    Ok(c) => c,
                    Err(e) => {
                        if tokio::time::Instant::now() >= deadline { return Err(e); }
                        // Connection-level error (not handshake); count as failure too
                        handshake_failures += 1;
                        eprintln!(
                            "[TRANSFER] ⚠️ Connexion échouée (tentative {}/{}): {}",
                            handshake_failures, MAX_HANDSHAKE_ATTEMPTS, e
                        );
                        if handshake_failures >= MAX_HANDSHAKE_ATTEMPTS {
                            return Err(format!(
                                "Trop de tentatives échouées ({}/{}), possible attaque — abandon",
                                handshake_failures, MAX_HANDSHAKE_ATTEMPTS
                            ));
                        }
                        let delay = BASE_BACKOFF_MS * (1u64 << (handshake_failures - 1));
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        continue;
                    }
                };

                let peer_addr_log = conn.peer_addr.clone();
                eprintln!("[TRANSFER] Sender: connected to {}! Starting handshake...", peer_addr_log);

                // ─── Attempt full SPAKE2 + ML-KEM handshake ───
                let handshake_result: Result<(), String> = tokio::time::timeout(remaining.min(NEGOTIATION_TIMEOUT), async {
                    let mut conn = conn;
                    let stream = &mut conn.stream;

                    if let Some(info) = active_transfers.lock().await.get_mut(&tid) {
                        info.state = TransferState::Handshaking;
                    }
                    let (peer, mut secure_session, safety_number) =
                        initiate_offer(stream, &wc, &peer_name_clone, OfferKind::Transfer).await?;
                    send_transfer_offer(
                        stream, &mut secure_session, offer_items.clone(), offer_total_size, peer.acknowledge_offer,
                    ).await?;

                    active_connections.lock().await.insert(tid.clone(), conn);
                    active_sessions.lock().await.insert(tid.clone(), secure_session);
                    if let Some(info) = active_transfers.lock().await.get_mut(&tid) {
                        info.state = TransferState::ConfirmingSafetyNumber;
                        info.safety_number = Some(safety_number);
                        info.peer_name = Some(peer.name);
                    }

                    Ok(())
                }).await.unwrap_or_else(|_| Err("Délai de négociation dépassé".into()));

                match handshake_result {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        handshake_failures += 1;
                        eprintln!(
                            "[TRANSFER] ⚠️ Handshake échoué depuis {} (tentative {}/{}): {}",
                            peer_addr_log, handshake_failures, MAX_HANDSHAKE_ATTEMPTS, e
                        );
                        if handshake_failures >= MAX_HANDSHAKE_ATTEMPTS {
                            return Err(format!(
                                "Trop de tentatives de handshake échouées ({}/{}), possible attaque par force brute — abandon",
                                handshake_failures, MAX_HANDSHAKE_ATTEMPTS
                            ));
                        }
                        // Exponential backoff: 1s, 2s, 4s, 8s, 16s
                        let delay = BASE_BACKOFF_MS * (1u64 << (handshake_failures - 1));
                        eprintln!(
                            "[TRANSFER] Rate-limit: backoff {}ms avant prochaine tentative",
                            delay
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        // Continue loop: accept next connection
                    }
                }
            } // end rate-limit loop
        }.await;

        if let Err(e) = result {
            if let Some(info) = active_transfers.lock().await.get_mut(&tid) {
                info.state = TransferState::Failed { reason: e };
            }
        }
        let mut active = active_slot.lock().await;
        if active.as_ref().is_some_and(|(id, _)| id == &tid) {
            discovery.clear_offer().await;
            active.take();
        }
    });
    *active_offer = Some((transfer_id.clone(), task));

    Ok(CreateOfferResponse {
        transfer_id,
        wormhole_code,
        connection_method: format!("Local TLS (port {})", actual_port),
    })
}

/// C2 : Connecte au pair et lance le handshake (côté receiver)
///
/// 1. Scan réseau (mDNS + IPv6)
/// 2. Connecte au sender via TLS
/// 3. Échange SPAKE2 + ML-KEM handshake
/// 4. Reçoit l'offre via SecureSession (chiffrée)
/// 5. Retourne safety number pour confirmation
#[tauri::command]
pub async fn transfer_connect(
    request: ConnectRequest,
    state: tauri::State<'_, crate::AppState>,
) -> Result<ConnectResponse, String> {
    // Vérifier le mode isolation réseau
    if *state.isolation_mode.lock().await {
        return Err("Mode isolation activé — transferts réseau désactivés".to_string());
    }
    // Vérifier l'authentification
    crate::validate_session(&state).await?;

    let session_token = state.session_token.lock().await.clone();
    let (discovery, name) = {
        let tm = state.transfer_manager.lock().await;
        let tm = tm.as_ref().ok_or("Module de transfert non initialisé")?;
        (tm.discovery.clone(), tm.peer_name.clone())
    };
    let (code, endpoint) = parse_access_code(&request.wormhole_code)?;
    let direct_peer = request.peer_addr.zip(request.peer_port).map(|(addr, port)| DiscoveredPeer {
        name: "Pair découvert".into(), addr, port, method: "Direct".into(), verified: false,
    });
    let offer = receive_offer(&discovery, code, &name, OfferKind::Transfer,
        endpoint.into_iter().chain(direct_peer).collect()).await?;
    let NegotiatedOffer {
        connection, session: secure_session, safety_number, peer_name: sender_name,
        first_message: TransferMessage::TransferOffer { items, total_size }, ..
    } = offer else {
        return Err("Offre de transfert invalide".into());
    };
    let items = items.into_iter().map(|i| TransferItemInfo {
        name: i.name, item_type: format!("{:?}", i.item_type), size: i.size,
    }).collect();
    let method = connection.method.clone();
    let connection_method = method.to_string();
    let user_id = crate::validate_session(&state).await?;
    let tm_guard = state.transfer_manager.lock().await;
    if *state.isolation_mode.lock().await || *state.session_token.lock().await != session_token {
        return Err("Transfert annulé".into());
    }
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;
    let transfer_id = uuid::Uuid::new_v4().to_string();
    tm.active_connections.lock().await.insert(transfer_id.clone(), connection);
    tm.active_sessions.lock().await.insert(transfer_id.clone(), secure_session);
    tm.transfer_roles.lock().await.insert(transfer_id.clone(), TransferRole::Receiver);

    // Record transfer state
    tm.active_transfers.lock().await.insert(transfer_id.clone(), TransferInfo {
        transfer_id: transfer_id.clone(),
        state: TransferState::ConfirmingSafetyNumber,
        connection_method: method,
        safety_number: Some(safety_number.clone()),
        peer_name: Some(sender_name.clone()),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });

    drop(tm_guard);
    if let Some(db) = state.db.lock().await.as_ref() {
        let _ = db.log_action(user_id, "TRANSFER_CONNECT", "transfer", None).await;
    }

    Ok(ConnectResponse {
        transfer_id,
        safety_number,
        peer_name: sender_name,
        connection_method,
        items,
        total_size,
    })
}

/// C3 : Confirme le safety number et exécute le transfert
///
/// Gère les deux rôles :
/// - **Receiver** : envoie confirmation, reçoit les chunks chiffrés via SecureSession,
///   re-chiffre avec la clé vault locale et stocke dans la DB
/// - **Sender** : attend la confirmation, lit les items du vault, les déchiffre,
///   les envoie via SecureSession
#[tauri::command]
pub async fn transfer_confirm_and_execute(
    transfer_id: String,
    confirmed: bool,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    crate::validate_session(&state).await?;
    if *state.isolation_mode.lock().await {
        return Err("Transfert bloqué en mode isolation".into());
    }

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    if !confirmed {
        // Annuler le transfert
        tm.active_transfers.lock().await.remove(&transfer_id);
        tm.active_connections.lock().await.remove(&transfer_id);
        tm.active_sessions.lock().await.remove(&transfer_id);
        tm.transfer_roles.lock().await.remove(&transfer_id);
        tm.pending_items.lock().await.remove(&transfer_id);
        return Ok(false);
    }

    // Determine our role
    let role = tm.transfer_roles.lock().await.get(&transfer_id).cloned()
        .unwrap_or(TransferRole::Receiver);

    // Take ownership of connection and session (remove from maps to avoid holding locks during I/O)
    let conn = tm.active_connections.lock().await.remove(&transfer_id);
    let session = tm.active_sessions.lock().await.remove(&transfer_id);

    let (mut stream, mut secure_session) = match (conn, session) {
        (Some(c), Some(s)) => (c.stream, s),
        _ => return Err("Connexion ou session de transfert introuvable".to_string()),
    };

    // Get user_id and DB access
    let user_id = state.current_user_id.lock().await
        .ok_or("Non authentifié")?;

    // Update state
    if let Some(info) = tm.active_transfers.lock().await.get_mut(&transfer_id) {
        info.state = TransferState::Transferring {
            progress_pct: 0,
            bytes_sent: 0,
            total_bytes: 0,
        };
    }

    // Drop tm_guard before long I/O operations to not hold the lock
    drop(tm_guard);

    match role {
        TransferRole::Receiver => {
            // === RECEIVER: send confirmation, receive data, store in vault ===

            // Send safety number confirmation via SecureSession
            let confirm_msg = TransferMessage::SafetyNumberConfirm { confirmed: true };
            secure_session.send_message(&mut stream, &confirm_msg).await?;

            // Send transfer accept via SecureSession
            let accept = TransferMessage::TransferAccept { accepted: true };
            secure_session.send_message(&mut stream, &accept).await?;

            // Get vault key for re-encryption
            let vault_key = crate::get_or_fetch_vault_key(&state, user_id).await
                .map_err(|e| format!("Erreur récupération clé vault: {}", e))?;

            // Receive encrypted data chunks and store them
            // Chunk accumulator: reassemble multi-chunk items before processing
            let mut chunk_accumulator = zeroize::Zeroizing::new(Vec::new());
            let mut next_chunk = 0;
            let mut received_count = 0u32;
            let mut final_item_received = false;
            let mut total_received_bytes = 0u64;
            loop {
                match secure_session.recv_message(&mut stream).await {
                    Ok(TransferMessage::DataChunk { item_index, chunk_index, data, is_last, integrity_hash, is_last_chunk }) => {
                        let data = zeroize::Zeroizing::new(data);
                        validate_transfer_chunk(received_count, next_chunk, chunk_accumulator.len(),
                            item_index, chunk_index, data.len(), final_item_received, is_last, is_last_chunk)?;
                        total_received_bytes += data.len() as u64;

                        // VULN-012: Rejeter les chunks sans hash d'intégrité
                        let hash_ok = if integrity_hash.is_empty() {
                            eprintln!("[TRANSFER] REJET: chunk sans integrity_hash (item {})", item_index);
                            false
                        } else {
                            let computed = hex::encode(secure_vault_crypto::blake3_hash(&data));
                            subtle::ConstantTimeEq::ct_eq(computed.as_bytes(), integrity_hash.as_bytes()).into()
                        };

                        if !hash_ok {
                            return Err("Contrôle d’intégrité du bloc de transfert en échec".into());
                        }

                        chunk_accumulator.extend_from_slice(&data);
                        next_chunk += 1;
                        if is_last_chunk {
                            let mut complete_data = zeroize::Zeroizing::new(std::mem::take(&mut *chunk_accumulator));
                            next_chunk = 0;

                            // Auto-detect: fichier (préfixe binaire 4 octets LE) vs mot de passe (JSON pur)
                            let is_file_payload = complete_data.len() >= 4 && complete_data[0] != b'{';

                            if is_file_payload {
                                // ═══ FILE PAYLOAD: [4-byte meta_len LE][metadata JSON][plaintext bytes] ═══
                                let meta_len = u32::from_le_bytes([
                                    complete_data[0], complete_data[1],
                                    complete_data[2], complete_data[3],
                                ]) as usize;

                                if meta_len > MAX_TRANSFER_METADATA_BYTES || complete_data.len() < 4 + meta_len {
                                    complete_data.zeroize();
                                    eprintln!("[TRANSFER] Receiver: fichier tronqué (metadata)");
                                } else if let Ok(metadata) = serde_json::from_slice::<TransferFileMetadata>(&complete_data[4..4+meta_len]) {
                                    let plaintext_start = 4 + meta_len;
                                    let plaintext_data = &complete_data[plaintext_start..];
                                    if metadata.original_size != plaintext_data.len() as i64
                                        || !crate::commands::files::valid_export_name(&metadata.filename)
                                    {
                                        return Err("Métadonnées de fichier incohérentes".into());
                                    }

                                    // Re-chiffrer le nom de fichier avec notre clé vault
                                    let encrypted_filename = encrypt_data_secure(&metadata.filename, &vault_key)
                                        .map_err(|e| format!("Erreur chiffrement nom fichier: {}", e))?;

                                    // Générer un ID unique et chiffrer avec streaming
                                    let file_id = uuid::Uuid::new_v4().to_string();
                                    let files_dir = crate::commands::files::files_dir(&state).await?;
                                    let output_path = files_dir.join(format!("{}.senc", file_id));

                                    // Chiffrer en streaming vers un fichier .senc
                                    let out_path = output_path.clone();
                                    let key_copy = vault_key.to_vec();
                                    let plaintext_vec = zeroize::Zeroizing::new(plaintext_data.to_vec());
                                    let encrypt_result = tokio::task::spawn_blocking(move || -> Result<u64, String> {
                                        let key_arr: &[u8; 32] = key_copy.as_slice().try_into()
                                            .map_err(|_| "Clé invalide".to_string())?;
                                        let mut reader = std::io::Cursor::new(plaintext_vec.as_slice());
                                        crate::commands::files::publish_new_file(&out_path, |dst| {
                                            let mut writer = std::io::BufWriter::with_capacity(65536, dst);
                                            secure_vault_crypto::encrypt_stream(key_arr, &mut reader, &mut writer, 0)
                                                .map_err(|e| format!("Chiffrement streaming: {e}"))
                                        })
                                    }).await
                                        .map_err(|e| format!("Thread: {}", e))?;

                                    complete_data.zeroize();

                                    match encrypt_result {
                                        Ok(_bytes) => {
                                            let output_path_str = output_path.to_str()
                                                .ok_or_else(|| "Chemin sortie invalide".to_string())?;

                                            let db_guard = state.db.lock().await;
                                            if let Some(db) = db_guard.as_ref() {
                                                match db.create_secure_file(
                                                    user_id,
                                                    &encrypted_filename,
                                                    output_path_str,
                                                    metadata.original_size,
                                                    metadata.mime_type.as_deref(),
                                                    metadata.integrity_hash.as_deref(),
                                                ).await {
                                                    Ok(sf_id) => {
                                                        received_count += 1;
                                                        let _ = db.log_action(user_id, "TRANSFER_RECEIVE", "file", Some(sf_id)).await;
                                                        eprintln!("[TRANSFER] Receiver: stored file (id={})", sf_id);
                                                    }
                                                    Err(e) => {
                                                        eprintln!("[TRANSFER] Receiver: DB insert file error: {}", e);
                                                        let _ = std::fs::remove_file(&output_path);
                                                    }
                                                }
                                            }
                                            drop(db_guard);
                                        }
                                        Err(e) => {
                                            eprintln!("[TRANSFER] Receiver: file encryption error: {}", e);
                                        }
                                    }
                                } else {
                                    complete_data.zeroize();
                                    eprintln!("[TRANSFER] Receiver: failed to parse file metadata");
                                }
                            } else if let Ok(payload) = serde_json::from_slice::<TransferPasswordPayload>(&complete_data) {
                                // ═══ PASSWORD PAYLOAD: JSON pur ═══
                                // Zeroize reassembled plaintext buffer
                                complete_data.zeroize();
                            // Re-encrypt ALL fields with our vault key (title & category included)
                            let encrypted_title = encrypt_data_secure(&payload.title, &vault_key)
                                .map_err(|e| format!("Erreur chiffrement titre: {}", e))?;
                            let encrypted_password = encrypt_data_secure(&payload.password, &vault_key)
                                .map_err(|e| format!("Erreur re-chiffrement: {}", e))?;
                            let encrypted_username = payload.username.as_ref()
                                .map(|u| encrypt_data_secure(u, &vault_key))
                                .transpose()
                                .map_err(|e| format!("Erreur chiffrement username: {}", e))?;
                            let encrypted_url = payload.url.as_ref()
                                .map(|u| encrypt_data_secure(u, &vault_key))
                                .transpose()
                                .map_err(|e| format!("Erreur chiffrement url: {}", e))?;
                            let encrypted_notes = payload.notes.as_ref()
                                .map(|n| encrypt_data_secure(n, &vault_key))
                                .transpose()
                                .map_err(|e| format!("Erreur chiffrement notes: {}", e))?;
                            let encrypted_category = payload.category.as_ref()
                                .map(|c| encrypt_data_secure(c, &vault_key))
                                .transpose()
                                .map_err(|e| format!("Erreur chiffrement catégorie: {}", e))?;

                            // Store in local DB — preserve original category, fallback to "📥 Transfert"
                            let db_guard = state.db.lock().await;
                            if let Some(db) = db_guard.as_ref() {
                                let final_category = if let Some(ref cat) = encrypted_category {
                                    cat.clone()
                                } else {
                                    encrypt_data_secure("📥 Transfert", &vault_key)
                                        .unwrap_or_else(|_| "📥 Transfert".to_string())
                                };
                                match db.create_password(
                                    user_id,
                                    &encrypted_title,
                                    encrypted_username.as_deref(),
                                    &encrypted_password,
                                    encrypted_url.as_deref(),
                                    encrypted_notes.as_deref(),
                                    Some(&final_category),
                                ).await {
                                    Ok(pw_id) => {
                                        received_count += 1;
                                        let _ = db.log_action(user_id, "TRANSFER_RECEIVE", "password", Some(pw_id)).await;
                                        // EXP-009: Ne pas logger les titres en production
                                        #[cfg(debug_assertions)]
                                        eprintln!("[TRANSFER] Receiver: stored password '{}' (id={})", payload.title, pw_id);
                                        #[cfg(not(debug_assertions))]
                                        eprintln!("[TRANSFER] Receiver: stored password (id={})", pw_id);
                                    }
                                    Err(e) => {
                                        eprintln!("[TRANSFER] Receiver: DB insert error: {}", e);
                                    }
                                }
                            }
                            drop(db_guard);
                        } else {
                            complete_data.zeroize();
                            eprintln!("[TRANSFER] Receiver: failed to parse DataChunk payload");
                        }

                        if received_count != item_index + 1 {
                            return Err("L’élément reçu n’a pas été enregistré".into());
                        }
                        final_item_received = is_last;
                        let ack = TransferMessage::Ack { item_index, integrity_ok: true };
                        secure_session.send_message(&mut stream, &ack).await?;
                        } // end is_last_chunk

                        if is_last {
                            let tm_guard2 = state.transfer_manager.lock().await;
                            if let Some(tm2) = tm_guard2.as_ref() {
                                if let Some(info) = tm2.active_transfers.lock().await.get_mut(&transfer_id) {
                                    info.state = TransferState::Transferring {
                                        progress_pct: 100,
                                        bytes_sent: total_received_bytes,
                                        total_bytes: total_received_bytes,
                                    };
                                }
                            }
                        }
                    }
                    Ok(TransferMessage::TransferComplete) => {
                        if !final_item_received || !chunk_accumulator.is_empty() {
                            return Err("Fin du transfert prématurée".into());
                        }
                        let tm_guard2 = state.transfer_manager.lock().await;
                        if let Some(tm2) = tm_guard2.as_ref() {
                            if let Some(info) = tm2.active_transfers.lock().await.get_mut(&transfer_id) {
                                info.state = TransferState::Completed;
                            }
                        }
                        eprintln!("[TRANSFER] Receiver: transfer complete — {} items stored", received_count);
                        break;
                    }
                    Ok(TransferMessage::Error { message, .. }) => {
                        let tm_guard2 = state.transfer_manager.lock().await;
                        if let Some(tm2) = tm_guard2.as_ref() {
                            if let Some(info) = tm2.active_transfers.lock().await.get_mut(&transfer_id) {
                                info.state = TransferState::Failed { reason: message.clone() };
                            }
                        }
                        return Err(format!("Transfert échoué : {}", message));
                    }
                    Err(e) => return Err(format!("Transfert interrompu : {e}")),
                    _ => return Err("Message inattendu pendant le transfert".into()),
                }
            }

            // Final audit log for the whole receive operation
            let db_guard = state.db.lock().await;
            if let Some(db) = db_guard.as_ref() {
                let _ = db.log_action(user_id, "TRANSFER_RECEIVE_COMPLETE", "transfer", None).await;
            }
        }
        TransferRole::Sender => {
            // === SENDER: wait for confirmation, send actual data from vault ===

            // Wait for receiver's safety number confirmation
            let confirm_msg = secure_session.recv_message(&mut stream).await?;
            match confirm_msg {
                TransferMessage::SafetyNumberConfirm { confirmed: true } => {}
                TransferMessage::SafetyNumberConfirm { confirmed: false } => {
                    return Err("Le pair a rejeté le safety number".to_string());
                }
                _ => return Err("Protocole invalide : confirmation attendue".to_string()),
            }

            // Wait for transfer accept
            let accept_msg = secure_session.recv_message(&mut stream).await?;
            match accept_msg {
                TransferMessage::TransferAccept { accepted: true } => {}
                TransferMessage::TransferAccept { accepted: false } => {
                    return Err("Le pair a refusé le transfert".to_string());
                }
                _ => return Err("Protocole invalide : acceptation attendue".to_string()),
            }

            // Get pending items for this transfer
            let tm_guard2 = state.transfer_manager.lock().await;
            let tm2 = tm_guard2.as_ref().ok_or("Module de transfert non initialisé")?;
            let pending = tm2.pending_items.lock().await.remove(&transfer_id);
            drop(tm_guard2);

            let (item_type, item_ids) = pending.unwrap_or_else(|| ("passwords".to_string(), vec![]));

            // Get vault key to decrypt items before sending
            let vault_key = crate::get_or_fetch_vault_key(&state, user_id).await
                .map_err(|e| format!("Erreur récupération clé vault: {}", e))?;

            let mut sent_count = 0u32;

            if item_type == "passwords" {
                let db_guard = state.db.lock().await;
                let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

                for (idx, pw_id) in item_ids.iter().enumerate() {
                    if let Ok(Some(pw)) = db.get_password(*pw_id, user_id).await {
                        // Decrypt ALL sensitive fields (title & category are also encrypted in DB)
                        let decrypted_title = decrypt_data_secure(&pw.title, &vault_key)
                            .unwrap_or_else(|_| pw.title.clone());
                        let decrypted_password = decrypt_data_secure(&pw.password, &vault_key)
                            .unwrap_or_else(|_| pw.password.clone());
                        let decrypted_username = pw.username.as_ref()
                            .and_then(|u| decrypt_data_secure(u, &vault_key).ok());
                        let decrypted_url = pw.url.as_ref()
                            .and_then(|u| decrypt_data_secure(u, &vault_key).ok());
                        let decrypted_notes = pw.notes.as_ref()
                            .and_then(|n| decrypt_data_secure(n, &vault_key).ok());
                        let decrypted_category = pw.category.as_ref()
                            .and_then(|c| decrypt_data_secure(c, &vault_key).ok());

                        let payload = TransferPasswordPayload {
                            title: decrypted_title,
                            username: decrypted_username,
                            password: decrypted_password,
                            url: decrypted_url,
                            notes: decrypted_notes,
                            category: decrypted_category,
                        };

                        let mut data = serde_json::to_vec(&payload)
                            .map_err(|e| format!("Sérialisation: {}", e))?;

                        // Stream: split large payloads into multiple chunks
                        let num_chunks = (data.len() + CHUNK_DATA_SIZE - 1) / CHUNK_DATA_SIZE;
                        let is_last_item = idx == item_ids.len() - 1;

                        for ci in 0..num_chunks {
                            let start = ci * CHUNK_DATA_SIZE;
                            let end = ((ci + 1) * CHUNK_DATA_SIZE).min(data.len());
                            let chunk_data = &data[start..end];

                            let integrity_hash = hex::encode(secure_vault_crypto::blake3_hash(chunk_data));
                            let is_last_chunk = ci == num_chunks - 1;

                            let chunk = TransferMessage::DataChunk {
                                item_index: idx as u32,
                                chunk_index: ci as u32,
                                data: chunk_data.to_vec(),
                                is_last: is_last_chunk && is_last_item,
                                integrity_hash,
                                is_last_chunk,
                            };
                            secure_session.send_message(&mut stream, &chunk).await?;
                        }
                        // Zeroize plaintext JSON buffer (defense in depth)
                        data.zeroize();

                        // Wait for ACK (one per item, after all chunks sent)
                        match secure_session.recv_message(&mut stream).await {
                            Ok(TransferMessage::Ack { integrity_ok: true, item_index }) if item_index == idx as u32 => {
                                sent_count += 1;
                                // EXP-009: Ne pas logger les titres en production
                                #[cfg(debug_assertions)]
                                eprintln!("[TRANSFER] Sender: sent password '{}' ({}/{}, {} chunk(s))", pw.title, idx + 1, item_ids.len(), num_chunks);
                                #[cfg(not(debug_assertions))]
                                eprintln!("[TRANSFER] Sender: sent item {}/{} ({} chunk(s))", idx + 1, item_ids.len(), num_chunks);
                            }
                            _ => return Err("Le pair n’a pas confirmé l’enregistrement du mot de passe".into()),
                        }

                        // Log each item sent
                        let _ = db.log_action(user_id, "TRANSFER_SEND", "password", Some(*pw_id)).await;
                    }
                }
                drop(db_guard);
            } else if item_type == "files" {
                // === FILE TRANSFER: déchiffre le fichier local, envoie en chunks plaintext ===
                let db_guard = state.db.lock().await;
                let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

                for (idx, file_id) in item_ids.iter().enumerate() {
                    if let Ok(Some(file)) = db.get_secure_file(*file_id, user_id).await {
                        let is_last_item = idx == item_ids.len() - 1;

                        // Déchiffrer le nom du fichier pour le transmettre
                        let decrypted_filename = decrypt_data_secure(&file.filename, &vault_key)
                            .unwrap_or_else(|_| file.filename.clone());

                        // Envoyer les métadonnées en tant que premier chunk (chunk_index=0, is_last_chunk=false si > 0 octets)
                        let metadata = TransferFileMetadata {
                            filename: decrypted_filename,
                            original_size: file.file_size,
                            mime_type: file.mime_type.clone(),
                            integrity_hash: file.integrity_hash.clone(),
                        };
                        let meta_json = serde_json::to_vec(&metadata)
                            .map_err(|e| format!("Sérialisation metadata: {}", e))?;

                        // Déchiffrer le fichier en mémoire
                        if file.file_size < 0 || file.file_size as usize > MAX_TRANSFER_ITEM_BYTES {
                            return Err("Les transferts acceptent des fichiers de 32 Mio maximum".into());
                        }
                        let file_path = crate::commands::files::encrypted_file_path(&state, &file.file_path).await?;
                        let key_copy = vault_key.to_vec();
                        let plaintext_data = tokio::task::spawn_blocking(move || {
                            let key = crate::secure_key::SecureKey::from_slice(&key_copy);
                            let mut output = LimitedTransferBuffer::default();
                            crate::commands::files::decrypt_into(&file_path, &key, &mut output)?;
                            Ok::<_, String>(output.bytes)
                        }).await.map_err(|e| e.to_string())??;

                        // Construire le flux de données: [metadata_json] + [plaintext_file_bytes]
                        // Préfixer la metadata par sa taille (4 octets LE) pour que le receiver puisse la séparer
                        let meta_len = (meta_json.len() as u32).to_le_bytes();
                        let mut data = zeroize::Zeroizing::new(Vec::with_capacity(4 + meta_json.len() + plaintext_data.len()));
                        data.extend_from_slice(&meta_len);
                        data.extend_from_slice(&meta_json);
                        data.extend_from_slice(&plaintext_data);
                        // Zeroize plaintext dès qu'il est copié dans data
                        drop(plaintext_data);

                        let num_chunks = (data.len() + CHUNK_DATA_SIZE - 1) / CHUNK_DATA_SIZE;

                        for ci in 0..num_chunks {
                            let start = ci * CHUNK_DATA_SIZE;
                            let end = ((ci + 1) * CHUNK_DATA_SIZE).min(data.len());
                            let chunk_data = &data[start..end];

                            let integrity_hash = hex::encode(secure_vault_crypto::blake3_hash(chunk_data));
                            let is_last_chunk = ci == num_chunks - 1;

                            let chunk = TransferMessage::DataChunk {
                                item_index: idx as u32,
                                chunk_index: ci as u32,
                                data: chunk_data.to_vec(),
                                is_last: is_last_chunk && is_last_item,
                                integrity_hash,
                                is_last_chunk,
                            };
                            secure_session.send_message(&mut stream, &chunk).await?;
                        }
                        data.zeroize();

                        // Wait for ACK
                        match secure_session.recv_message(&mut stream).await {
                            Ok(TransferMessage::Ack { integrity_ok: true, item_index }) if item_index == idx as u32 => {
                                sent_count += 1;
                                eprintln!("[TRANSFER] Sender: sent file {}/{} ({} chunk(s))", idx + 1, item_ids.len(), num_chunks);
                            }
                            _ => return Err("Le pair n’a pas confirmé l’enregistrement du fichier".into()),
                        }
                        let _ = db.log_action(user_id, "TRANSFER_SEND", "file", Some(*file_id)).await;
                    }
                }
                drop(db_guard);
            }

            if sent_count == 0 || sent_count as usize != item_ids.len() {
                return Err("Certains éléments sélectionnés n’ont pas été envoyés".into());
            }
            // Send TransferComplete
            let complete = TransferMessage::TransferComplete;
            secure_session.send_message(&mut stream, &complete).await?;

            let tm_guard3 = state.transfer_manager.lock().await;
            if let Some(tm3) = tm_guard3.as_ref() {
                if let Some(info) = tm3.active_transfers.lock().await.get_mut(&transfer_id) {
                    info.state = TransferState::Completed;
                }
            }
            drop(tm_guard3);

            eprintln!("[TRANSFER] Sender: transfer complete — {} items sent", sent_count);

            // Final audit log
            let db_guard = state.db.lock().await;
            if let Some(db) = db_guard.as_ref() {
                let _ = db.log_action(user_id, "TRANSFER_SEND_COMPLETE", "transfer", None).await;
            }
        }
    }

    // Cleanup
    let tm_guard4 = state.transfer_manager.lock().await;
    if let Some(tm4) = tm_guard4.as_ref() {
        tm4.transfer_roles.lock().await.remove(&transfer_id);
        tm4.pending_items.lock().await.remove(&transfer_id);
    }

    Ok(true)
}

/// C4 : Scan le réseau local pour trouver des pairs
#[tauri::command]
pub async fn transfer_scan_local_network(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Vec<DiscoveredPeer>, String> {
    // Vérifier le mode isolation réseau
    if *state.isolation_mode.lock().await {
        return Err("Mode isolation activé — scan réseau désactivé".to_string());
    }
    // Vérifier l'authentification
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    // Ensure discovery is running (mDNS + UDP beacon)
    let first_start = !tm.discovery.is_started().await;
    if let Err(e) = tm.discovery.start_mdns_discovery().await {
        eprintln!("[TRANSFER] start_mdns_discovery failed: {}", e);
    }

    // On first start, give beacon/mDNS 2s to receive initial responses
    if first_start {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    let peers = tm.discovery.get_discovered_peers().await;
    Ok(peers)
}

/// C5 : Liste les pairs de confiance
#[tauri::command]
pub async fn transfer_get_trusted_peers(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Vec<super::trust_store::TrustedPeer>, String> {
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    let store = tm.trust_store.lock().await;
    Ok(store.list_trusted())
}

/// C6 : Révoque la confiance d'un pair
#[tauri::command]
pub async fn transfer_revoke_trust(
    fingerprint: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    let mut store = tm.trust_store.lock().await;
    store.revoke_trust(&fingerprint)
}

/// C6b : Ajoute un pair de confiance manuellement (depuis la liste des pairs découverts)
#[tauri::command]
pub async fn transfer_add_trusted_peer(
    name: String,
    fingerprint: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    let mut store = tm.trust_store.lock().await;
    store.trust_peer(&name, &fingerprint)?;
    Ok(true)
}

/// C7 : Statut d'un transfert en cours
#[tauri::command]
pub async fn transfer_get_status(
    transfer_id: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<Option<TransferInfo>, String> {
    crate::validate_session(&state).await?;
    let tm_guard = state.transfer_manager.lock().await;
    if let Some(ref tm) = *tm_guard {
        let transfers = tm.active_transfers.lock().await;
        Ok(transfers.get(&transfer_id).cloned())
    } else {
        Ok(None)
    }
}

/// C8 : Annule un transfert en cours
#[tauri::command]
pub async fn transfer_cancel(
    transfer_id: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    crate::validate_session(&state).await?;
    let tm_guard = state.transfer_manager.lock().await;
    if let Some(ref tm) = *tm_guard {
        let mut offer = tm.active_offer.lock().await;
        if offer.as_ref().is_some_and(|(id, _)| id == &transfer_id) {
            if let Some((_, task)) = offer.take() {
                task.abort();
                let _ = task.await;
            }
            tm.discovery.clear_offer().await;
        }
        let removed = tm.active_transfers.lock().await.remove(&transfer_id).is_some();
        tm.active_connections.lock().await.remove(&transfer_id);
        tm.active_sessions.lock().await.remove(&transfer_id);
        tm.transfer_roles.lock().await.remove(&transfer_id);
        tm.pending_items.lock().await.remove(&transfer_id);
        Ok(removed)
    } else {
        Ok(false)
    }
}

/// C9 : Active/désactive la visibilité sur le réseau local (mDNS)
#[tauri::command]
pub async fn transfer_set_visibility(
    visible: bool,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    // Vérifier le mode isolation réseau
    if *state.isolation_mode.lock().await {
        return Err("Mode isolation activé — visibilité réseau désactivée".to_string());
    }
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    if visible {
        tm.discovery.start_mdns_discovery().await?;
        if let Err(error) = tm.start_registry_sync(&state).await {
            eprintln!("[SYNC] Synchronisation indisponible : {error}");
        }
        *tm.visible.lock().await = true;
    } else {
        *tm.visible.lock().await = false;
        tm.stop_registry_sync().await;
    }

    Ok(visible)
}

/// C10 : Retourne l'état de visibilité actuel
#[tauri::command]
pub async fn transfer_get_visibility(
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;
    let visible = *tm.visible.lock().await;
    Ok(visible)
}
/// Info d'un appareil de synchronisation pour le frontend
#[derive(Debug, Clone, Serialize)]
pub struct SyncDeviceInfo {
    pub name: String,
    pub verifying_key: String,
    pub added_at: String,
    pub last_sync: Option<String>,
}

/// Paramètres de synchronisation pour le frontend
#[derive(Debug, Serialize)]
pub struct SyncSettings {
    pub enabled: bool,
    pub devices: Vec<SyncDeviceInfo>,
    pub device_verifying_key: String,
}

/// C12 : Récupère les paramètres de synchronisation
#[tauri::command]
pub async fn transfer_get_sync_settings(
    state: tauri::State<'_, crate::AppState>,
) -> Result<SyncSettings, String> {
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;
    let store = tm.trust_store.lock().await;

    if !store.is_unlocked() {
        return Err("Trust store non déverrouillé".to_string());
    }

    let device_vk = store.device_verifying_key_b64()?;
    let devices: Vec<SyncDeviceInfo> = store.list_sync_devices().into_iter().map(|d| {
        SyncDeviceInfo {
            name: d.name,
            verifying_key: d.verifying_key,
            added_at: d.added_at,
            last_sync: d.last_sync,
        }
    }).collect();

    Ok(SyncSettings {
        enabled: store.is_sync_enabled(),
        devices,
        device_verifying_key: device_vk,
    })
}

/// C13 : Active ou désactive la synchronisation
#[tauri::command]
pub async fn transfer_set_sync_enabled(
    enabled: bool,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;
    let mut store = tm.trust_store.lock().await;

    store.set_sync_enabled(enabled)?;
    eprintln!("[SYNC] Synchronisation {}", if enabled { "activée" } else { "désactivée" });
    Ok(enabled)
}

/// C14 : Ajoute un appareil autorisé pour la synchronisation
#[tauri::command]
pub async fn transfer_add_sync_device(
    name: String,
    verifying_key: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;
    let mut store = tm.trust_store.lock().await;

    store.add_sync_device(&name, &verifying_key)?;
    eprintln!("[SYNC] Appareil '{}' ajouté aux appareils autorisés", name);
    Ok(true)
}

/// C15 : Supprime un appareil autorisé de la synchronisation
#[tauri::command]
pub async fn transfer_remove_sync_device(
    verifying_key: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, String> {
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;
    let mut store = tm.trust_store.lock().await;

    store.remove_sync_device(&verifying_key)
}

// ─────────────────────────────────────────────────────────
// C16 / C17 : Appairage automatique de sync via wormhole codes
// ─────────────────────────────────────────────────────────

/// Réponse de l'appairage (côté initiateur)
#[derive(Debug, Serialize)]
pub struct SyncPairingOffer {
    pub pairing_id: String,
    pub wormhole_code: String,
}

/// Résultat de l'appairage (côté joiner)
#[derive(Debug, Serialize)]
pub struct SyncPairingResult {
    pub success: bool,
    pub device_name: String,
}

/// C16 : Démarre l'appairage sync (côté initiateur).
///
/// 1. Génère un code wormhole (avec IPv6 si cross_network)
/// 2. Lance un TLS listener
/// 3. Spawne un background task qui attend la connexion, fait le handshake
///    PQC complet (SPAKE2 + ML-KEM-768), puis échange les clés ML-DSA-65
///    via SyncPairRequest/SyncPairResponse dans la SecureSession.
/// 4. Les deux appareils s'ajoutent mutuellement comme appareils autorisés.
#[tauri::command]
pub async fn transfer_start_sync_pairing(
    cross_network: bool,
    state: tauri::State<'_, crate::AppState>,
) -> Result<SyncPairingOffer, String> {
    // Vérifier le mode isolation réseau
    if *state.isolation_mode.lock().await {
        return Err("Mode isolation activé — appairage sync désactivé".to_string());
    }
    // Vérifier l'authentification
    crate::validate_session(&state).await?;

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    // Vérifier que le trust store est déverrouillé et obtenir notre clé ML-DSA
    let (our_vk_b64, our_name) = {
        let store = tm.trust_store.lock().await;
        if !store.is_unlocked() {
            return Err("Trust store non déverrouillé".to_string());
        }
        (store.device_verifying_key_b64()?, tm.peer_name.clone())
    };

    let base_wormhole_code = handshake::generate_wormhole_code();
    let pairing_id = uuid::Uuid::new_v4().to_string();

    let mut active_offer = tm.active_offer.lock().await;
    if active_offer.is_some() {
        return Err("Une offre est déjà en attente sur cet appareil.".into());
    }

    // Start TCP/TLS listener
    let listener = match TransportListener::bind(DEFAULT_TRANSFER_PORT).await {
        Ok(l) => l,
        Err(_) => TransportListener::bind(0).await
            .map_err(|e| format!("Erreur listener : {}", e))?,
    };
    let actual_port = listener.local_port;
    eprintln!("[SYNC-PAIR] Initiator: listener on port {}", actual_port);

    // Start mDNS
    if let Err(e) = tm.discovery.start_mdns_discovery().await {
        eprintln!("[SYNC-PAIR] start_mdns_discovery failed: {}", e);
    }
    if let Err(e) = tm.discovery.advertise_offer(actual_port).await {
        eprintln!("[SYNC-PAIR] register_mdns_service_on_port({}) failed: {}", actual_port, e);
    }

    // Build wormhole code with optional IPv6 for cross-network
    let wormhole_code = if cross_network {
        if let Some(v6) = super::discovery::get_public_ipv6_address() {
            eprintln!("[SYNC-PAIR] Cross-network: public IPv6 = {}", v6);
            format!("{}@[{}]:{}", base_wormhole_code, v6, actual_port)
        } else {
            eprintln!("[SYNC-PAIR] Cross-network requested but no public IPv6 found");
            base_wormhole_code.clone()
        }
    } else {
        base_wormhole_code.clone()
    };

    let listener = Arc::new(listener);

    // Register pairing transfer state
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    tm.active_transfers.lock().await.insert(pairing_id.clone(), TransferInfo {
        transfer_id: pairing_id.clone(),
        state: TransferState::WaitingForPeer,
        connection_method: ConnectionMethod::MdnsLocal,
        safety_number: None,
        peer_name: None,
        created_at: now_epoch,
    });

    // Clone for background task
    let active_transfers = tm.active_transfers.clone();
    let trust_store = tm.trust_store.clone();
    let pid = pairing_id.clone();
    let wc = base_wormhole_code.clone();
    let vk_b64 = our_vk_b64;
    let name = our_name;
    let session_token = state.session_token.clone();
    let pairing_token = session_token.lock().await.clone();
    let isolation = state.isolation_mode.clone();


    // ── Background task: accept connection → handshake → exchange ML-DSA keys ──
    let discovery = tm.discovery.clone();
    let active_slot = tm.active_offer.clone();
    let task = tokio::spawn(async move {
        let result: Result<(), String> = async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(WORMHOLE_TTL_SECS);
            for attempt in 0..5 {
                let mut conn = listen_for_offer(&listener, deadline).await?;
                let stream = &mut conn.stream;
                let negotiation_deadline = deadline.min(tokio::time::Instant::now() + NEGOTIATION_TIMEOUT);
                let result = tokio::time::timeout_at(negotiation_deadline, async {
                    let (peer, mut secure_session, _) =
                        initiate_offer(stream, &wc, &name, OfferKind::Pairing).await?;
                    let pairing_protocol = peer.pairing_protocol;
                    if let Some(info) = active_transfers.lock().await.get_mut(&pid) {
                        info.state = TransferState::Handshaking;
                        info.peer_name = Some(peer.name);
                    }

                    // ── Exchange ML-DSA-65 keys via encrypted channel ──
                    // Initiator sends SyncPairRequest
                    if *isolation.lock().await || *session_token.lock().await != pairing_token
                        || !active_transfers.lock().await.contains_key(&pid)
                    {
                        return Err("Appairage annulé".into());
                    }
                    let request = TransferMessage::SyncPairRequest {
                        device_name: name.clone(),
                        verifying_key_b64: vk_b64.clone(),
                        trust_data: match pairing_protocol {
                            PairingProtocol::SignedRegistry => trust_store.lock().await.export_for_sync()?,
                            PairingProtocol::Legacy => String::new(),
                        },
                    };
                    secure_session.send_message(stream, &request).await?;

                    // Wait for SyncPairResponse from joiner
                    let response = secure_session.recv_message(stream).await?;
                    match response {
                        TransferMessage::SyncPairResponse { device_name, verifying_key_b64, accepted, trust_data } => {
                            if !accepted {
                                return Err("L'autre appareil a refusé l'appairage".to_string());
                            }

                            if *isolation.lock().await || *session_token.lock().await != pairing_token
                                || !active_transfers.lock().await.contains_key(&pid)
                            {
                                return Err("Appairage annulé".into());
                            }
                            finish_pairing(&mut *trust_store.lock().await, pairing_protocol,
                                &device_name, &verifying_key_b64, &trust_data)?;

                            if let Some(info) = active_transfers.lock().await.get_mut(&pid) {
                                info.state = TransferState::Completed;
                                info.peer_name = Some(device_name);
                            }
                        }
                        _ => return Err("Réponse d'appairage invalide".to_string()),
                    }

                    Ok(())
                }).await.unwrap_or_else(|_| Err("Délai d’appairage dépassé".into()));
                match result {
                    Ok(()) => return Ok(()),
                    Err(error) if attempt == 4 => return Err(error),
                    Err(error) => {
                        eprintln!("[SYNC-PAIR] Échec de la négociation : {error}");
                        tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                    }
                }
            }
            unreachable!("The last pairing attempt returns a result")
        }.await;

        if let Err(e) = result {
            eprintln!("[SYNC-PAIR] Initiator error: {}", e);
            if let Some(info) = active_transfers.lock().await.get_mut(&pid) {
                info.state = TransferState::Failed { reason: e };
            }
        }
        let mut active = active_slot.lock().await;
        if active.as_ref().is_some_and(|(id, _)| id == &pid) {
            discovery.clear_offer().await;
            active.take();
        }
    });
    *active_offer = Some((pairing_id.clone(), task));

    Ok(SyncPairingOffer {
        pairing_id,
        wormhole_code,
    })
}

/// C17 : Rejoint un appairage sync (côté joiner).
///
/// 1. Parse le wormhole code (avec IPv6 cross-network si présent)
/// 2. Connecte au pair via TLS (4 stratégies de fallback)
/// 3. Fait le handshake PQC (SPAKE2 + ML-KEM-768) comme responder
/// 4. Reçoit la SyncPairRequest, renvoie SyncPairResponse
/// 5. Les deux appareils s'ajoutent mutuellement
#[tauri::command]
pub async fn transfer_join_sync_pairing(
    wormhole_code: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<SyncPairingResult, String> {
    // Vérifier le mode isolation réseau
    if *state.isolation_mode.lock().await {
        return Err("Mode isolation activé — appairage sync désactivé".to_string());
    }
    // Vérifier l'authentification
    crate::validate_session(&state).await?;

    let session_token = state.session_token.lock().await.clone();
    let (discovery, our_vk_b64, our_name) = {
        let guard = state.transfer_manager.lock().await;
        let tm = guard.as_ref().ok_or("Module de transfert non initialisé")?;
        let store = tm.trust_store.lock().await;
        if !store.is_unlocked() {
            return Err("Registre de confiance verrouillé".into());
        }
        (tm.discovery.clone(), store.device_verifying_key_b64()?, tm.peer_name.clone())
    };
    let (code, endpoint) = parse_access_code(&wormhole_code)?;
    let offer = receive_offer(&discovery, code, &our_name, OfferKind::Pairing,
        endpoint.into_iter().collect()).await?;
    let NegotiatedOffer {
        mut connection, session: mut secure_session, pairing_protocol,
        first_message: TransferMessage::SyncPairRequest {
            device_name: initiator_device_name, verifying_key_b64: initiator_vk_b64, trust_data,
        }, ..
    } = offer else {
        return Err("Requête d’appairage invalide".into());
    };
    crate::validate_session(&state).await?;
    if *state.isolation_mode.lock().await || *state.session_token.lock().await != session_token {
        return Err("Appairage annulé".into());
    }
    let local_export = {
        let tm_guard = state.transfer_manager.lock().await;
        let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;
        let mut store = tm.trust_store.lock().await;
        let export = match pairing_protocol {
            PairingProtocol::SignedRegistry => store.export_for_sync()?,
            PairingProtocol::Legacy => String::new(),
        };
        finish_pairing(&mut store, pairing_protocol, &initiator_device_name, &initiator_vk_b64, &trust_data)?;
        export
    };

    let response = TransferMessage::SyncPairResponse {
        device_name: our_name,
        verifying_key_b64: our_vk_b64,
        accepted: true,
        trust_data: local_export,
    };
    secure_session.send_message(&mut connection.stream, &response).await?;

    Ok(SyncPairingResult {
        success: true,
        device_name: initiator_device_name,
    })
}

// ─────────────────────────────────────────────────────────
// C18 : Auto-sync avec un pair appairé découvert sur le même réseau

fn finish_pairing(
    store: &mut TrustStore, protocol: PairingProtocol, name: &str, key: &str, trust_data: &str,
) -> Result<(), String> {
    match protocol {
        PairingProtocol::SignedRegistry => store.pair_and_merge(name, key, trust_data).map(|_| ()),
        PairingProtocol::Legacy if trust_data.is_empty() => store.pair_device(name, key),
        PairingProtocol::Legacy => Err("Registre inattendu pour un appairage de première génération".into()),
    }
}

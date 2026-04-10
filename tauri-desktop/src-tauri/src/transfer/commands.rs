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
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::Zeroize;

use super::discovery::{DiscoveryService, DiscoveredPeer};
use super::handshake;
use super::trust_store::TrustStore;
use super::transport::{TransportListener, TransportConnection, connect_to_peer, establish_connection};
use super::protocol::{self, TransferMessage, TransferItem, TransferItemType, DEFAULT_TRANSFER_PORT, CHUNK_DATA_SIZE};
use super::session::SecureSession;
use super::{ConnectionMethod, TransferState, TransferInfo, WORMHOLE_TTL_SECS};
use secure_vault_crypto::crypto::kem;

use crate::crypto::{encrypt_data_secure, decrypt_data_secure, is_senc_format, decrypt_data_bytes_secure};

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
    /// Active TCP/TLS listener for the sender side (if any)
    pub active_listener: Mutex<Option<Arc<TransportListener>>>,
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
        let discovery = DiscoveryService::new(peer_name, DEFAULT_TRANSFER_PORT, visible.clone());

        Ok(Self {
            discovery,
            trust_store: Arc::new(Mutex::new(trust_store)),
            active_transfers: Arc::new(Mutex::new(HashMap::new())),
            active_listener: Mutex::new(None),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
            transfer_roles: Arc::new(Mutex::new(HashMap::new())),
            pending_items: Arc::new(Mutex::new(HashMap::new())),
            visible,
            peer_name: peer_name.to_string(),
        })
    }

    /// Update the peer name (called after login with the actual username)
    pub fn set_peer_name(&mut self, name: &str) {
        self.peer_name = name.to_string();
        self.discovery.set_instance_name(name);
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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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

    // Store pending items for C3
    tm.pending_items.lock().await.insert(
        transfer_id.clone(),
        (request.item_type.clone(), request.item_ids.clone()),
    );

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
    if let Err(e) = tm.discovery.register_mdns_service_on_port(actual_port).await {
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

    // Store listener for accept phase
    let listener = Arc::new(listener);
    *tm.active_listener.lock().await = Some(listener.clone());

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
    tokio::spawn(async move {
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

                // Race: Path A (receiver connects to our listener) vs
                //       Path B (we discover receiver's reverse listener via mDNS and connect OUT)
                let conn = match tokio::time::timeout(remaining, async {
                    tokio::select! {
                        accept_result = listener.accept() => {
                            eprintln!("[TRANSFER] Sender: accept() won the race");
                            accept_result
                        }
                        discover_result = async {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            eprintln!("[TRANSFER] Sender: scanning mDNS for receiver reverse listener...");
                            let peer = super::discovery::discover_receiver_peer(55).await?;
                            eprintln!("[TRANSFER] Sender: found receiver at {}:{}", peer.addr, peer.port);
                            connect_to_peer(&peer).await
                        } => {
                            eprintln!("[TRANSFER] Sender: mDNS discover won the race");
                            discover_result
                        }
                    }
                })
                .await
                {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
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
                    Err(_) => {
                        return Err(format!(
                            "Code wormhole expiré après {} secondes",
                            WORMHOLE_TTL_SECS
                        ));
                    }
                };

                let peer_addr_log = conn.peer_addr.clone();
                eprintln!("[TRANSFER] Sender: connected to {}! Starting handshake...", peer_addr_log);

                // ─── Attempt full SPAKE2 + ML-KEM handshake ───
                let handshake_result: Result<(), String> = async {
                    let mut stream = conn.stream;
                    let peer_addr = peer_addr_log.clone();
                    let method = conn.method.clone();

                    // Read Hello from receiver
                    let receiver_hello = protocol::read_message(&mut stream).await?;
                    let receiver_name = match &receiver_hello {
                        TransferMessage::Hello { peer_name, .. } => peer_name.clone(),
                        _ => "FluXlock Peer".to_string(),
                    };

                    // Send our Hello
                    let hello = TransferMessage::Hello {
                        protocol_version: protocol::PROTOCOL_VERSION,
                        peer_name: peer_name_clone.clone(),
                        capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string()],
                    };
                    protocol::write_message(&mut stream, &hello).await?;

                    // Update state
                    if let Some(info) = active_transfers.lock().await.get_mut(&tid) {
                        info.state = TransferState::Handshaking;
                        info.peer_name = Some(receiver_name.clone());
                    }

                    // Read receiver's SPAKE2 message
                    let receiver_spake = protocol::read_message(&mut stream).await?;
                    let receiver_spake_body = match receiver_spake {
                        TransferMessage::SpakeMessage { body } => body,
                        _ => return Err("Protocole invalide : message SPAKE2 attendu".to_string()),
                    };

                    // Create initiator and complete SPAKE2 (phase 1)
                    let initiator = handshake::HandshakeInitiator::new(&wc)?;

                    // Send our SPAKE2 message
                    let spake_msg = TransferMessage::SpakeMessage {
                        body: initiator.spake_message().to_vec(),
                    };
                    protocol::write_message(&mut stream, &spake_msg).await?;

                    // Phase 1: SPAKE2 finish + KEM keypair generation
                    let phase1 = initiator.complete_spake2(&receiver_spake_body)?;

                    // Send KEM public key
                    let kem_pub = TransferMessage::KemEncapsulation {
                        ek_bytes: phase1.ek_bytes.clone(),
                    };
                    protocol::write_message(&mut stream, &kem_pub).await?;

                    // Read KEM ciphertext from receiver
                    let kem_ct_msg = protocol::read_message(&mut stream).await?;
                    let ct_bytes = match kem_ct_msg {
                        TransferMessage::KemCiphertext { ct_bytes } => ct_bytes,
                        _ => return Err("Protocole invalide : KEM ciphertext attendu".to_string()),
                    };

                    // Phase 2: KEM decapsulation + hybrid key derivation
                    let hs_result = phase1.finalize_with_kem(&ct_bytes)?;

                    // Create SecureSession from handshake key (initiator)
                    let mut secure_session = SecureSession::new(hs_result.session_key, true)?;

                    // Send the transfer offer via SecureSession (encrypted)
                    let offer = TransferMessage::TransferOffer {
                        items: offer_items.clone(),
                        total_size: offer_total_size,
                    };
                    secure_session.send_message(&mut stream, &offer).await?;

                    // Update state with safety number
                    if let Some(info) = active_transfers.lock().await.get_mut(&tid) {
                        info.state = TransferState::ConfirmingSafetyNumber;
                        info.safety_number = Some(hs_result.safety_number.clone());
                        info.peer_name = Some(receiver_name);
                    }

                    // Store connection and session for the confirm phase
                    active_connections.lock().await.insert(tid.clone(), TransportConnection {
                        stream,
                        method,
                        peer_addr,
                    });
                    active_sessions.lock().await.insert(tid.clone(), secure_session);

                    Ok(())
                }
                .await;

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
    });

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    let transfer_id = uuid::Uuid::new_v4().to_string();

    // ── Parse wormhole code: extract IPv6 endpoint if present ──
    // Format A: "42-alpha-beacon-drift" (same network — mDNS or Peers tab)
    // Format B: "42-alpha-beacon-drift@[2001:db8::1]:52820" (cross-network IPv6)
    let raw_code = request.wormhole_code.trim().to_string();
    // EXP-009: Ne pas logger le code wormhole en production
    #[cfg(debug_assertions)]
    eprintln!("[TRANSFER] Receiver: raw wormhole code = {}", raw_code);

    let (spake_code, ipv6_endpoint) = if let Some(idx) = raw_code.find('@') {
        let code_part = raw_code[..idx].to_string();
        let endpoint_part = raw_code[idx + 1..].to_string();
        // Parse "[IPv6]:port"
        let parsed = if endpoint_part.starts_with('[') {
            if let Some(bracket_end) = endpoint_part.find(']') {
                let ip = endpoint_part[1..bracket_end].to_string();
                let port = endpoint_part.get(bracket_end + 2..)
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(DEFAULT_TRANSFER_PORT);
                Some((ip, port))
            } else { None }
        } else { None };
        (code_part, parsed)
    } else {
        (raw_code.clone(), None)
    };

    // ── Strategy 1: Direct peer from Peers tab (mDNS discovered) ──
    let mut conn: Option<TransportConnection> = None;

    if let (Some(addr), Some(port)) = (&request.peer_addr, request.peer_port) {
        let direct_peer = DiscoveredPeer {
            name: "discovered-peer".to_string(),
            addr: addr.clone(),
            port,
            method: "mDNS-Direct".to_string(),
            verified: false,
        };
        eprintln!("[TRANSFER] Receiver: trying discovered peer {}:{}", addr, port);
        match connect_to_peer(&direct_peer).await {
            Ok(c) => { eprintln!("[TRANSFER] Receiver: discovered peer connection OK!"); conn = Some(c); }
            Err(e) => { eprintln!("[TRANSFER] Receiver: discovered peer failed: {}", e); }
        }
    }

    // ── Strategy 2: Cross-network IPv6 from wormhole code ──
    if conn.is_none() {
        if let Some((ref ip, port)) = ipv6_endpoint {
            let v6_peer = DiscoveredPeer {
                name: "ipv6-endpoint".to_string(),
                addr: ip.clone(),
                port,
                method: "IPv6-Direct".to_string(),
                verified: false,
            };
            eprintln!("[TRANSFER] Receiver: trying IPv6 {}:{}", ip, port);
            match connect_to_peer(&v6_peer).await {
                Ok(c) => { eprintln!("[TRANSFER] Receiver: IPv6 connection OK!"); conn = Some(c); }
                Err(e) => { eprintln!("[TRANSFER] Receiver: IPv6 failed: {}", e); }
            }
        }
    }

    // ── Strategy 3: mDNS + IPv6 link-local discovery ──
    if conn.is_none() {
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[TRANSFER] Receiver: start_mdns_discovery failed: {}", e);
        }
        // Short wait for mDNS
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let mut peers = tm.discovery.get_discovered_peers().await;
        if let Ok(v6_peers) = tm.discovery.scan_ipv6_link_local().await {
            peers.extend(v6_peers);
        }

        if !peers.is_empty() {
            if let Ok(c) = establish_connection(&peers).await {
                conn = Some(c);
            }
        }
    }

    // ── Strategy 3: Localhost fallback (same machine testing) ──
    if conn.is_none() {
        let localhost = DiscoveredPeer {
            name: "localhost".to_string(),
            addr: "127.0.0.1".to_string(),
            port: DEFAULT_TRANSFER_PORT,
            method: "Direct".to_string(),
            verified: false,
        };
        if let Ok(c) = connect_to_peer(&localhost).await {
            conn = Some(c);
        }
    }

    // ── Strategy 4: Reverse connection — start our own listener, let sender connect to us ──
    // This handles the case where the sender is on Android (which blocks incoming TCP).
    // We start a TLS listener, advertise it via mDNS, and wait for the sender to connect OUT.
    if conn.is_none() {
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[TRANSFER] Receiver: start_mdns_discovery for reverse failed: {}", e);
        }

        let reverse_listener = match TransportListener::bind(DEFAULT_TRANSFER_PORT).await {
            Ok(l) => l,
            Err(_) => TransportListener::bind(0).await
                .map_err(|e| format!("Reverse listener : {}", e))?,
        };
        let reverse_port = reverse_listener.local_port;

        eprintln!("[TRANSFER] Receiver: starting reverse listener on port {}", reverse_port);
        // Advertise our reverse listener via mDNS so sender can find us
        if let Err(e) = tm.discovery.register_receiver_mdns(reverse_port).await {
            eprintln!("[TRANSFER] Receiver: register_receiver_mdns failed: {}", e);
        }
        eprintln!("[TRANSFER] Receiver: registered mDNS _fluxlock-recv._tcp on port {}", reverse_port);

        // Wait up to 60s for the sender to discover us and connect
        match tokio::time::timeout(
            std::time::Duration::from_secs(60),
            reverse_listener.accept(),
        ).await {
            Ok(Ok(c)) => { eprintln!("[TRANSFER] Receiver: sender connected to our reverse listener!"); conn = Some(c); }
            Ok(Err(e)) => { eprintln!("[TRANSFER] Receiver: reverse accept error: {}", e); }
            Err(_) => { eprintln!("[TRANSFER] Receiver: reverse listener timeout (60s)"); }
        }
    }

    let conn = conn.ok_or_else(|| {
        if ipv6_endpoint.is_some() {
            "Impossible de se connecter via IPv6. Vérifiez que l'autre appareil est accessible et a créé une offre.".to_string()
        } else if request.peer_addr.is_some() {
            "Impossible de se connecter au pair découvert. Vérifiez que l'autre appareil a bien créé une offre.".to_string()
        } else {
            "Pair introuvable. Utilisez l'onglet Pairs pour un appareil sur le même réseau, ou entrez le code complet avec @[IPv6] pour un réseau différent.".to_string()
        }
    })?;

    let connection_method = format!("{:?}", conn.method);
    let peer_addr = conn.peer_addr.clone();

    // Perform SPAKE2 handshake as responder (use code portion only, without endpoint)
    let responder = handshake::HandshakeResponder::new(&spake_code)?;

    // Exchange SPAKE2 messages over the TLS connection
    let mut stream = conn.stream;

    // Send Hello
    let hello = TransferMessage::Hello {
        protocol_version: protocol::PROTOCOL_VERSION,
        peer_name: tm.peer_name.clone(),
        capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string()],
    };
    protocol::write_message(&mut stream, &hello).await?;

    // Read Hello from sender
    let sender_hello = protocol::read_message(&mut stream).await?;
    let sender_name = match &sender_hello {
        TransferMessage::Hello { peer_name, .. } => peer_name.clone(),
        _ => "FluXlock Peer".to_string(),
    };

    // Send our SPAKE2 message
    let spake_msg = TransferMessage::SpakeMessage {
        body: responder.spake_message().to_vec(),
    };
    protocol::write_message(&mut stream, &spake_msg).await?;

    // Read sender's SPAKE2 message
    let sender_spake = protocol::read_message(&mut stream).await?;
    let sender_spake_body = match sender_spake {
        TransferMessage::SpakeMessage { body } => body,
        _ => return Err("Protocole invalide : message SPAKE2 attendu".to_string()),
    };

    // Read sender's KEM public key
    let kem_msg = protocol::read_message(&mut stream).await?;
    let ek_bytes = match kem_msg {
        TransferMessage::KemEncapsulation { ek_bytes } => ek_bytes,
        _ => return Err("Protocole invalide : KEM encapsulation attendue".to_string()),
    };

    // Complete handshake as responder
    let (result, ct_bytes) = responder.complete_handshake(&sender_spake_body, &ek_bytes)?;

    // Send KEM ciphertext back to sender
    let kem_ct = TransferMessage::KemCiphertext { ct_bytes };
    protocol::write_message(&mut stream, &kem_ct).await?;

    // Create SecureSession for encrypted communication (responder)
    let mut secure_session = SecureSession::new(result.session_key, false)?;

    // Read transfer offer via SecureSession (encrypted end-to-end)
    let offer_msg = secure_session.recv_message(&mut stream).await?;
    let (items, total_size) = match offer_msg {
        TransferMessage::TransferOffer { items, total_size } => {
            let info_items: Vec<TransferItemInfo> = items.iter().map(|i| TransferItemInfo {
                name: i.name.clone(),
                item_type: format!("{:?}", i.item_type),
                size: i.size,
            }).collect();
            (info_items, total_size)
        }
        _ => (Vec::new(), 0),
    };

    let safety_number = result.safety_number.clone();

    // Store connection and session for the confirm phase
    tm.active_connections.lock().await.insert(transfer_id.clone(), TransportConnection {
        stream,
        method: conn.method,
        peer_addr,
    });
    tm.active_sessions.lock().await.insert(transfer_id.clone(), secure_session);
    tm.transfer_roles.lock().await.insert(transfer_id.clone(), TransferRole::Receiver);

    // Record transfer state
    tm.active_transfers.lock().await.insert(transfer_id.clone(), TransferInfo {
        transfer_id: transfer_id.clone(),
        state: TransferState::ConfirmingSafetyNumber,
        connection_method: ConnectionMethod::MdnsLocal,
        safety_number: Some(safety_number.clone()),
        peer_name: Some(sender_name.clone()),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });

    // Log the connection event
    {
        let user_id = state.current_user_id.lock().await;
        if let Some(uid) = *user_id {
            let db_guard = state.db.lock().await;
            if let Some(db) = db_guard.as_ref() {
                let _ = db.log_action(uid, "TRANSFER_CONNECT", "transfer", None).await;
            }
        }
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
            let mut chunk_accumulator: std::collections::HashMap<u32, Vec<u8>> = std::collections::HashMap::new();
            let mut received_count = 0u32;
            let mut total_received_bytes = 0u64;
            loop {
                match secure_session.recv_message(&mut stream).await {
                    Ok(TransferMessage::DataChunk { item_index, chunk_index: _, mut data, is_last, integrity_hash, is_last_chunk }) => {
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
                            eprintln!("[TRANSFER] Receiver: integrity check FAILED for chunk");
                            data.zeroize();
                            let ack = TransferMessage::Ack {
                                item_index: received_count,
                                integrity_ok: false,
                            };
                            secure_session.send_message(&mut stream, &ack).await?;
                            continue;
                        }

                        // Accumulate chunk data for this item
                        chunk_accumulator.entry(item_index).or_default().extend_from_slice(&data);
                        data.zeroize();

                        // Process the complete item only when last chunk is received
                        if is_last_chunk {
                            let mut complete_data = chunk_accumulator.remove(&item_index).unwrap_or_default();

                            // Auto-detect: fichier (préfixe binaire 4 octets LE) vs mot de passe (JSON pur)
                            let is_file_payload = complete_data.len() >= 4 && complete_data[0] != b'{';

                            if is_file_payload {
                                // ═══ FILE PAYLOAD: [4-byte meta_len LE][metadata JSON][plaintext bytes] ═══
                                let meta_len = u32::from_le_bytes([
                                    complete_data[0], complete_data[1],
                                    complete_data[2], complete_data[3],
                                ]) as usize;

                                if complete_data.len() < 4 + meta_len {
                                    complete_data.zeroize();
                                    eprintln!("[TRANSFER] Receiver: fichier tronqué (metadata)");
                                } else if let Ok(metadata) = serde_json::from_slice::<TransferFileMetadata>(&complete_data[4..4+meta_len]) {
                                    let plaintext_start = 4 + meta_len;
                                    let plaintext_data = &complete_data[plaintext_start..];

                                    // Re-chiffrer le nom de fichier avec notre clé vault
                                    let encrypted_filename = encrypt_data_secure(&metadata.filename, &vault_key)
                                        .map_err(|e| format!("Erreur chiffrement nom fichier: {}", e))?;

                                    // Générer un ID unique et chiffrer avec streaming
                                    let file_id = uuid::Uuid::new_v4().to_string();
                                    let files_dir = crate::hidden_storage::get_hidden_files_dir()
                                        .map_err(|e| format!("Erreur dossier: {}", e))?;
                                    let output_path = files_dir.join(format!("{}.senc", file_id));

                                    // Chiffrer en streaming vers un fichier .senc
                                    let out_path = output_path.clone();
                                    let key_copy = vault_key.to_vec();
                                    let plaintext_vec = plaintext_data.to_vec();
                                    let encrypt_result = tokio::task::spawn_blocking(move || -> Result<u64, String> {
                                        let key_arr: &[u8; 32] = key_copy.as_slice().try_into()
                                            .map_err(|_| "Clé invalide".to_string())?;
                                        let mut reader = std::io::Cursor::new(&plaintext_vec);
                                        let dst = std::fs::File::create(&out_path)
                                            .map_err(|e| format!("Création fichier: {}", e))?;
                                        let mut writer = std::io::BufWriter::with_capacity(65536, dst);
                                        secure_vault_crypto::encrypt_stream(key_arr, &mut reader, &mut writer, 0)
                                            .map_err(|e| format!("Chiffrement streaming: {}", e))
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

                        // Send ACK via SecureSession (one per complete item)
                        let ack = TransferMessage::Ack {
                            item_index: received_count.saturating_sub(1),
                            integrity_ok: true,
                        };
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
                    Err(e) => {
                        if received_count > 0 {
                            let tm_guard2 = state.transfer_manager.lock().await;
                            if let Some(tm2) = tm_guard2.as_ref() {
                                if let Some(info) = tm2.active_transfers.lock().await.get_mut(&transfer_id) {
                                    info.state = TransferState::Completed;
                                }
                            }
                            break;
                        }
                        return Err(format!("Erreur réception : {}", e));
                    }
                    _ => {}
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
                            Ok(TransferMessage::Ack { integrity_ok: true, .. }) => {
                                sent_count += 1;
                                // EXP-009: Ne pas logger les titres en production
                                #[cfg(debug_assertions)]
                                eprintln!("[TRANSFER] Sender: sent password '{}' ({}/{}, {} chunk(s))", pw.title, idx + 1, item_ids.len(), num_chunks);
                                #[cfg(not(debug_assertions))]
                                eprintln!("[TRANSFER] Sender: sent item {}/{} ({} chunk(s))", idx + 1, item_ids.len(), num_chunks);
                            }
                            Ok(TransferMessage::Ack { integrity_ok: false, .. }) => {
                                // EXP-009: Ne pas logger les titres en production
                                #[cfg(debug_assertions)]
                                eprintln!("[TRANSFER] Sender: receiver reported integrity error for '{}'", pw.title);
                                #[cfg(not(debug_assertions))]
                                eprintln!("[TRANSFER] Sender: receiver reported integrity error for item {}", idx + 1);
                            }
                            _ => {
                                eprintln!("[TRANSFER] Sender: unexpected response for ACK");
                            }
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
                        let file_path = file.file_path.clone();
                        let plaintext_data = {
                            // Détecter le format
                            let header = {
                                let mut f = std::fs::File::open(&file_path)
                                    .map_err(|e| format!("Erreur ouverture fichier: {}", e))?;
                                let mut buf = [0u8; 6];
                                use std::io::Read;
                                let _ = f.read(&mut buf).map_err(|e| format!("Erreur lecture header: {}", e))?;
                                buf
                            };
                            if is_senc_format(&header) {
                                let fp = file_path.clone();
                                let key_copy = vault_key.to_vec();
                                tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
                                    let key_arr: &[u8; 32] = key_copy.as_slice().try_into()
                                        .map_err(|_| "Clé invalide".to_string())?;
                                    let src = std::fs::File::open(&fp)
                                        .map_err(|e| format!("Ouverture: {}", e))?;
                                    let mut reader = std::io::BufReader::with_capacity(65536, src);
                                    let mut output = Vec::new();
                                    let mut writer = std::io::Cursor::new(&mut output);
                                    secure_vault_crypto::decrypt_stream(key_arr, &mut reader, &mut writer)
                                        .map_err(|e| format!("Déchiffrement streaming: {}", e))?;
                                    Ok(output)
                                }).await
                                    .map_err(|e| format!("Thread: {}", e))?
                                    .map_err(|e| e)?
                            } else {
                                // Format legacy (v2:base64)
                                let encrypted_str = std::fs::read_to_string(&file_path)
                                    .map_err(|e| format!("Lecture: {}", e))?;
                                decrypt_data_bytes_secure(&encrypted_str, &vault_key)
                                    .map_err(|e| format!("Déchiffrement legacy: {}", e))?
                            }
                        };

                        // Construire le flux de données: [metadata_json] + [plaintext_file_bytes]
                        // Préfixer la metadata par sa taille (4 octets LE) pour que le receiver puisse la séparer
                        let meta_len = (meta_json.len() as u32).to_le_bytes();
                        let mut data = Vec::with_capacity(4 + meta_json.len() + plaintext_data.len());
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
                            Ok(TransferMessage::Ack { integrity_ok: true, .. }) => {
                                sent_count += 1;
                                eprintln!("[TRANSFER] Sender: sent file {}/{} ({} chunk(s))", idx + 1, item_ids.len(), num_chunks);
                            }
                            Ok(TransferMessage::Ack { integrity_ok: false, .. }) => {
                                eprintln!("[TRANSFER] Sender: receiver reported integrity error for file {}", idx + 1);
                            }
                            _ => {
                                eprintln!("[TRANSFER] Sender: unexpected response for file ACK");
                            }
                        }
                        let _ = db.log_action(user_id, "TRANSFER_SEND", "file", Some(*file_id)).await;
                    }
                }
                drop(db_guard);
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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    let tm_guard = state.transfer_manager.lock().await;
    if let Some(ref tm) = *tm_guard {
        let removed = tm.active_transfers.lock().await.remove(&transfer_id).is_some();
        tm.active_connections.lock().await.remove(&transfer_id);
        tm.active_sessions.lock().await.remove(&transfer_id);
        tm.transfer_roles.lock().await.remove(&transfer_id);
        tm.pending_items.lock().await.remove(&transfer_id);
        // Unregister mDNS when no more active transfers
        if tm.active_transfers.lock().await.is_empty() {
            tm.discovery.unregister_mdns_service().await;
            *tm.active_listener.lock().await = None;
        }
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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    let mut vis = tm.visible.lock().await;
    if visible {
        // Set visible BEFORE starting discovery so the beacon + mDNS registration see it
        *vis = visible;
        drop(vis);
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[TRANSFER] Visibility: start_mdns_discovery failed: {}", e);
        }
        // Use the actual listener port if a transfer is active, otherwise DEFAULT
        let port = match tm.active_listener.lock().await.as_ref() {
            Some(listener) => listener.local_port,
            None => DEFAULT_TRANSFER_PORT,
        };
        if let Err(e) = tm.discovery.register_mdns_service_on_port(port).await {
            eprintln!("[TRANSFER] Visibility: register_mdns on port {} failed: {}", port, e);
        }
        eprintln!("[TRANSFER] Visibility ON — device is now discoverable via mDNS (port {})", port);
    } else {
        *vis = visible;
        drop(vis);
        tm.discovery.unregister_mdns_service().await;
        eprintln!("[TRANSFER] Visibility OFF — device is no longer discoverable");
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

/// C11 : Synchronise le trust store avec un pair via une session sécurisée existante.
///
/// Utilise le canal PQC déjà établi (SPAKE2 + ML-KEM-768 → ChaCha20-Poly1305)
/// pour échanger les trust stores de manière bidirectionnelle sans serveur.
///
/// Prérequis : un transfert (handshake terminé) existe pour `transfer_id`.
#[tauri::command]
pub async fn transfer_sync_trust_store(
    transfer_id: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<u32, String> {
    // Vérifier le mode isolation réseau
    if *state.isolation_mode.lock().await {
        return Err("Mode isolation activé — synchronisation désactivée".to_string());
    }
    let session_check = state.session.lock().await;
    if session_check.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session_check);

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    // Vérifier que le trust store est déverrouillé
    {
        let store = tm.trust_store.lock().await;
        if !store.is_unlocked() {
            return Err("Trust store non déverrouillé".to_string());
        }
        if !store.is_sync_enabled() {
            return Err("Synchronisation non activée dans les paramètres".to_string());
        }
    }

    // Récupérer la session sécurisée PQC et la connexion
    let mut sessions = tm.active_sessions.lock().await;
    let mut connections = tm.active_connections.lock().await;

    let secure_session = sessions.get_mut(&transfer_id)
        .ok_or("Aucune session sécurisée pour ce transfert")?;
    let conn = connections.get_mut(&transfer_id)
        .ok_or("Aucune connexion active pour ce transfert")?;
    let stream = &mut *conn.stream;

    // 1. Exporter notre trust store
    let local_data = {
        let store = tm.trust_store.lock().await;
        store.export_for_sync()?
    };

    // 2. Envoyer via la session PQC (déjà chiffré ChaCha20-Poly1305 + clé hybride ML-KEM)
    let sync_msg = TransferMessage::TrustStoreSync {
        trust_data: local_data,
    };
    secure_session.send_message(stream, &sync_msg).await
        .map_err(|e| format!("Envoi sync: {}", e))?;

    // 3. Recevoir la réponse du pair (son trust store + ack)
    let response = secure_session.recv_message(stream).await
        .map_err(|e| format!("Réception sync: {}", e))?;

    let mut merged_count = 0u32;

    match response {
        TransferMessage::TrustStoreSync { trust_data } => {
            // Fusionner les données du pair
            let mut store = tm.trust_store.lock().await;
            merged_count = store.merge_from_sync(&trust_data)?;

            // Envoyer notre ACK
            let ack_msg = TransferMessage::TrustStoreSyncAck { merged_count };
            secure_session.send_message(stream, &ack_msg).await
                .map_err(|e| format!("Envoi ack sync: {}", e))?;
        }
        TransferMessage::TrustStoreSyncAck { merged_count: remote_merged } => {
            eprintln!("[SYNC] Pair a fusionné {} entrées de notre trust store", remote_merged);
        }
        _ => {
            return Err("Réponse sync inattendue".to_string());
        }
    }

    eprintln!("[SYNC] Trust store synchronisé : {} entrées fusionnées", merged_count);
    Ok(merged_count)
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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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
    if let Err(e) = tm.discovery.register_mdns_service_on_port(actual_port).await {
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
    *tm.active_listener.lock().await = Some(listener.clone());

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

    // ── Background task: accept connection → handshake → exchange ML-DSA keys ──
    tokio::spawn(async move {
        let result: Result<(), String> = async {
            // Wait for joiner connection (same race logic as C1)
            eprintln!("[SYNC-PAIR] Initiator: waiting for joiner, TTL={}s", WORMHOLE_TTL_SECS);
            let conn = tokio::time::timeout(
                std::time::Duration::from_secs(WORMHOLE_TTL_SECS),
                async {
                    tokio::select! {
                        accept_result = listener.accept() => {
                            eprintln!("[SYNC-PAIR] Initiator: accept() won the race");
                            accept_result
                        }
                        discover_result = async {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            eprintln!("[SYNC-PAIR] Initiator: scanning mDNS for joiner...");
                            let peer = super::discovery::discover_receiver_peer(55).await?;
                            eprintln!("[SYNC-PAIR] Initiator: found joiner at {}:{}", peer.addr, peer.port);
                            connect_to_peer(&peer).await
                        } => {
                            eprintln!("[SYNC-PAIR] Initiator: mDNS discover won the race");
                            discover_result
                        }
                    }
                }
            ).await
            .map_err(|_| format!("Code wormhole expiré après {} secondes", WORMHOLE_TTL_SECS))??;

            let mut stream = conn.stream;

            // ── Hello exchange (initiator reads first, then sends) ──
            let joiner_hello = protocol::read_message(&mut stream).await?;
            let joiner_name = match &joiner_hello {
                TransferMessage::Hello { peer_name, .. } => peer_name.clone(),
                _ => "FluXlock Peer".to_string(),
            };

            let hello = TransferMessage::Hello {
                protocol_version: protocol::PROTOCOL_VERSION,
                peer_name: name.clone(),
                capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string(), "sync-pair".to_string()],
            };
            protocol::write_message(&mut stream, &hello).await?;

            if let Some(info) = active_transfers.lock().await.get_mut(&pid) {
                info.state = TransferState::Handshaking;
                info.peer_name = Some(joiner_name.clone());
            }

            // ── SPAKE2 + ML-KEM handshake (initiator side) ──
            let joiner_spake = protocol::read_message(&mut stream).await?;
            let joiner_spake_body = match joiner_spake {
                TransferMessage::SpakeMessage { body } => body,
                _ => return Err("Protocole invalide : message SPAKE2 attendu".to_string()),
            };

            let initiator = handshake::HandshakeInitiator::new(&wc)?;
            let spake_msg = TransferMessage::SpakeMessage {
                body: initiator.spake_message().to_vec(),
            };
            protocol::write_message(&mut stream, &spake_msg).await?;

            let phase1 = initiator.complete_spake2(&joiner_spake_body)?;
            let kem_pub = TransferMessage::KemEncapsulation {
                ek_bytes: phase1.ek_bytes.clone(),
            };
            protocol::write_message(&mut stream, &kem_pub).await?;

            let kem_ct_msg = protocol::read_message(&mut stream).await?;
            let ct_bytes = match kem_ct_msg {
                TransferMessage::KemCiphertext { ct_bytes } => ct_bytes,
                _ => return Err("Protocole invalide : KEM ciphertext attendu".to_string()),
            };

            let hs_result = phase1.finalize_with_kem(&ct_bytes)?;
            let mut secure_session = SecureSession::new(hs_result.session_key, true)?;
            eprintln!("[SYNC-PAIR] Initiator: PQC handshake complete, safety_number={}", hs_result.safety_number);

            // ── Exchange ML-DSA-65 keys via encrypted channel ──
            // Initiator sends SyncPairRequest
            let request = TransferMessage::SyncPairRequest {
                device_name: name.clone(),
                verifying_key_b64: vk_b64.clone(),
            };
            secure_session.send_message(&mut stream, &request).await?;

            // Wait for SyncPairResponse from joiner
            let response = secure_session.recv_message(&mut stream).await?;
            match response {
                TransferMessage::SyncPairResponse { device_name, verifying_key_b64, accepted } => {
                    if !accepted {
                        return Err("L'autre appareil a refusé l'appairage".to_string());
                    }

                    // Register the joiner as a sync device
                    let mut store = trust_store.lock().await;
                    store.add_sync_device(&device_name, &verifying_key_b64)?;
                    // Auto-enable sync
                    let _ = store.set_sync_enabled(true);
                    eprintln!("[SYNC-PAIR] Initiator: paired with '{}', sync enabled", device_name);

                    if let Some(info) = active_transfers.lock().await.get_mut(&pid) {
                        info.state = TransferState::Completed;
                        info.peer_name = Some(device_name);
                    }
                }
                _ => return Err("Réponse d'appairage invalide".to_string()),
            }

            Ok(())
        }.await;

        if let Err(e) = result {
            eprintln!("[SYNC-PAIR] Initiator error: {}", e);
            if let Some(info) = active_transfers.lock().await.get_mut(&pid) {
                info.state = TransferState::Failed { reason: e };
            }
        }
    });

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
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

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

    // ── Parse wormhole code: extract IPv6 endpoint if present ──
    let raw_code = wormhole_code.trim().to_string();
    eprintln!("[SYNC-PAIR] Joiner: raw wormhole code = {}", raw_code);

    let (spake_code, ipv6_endpoint) = if let Some(idx) = raw_code.find('@') {
        let code_part = raw_code[..idx].to_string();
        let endpoint_part = raw_code[idx + 1..].to_string();
        let parsed = if endpoint_part.starts_with('[') {
            if let Some(bracket_end) = endpoint_part.find(']') {
                let ip = endpoint_part[1..bracket_end].to_string();
                let port = endpoint_part.get(bracket_end + 2..)
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(DEFAULT_TRANSFER_PORT);
                Some((ip, port))
            } else { None }
        } else { None };
        (code_part, parsed)
    } else {
        (raw_code.clone(), None)
    };

    // ── Multi-strategy connection (same as C2) ──
    let mut conn: Option<TransportConnection> = None;

    // Strategy 1: Cross-network IPv6 from wormhole code
    if conn.is_none() {
        if let Some((ref ip, port)) = ipv6_endpoint {
            let v6_peer = super::discovery::DiscoveredPeer {
                name: "ipv6-endpoint".to_string(),
                addr: ip.clone(),
                port,
                method: "IPv6-Direct".to_string(),
                verified: false,
            };
            eprintln!("[SYNC-PAIR] Joiner: trying IPv6 {}:{}", ip, port);
            match connect_to_peer(&v6_peer).await {
                Ok(c) => { eprintln!("[SYNC-PAIR] Joiner: IPv6 connection OK!"); conn = Some(c); }
                Err(e) => { eprintln!("[SYNC-PAIR] Joiner: IPv6 failed: {}", e); }
            }
        }
    }

    // Strategy 2: mDNS + link-local
    if conn.is_none() {
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[SYNC-PAIR] Joiner: start_mdns_discovery failed: {}", e);
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let mut peers = tm.discovery.get_discovered_peers().await;
        if let Ok(v6_peers) = tm.discovery.scan_ipv6_link_local().await {
            peers.extend(v6_peers);
        }
        if !peers.is_empty() {
            if let Ok(c) = establish_connection(&peers).await {
                conn = Some(c);
            }
        }
    }

    // Strategy 3: Localhost fallback (same machine testing)
    if conn.is_none() {
        let localhost = super::discovery::DiscoveredPeer {
            name: "localhost".to_string(),
            addr: "127.0.0.1".to_string(),
            port: DEFAULT_TRANSFER_PORT,
            method: "Direct".to_string(),
            verified: false,
        };
        if let Ok(c) = connect_to_peer(&localhost).await {
            conn = Some(c);
        }
    }

    // Strategy 4: Reverse connection — start our own listener, let initiator connect to us
    if conn.is_none() {
        if let Err(e) = tm.discovery.start_mdns_discovery().await {
            eprintln!("[SYNC-PAIR] Joiner: start_mdns for reverse failed: {}", e);
        }
        let reverse_listener = match TransportListener::bind(DEFAULT_TRANSFER_PORT).await {
            Ok(l) => l,
            Err(_) => TransportListener::bind(0).await
                .map_err(|e| format!("Reverse listener : {}", e))?,
        };
        let reverse_port = reverse_listener.local_port;
        eprintln!("[SYNC-PAIR] Joiner: starting reverse listener on port {}", reverse_port);
        if let Err(e) = tm.discovery.register_receiver_mdns(reverse_port).await {
            eprintln!("[SYNC-PAIR] Joiner: register_receiver_mdns failed: {}", e);
        }

        match tokio::time::timeout(
            std::time::Duration::from_secs(60),
            reverse_listener.accept(),
        ).await {
            Ok(Ok(c)) => { eprintln!("[SYNC-PAIR] Joiner: initiator connected via reverse"); conn = Some(c); }
            Ok(Err(e)) => { eprintln!("[SYNC-PAIR] Joiner: reverse accept error: {}", e); }
            Err(_) => { eprintln!("[SYNC-PAIR] Joiner: reverse listener timeout (60s)"); }
        }
    }

    let conn = conn.ok_or_else(|| {
        if ipv6_endpoint.is_some() {
            "Impossible de se connecter via IPv6. Vérifiez que l'autre appareil attend l'appairage.".to_string()
        } else {
            "Appareil introuvable. Vérifiez le code wormhole et que l'autre appareil attend l'appairage.".to_string()
        }
    })?;

    let mut stream = conn.stream;
    drop(tm_guard); // Release lock before long I/O

    // ── Hello exchange (joiner sends first, then reads) ──
    let hello = TransferMessage::Hello {
        protocol_version: protocol::PROTOCOL_VERSION,
        peer_name: our_name.clone(),
        capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string(), "sync-pair".to_string()],
    };
    protocol::write_message(&mut stream, &hello).await?;

    let initiator_hello = protocol::read_message(&mut stream).await?;
    let _initiator_name = match &initiator_hello {
        TransferMessage::Hello { peer_name, .. } => peer_name.clone(),
        _ => "FluXlock Peer".to_string(),
    };

    // ── SPAKE2 + ML-KEM handshake (responder side) ──
    let responder = handshake::HandshakeResponder::new(&spake_code)?;

    let spake_msg = TransferMessage::SpakeMessage {
        body: responder.spake_message().to_vec(),
    };
    protocol::write_message(&mut stream, &spake_msg).await?;

    let initiator_spake = protocol::read_message(&mut stream).await?;
    let initiator_spake_body = match initiator_spake {
        TransferMessage::SpakeMessage { body } => body,
        _ => return Err("Protocole invalide : message SPAKE2 attendu".to_string()),
    };

    let kem_msg = protocol::read_message(&mut stream).await?;
    let ek_bytes = match kem_msg {
        TransferMessage::KemEncapsulation { ek_bytes } => ek_bytes,
        _ => return Err("Protocole invalide : KEM encapsulation attendue".to_string()),
    };

    let (result, ct_bytes) = responder.complete_handshake(&initiator_spake_body, &ek_bytes)?;
    let kem_ct = TransferMessage::KemCiphertext { ct_bytes };
    protocol::write_message(&mut stream, &kem_ct).await?;

    let mut secure_session = SecureSession::new(result.session_key, false)?;
    eprintln!("[SYNC-PAIR] Joiner: PQC handshake complete, safety_number={}", result.safety_number);

    // ── Receive SyncPairRequest from initiator ──
    let request = secure_session.recv_message(&mut stream).await?;
    let (initiator_device_name, initiator_vk_b64) = match request {
        TransferMessage::SyncPairRequest { device_name, verifying_key_b64 } => {
            (device_name, verifying_key_b64)
        }
        _ => return Err("Protocole invalide : SyncPairRequest attendu".to_string()),
    };

    // ── Send SyncPairResponse with our key ──
    let response = TransferMessage::SyncPairResponse {
        device_name: our_name.clone(),
        verifying_key_b64: our_vk_b64.clone(),
        accepted: true,
    };
    secure_session.send_message(&mut stream, &response).await?;

    // ── Register the initiator as a sync device ──
    let tm_guard2 = state.transfer_manager.lock().await;
    let tm2 = tm_guard2.as_ref().ok_or("Module de transfert non initialisé")?;
    {
        let mut store = tm2.trust_store.lock().await;
        store.add_sync_device(&initiator_device_name, &initiator_vk_b64)?;
        let _ = store.set_sync_enabled(true);
    }
    eprintln!("[SYNC-PAIR] Joiner: paired with '{}', sync enabled", initiator_device_name);

    Ok(SyncPairingResult {
        success: true,
        device_name: initiator_device_name,
    })
}

// ─────────────────────────────────────────────────────────
// C18 : Auto-sync avec un pair appairé découvert sur le même réseau
// ─────────────────────────────────────────────────────────

/// Résultat de l'auto-sync
#[derive(Debug, Serialize)]
pub struct AutoSyncResult {
    pub success: bool,
    pub merged_count: u32,
    pub peer_name: String,
}

/// C18 : Synchronise automatiquement le trust store avec un pair appairé
/// découvert sur le réseau local (verified = true dans le beacon).
///
/// Protocole simplifié (pas de SPAKE2 — l'authentification repose sur ML-DSA-65) :
/// 1. Connexion TLS au pair
/// 2. Hello avec capability "auto-sync"
/// 3. ML-KEM-768 pour chiffrement de session
/// 4. Échange de trust stores signés ML-DSA-65
/// 5. Vérification croisée des VK contre les sync_devices connus
#[tauri::command]
pub async fn transfer_auto_sync_with_peer(
    peer_addr: String,
    peer_port: u16,
    state: tauri::State<'_, crate::AppState>,
) -> Result<AutoSyncResult, String> {
    // Vérifier le mode isolation réseau
    if *state.isolation_mode.lock().await {
        return Err("Mode isolation activé — sync automatique désactivée".to_string());
    }
    let session = state.session.lock().await;
    if session.is_none() {
        return Err("Non authentifié".to_string());
    }
    drop(session);

    let tm_guard = state.transfer_manager.lock().await;
    let tm = tm_guard.as_ref().ok_or("Module de transfert non initialisé")?;

    // Vérifier que la sync est activée et le trust store déverrouillé
    let (our_vk_b64, our_name, trust_data) = {
        let store = tm.trust_store.lock().await;
        if !store.is_unlocked() {
            return Err("Trust store non déverrouillé".to_string());
        }
        if !store.is_sync_enabled() {
            return Err("Synchronisation non activée".to_string());
        }
        let vk = store.device_verifying_key_b64()?;
        let data = store.export_for_sync()?;
        (vk, tm.peer_name.clone(), data)
    };

    drop(tm_guard);

    // Connecter au pair
    let peer = DiscoveredPeer {
        name: "auto-sync-peer".to_string(),
        addr: peer_addr.clone(),
        port: peer_port,
        method: "AutoSync".to_string(),
        verified: true,
    };
    let conn = connect_to_peer(&peer).await
        .map_err(|e| format!("Connexion auto-sync échouée: {}", e))?;
    let mut stream = conn.stream;

    // Hello avec capability auto-sync
    let hello = TransferMessage::Hello {
        protocol_version: protocol::PROTOCOL_VERSION,
        peer_name: our_name.clone(),
        capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string(), "auto-sync".to_string()],
    };
    protocol::write_message(&mut stream, &hello).await?;

    // Lire Hello du pair
    let peer_hello = protocol::read_message(&mut stream).await?;
    let _peer_name = match &peer_hello {
        TransferMessage::Hello { peer_name, capabilities, .. } => {
            if !capabilities.contains(&"auto-sync".to_string()) {
                return Err("Le pair ne supporte pas l'auto-sync".to_string());
            }
            peer_name.clone()
        }
        _ => return Err("Protocole invalide : Hello attendu".to_string()),
    };

    // ML-KEM-768 key exchange (initiator: generate keypair, send encapsulation key)
    let (keypair_ek, keypair_dk) = kem::generate_recipient_keypair()
        .map_err(|e| format!("ML-KEM keygen: {}", e))?;

    let kem_pub = TransferMessage::KemEncapsulation {
        ek_bytes: keypair_ek.to_bytes(),
    };
    protocol::write_message(&mut stream, &kem_pub).await?;

    // Receive KEM ciphertext from peer
    let kem_ct_msg = protocol::read_message(&mut stream).await?;
    let ct_bytes = match kem_ct_msg {
        TransferMessage::KemCiphertext { ct_bytes } => ct_bytes,
        _ => return Err("Protocole invalide : KEM ciphertext attendu".to_string()),
    };

    // Derive shared secret
    let dk = kem::KemPrivateKey::from_bytes(&keypair_dk.to_bytes())
        .map_err(|e| format!("ML-KEM import dk: {}", e))?;
    let ct = kem::KemCiphertext::from_bytes(&ct_bytes);
    let kem_shared = kem::decapsulate(&dk, &ct)
        .map_err(|e| format!("ML-KEM decapsulate: {}", e))?;

    // Derive session key via HKDF (KEM-only, no SPAKE2)
    let session_key = {
        let salt = b"fluxlock-autosync-v1";
        let info = b"session-key";
        let derived = secure_vault_crypto::derive_key_hkdf(kem_shared.as_bytes(), Some(salt), info, 32)
            .map_err(|e| format!("HKDF derivation: {}", e))?;
        let mut key = [0u8; 32];
        key.copy_from_slice(derived.expose_secret());
        key
    };
    let mut secure_session = SecureSession::new(session_key, true)?;

    // Envoyer notre trust store signé ML-DSA-65 via la session chiffrée
    let sync_request = TransferMessage::AutoSyncRequest {
        device_name: our_name.clone(),
        verifying_key_b64: our_vk_b64.clone(),
        trust_data,
    };
    secure_session.send_message(&mut stream, &sync_request).await?;

    // Recevoir la réponse du pair
    let response = secure_session.recv_message(&mut stream).await?;
    match response {
        TransferMessage::AutoSyncResponse {
            accepted, device_name, verifying_key_b64, trust_data, merged_count: remote_merged,
        } => {
            if !accepted {
                return Err(format!("Le pair '{}' a refusé l'auto-sync", device_name));
            }

            // Vérifier que le pair est un sync device connu
            let tm_guard2 = state.transfer_manager.lock().await;
            let tm2 = tm_guard2.as_ref().ok_or("Module de transfert non initialisé")?;
            let mut store = tm2.trust_store.lock().await;

            let known_devices = store.list_sync_devices();
            let is_known = known_devices.iter().any(|d| d.verifying_key == verifying_key_b64);
            if !is_known {
                return Err("Le pair n'est pas un appareil de sync autorisé".to_string());
            }

            // Fusionner le trust store du pair (vérifie la signature ML-DSA-65)
            let merged_count = store.merge_from_sync(&trust_data)?;

            eprintln!("[AUTO-SYNC] Sync terminée avec '{}': {} entrées fusionnées (pair: {})",
                device_name, merged_count, remote_merged);

            Ok(AutoSyncResult {
                success: true,
                merged_count,
                peer_name: device_name,
            })
        }
        TransferMessage::Error { message, .. } => {
            Err(format!("Erreur auto-sync: {}", message))
        }
        _ => Err("Réponse auto-sync invalide".to_string()),
    }
}

/// C18b : Handler côté récepteur pour l'auto-sync.
/// Appelé quand on reçoit une connexion entrante avec capability "auto-sync".
/// N'est PAS une commande Tauri — c'est un handler interne appelé depuis le listener.
pub async fn handle_auto_sync_incoming(
    mut stream: Box<dyn super::transport::AsyncReadWrite>,
    trust_store: Arc<Mutex<TrustStore>>,
    our_name: String,
) -> Result<(), String> {
    // Lire Hello du pair (déjà envoyé par l'initiateur)
    let peer_hello = protocol::read_message(&mut stream).await?;
    let _peer_name = match &peer_hello {
        TransferMessage::Hello { peer_name, capabilities, .. } => {
            if !capabilities.contains(&"auto-sync".to_string()) {
                let err = TransferMessage::Error {
                    code: 400,
                    message: "auto-sync non supporté".to_string(),
                };
                protocol::write_message(&mut stream, &err).await?;
                return Err("Pair ne supporte pas auto-sync".to_string());
            }
            peer_name.clone()
        }
        _ => return Err("Protocole invalide : Hello attendu".to_string()),
    };

    // Envoyer notre Hello
    let store = trust_store.lock().await;
    let our_vk = store.device_verifying_key_b64()?;
    drop(store);

    let hello = TransferMessage::Hello {
        protocol_version: protocol::PROTOCOL_VERSION,
        peer_name: our_name.clone(),
        capabilities: vec!["pqc-kem".to_string(), "chacha20".to_string(), "auto-sync".to_string()],
    };
    protocol::write_message(&mut stream, &hello).await?;

    // Recevoir ML-KEM encapsulation key de l'initiateur
    let kem_msg = protocol::read_message(&mut stream).await?;
    let ek_bytes = match kem_msg {
        TransferMessage::KemEncapsulation { ek_bytes } => ek_bytes,
        _ => return Err("Protocole invalide : KEM encapsulation attendue".to_string()),
    };

    // Encapsuler et renvoyer le ciphertext
    let ek = kem::KemPublicKey::from_bytes(&ek_bytes)
        .map_err(|e| format!("ML-KEM import ek: {}", e))?;
    let (kem_shared, ct) = kem::encapsulate(&ek)
        .map_err(|e| format!("ML-KEM encapsulate: {}", e))?;

    let kem_ct = TransferMessage::KemCiphertext { ct_bytes: ct.as_bytes().to_vec() };
    protocol::write_message(&mut stream, &kem_ct).await?;

    // Derive session key via HKDF (KEM-only, no SPAKE2)
    let session_key = {
        let salt = b"fluxlock-autosync-v1";
        let info = b"session-key";
        let derived = secure_vault_crypto::derive_key_hkdf(kem_shared.as_bytes(), Some(salt), info, 32)
            .map_err(|e| format!("HKDF derivation: {}", e))?;
        let mut key = [0u8; 32];
        key.copy_from_slice(derived.expose_secret());
        key
    };
    let mut secure_session = SecureSession::new(session_key, false)?;

    // Recevoir la demande de sync du pair
    let request = secure_session.recv_message(&mut stream).await?;
    match request {
        TransferMessage::AutoSyncRequest {
            device_name, verifying_key_b64, trust_data,
        } => {
            let mut store = trust_store.lock().await;

            // Vérifier que le pair est un sync device connu
            let known_devices = store.list_sync_devices();
            let is_known = known_devices.iter().any(|d| d.verifying_key == verifying_key_b64);

            if !is_known || !store.is_sync_enabled() {
                let response = TransferMessage::AutoSyncResponse {
                    accepted: false,
                    device_name: our_name,
                    verifying_key_b64: our_vk,
                    trust_data: String::new(),
                    merged_count: 0,
                };
                secure_session.send_message(&mut stream, &response).await?;
                return Err("Pair non autorisé ou sync désactivée".to_string());
            }

            // Fusionner le trust store du pair
            let merged_count = store.merge_from_sync(&trust_data)?;

            // Exporter notre trust store signé
            let our_trust_data = store.export_for_sync()?;

            let response = TransferMessage::AutoSyncResponse {
                accepted: true,
                device_name: our_name,
                verifying_key_b64: our_vk,
                trust_data: our_trust_data,
                merged_count,
            };
            secure_session.send_message(&mut stream, &response).await?;

            eprintln!("[AUTO-SYNC] Incoming sync avec '{}': {} entrées fusionnées",
                device_name, merged_count);

            Ok(())
        }
        _ => Err("Protocole invalide : AutoSyncRequest attendu".to_string()),
    }
}

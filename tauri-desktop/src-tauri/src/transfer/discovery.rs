//! Discovery — Découverte de pairs sur le réseau local.
//!
//! Stratégie (ordonnée par préférence) :
//! 1. mDNS/DNS-SD : annonce le service `_fluxlock-transfer._tcp.local.`
//! 2. Balises UDP sur le réseau local
//!
//! Le module expose un `DiscoveryService` qui gère à la fois l'annonce et la
//! découverte, et retourne une liste de `DiscoveredPeer`.

use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::Mutex;

use super::protocol::MDNS_SERVICE_TYPE;

/// Pair découvert sur le réseau
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    pub name: String,
    pub addr: String,
    pub port: u16,
    pub method: String,
    /// V-08: true si le fingerprint du beacon correspond à un pair de confiance
    #[serde(default)]
    pub verified: bool,
}

/// Port UDP dédié au beacon de découverte (distinct du port TCP de transfert)
const BEACON_PORT: u16 = 52_821;

/// Multicast group for LAN discovery (works on Android where broadcast is blocked)
const MULTICAST_GROUP: &str = "239.255.77.77";

const BEACON_TTL: Duration = Duration::from_secs(10);
const REGISTRY_MDNS_SERVICE: &str = "_fluxlock-sync._tcp.local.";

struct MdnsPeer {
    endpoints: Vec<DiscoveredPeer>,
    fingerprint: Option<String>,
}

struct LanPeer {
    peer: DiscoveredPeer,
    fingerprint: String,
    sync_port: u16,
    seen: Instant,
}

/// Service de découverte réseau.
#[derive(Clone)]
pub struct DiscoveryService {
    peers: Arc<Mutex<HashMap<String, MdnsPeer>>>,
    lan_peers: Arc<Mutex<HashMap<String, LanPeer>>>,
    offer_port: Arc<AtomicU16>,
    sync_port: Arc<AtomicU16>,
    instance_name: String,
    service_instance: String,
    mdns_daemon: Arc<Mutex<Option<mdns_sd::ServiceDaemon>>>,
    discovery_started: Arc<Mutex<bool>>,
    /// Drapeau de visibilité — le beacon ne diffuse que quand visible = true (E-01)
    visible: Arc<Mutex<bool>>,
    /// V-08: Empreintes BLAKE3 des pairs de confiance (remplies au unlock du trust store)
    trusted_fingerprints: Arc<Mutex<Vec<String>>>,
    /// V-08: Empreinte de cet appareil (BLAKE3 de la clé de vérification ML-DSA)
    device_fingerprint: Arc<Mutex<Option<String>>>,
}

impl DiscoveryService {
    pub fn new(instance_name: &str, visible: Arc<Mutex<bool>>) -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            lan_peers: Arc::new(Mutex::new(HashMap::new())),
            offer_port: Arc::new(AtomicU16::new(0)),
            sync_port: Arc::new(AtomicU16::new(0)),
            instance_name: instance_name.to_string(),
            service_instance: format!("FluXlock-{}", uuid::Uuid::new_v4().simple()),
            mdns_daemon: Arc::new(Mutex::new(None)),
            discovery_started: Arc::new(Mutex::new(false)),
            visible,
            trusted_fingerprints: Arc::new(Mutex::new(Vec::new())),
            device_fingerprint: Arc::new(Mutex::new(None)),
        }
    }

    /// V-08: Met à jour les empreintes de confiance et le fingerprint de cet appareil.
    /// Appelé après unlock du trust store pour permettre la vérification des beacons.
    pub async fn set_trust_info(&self, device_fp: Option<String>, trusted_fps: Vec<String>) {
        *self.device_fingerprint.lock().await = device_fp;
        *self.trusted_fingerprints.lock().await = trusted_fps;
    }

    /// Returns whether discovery has already been started
    pub async fn is_started(&self) -> bool {
        *self.discovery_started.lock().await
    }

    /// Lance la découverte mDNS en arrière-plan (idempotent)
    pub async fn start_mdns_discovery(&self) -> Result<(), String> {
        let mut started = self.discovery_started.lock().await;
        if *started {
            return Ok(());
        }

        // ── 1. Start UDP broadcast beacon (primary, most reliable) ──
        self.start_lan_beacon().await;

        // Mark as started — UDP beacon is active even if mDNS fails below
        *started = true;

        // ── 2. Start mDNS/DNS-SD (secondary, non-fatal if unavailable) ──
        let daemon = match mdns_sd::ServiceDaemon::new() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("[DISCOVERY] mDNS daemon creation failed (UDP beacon still active): {}", e);
                return Ok(());
            }
        };

        // RFC 6763 §7.2: service name limited to 15 chars by default.
        // "fluxlock-transfer" = 17 chars — extend limit so mDNS queries work.
        let _ = daemon.set_service_name_len_max(24);

        for service in [MDNS_SERVICE_TYPE, REGISTRY_MDNS_SERVICE] {
            match daemon.browse(service) {
                Ok(receiver) => self.collect_mdns_peers(receiver, service),
                Err(error) => eprintln!("[DISCOVERY] Recherche mDNS {service} : {error}"),
            }
        }
        *self.mdns_daemon.lock().await = Some(daemon);
        Ok(())
    }

    fn collect_mdns_peers(&self, receiver: mdns_sd::Receiver<mdns_sd::ServiceEvent>, service: &'static str) {
        let peers = self.peers.clone();
        let own_instance = format!("{}.{service}", self.service_instance);
        let suffix = format!(".{service}");
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                match event {
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        let fullname = info.get_fullname().to_owned();
                        if fullname == own_instance {
                            continue;
                        }
                        let name = info.get_property_val_str("name")
                            .or_else(|| fullname.strip_suffix(&suffix)).unwrap_or(&fullname);
                        let endpoints = mdns_endpoints(&info, name);
                        let fingerprint = info.get_property_val_str("fingerprint").map(str::to_owned);
                        peers.lock().await.insert(fullname, MdnsPeer { endpoints, fingerprint });
                    }
                    mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                        peers.lock().await.remove(&fullname);
                    }
                    _ => {}
                }
            }
        });
    }

    /// UDP broadcast beacon — reliable P2P discovery on the LAN.
    /// Periodically announces this device and listens for other devices.
    /// Uses broadcast (desktop) + multicast 239.255.77.77 (all platforms, especially Android
    /// where broadcast is often blocked by Wi-Fi chipset power management).
    async fn start_lan_beacon(&self) {
        // Use a dedicated beacon port (distinct from the TCP transfer port)
        // and SO_REUSEADDR+SO_REUSEPORT so multiple devices on the same machine can coexist
        let socket = match create_reusable_udp_socket(BEACON_PORT).await {
            Ok(s) => std::sync::Arc::new(s),
            Err(e) => {
                eprintln!("[DISCOVERY] LAN beacon bind failed (port {} in use?): {}", BEACON_PORT, e);
                return;
            }
        };
        if let Err(e) = socket.set_broadcast(true) {
            eprintln!("[DISCOVERY] LAN beacon set_broadcast failed: {}", e);
            // Don't return — multicast may still work (especially on Android)
        }

        // Join multicast group for platforms where broadcast is unreliable (Android)
        let multicast_addr: std::net::Ipv4Addr = MULTICAST_GROUP.parse().unwrap();
        let local_ips = get_local_ipv4_addresses();
        let multicast_if = local_ips.first().copied().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

        // Try joining multicast with specific interface first, fallback to UNSPECIFIED
        let joined = if multicast_if != std::net::Ipv4Addr::UNSPECIFIED {
            match socket.join_multicast_v4(multicast_addr, multicast_if) {
                Ok(_) => {
                    eprintln!("[DISCOVERY] Multicast join OK via {}", multicast_if);
                    true
                }
                Err(e) => {
                    eprintln!("[DISCOVERY] Multicast join via {} failed: {}, trying UNSPECIFIED", multicast_if, e);
                    socket.join_multicast_v4(multicast_addr, std::net::Ipv4Addr::UNSPECIFIED)
                        .map(|_| {
                            eprintln!("[DISCOVERY] Multicast join OK via UNSPECIFIED");
                        })
                        .is_ok()
                }
            }
        } else {
            match socket.join_multicast_v4(multicast_addr, std::net::Ipv4Addr::UNSPECIFIED) {
                Ok(_) => {
                    eprintln!("[DISCOVERY] Multicast join OK via UNSPECIFIED (no local IP found)");
                    true
                }
                Err(e) => {
                    eprintln!("[DISCOVERY] Multicast join failed (non-fatal): {}", e);
                    false
                }
            }
        };

        if !joined {
            eprintln!("[DISCOVERY] WARNING: multicast not joined — will rely on broadcast only");
        }

        // Tell the OS which interface to use for outgoing multicast (required on macOS/Android)
        #[cfg(unix)]
        {
            let sock_ref = socket2::SockRef::from(&socket);
            if let Err(e) = sock_ref.set_multicast_if_v4(&multicast_if) {
                eprintln!("[DISCOVERY] set_multicast_if failed (non-fatal): {}", e);
            }
        }

        eprintln!("[DISCOVERY] LAN beacon started on UDP port {}", BEACON_PORT);

        let own_ips: Vec<String> = get_local_ipv4_addresses()
            .iter()
            .map(|ip| ip.to_string())
            .collect();
        let own_name = self.instance_name.clone();
        let offer_port = self.offer_port.clone();
        let sync_port = self.sync_port.clone();
        let peers = self.lan_peers.clone();
        let broadcast_targets = get_broadcast_addresses(BEACON_PORT);

        // ── Announce task: send periodic UDP broadcasts (seulement si visible, E-01) ──
        let socket_tx = socket.clone();
        let name_tx = own_name.clone();
        let visible_flag = self.visible.clone();
        let device_fp = self.device_fingerprint.clone();
        tokio::spawn(async move {
            let mut send_error_count: u32 = 0;
            loop {
                let transfer_port = offer_port.load(Ordering::Relaxed);
                if transfer_port != 0 || *visible_flag.lock().await {
                    // V-08: include device fingerprint in beacon for trust verification
                    let fp = device_fp.lock().await.clone().unwrap_or_default();
                    let sync_port = sync_port.load(Ordering::Relaxed);
                    let msg = format!("FLUXLOCK|{name_tx}|{transfer_port}|{fp}|{sync_port}");
                    for target in &broadcast_targets {
                        if let Err(e) = socket_tx.send_to(msg.as_bytes(), target).await {
                            // Only log first few errors to avoid log spam
                            // (macOS Local Network Privacy causes persistent errno 65)
                            if send_error_count < 3 {
                                eprintln!("[DISCOVERY] beacon send_to {} failed: {}", target, e);
                            } else if send_error_count == 3 {
                                eprintln!("[DISCOVERY] suppressing further beacon send errors");
                            }
                            send_error_count = send_error_count.saturating_add(1);
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });

        // ── Listen task: receive announcements from other devices ──
        let own_ips_rx = own_ips;
        let trusted_fps = self.trusted_fingerprints.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let msg = String::from_utf8_lossy(&buf[..n]);
                        if let Some(rest) = msg.strip_prefix("FLUXLOCK|") {
                            // V-08: parse format "name|port|fingerprint" (fingerprint optional for compat)
                            let parts: Vec<&str> = rest.splitn(3, '|').collect();
                            if parts.len() >= 2 {
                                let name = parts[0].to_string();
                                let Ok(port) = parts[1].trim().parse::<u16>() else { continue };
                                let peer_fp = if parts.len() >= 3 {
                                    parts[2].trim().to_string()
                                } else {
                                    String::new()
                                };

                                // Skip our own announcements (by IP)
                                let source_ip = addr.ip().to_string();
                                let clean_ip = source_ip
                                    .strip_prefix("::ffff:")
                                    .unwrap_or(&source_ip)
                                    .to_string();
                                if own_ips_rx.iter().any(|ip| ip == &clean_ip) {
                                    continue;
                                }
                                // V-08: check if fingerprint matches a trusted peer
                                let verified = if !peer_fp.is_empty() {
                                    trusted_fps.lock().await.iter().any(|fp| fp == &peer_fp)
                                } else {
                                    false
                                };

                                let peer = DiscoveredPeer {
                                    name: name.clone(),
                                    addr: clean_ip.clone(),
                                    port,
                                    method: "LAN".to_string(),
                                    verified,
                                };
                                peers.lock().await.insert(clean_ip, LanPeer {
                                    peer,
                                    fingerprint: peer_fp,
                                    sync_port: parts.get(3).and_then(|port| port.parse().ok()).unwrap_or(0),
                                    seen: Instant::now(),
                                });
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[DISCOVERY] beacon recv error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
    }

    pub async fn advertise_offer(&self, port: u16) -> Result<(), String> {
        self.offer_port.store(port, Ordering::Relaxed);
        self.publish_mdns_service(MDNS_SERVICE_TYPE, &self.service_instance, port, &[]).await
    }

    pub async fn clear_offer(&self) {
        self.offer_port.store(0, Ordering::Relaxed);
        self.remove_mdns_service(MDNS_SERVICE_TYPE, &self.service_instance).await;
    }

    async fn publish_mdns_service(
        &self, service: &str, instance: &str, port: u16, extra: &[(&str, &str)],
    ) -> Result<(), String> {
        let guard = self.mdns_daemon.lock().await;
        let daemon = guard.as_ref().ok_or("Découverte mDNS indisponible")?;
        let mut addresses: HashSet<IpAddr> = get_local_ipv4_addresses().into_iter().map(IpAddr::V4).collect();
        addresses.extend(if_addrs::get_if_addrs().unwrap_or_default().into_iter()
            .filter(|interface| !interface.is_loopback()).map(|interface| interface.addr.ip()));
        let mut properties = vec![("name", self.instance_name.as_str())];
        properties.extend_from_slice(extra);
        let info = mdns_sd::ServiceInfo::new(
            service, instance, &format!("{}.local.", self.service_instance),
            addresses.into_iter().collect::<Vec<_>>().as_slice(), port, properties.as_slice(),
        ).map_err(|error| format!("Service mDNS : {error}"))?;
        daemon.register(info).map_err(|error| format!("Annonce mDNS : {error}"))
    }

    async fn remove_mdns_service(&self, service: &str, instance: &str) {
        if let Some(daemon) = self.mdns_daemon.lock().await.as_ref() {
            if let Ok(status) = daemon.unregister(&format!("{instance}.{service}")) {
                let _ = tokio::time::timeout(Duration::from_secs(1), status.recv_async()).await;
            }
        }
    }

    pub async fn get_discovered_peers(&self) -> Vec<DiscoveredPeer> {
        let mdns = self.peers.lock().await;
        let mut lan = self.lan_peers.lock().await;
        lan.retain(|_, entry| entry.seen.elapsed() < BEACON_TTL);
        let mut peers: Vec<_> = mdns.iter()
            .filter(|(name, _)| name.ends_with(MDNS_SERVICE_TYPE))
            .flat_map(|(_, peer)| peer.endpoints.iter().cloned()).collect();
        peers.extend(lan.values().map(|entry| entry.peer.clone()));
        unique_endpoints(&mut peers);
        peers
    }

    pub(crate) async fn advertise_registry_sync(&self, port: u16) {
        if self.sync_port.swap(port, Ordering::Relaxed) == port {
            return;
        }
        if port == 0 {
            self.remove_mdns_service(REGISTRY_MDNS_SERVICE, &self.service_instance).await;
        } else if let Some(fingerprint) = self.device_fingerprint.lock().await.clone() {
            let _ = self.publish_mdns_service(REGISTRY_MDNS_SERVICE, &self.service_instance,
                port, &[("fingerprint", &fingerprint)]).await;
        }
    }

    pub(crate) async fn get_registry_sync_peers(
        &self, fingerprints: &HashSet<String>,
    ) -> Vec<DiscoveredPeer> {
        let mdns = self.peers.lock().await;
        let mut lan = self.lan_peers.lock().await;
        lan.retain(|_, entry| entry.seen.elapsed() < BEACON_TTL);
        let mut peers: Vec<_> = mdns.iter()
            .filter(|(name, peer)| name.ends_with(REGISTRY_MDNS_SERVICE)
                && peer.fingerprint.as_ref().is_some_and(|fingerprint| fingerprints.contains(fingerprint)))
            .flat_map(|(_, peer)| peer.endpoints.iter().cloned()).collect();
        peers.extend(lan.values().filter(|entry| entry.sync_port != 0 && fingerprints.contains(&entry.fingerprint))
            .map(|entry| DiscoveredPeer { port: entry.sync_port, ..entry.peer.clone() }));
        unique_endpoints(&mut peers);
        peers
    }
}

fn unique_endpoints(peers: &mut Vec<DiscoveredPeer>) {
    let mut endpoints = HashSet::new();
    peers.retain(|peer| endpoints.insert((peer.addr.clone(), peer.port)));
}

fn mdns_endpoints(info: &mdns_sd::ServiceInfo, name: &str) -> Vec<DiscoveredPeer> {
    let interfaces = if_addrs::get_if_addrs().unwrap_or_default();
    let local_addresses: HashSet<_> = interfaces.iter().map(|interface| interface.addr.ip()).collect();
    let scopes: HashSet<_> = interfaces.iter().filter_map(|interface| match interface.addr.ip() {
        IpAddr::V6(ip) if ip.is_unicast_link_local() => interface.index.filter(|index| *index != 0),
        _ => None,
    }).collect();
    let build = |addr: String| DiscoveredPeer {
        name: name.to_owned(), addr, port: info.get_port(), method: "mDNS".into(), verified: false,
    };
    let mut peers = Vec::new();
    for ip in info.get_addresses() {
        if ip.is_loopback() || local_addresses.contains(ip) {
            continue;
        }
        match ip {
            // DNS-SD returns no scope. Try the local interfaces that carry a link-local address.
            IpAddr::V6(ip) if ip.is_unicast_link_local() => {
                peers.extend(scopes.iter().map(|scope| build(format!("{ip}%{scope}"))));
            }
            _ => peers.push(build(ip.to_string())),
        }
    }
    peers.sort_by_key(|peer| peer.addr.contains(':'));
    peers
}

/// Create a UDP socket with SO_REUSEADDR (+ SO_REUSEPORT on Unix) so multiple
/// instances on the same machine can all receive beacon broadcasts.
async fn create_reusable_udp_socket(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.set_multicast_ttl_v4(1)?;
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    socket.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// Returns broadcast + multicast target addresses for LAN discovery.
/// Uses the actual broadcast address reported by each interface (respects subnet mask).
/// On macOS, limited broadcast (255.255.255.255) and multicast sending often fail
/// due to Local Network Privacy restrictions; subnet-directed broadcast is preferred.
/// On Android, broadcast is unreliable; multicast is the primary mechanism.
fn get_broadcast_addresses(port: u16) -> Vec<String> {
    let mut addrs = Vec::new();

    // --- Multicast: always included on all platforms (most reliable on Android) ---
    let multicast = format!("{}:{}", MULTICAST_GROUP, port);
    addrs.push(multicast);

    // --- Subnet-directed broadcast from interface info ---
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = &iface.addr {
                if let Some(bcast) = v4.broadcast {
                    let bcast_str = format!("{}:{}", bcast, port);
                    if !addrs.contains(&bcast_str) {
                        addrs.push(bcast_str);
                    }
                }
            }
        }
    }

    // --- Platform-specific extras ---
    #[cfg(not(target_os = "macos"))]
    {
        // Limited broadcast (255.255.255.255) — works on Linux/Windows as fallback.
        // Often blocked on Android WiFi, but harmless to try.
        let limited = format!("255.255.255.255:{}", port);
        if !addrs.contains(&limited) {
            addrs.push(limited);
        }
    }

    // Fallback: if no subnet broadcast was found (common on Android),
    // compute one from the local IP assuming /24 (most WiFi networks).
    if addrs.len() <= 2 {
        // Only multicast + maybe limited broadcast — no subnet broadcast found
        let local_ips = get_local_ipv4_addresses();
        for ip in &local_ips {
            let octets = ip.octets();
            let guess_bcast = format!("{}.{}.{}.255:{}", octets[0], octets[1], octets[2], port);
            if !addrs.contains(&guess_bcast) {
                eprintln!("[DISCOVERY] No broadcast from if_addrs, guessing /24: {}", guess_bcast);
                addrs.push(guess_bcast);
            }
        }
    }

    eprintln!("[DISCOVERY] Beacon targets: {:?}", addrs);
    addrs
}

/// Récupère les adresses IPv4 locales (non-loopback) du système.
///
/// Utilise `if_addrs` en premier, puis un fallback UDP "connect trick"
/// si aucune adresse n'est trouvée (courant sur certains appareils Android
/// où `getifaddrs()` est absent ou ne retourne pas l'interface WiFi).
pub fn get_local_ipv4_addresses() -> Vec<std::net::Ipv4Addr> {
    let mut addrs = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let IpAddr::V4(v4) = iface.addr.ip() {
                if !addrs.contains(&v4) {
                    addrs.push(v4);
                }
            }
        }
    }

    // Fallback: UDP connect trick — works on all platforms including Android
    // when if_addrs returns empty (common on some Android OEM builds).
    // Connect a UDP socket to a public IP (no packet sent) and read local addr.
    if addrs.is_empty() {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            // Connect to Google DNS — no packet is actually sent for UDP
            if sock.connect("8.8.8.8:80").is_ok() {
                if let Ok(local_addr) = sock.local_addr() {
                    if let IpAddr::V4(v4) = local_addr.ip() {
                        if !v4.is_loopback() && !v4.is_unspecified() {
                            eprintln!("[DISCOVERY] if_addrs empty, fallback detected local IP: {}", v4);
                            addrs.push(v4);
                        }
                    }
                }
            }
        }
    }

    if addrs.is_empty() {
        eprintln!("[DISCOVERY] WARNING: no local IPv4 address found — discovery will be limited");
    }

    addrs
}

/// Returns the first non-link-local, non-loopback public IPv6 address, if any.
/// Used for cross-network transfer (embedded in wormhole code as @[IPv6]:port).
pub fn get_public_ipv6_address() -> Option<std::net::Ipv6Addr> {
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let IpAddr::V6(v6) = iface.addr.ip() {
                // Skip link-local (fe80::/10) and loopback (::1)
                if v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80 {
                    continue;
                }
                // Skip ULA (fc00::/7) — only return GUA (2000::/3)
                if (v6.segments()[0] & 0xe000) == 0x2000 {
                    return Some(v6);
                }
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════
// Reverse connection: receiver registers mDNS, sender discovers and connects
// ═══════════════════════════════════════════════════════════════════════════

/// mDNS service type for receiver's reverse listener.
/// Android blocks incoming TCP, so when the sender is on Android,
/// the receiver (desktop) starts a listener and advertises it here.
pub const RECEIVER_MDNS_SERVICE: &str = "_fluxlock-recv._tcp.local.";

impl DiscoveryService {
    /// Advertise a temporary listener for the reverse connection.
    pub async fn register_receiver_mdns(&self, port: u16) -> Result<(), String> {
        self.publish_mdns_service(RECEIVER_MDNS_SERVICE,
            &format!("{}-{port}", self.service_instance), port, &[]).await
    }

    pub async fn unregister_receiver_mdns(&self, port: u16) {
        self.remove_mdns_service(RECEIVER_MDNS_SERVICE,
            &format!("{}-{port}", self.service_instance)).await;
    }
}

struct TemporaryDaemon(mdns_sd::ServiceDaemon);

impl Drop for TemporaryDaemon {
    fn drop(&mut self) {
        let _ = self.0.shutdown();
    }
}

/// Discover a receiver's reverse listener via mDNS.
/// Creates its own daemon so it can be used from a spawned task.
/// Returns the first resolved receiver peer within the timeout.
pub async fn discover_receiver_peer(timeout_secs: u64) -> Result<DiscoveredPeer, String> {
    let daemon = TemporaryDaemon(mdns_sd::ServiceDaemon::new()
        .map_err(|e| format!("mDNS daemon: {}", e))?);

    // Extend service name length limit for consistency across all daemons
    let _ = daemon.0.set_service_name_len_max(24);

    let browse_chan = daemon.0.browse(RECEIVER_MDNS_SERVICE)
        .map_err(|e| format!("mDNS browse receivers: {}", e))?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("Timeout : aucun receiver trouvé via mDNS".to_string());
        }

        match tokio::time::timeout(remaining, browse_chan.recv_async()).await {
            Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(info))) => {
                if let Some(peer) = mdns_endpoints(&info, info.get_fullname()).into_iter().next() {
                    return Ok(peer);
                }
            }
            Ok(Ok(_)) => continue, // Other mDNS events, keep waiting
            Ok(Err(_)) => {
                return Err("mDNS channel closed".to_string());
            }
            Err(_) => {
                return Err("Timeout : aucun receiver trouvé via mDNS".to_string());
            }
        }
    }
}

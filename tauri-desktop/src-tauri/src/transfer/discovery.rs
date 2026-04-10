//! Discovery — Découverte de pairs sur le réseau local.
//!
//! Stratégie (ordonnée par préférence) :
//! 1. mDNS/DNS-SD : annonce le service `_fluxlock-transfer._tcp.local.`
//! 2. IPv6 link-local : scan des interfaces pour trouver des pairs directs
//!
//! Le module expose un `DiscoveryService` qui gère à la fois l'annonce et la
//! découverte, et retourne une liste de `DiscoveredPeer`.

use serde::{Serialize, Deserialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;

use super::protocol::DEFAULT_TRANSFER_PORT;

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

/// Service de découverte réseau
pub struct DiscoveryService {
    peers: Arc<Mutex<Vec<DiscoveredPeer>>>,
    instance_name: String,
    port: u16,
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
    pub fn new(instance_name: &str, port: u16, visible: Arc<Mutex<bool>>) -> Self {
        Self {
            peers: Arc::new(Mutex::new(Vec::new())),
            instance_name: instance_name.to_string(),
            port,
            mdns_daemon: Arc::new(Mutex::new(None)),
            discovery_started: Arc::new(Mutex::new(false)),
            visible,
            trusted_fingerprints: Arc::new(Mutex::new(Vec::new())),
            device_fingerprint: Arc::new(Mutex::new(None)),
        }
    }

    /// Update the instance name (e.g. after login with actual username)
    pub fn set_instance_name(&mut self, name: &str) {
        self.instance_name = name.to_string();
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

        let service_type = "_fluxlock-transfer._tcp.local.";
        let receiver = match daemon.browse(service_type) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[DISCOVERY] mDNS browse failed (UDP beacon still active): {}", e);
                let _ = daemon.shutdown();
                return Ok(());
            }
        };

        // Auto-register this device so peers can discover us — seulement si visible (E-01)
        if *self.visible.lock().await {
            self.register_mdns_with_daemon(&daemon, service_type);
        }

        // Store daemon for later registration / shutdown
        *self.mdns_daemon.lock().await = Some(daemon);

        let peers = self.peers.clone();
        let own_name = self.instance_name.clone();

        tokio::spawn(async move {
            loop {
                match receiver.recv_async().await {
                    Ok(event) => {
                        match event {
                            mdns_sd::ServiceEvent::ServiceResolved(info) => {
                                let fullname = info.get_fullname().to_string();
                                // Skip our own registration
                                if fullname.contains(&own_name) {
                                    continue;
                                }
                                let port = info.get_port();
                                // Extract clean peer name from mDNS instance name
                                // fullname is like "username._fluxlock-transfer._tcp.local."
                                let clean_name = fullname
                                    .split("._fluxlock")
                                    .next()
                                    .unwrap_or(&fullname)
                                    .to_string();
                                // Pick only ONE address per peer (prefer IPv4 over IPv6)
                                let addrs: Vec<_> = info.get_addresses().iter().cloned().collect();
                                let best_addr = addrs.iter()
                                    .find(|a| a.is_ipv4())
                                    .or_else(|| addrs.first());
                                if let Some(addr) = best_addr {
                                    let peer = DiscoveredPeer {
                                        name: clean_name.clone(),
                                        addr: addr.to_string(),
                                        port,
                                        method: "mDNS".to_string(),
                                        verified: false,
                                    };
                                    let mut guard = peers.lock().await;
                                    // Deduplicate: one entry per clean_name
                                    guard.retain(|p| p.name != clean_name);
                                    guard.push(peer);
                                }
                            }
                            mdns_sd::ServiceEvent::ServiceRemoved(_, fullname) => {
                                let clean_name = fullname
                                    .split("._fluxlock")
                                    .next()
                                    .unwrap_or(&fullname)
                                    .to_string();
                                let mut guard = peers.lock().await;
                                guard.retain(|p| p.name != clean_name);
                            }
                            _ => {}
                        }
                    }
                    Err(_) => break, // channel closed or daemon shutdown
                }
            }
        });

        Ok(())
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
        let transfer_port = self.port;
        let peers = self.peers.clone();
        let broadcast_targets = get_broadcast_addresses(BEACON_PORT);

        // ── Announce task: send periodic UDP broadcasts (seulement si visible, E-01) ──
        let socket_tx = socket.clone();
        let name_tx = own_name.clone();
        let visible_flag = self.visible.clone();
        let device_fp = self.device_fingerprint.clone();
        tokio::spawn(async move {
            let mut send_error_count: u32 = 0;
            loop {
                if *visible_flag.lock().await {
                    // V-08: include device fingerprint in beacon for trust verification
                    let fp = device_fp.lock().await.clone().unwrap_or_default();
                    let msg = format!("FLUXLOCK|{}|{}|{}", name_tx, transfer_port, fp);
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
        let own_name_rx = own_name;
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
                                let port: u16 = parts[1].trim().parse().unwrap_or(DEFAULT_TRANSFER_PORT);
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
                                // Also skip by name in case IP check missed
                                if name == own_name_rx {
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
                                    addr: clean_ip,
                                    port,
                                    method: "LAN".to_string(),
                                    verified,
                                };
                                let mut guard = peers.lock().await;
                                guard.retain(|p| p.name != name);
                                guard.push(peer);
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

    /// Enregistre ce noeud comme service mDNS (pour être découvert par d'autres)
    pub async fn register_mdns_service(&self) -> Result<(), String> {
        self.register_mdns_service_on_port(self.port).await
    }

    /// Enregistre ce noeud comme service mDNS sur un port spécifique
    /// (utilisé quand le listener a dû choisir un port différent du défaut)
    pub async fn register_mdns_service_on_port(&self, port: u16) -> Result<(), String> {
        // Ensure discovery daemon exists
        let daemon_guard = self.mdns_daemon.lock().await;
        let daemon = daemon_guard.as_ref()
            .ok_or_else(|| "mDNS daemon not started — call start_mdns_discovery first".to_string())?;

        let service_type = "_fluxlock-transfer._tcp.local.";
        let host = format!("{}.local.", self.instance_name);

        // Provide real local IPv4 addresses so other peers can reach us
        let ip_str = get_local_ipv4_addresses()
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let service_info = mdns_sd::ServiceInfo::new(
            service_type,
            &self.instance_name,
            &host,
            &ip_str,
            port,
            None,
        ).map_err(|e| format!("ServiceInfo: {}", e))?;

        daemon.register(service_info)
            .map_err(|e| format!("mDNS register: {}", e))?;

        Ok(())
    }

    /// Unregister mDNS service (when transfer is done or app quits)
    pub async fn unregister_mdns_service(&self) {
        if let Some(daemon) = self.mdns_daemon.lock().await.as_ref() {
            let service_type = "_fluxlock-transfer._tcp.local.";
            let fullname = format!("{}.{}", self.instance_name, service_type);
            let _ = daemon.unregister(&fullname);
        }
    }

    /// Scan IPv6 link-local des interfaces réseau
    pub async fn scan_ipv6_link_local(&self) -> Result<Vec<DiscoveredPeer>, String> {
        let mut found = Vec::new();

        let addrs = get_ipv6_link_local_addresses();

        for (addr, scope_id) in &addrs {
            // Format the scoped address for connecting (required for link-local)
            let scoped_addr = format!("{}%{}", addr, scope_id);
            let sock_str = format!("[{}%{}]:{}", addr, scope_id, DEFAULT_TRANSFER_PORT);
            let socket_addr: SocketAddr = match sock_str.parse() {
                Ok(sa) => sa,
                Err(_) => {
                    // Fallback: build SocketAddrV6 manually
                    SocketAddr::V6(std::net::SocketAddrV6::new(*addr, DEFAULT_TRANSFER_PORT, 0, *scope_id))
                }
            };

            match tokio::time::timeout(
                std::time::Duration::from_millis(300),
                tokio::net::TcpStream::connect(socket_addr),
            ).await {
                Ok(Ok(_stream)) => {
                    found.push(DiscoveredPeer {
                        name: format!("FluXlock@{}", scoped_addr),
                        addr: addr.to_string(),
                        port: DEFAULT_TRANSFER_PORT,
                        method: "IPv6".to_string(),
                        verified: false,
                    });
                }
                _ => {}
            }
        }

        Ok(found)
    }

    /// Retourne les pairs découverts (mDNS + cached)
    pub async fn get_discovered_peers(&self) -> Vec<DiscoveredPeer> {
        self.peers.lock().await.clone()
    }

    /// Register this device with the given mDNS daemon (using real local IPs).
    fn register_mdns_with_daemon(&self, daemon: &mdns_sd::ServiceDaemon, service_type: &str) {
        let host = format!("{}.local.", self.instance_name);
        let local_ips: Vec<std::net::Ipv4Addr> = get_local_ipv4_addresses()
            .iter()
            .copied()
            .collect();
        let ip_str = local_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");

        match mdns_sd::ServiceInfo::new(
            service_type,
            &self.instance_name,
            &host,
            &ip_str,
            self.port,
            None,
        ) {
            Ok(info) => {
                if let Err(e) = daemon.register(info) {
                    eprintln!("[DISCOVERY] mDNS register failed: {}", e);
                }
            }
            Err(e) => eprintln!("[DISCOVERY] ServiceInfo error: {}", e),
        }
    }
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

/// Récupère les adresses IPv6 link-local du système avec le scope_id
fn get_ipv6_link_local_addresses() -> Vec<(std::net::Ipv6Addr, u32)> {
    let mut addrs = Vec::new();

    // Use if-addrs crate for reliable interface enumeration
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let IpAddr::V6(v6) = iface.addr.ip() {
                // link-local: fe80::/10
                if v6.segments()[0] & 0xffc0 == 0xfe80 {
                    // Extract scope_id from the interface index
                    // On macOS/Linux, the scope_id corresponds to the interface index
                    let scope_id = get_interface_index(&iface.name).unwrap_or(0);
                    if !addrs.iter().any(|(a, _)| a == &v6) {
                        addrs.push((v6, scope_id));
                    }
                }
            }
        }
    }

    addrs
}

/// Get the OS interface index by name (needed for IPv6 scope_id)
fn get_interface_index(name: &str) -> Option<u32> {
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "android"))]
    {
        use std::ffi::CString;
        if let Ok(cname) = CString::new(name) {
            let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
            if idx > 0 {
                return Some(idx);
            }
        }
        None
    }
    #[cfg(target_os = "windows")]
    {
        // On Windows, use the if_addrs interface index from the adapter name
        // The Windows API `if_nametoindex` is available via iphlpapi.dll
        // We approximate by matching the interface name in if_addrs
        if let Ok(ifaces) = if_addrs::get_if_addrs() {
            for (idx, iface) in ifaces.iter().enumerate() {
                if iface.name == name {
                    return Some((idx + 1) as u32);
                }
            }
        }
        let _ = name;
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "android", target_os = "windows")))]
    {
        let _ = name;
        None
    }
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
    /// Register this node as a receiver reverse listener (for when sender can't accept incoming).
    pub async fn register_receiver_mdns(&self, port: u16) -> Result<(), String> {
        let daemon_guard = self.mdns_daemon.lock().await;
        let daemon = daemon_guard.as_ref()
            .ok_or_else(|| "mDNS daemon not started — call start_mdns_discovery first".to_string())?;

        let local_ips: Vec<std::net::Ipv4Addr> = get_local_ipv4_addresses()
            .iter()
            .copied()
            .collect();
        let ip_str = local_ips
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let service_info = mdns_sd::ServiceInfo::new(
            RECEIVER_MDNS_SERVICE,
            &self.instance_name,
            &format!("{}.local.", self.instance_name),
            &ip_str,
            port,
            None,
        ).map_err(|e| format!("ServiceInfo receiver: {}", e))?;

        daemon.register(service_info)
            .map_err(|e| format!("mDNS register receiver: {}", e))?;

        Ok(())
    }
}

/// Discover a receiver's reverse listener via mDNS.
/// Creates its own daemon so it can be used from a spawned task.
/// Returns the first resolved receiver peer within the timeout.
pub async fn discover_receiver_peer(timeout_secs: u64) -> Result<DiscoveredPeer, String> {
    let daemon = mdns_sd::ServiceDaemon::new()
        .map_err(|e| format!("mDNS daemon: {}", e))?;

    // Extend service name length limit for consistency across all daemons
    let _ = daemon.set_service_name_len_max(24);

    let browse_chan = daemon.browse(RECEIVER_MDNS_SERVICE)
        .map_err(|e| format!("mDNS browse receivers: {}", e))?;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);

    loop {
        let remaining = deadline - tokio::time::Instant::now();
        if remaining.is_zero() {
            let _ = daemon.shutdown();
            return Err("Timeout : aucun receiver trouvé via mDNS".to_string());
        }

        match tokio::time::timeout(remaining, browse_chan.recv_async()).await {
            Ok(Ok(mdns_sd::ServiceEvent::ServiceResolved(info))) => {
                let port = info.get_port();
                if let Some(addr) = info.get_addresses().iter().next() {
                    let _ = daemon.shutdown();
                    return Ok(DiscoveredPeer {
                        name: info.get_fullname().to_string(),
                        addr: addr.to_string(),
                        port,
                        method: "mDNS-reverse".to_string(),
                        verified: false,
                    });
                }
            }
            Ok(Ok(_)) => continue, // Other mDNS events, keep waiting
            Ok(Err(_)) => {
                let _ = daemon.shutdown();
                return Err("mDNS channel closed".to_string());
            }
            Err(_) => {
                let _ = daemon.shutdown();
                return Err("Timeout : aucun receiver trouvé via mDNS".to_string());
            }
        }
    }
}

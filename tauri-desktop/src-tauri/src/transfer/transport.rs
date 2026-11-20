//! Transport — Couche de transport TLS avec fallback automatique.
//!
//! Stratégie de connexion (ordonnée par préférence) :
//! 1. IPv6 direct : connexion TCP + TLS directe sur le réseau local
//! 2. mDNS local : résolution du service puis connexion TCP + TLS
//! 3. Relay TLS : connexion via un relay de confiance (fallback)
//!
//! ## Sécurité — Double chiffrement (defense in depth)
//! - **TLS** : chiffrement transport éphémère (certificat auto-signé)
//! - **SPAKE2 + ML-KEM-768** : authentification mutuelle (handshake applicatif)
//! - **ChaCha20-Poly1305** : chiffrement session applicatif (SecureSession)
//!
//! La vérification du certificat TLS est désactivée côté client car
//! l'authentification est assurée par SPAKE2 (PAKE résistant MITM)
//! + safety number vérifié par l'utilisateur.

use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;
use std::sync::Arc;

use super::ConnectionMethod;
use super::discovery::DiscoveredPeer;

/// Trait combiné pour le transport
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

/// Connexion de transport unifiée (TLS)
pub struct TransportConnection {
    pub(crate) channel_binding: [u8; 32],
    pub stream: Box<dyn AsyncReadWrite>,
    pub method: ConnectionMethod,
    pub peer_addr: String,
}

/// Listener TLS pour accepter les connexions entrantes
pub struct TransportListener {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    pub local_port: u16,
}

impl TransportListener {
    /// Crée un listener TLS sur le port de transfert.
    /// Génère un certificat auto-signé éphémère pour chaque session.
    pub async fn bind(port: u16) -> Result<Self, String> {
        let tls_config = generate_server_tls_config()?;
        let tls_acceptor = TlsAcceptor::from(tls_config);

        // Tente d'écouter sur IPv6 d'abord (dual-stack), sinon IPv4
        let addr = format!("[::]:{}", port);
        let listener = match TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(_) => {
                let addr4 = format!("0.0.0.0:{}", port);
                TcpListener::bind(&addr4).await
                    .map_err(|e| format!("Bind transport listener: {}", e))?
            }
        };

        let local_port = listener.local_addr()
            .map_err(|e| format!("Local addr: {}", e))?
            .port();

        Ok(Self { listener, tls_acceptor, local_port })
    }

    /// Accepte une connexion entrante et établit le tunnel TLS.
    /// Tolère jusqu'à MAX_ACCEPT_ATTEMPTS échecs TLS avant d'abandonner
    /// (protection contre le DoS pendant la fenêtre du code wormhole).
    pub async fn accept(&self) -> Result<TransportConnection, String> {
        const MAX_ACCEPT_ATTEMPTS: u32 = 5;
        let mut attempts = 0u32;

        loop {
            let (tcp_stream, peer_addr) = self.listener.accept().await
                .map_err(|e| format!("Accept: {}", e))?;

            // TCP → TLS upgrade
            match tokio::time::timeout(CONNECT_TIMEOUT, self.tls_acceptor.accept(tcp_stream)).await {
                Ok(Ok(tls_stream)) => {
                    let channel_binding = tls_stream.get_ref().1.export_keying_material(
                        [0; 32], SYNC_EXPORTER_LABEL, None,
                    ).map_err(|error| format!("Identifiant de canal TLS : {error}"))?;
                    // Déterminer la méthode de connexion
                    let method = if peer_addr.ip().is_ipv6() {
                        if let std::net::IpAddr::V6(v6) = peer_addr.ip() {
                            if v6.segments()[0] & 0xffc0 == 0xfe80 {
                                ConnectionMethod::DirectIPv6
                            } else {
                                ConnectionMethod::MdnsLocal
                            }
                        } else {
                            ConnectionMethod::MdnsLocal
                        }
                    } else {
                        ConnectionMethod::MdnsLocal
                    };

                    return Ok(TransportConnection {
                        stream: Box::new(tls_stream),
                        channel_binding,
                        method,
                        peer_addr: peer_addr.to_string(),
                    });
                }
                failure => {
                    attempts += 1;
                    let error = match failure {
                        Ok(Err(error)) => error.to_string(),
                        _ => "délai dépassé".into(),
                    };
                    eprintln!("[TRANSPORT] Échec TLS depuis {peer_addr} ({attempts}/{MAX_ACCEPT_ATTEMPTS}) : {error}");
                    if attempts >= MAX_ACCEPT_ATTEMPTS {
                        return Err(format!(
                            "Trop de tentatives TLS échouées ({}/{}), abandon",
                            attempts, MAX_ACCEPT_ATTEMPTS
                        ));
                    }
                    // Retry — accept next connection
                }
            }
        }
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const SYNC_EXPORTER_LABEL: &[u8] = b"EXPORTER-FluXlock-Trust-Sync-v1";

pub(crate) fn peer_socket_addr(address: &str, port: u16) -> Result<SocketAddr, String> {
    let address = address.strip_prefix('[').and_then(|value| value.strip_suffix(']'))
        .unwrap_or(address);
    if let Ok(ip) = address.parse::<Ipv4Addr>() {
        return Ok(SocketAddrV4::new(ip, port).into());
    }
    let (ip, scope) = match address.rsplit_once('%') {
        Some((ip, scope)) => (ip, scope.parse::<u32>()
            .map_err(|_| format!("Interface IPv6 invalide : {address}"))?),
        None => (address, 0),
    };
    let ip = ip.parse().map_err(|_| format!("Adresse de pair invalide : {address}"))?;
    Ok(SocketAddrV6::new(ip, port, 0, scope).into())
}

/// Établit une connexion TLS vers un pair découvert.
pub async fn connect_to_peer(peer: &DiscoveredPeer) -> Result<TransportConnection, String> {
    let addr = peer_socket_addr(&peer.addr, peer.port)?;
    let tcp_stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await
        .map_err(|_| "Délai de connexion TCP dépassé".to_string())?
        .map_err(|error| format!("Connexion TCP au pair : {error}"))?;

    let tls_connector = create_client_tls_connector()?;
    let server_name = rustls::pki_types::ServerName::try_from("fluxlock.local")
        .map_err(|error| format!("Nom du pair TLS : {error}"))?;
    let tls_stream = tokio::time::timeout(CONNECT_TIMEOUT, tls_connector.connect(server_name, tcp_stream)).await
        .map_err(|_| "Délai de négociation TLS dépassé".to_string())?
        .map_err(|error| format!("Connexion TLS au pair : {error}"))?;
    let channel_binding = tls_stream.get_ref().1.export_keying_material(
        [0; 32], SYNC_EXPORTER_LABEL, None,
    ).map_err(|error| format!("Identifiant de canal TLS : {error}"))?;
    let method = if addr.is_ipv6() { ConnectionMethod::DirectIPv6 } else { ConnectionMethod::MdnsLocal };
    Ok(TransportConnection {
        stream: Box::new(tls_stream),
        channel_binding,
        method,
        peer_addr: addr.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_bracketed_ipv6_and_scoped_ipv6() {
        assert_eq!(peer_socket_addr("192.0.2.1", 17).unwrap().to_string(), "192.0.2.1:17");
        assert_eq!(peer_socket_addr("[::1]", 17).unwrap().to_string(), "[::1]:17");
        assert_eq!(peer_socket_addr("fe80::1%4", 17).unwrap().to_string(), "[fe80::1%4]:17");
        assert!(peer_socket_addr("fe80::1%invalid", 17).is_err());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS helpers
// ═══════════════════════════════════════════════════════════════════════════

use rustls::pki_types;

/// Génère un certificat auto-signé éphémère et crée une ServerConfig rustls
fn generate_server_tls_config() -> Result<Arc<rustls::ServerConfig>, String> {
    let cert = rcgen::generate_simple_self_signed(vec!["fluxlock.local".to_string()])
        .map_err(|e| format!("Génération certificat TLS: {}", e))?;

    let cert_der = pki_types::CertificateDer::from(
        cert.serialize_der().map_err(|e| format!("Sérialisation cert: {}", e))?
    );
    let key_der = pki_types::PrivatePkcs8KeyDer::from(cert.serialize_private_key_der());

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            pki_types::PrivateKeyDer::Pkcs8(key_der),
        )
        .map_err(|e| format!("Configuration TLS serveur: {}", e))?;

    Ok(Arc::new(config))
}

/// Crée un TlsConnector qui accepte tout certificat.
///
/// SÉCURITÉ : La vérification du certificat TLS est volontairement désactivée.
/// L'authentification est assurée par un canal séparé et plus fort :
/// - SPAKE2 (PAKE résistant aux attaques MITM, basé sur le code wormhole)
/// - ML-KEM-768 (clé de session post-quantique)
/// - Safety number affiché et vérifié par l'utilisateur
fn create_client_tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpakeAuthenticatedVerifier))
        .with_no_client_auth();

    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// Vérificateur de certificat qui délègue l'authentification à SPAKE2.
///
/// Dans un contexte P2P local avec code wormhole + safety number,
/// la chaîne de certificats TLS est un canal de chiffrement additionnel,
/// pas le mécanisme d'authentification principal.
#[derive(Debug)]
struct SpakeAuthenticatedVerifier;

impl rustls::client::danger::ServerCertVerifier for SpakeAuthenticatedVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &pki_types::CertificateDer<'_>,
        _intermediates: &[pki_types::CertificateDer<'_>],
        _server_name: &pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

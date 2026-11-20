//! Exchanges signed trust records between paired devices on a TLS channel
//! authenticated by both device keys.
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::task::JoinSet;

use super::discovery::DiscoveryService;
use super::protocol::{self, TransferMessage};
use super::transport::{connect_to_peer, TransportConnection, TransportListener};
use super::trust_store::TrustStore;

const SYNC_INTERVAL: Duration = Duration::from_secs(30);
const SYNC_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 4;

#[derive(Clone)]
pub(crate) struct RegistrySync {
    pub trust_store: Arc<Mutex<TrustStore>>,
    pub session_token: Arc<Mutex<Option<String>>>,
    pub isolation: Arc<Mutex<bool>>,
    pub token: String,
}

impl RegistrySync {
    async fn check_access(&self) -> Result<(), String> {
        if *self.isolation.lock().await
            || self.session_token.lock().await.as_deref() != Some(self.token.as_str())
        {
            return Err("Synchronisation annulée".into());
        }
        Ok(())
    }

    pub async fn run(self, listener: TransportListener, discovery: DiscoveryService) {
        let mut ticks = tokio::time::interval(SYNC_INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut jobs = JoinSet::new();
        let accepting = listener.accept();
        tokio::pin!(accepting);
        loop {
            tokio::select! {
                _ = ticks.tick() => {
                    if self.check_access().await.is_err() {
                        break;
                    }
                    let fingerprints = self.trust_store.lock().await.registry_sync_fingerprints();
                    let port = if fingerprints.is_empty() { 0 } else { listener.local_port };
                    discovery.advertise_registry_sync(port).await;
                    for peer in discovery.get_registry_sync_peers(&fingerprints).await {
                        if jobs.len() >= MAX_CONNECTIONS - 1 {
                            break;
                        }
                        let sync = self.clone();
                        jobs.spawn(async move {
                            if let Ok(connection) = connect_to_peer(&peer).await {
                                let _ = tokio::time::timeout(SYNC_TIMEOUT, sync.exchange(connection, false)).await;
                            }
                        });
                    }
                }
                connection = &mut accepting, if jobs.len() < MAX_CONNECTIONS => {
                    accepting.set(listener.accept());
                    if let Ok(connection) = connection {
                        let sync = self.clone();
                        jobs.spawn(async move {
                            let _ = tokio::time::timeout(SYNC_TIMEOUT, sync.exchange(connection, true)).await;
                        });
                    } else {
                        // An invalid or interrupted connection must not stop the listener.
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                }
                _ = jobs.join_next(), if !jobs.is_empty() => {}
            }
        }
        discovery.advertise_registry_sync(0).await;
    }

    async fn exchange(
        &self,
        mut connection: TransportConnection,
        server: bool,
    ) -> Result<(), String> {
        self.check_access().await?;
        let stream = &mut connection.stream;
        let local_proof = || async {
            self.check_access().await?;
            let store = self.trust_store.lock().await;
            Ok::<_, String>(TransferMessage::RegistrySyncProof {
                verifying_key_b64: store.device_verifying_key_b64()?,
                signature: store
                    .sign_registry_sync(&proof_message(&connection.channel_binding, server))?,
            })
        };

        if server {
            protocol::write_message(stream, &local_proof().await?).await?;
        }
        let TransferMessage::RegistrySyncProof {
            verifying_key_b64,
            signature,
        } = protocol::read_message(stream).await?
        else {
            return Err("Preuve de synchronisation attendue".into());
        };
        self.check_access().await?;
        self.trust_store.lock().await.verify_registry_sync(
            &verifying_key_b64,
            &proof_message(&connection.channel_binding, !server),
            &signature,
        )?;
        if !server {
            protocol::write_message(stream, &local_proof().await?).await?;
        }

        self.check_access().await?;
        let trust_data = {
            let store = self.trust_store.lock().await;
            store.verify_registry_sync(
                &verifying_key_b64,
                &proof_message(&connection.channel_binding, !server),
                &signature,
            )?;
            store.export_for_sync()?
        };
        // Exchange in opposite order so both sides can send registers larger than the TCP buffer.
        if server {
            protocol::write_message(
                stream,
                &TransferMessage::TrustStoreSync {
                    trust_data: trust_data.clone(),
                },
            )
            .await?;
        }
        let TransferMessage::TrustStoreSync { trust_data: remote } =
            protocol::read_message(stream).await?
        else {
            return Err("Registre signé attendu".into());
        };
        self.check_access().await?;
        self.trust_store
            .lock()
            .await
            .merge_authenticated_sync(&remote, &verifying_key_b64)?;
        if !server {
            self.check_access().await?;
            protocol::write_message(stream, &TransferMessage::TrustStoreSync { trust_data })
                .await?;
        }
        Ok(())
    }
}

fn proof_message(binding: &[u8; 32], server: bool) -> [u8; 33] {
    let mut message = [0; 33];
    message[0] = u8::from(server);
    message[1..].copy_from_slice(binding);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_key::SecureKey;
    use crate::transfer::ConnectionMethod;

    fn fixture(directory: &std::path::Path, seed: u8) -> RegistrySync {
        let mut store = TrustStore::load(directory).unwrap();
        store.unlock(&SecureKey::new(vec![seed; 32])).unwrap();
        RegistrySync {
            trust_store: Arc::new(Mutex::new(store)),
            session_token: Arc::new(Mutex::new(Some("test-session".into()))),
            isolation: Arc::new(Mutex::new(false)),
            token: "test-session".into(),
        }
    }

    #[tokio::test]
    async fn both_devices_must_be_paired_and_prove_the_same_channel() {
        let left_directory = tempfile::tempdir().unwrap();
        let right_directory = tempfile::tempdir().unwrap();
        let left = fixture(left_directory.path(), 1);
        let right = fixture(right_directory.path(), 2);
        let left_key = left
            .trust_store
            .lock()
            .await
            .device_verifying_key_b64()
            .unwrap();
        let right_key = right
            .trust_store
            .lock()
            .await
            .device_verifying_key_b64()
            .unwrap();
        left.trust_store
            .lock()
            .await
            .pair_device("right", &right_key)
            .unwrap();
        right
            .trust_store
            .lock()
            .await
            .pair_device("left", &left_key)
            .unwrap();
        left.trust_store
            .lock()
            .await
            .trust_peer("fixture", "test-fingerprint")
            .unwrap();

        let connection = |stream, channel_binding| TransportConnection {
            stream: Box::new(stream),
            channel_binding,
            method: ConnectionMethod::MdnsLocal,
            peer_addr: "test".into(),
        };
        let (client, server) = tokio::io::duplex(1024);
        let (client_result, server_result) = tokio::join!(
            right.exchange(connection(client, [2; 32]), false),
            left.exchange(connection(server, [1; 32]), true),
        );
        assert!(client_result.is_err());
        assert!(server_result.is_err());
        assert!(!right
            .trust_store
            .lock()
            .await
            .is_trusted("test-fingerprint"));

        let (client, server) = tokio::io::duplex(1024);
        let (client_result, server_result) = tokio::join!(
            right.exchange(connection(client, [3; 32]), false),
            left.exchange(connection(server, [3; 32]), true),
        );
        client_result.unwrap();
        server_result.unwrap();
        assert!(right
            .trust_store
            .lock()
            .await
            .is_trusted("test-fingerprint"));
        assert!(right.trust_store.lock().await.list_sync_devices()[0]
            .last_sync
            .is_some());

        right
            .trust_store
            .lock()
            .await
            .revoke_trust("test-fingerprint")
            .unwrap();
        right
            .trust_store
            .lock()
            .await
            .unlock(&SecureKey::new(vec![2; 32]))
            .unwrap();
        let (client, server) = tokio::io::duplex(1024);
        let (client_result, server_result) = tokio::join!(
            right.exchange(connection(client, [4; 32]), false),
            left.exchange(connection(server, [4; 32]), true),
        );
        client_result.unwrap();
        server_result.unwrap();
        assert!(!right
            .trust_store
            .lock()
            .await
            .is_trusted("test-fingerprint"));

        right
            .trust_store
            .lock()
            .await
            .remove_sync_device(&left_key)
            .unwrap();
        let (client, server) = tokio::io::duplex(1024);
        let (client_result, server_result) = tokio::join!(
            right.exchange(connection(client, [5; 32]), false),
            left.exchange(connection(server, [5; 32]), true),
        );
        assert!(client_result.is_err());
        assert!(server_result.is_err());
    }
}

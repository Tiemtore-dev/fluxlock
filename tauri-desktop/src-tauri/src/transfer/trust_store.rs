//! Trust Store — Confiance par empreinte de clé (chiffré ChaCha20-Poly1305).
//!
//! Stocke les empreintes BLAKE3 des clés publiques des pairs de confiance.
//! Le fichier sur disque est chiffré avec une sous-clé dérivée par HKDF
//! depuis la vault_key de l'utilisateur (même niveau de protection que
//! les mots de passe au repos).
//!
//! Format sur disque :
//!   `v2:` + base64( nonce(12) || ciphertext || tag(16) )
//!
//! Le plaintext est du JSON sérialisé `TrustStoreData`.
//!
//! ## Authentification post-quantique (ML-DSA-65)
//! Chaque appareil génère une paire ML-DSA-65 (FIPS 204) au premier
//! `unlock()`. La clé privée (PKCS#8 DER) est stockée **dans** le
//! trust store chiffré (même protection ChaCha20). Les données
//! exportées pour la synchronisation P2P sont signées avec ML-DSA-65 ;
//! les pairs vérifient la signature avant de fusionner.

use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zeroize::Zeroize;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};

use crate::crypto::{encrypt_data_secure, decrypt_data_secure};
use crate::secure_key::SecureKey;

/// Info HKDF pour dériver la sous-clé du trust store
const TRUST_STORE_HKDF_INFO: &[u8] = b"fluxlock-trust-store-v1";

/// Entrée de confiance pour un pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedPeer {
    /// Nom du pair
    pub name: String,
    /// Empreinte BLAKE3 de la clé publique
    pub fingerprint: String,
    /// Date de première confiance (ISO 8601)
    pub trusted_since: String,
    /// Date du dernier transfert
    pub last_seen: String,
    /// Nombre total de transferts réussis
    pub transfer_count: u32,
    /// Signature ML-DSA-65 de l'entrée (base64), ajoutée lors de l'export sync
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Clé de vérification ML-DSA-65 du signataire (base64 SPKI DER)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_vk: Option<String>,
}

/// Appareil autorisé pour la synchronisation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncDevice {
    /// Nom de l'appareil
    pub name: String,
    /// Clé de vérification ML-DSA-65 (base64 SPKI DER) — identifiant unique
    pub verifying_key: String,
    /// Date d'ajout (ISO 8601)
    pub added_at: String,
    /// Dernière synchronisation réussie
    pub last_sync: Option<String>,
}

/// Données internes sérialisées en JSON puis chiffrées
#[derive(Debug, Serialize, Deserialize)]
struct TrustStoreData {
    peers: HashMap<String, TrustedPeer>,
    /// Clé de signature ML-DSA-65 de cet appareil (PKCS#8 DER, base64)
    #[serde(default)]
    device_signing_key: Option<String>,
    /// Clé de vérification ML-DSA-65 de cet appareil (SPKI DER, base64)
    #[serde(default)]
    device_verifying_key: Option<String>,
    /// Synchronisation activée depuis les paramètres
    #[serde(default)]
    sync_enabled: bool,
    /// Appareils autorisés pour la synchronisation
    #[serde(default)]
    sync_devices: Vec<SyncDevice>,
}

/// Données exportées pour la synchronisation P2P (signées ML-DSA-65)
#[derive(Debug, Serialize, Deserialize)]
struct SyncExportData {
    peers: HashMap<String, TrustedPeer>,
    /// Clé de vérification ML-DSA-65 du signataire (base64 SPKI DER)
    signer_verifying_key: String,
}

/// Store de confiance chiffré ChaCha20-Poly1305
pub struct TrustStore {
    peers: HashMap<String, TrustedPeer>,
    store_path: PathBuf,
    /// Sous-clé HKDF dédiée au chiffrement du trust store (None = pas encore déverrouillé)
    ts_key: Option<SecureKey>,
    /// Paire de clés ML-DSA-65 de cet appareil (chargée au unlock)
    device_keypair: Option<secure_vault_crypto::MlDsaKeyPair>,
    /// Synchronisation activée
    sync_enabled: bool,
    /// Appareils autorisés pour la synchronisation
    sync_devices: Vec<SyncDevice>,
}

impl TrustStore {
    /// Crée un trust store vide (avant le login, aucune clé disponible).
    /// Le fichier chiffré sera chargé plus tard via `unlock()`.
    pub fn load(app_data_dir: &std::path::Path) -> Result<Self, String> {
        let store_path = app_data_dir.join("trust_store.enc");

        // Migration : si l'ancien fichier JSON non chiffré existe, on le note
        // Il sera migré automatiquement au premier `unlock()`
        Ok(Self {
            peers: HashMap::new(),
            store_path,
            ts_key: None,
            device_keypair: None,
            sync_enabled: false,
            sync_devices: Vec::new(),
        })
    }

    /// Dérive la sous-clé trust-store depuis la vault_key et charge les données chiffrées.
    /// Appelé après le login quand la clé de chiffrement est disponible.
    pub fn unlock(&mut self, vault_key: &SecureKey) -> Result<(), String> {
        // Dériver une sous-clé dédiée via HKDF
        let ts_key = vault_key.use_key(|k| {
            let derived = secure_vault_crypto::derive_key_hkdf(
                k,
                Some(b"fluxlock-v1"),
                TRUST_STORE_HKDF_INFO,
                32,
            ).map_err(|e| format!("HKDF trust store key: {}", e))?;

            Ok::<SecureKey, String>(SecureKey::new(derived.expose_secret().to_vec()))
        })?;
        self.ts_key = Some(ts_key);

        // Migration de l'ancien fichier JSON non chiffré
        let legacy_path = self.store_path.with_extension("json");
        if legacy_path.exists() {
            let data = std::fs::read_to_string(&legacy_path)
                .map_err(|e| format!("Lecture legacy trust store: {}", e))?;
            if let Ok(legacy) = serde_json::from_str::<TrustStoreData>(&data) {
                self.peers = legacy.peers;
                // Sauvegarder en format chiffré
                self.save()?;
                // Supprimer l'ancien fichier non chiffré
                let _ = std::fs::remove_file(&legacy_path);
                eprintln!("[TRUST_STORE] Migré de JSON vers ChaCha20-Poly1305");
                // Fall through to generate ML-DSA key below
            }
        }

        // Charger le fichier chiffré s'il existe
        if self.store_path.exists() && self.device_keypair.is_none() {
            let encrypted = std::fs::read_to_string(&self.store_path)
                .map_err(|e| format!("Lecture trust store chiffré: {}", e))?;

            let key = self.ts_key.as_ref().ok_or("Trust store non déverrouillé")?;
            match decrypt_data_secure(&encrypted, key) {
                Ok(json) => {
                    let data: TrustStoreData = serde_json::from_str(&json)
                        .map_err(|e| format!("Parse trust store: {}", e))?;
                    self.peers = data.peers;
                    self.sync_enabled = data.sync_enabled;
                    self.sync_devices = data.sync_devices;

                    // Charger la clé de signature ML-DSA-65 si elle existe
                    if let Some(ref sk_b64) = data.device_signing_key {
                        let sk_der = B64.decode(sk_b64)
                            .map_err(|e| format!("Décodage base64 signing key: {}", e))?;
                        match secure_vault_crypto::MlDsaKeyPair::from_pkcs8_der(&sk_der) {
                            Ok(kp) => {
                                eprintln!("[TRUST_STORE] ML-DSA-65 signing key chargée");
                                self.device_keypair = Some(kp);
                            }
                            Err(e) => {
                                eprintln!("[TRUST_STORE] WARN: clé ML-DSA corrompue, régénération: {}", e);
                            }
                        }
                    }
                }
                Err(e) => {
                    // VULN-006: Ne pas réinitialiser silencieusement — signaler l'erreur.
                    // Le fichier est sauvegardé mais l'utilisateur doit être averti.
                    eprintln!("[TRUST_STORE] ERREUR: Déchiffrement du trust store échoué: {}", e);
                    let backup_path = self.store_path.with_extension("enc.bak");
                    let _ = std::fs::rename(&self.store_path, &backup_path);
                    eprintln!("[TRUST_STORE] Ancien fichier sauvegardé: {:?}", backup_path);
                    self.peers.clear();
                    self.sync_devices.clear();
                    self.sync_enabled = false;
                    // Retourner une erreur au lieu de continuer silencieusement
                    return Err(format!(
                        "Trust store corrompu ou clé changée. Ancien fichier sauvegardé. \
                         Les appareils de confiance devront être ré-appairés. Détail: {}", e
                    ));
                }
            }
        }

        // Générer une paire ML-DSA-65 si aucune n'existe
        if self.device_keypair.is_none() {
            let kp = secure_vault_crypto::MlDsaKeyPair::generate()
                .map_err(|e| format!("Génération ML-DSA-65: {}", e))?;
            eprintln!("[TRUST_STORE] Nouvelle paire ML-DSA-65 générée");
            self.device_keypair = Some(kp);
            self.save()?;
        }

        Ok(())
    }

    /// Sauvegarde le trust store chiffré sur le disque (permissions 0600)
    pub fn save(&self) -> Result<(), String> {
        let key = self.ts_key.as_ref().ok_or("Trust store non déverrouillé — save impossible")?;

        // Sérialiser la clé ML-DSA si disponible
        let (device_signing_key, device_verifying_key) = if let Some(ref kp) = self.device_keypair {
            let sk = kp.to_pkcs8_der()
                .map_err(|e| format!("Sérialisation ML-DSA sk: {}", e))?;
            let vk = kp.verifying_key_bytes()
                .map_err(|e| format!("Sérialisation ML-DSA vk: {}", e))?;
            (Some(B64.encode(&sk)), Some(B64.encode(&vk)))
        } else {
            (None, None)
        };

        let data = TrustStoreData {
            peers: self.peers.clone(),
            device_signing_key,
            device_verifying_key,
            sync_enabled: self.sync_enabled,
            sync_devices: self.sync_devices.clone(),
        };
        let json = serde_json::to_string(&data)
            .map_err(|e| format!("Sérialisation trust store: {}", e))?;

        let encrypted = encrypt_data_secure(&json, key)
            .map_err(|e| format!("Chiffrement trust store: {}", e))?;

        std::fs::write(&self.store_path, &encrypted)
            .map_err(|e| format!("Écriture trust store: {}", e))?;

        // Restreindre les permissions au propriétaire uniquement (E-03)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.store_path, perms)
                .map_err(|e| format!("Permissions trust store: {}", e))?;
        }

        Ok(())
    }

    /// Vérifie si le trust store est déverrouillé (clé disponible)
    pub fn is_unlocked(&self) -> bool {
        self.ts_key.is_some()
    }

    /// Vérifie si un pair est de confiance
    pub fn is_trusted(&self, fingerprint: &str) -> bool {
        self.peers.contains_key(fingerprint)
    }

    /// Ajoute un pair de confiance
    pub fn trust_peer(&mut self, name: &str, fingerprint: &str) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        self.peers.insert(fingerprint.to_string(), TrustedPeer {
            name: name.to_string(),
            fingerprint: fingerprint.to_string(),
            trusted_since: now.clone(),
            last_seen: now,
            transfer_count: 0,
            signature: None,
            signer_vk: None,
        });
        self.save()
    }

    /// Met à jour la date du dernier contact et le compteur
    pub fn record_transfer(&mut self, fingerprint: &str) -> Result<(), String> {
        if let Some(peer) = self.peers.get_mut(fingerprint) {
            peer.last_seen = chrono::Utc::now().to_rfc3339();
            peer.transfer_count += 1;
            self.save()?;
        }
        Ok(())
    }

    /// Supprime un pair de confiance
    pub fn revoke_trust(&mut self, fingerprint: &str) -> Result<bool, String> {
        let removed = self.peers.remove(fingerprint).is_some();
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Liste tous les pairs de confiance
    pub fn list_trusted(&self) -> Vec<TrustedPeer> {
        self.peers.values().cloned().collect()
    }

    /// Exporte les données pour la synchronisation P2P, signées avec ML-DSA-65
    pub fn export_for_sync(&self) -> Result<String, String> {
        let kp = self.device_keypair.as_ref()
            .ok_or("Clé ML-DSA non disponible pour la signature")?;
        let vk_bytes = kp.verifying_key_bytes()
            .map_err(|e| format!("Export VK: {}", e))?;
        let vk_b64 = B64.encode(&vk_bytes);

        // Signer chaque entrée individuellement
        let mut signed_peers = self.peers.clone();
        for (_, peer) in signed_peers.iter_mut() {
            // Données canoniques à signer : nom + fingerprint + trusted_since + transfer_count
            let canon = format!("{}|{}|{}|{}", peer.name, peer.fingerprint, peer.trusted_since, peer.transfer_count);
            let sig = kp.sign(canon.as_bytes())
                .map_err(|e| format!("Signature ML-DSA: {}", e))?;
            peer.signature = Some(B64.encode(&sig));
            peer.signer_vk = Some(vk_b64.clone());
        }

        let data = SyncExportData {
            peers: signed_peers,
            signer_verifying_key: vk_b64,
        };
        serde_json::to_string(&data)
            .map_err(|e| format!("Sérialisation pour sync: {}", e))
    }

    /// Importe et fusionne des données depuis un autre pair (sync P2P)
    /// Vérifie les signatures ML-DSA-65 avant la fusion.
    /// Stratégie de fusion : garder le pair avec le `transfer_count` le plus élevé
    pub fn merge_from_sync(&mut self, json: &str) -> Result<u32, String> {
        // Essayer d'abord le nouveau format signé
        let (remote_peers, signer_vk_b64) = if let Ok(signed) = serde_json::from_str::<SyncExportData>(json) {
            (signed.peers, Some(signed.signer_verifying_key))
        } else {
            // Fallback : ancien format non signé (migration)
            let legacy: TrustStoreData = serde_json::from_str(json)
                .map_err(|e| format!("Parse sync data: {}", e))?;
            (legacy.peers, None)
        };

        // Vérifier que le signataire est autorisé (si sync activé)
        if self.sync_enabled {
            if let Some(ref vk_b64) = signer_vk_b64 {
                let authorized = self.sync_devices.iter().any(|d| d.verifying_key == *vk_b64);
                if !authorized {
                    return Err("Appareil non autorisé pour la synchronisation".to_string());
                }
            } else {
                return Err("Données non signées rejetées (ML-DSA requis)".to_string());
            }
        }

        // Vérifier les signatures si présentes
        if let Some(ref vk_b64) = signer_vk_b64 {
            let vk_der = B64.decode(vk_b64)
                .map_err(|e| format!("Décodage VK base64: {}", e))?;
            for (_, peer) in &remote_peers {
                if let (Some(ref sig_b64), Some(_)) = (&peer.signature, &peer.signer_vk) {
                    let sig_bytes = B64.decode(sig_b64)
                        .map_err(|e| format!("Décodage signature base64: {}", e))?;
                    let canon = format!("{}|{}|{}|{}", peer.name, peer.fingerprint, peer.trusted_since, peer.transfer_count);
                    let valid = secure_vault_crypto::verify_ml_dsa(&vk_der, canon.as_bytes(), &sig_bytes)
                        .map_err(|e| format!("Vérification ML-DSA: {}", e))?;
                    if !valid {
                        return Err(format!("Signature invalide pour le pair '{}'", peer.name));
                    }
                }
            }
        }

        let mut merged_count = 0u32;
        for (fingerprint, remote_peer) in remote_peers {
            match self.peers.get(&fingerprint) {
                Some(local_peer) if local_peer.transfer_count >= remote_peer.transfer_count => {
                    // Local est plus récent ou égal, on garde le local
                }
                _ => {
                    // Remote est plus récent ou le pair n'existe pas localement
                    self.peers.insert(fingerprint, remote_peer);
                    merged_count += 1;
                }
            }
        }

        // Mettre à jour la date de dernière sync pour l'appareil
        if let Some(ref vk_b64) = signer_vk_b64 {
            let now = chrono::Utc::now().to_rfc3339();
            if let Some(dev) = self.sync_devices.iter_mut().find(|d| d.verifying_key == *vk_b64) {
                dev.last_sync = Some(now);
            }
        }

        if merged_count > 0 {
            self.save()?;
        }
        Ok(merged_count)
    }

    /// Retourne la clé de vérification ML-DSA-65 de cet appareil (base64 SPKI DER)
    pub fn device_verifying_key_b64(&self) -> Result<String, String> {
        let kp = self.device_keypair.as_ref()
            .ok_or("Clé ML-DSA non disponible")?;
        let vk = kp.verifying_key_bytes()
            .map_err(|e| format!("Export VK: {}", e))?;
        Ok(B64.encode(&vk))
    }

    /// Active ou désactive la synchronisation
    pub fn set_sync_enabled(&mut self, enabled: bool) -> Result<(), String> {
        self.sync_enabled = enabled;
        self.save()
    }

    /// Retourne si la synchronisation est activée
    pub fn is_sync_enabled(&self) -> bool {
        self.sync_enabled
    }

    /// Ajoute un appareil autorisé pour la synchronisation
    pub fn add_sync_device(&mut self, name: &str, verifying_key_b64: &str) -> Result<(), String> {
        // Vérifier que l'appareil n'est pas déjà autorisé
        if self.sync_devices.iter().any(|d| d.verifying_key == verifying_key_b64) {
            return Err("Appareil déjà autorisé".to_string());
        }
        self.sync_devices.push(SyncDevice {
            name: name.to_string(),
            verifying_key: verifying_key_b64.to_string(),
            added_at: chrono::Utc::now().to_rfc3339(),
            last_sync: None,
        });
        self.save()
    }

    /// Supprime un appareil autorisé
    pub fn remove_sync_device(&mut self, verifying_key_b64: &str) -> Result<bool, String> {
        let before = self.sync_devices.len();
        self.sync_devices.retain(|d| d.verifying_key != verifying_key_b64);
        let removed = self.sync_devices.len() < before;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Liste les appareils autorisés
    pub fn list_sync_devices(&self) -> Vec<SyncDevice> {
        self.sync_devices.clone()
    }

    /// Calcule l'empreinte BLAKE3 d'une clé publique
    pub fn compute_fingerprint(pubkey_bytes: &[u8]) -> String {
        let hash = secure_vault_crypto::blake3_hash(pubkey_bytes);
        // Format: XX:XX:XX:XX:XX:XX:XX:XX (8 bytes = 16 hex chars)
        hash[..8].iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl Drop for TrustStore {
    fn drop(&mut self) {
        // Zeroize les fingerprints et noms en mémoire
        for (_, peer) in self.peers.iter_mut() {
            peer.name.zeroize();
            peer.fingerprint.zeroize();
        }
        self.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Crée un TrustStore déverrouillé dans un dossier temporaire
    fn setup_unlocked_store() -> (TrustStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let mut store = TrustStore::load(tmp.path()).unwrap();
        let key = SecureKey::from_slice(&[0x42u8; 32]);
        store.unlock(&key).unwrap();
        (store, tmp)
    }

    #[test]
    fn test_load_creates_empty_store() {
        let tmp = TempDir::new().unwrap();
        let store = TrustStore::load(tmp.path()).unwrap();
        assert!(!store.is_unlocked());
        assert_eq!(store.list_trusted().len(), 0);
    }

    #[test]
    fn test_unlock_generates_mldsa_keypair() {
        let (store, _tmp) = setup_unlocked_store();
        assert!(store.is_unlocked());
        // Si le keypair ML-DSA est généré, on peut récupérer la VK
        let vk = store.device_verifying_key_b64();
        assert!(vk.is_ok());
        assert!(!vk.unwrap().is_empty());
    }

    #[test]
    fn test_trust_and_revoke_peer() {
        let (mut store, _tmp) = setup_unlocked_store();
        store.trust_peer("Alice", "AA:BB:CC:DD:EE:FF:00:11").unwrap();
        assert!(store.is_trusted("AA:BB:CC:DD:EE:FF:00:11"));
        assert!(!store.is_trusted("00:00:00:00:00:00:00:00"));

        let peers = store.list_trusted();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "Alice");

        let removed = store.revoke_trust("AA:BB:CC:DD:EE:FF:00:11").unwrap();
        assert!(removed);
        assert!(!store.is_trusted("AA:BB:CC:DD:EE:FF:00:11"));
        assert_eq!(store.list_trusted().len(), 0);
    }

    #[test]
    fn test_revoke_nonexistent_peer() {
        let (mut store, _tmp) = setup_unlocked_store();
        let removed = store.revoke_trust("NO:PE:NO:PE:NO:PE:NO:PE").unwrap();
        assert!(!removed);
    }

    #[test]
    fn test_record_transfer_increments_count() {
        let (mut store, _tmp) = setup_unlocked_store();
        store.trust_peer("Bob", "11:22:33:44:55:66:77:88").unwrap();
        store.record_transfer("11:22:33:44:55:66:77:88").unwrap();
        store.record_transfer("11:22:33:44:55:66:77:88").unwrap();

        let peers = store.list_trusted();
        let bob = peers.iter().find(|p| p.name == "Bob").unwrap();
        assert_eq!(bob.transfer_count, 2);
    }

    #[test]
    fn test_sync_devices_management() {
        let (mut store, _tmp) = setup_unlocked_store();
        assert!(!store.is_sync_enabled());
        assert_eq!(store.list_sync_devices().len(), 0);

        store.set_sync_enabled(true).unwrap();
        assert!(store.is_sync_enabled());

        store.add_sync_device("MonTéléphone", "dmtfa2V5X2Jhc2U2NA==").unwrap();
        store.add_sync_device("Tablette", "dGFibGV0dGVfa2V5").unwrap();

        let devices = store.list_sync_devices();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].name, "MonTéléphone");
        assert!(devices[0].last_sync.is_none());
    }

    #[test]
    fn test_add_duplicate_sync_device_rejected() {
        let (mut store, _tmp) = setup_unlocked_store();
        store.add_sync_device("Device1", "a2V5MQ==").unwrap();
        let result = store.add_sync_device("Device1-dup", "a2V5MQ==");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("déjà autorisé"));
    }

    #[test]
    fn test_remove_sync_device() {
        let (mut store, _tmp) = setup_unlocked_store();
        store.add_sync_device("ToRemove", "cmVtb3Zl").unwrap();
        assert_eq!(store.list_sync_devices().len(), 1);

        let removed = store.remove_sync_device("cmVtb3Zl").unwrap();
        assert!(removed);
        assert_eq!(store.list_sync_devices().len(), 0);

        let removed2 = store.remove_sync_device("bm9wZQ==").unwrap();
        assert!(!removed2);
    }

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let fp1 = TrustStore::compute_fingerprint(b"test-pubkey-data");
        let fp2 = TrustStore::compute_fingerprint(b"test-pubkey-data");
        assert_eq!(fp1, fp2);
        // Format: XX:XX:XX:XX:XX:XX:XX:XX (8 bytes = 24 chars with colons)
        assert_eq!(fp1.len(), 23);
        assert_eq!(fp1.matches(':').count(), 7);
    }

    #[test]
    fn test_compute_fingerprint_different_keys() {
        let fp1 = TrustStore::compute_fingerprint(b"key-alpha");
        let fp2 = TrustStore::compute_fingerprint(b"key-beta");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_export_for_sync_produces_signed_json() {
        let (mut store, _tmp) = setup_unlocked_store();
        store.trust_peer("Peer1", "AA:BB:CC:DD:EE:FF:00:11").unwrap();
        store.trust_peer("Peer2", "11:22:33:44:55:66:77:88").unwrap();

        let export = store.export_for_sync().unwrap();
        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&export).unwrap();
        assert!(parsed.get("signer_verifying_key").is_some());
        assert!(parsed.get("peers").is_some());
        let peers = parsed["peers"].as_object().unwrap();
        assert_eq!(peers.len(), 2);
        // Each peer should have a signature
        for (_, peer) in peers {
            assert!(peer.get("signature").is_some());
            assert!(peer.get("signer_vk").is_some());
        }
    }

    #[test]
    fn test_merge_from_sync_self_roundtrip() {
        let (mut store, _tmp) = setup_unlocked_store();
        store.set_sync_enabled(true).unwrap();
        // Add ourselves as a sync device
        let vk = store.device_verifying_key_b64().unwrap();
        store.add_sync_device("Self", &vk).unwrap();

        store.trust_peer("Original", "AA:BB:CC:DD:EE:FF:00:11").unwrap();
        let export = store.export_for_sync().unwrap();

        // Create a second store and merge
        let tmp2 = TempDir::new().unwrap();
        let mut store2 = TrustStore::load(tmp2.path()).unwrap();
        let key2 = SecureKey::from_slice(&[0x43u8; 32]);
        store2.unlock(&key2).unwrap();
        store2.set_sync_enabled(true).unwrap();
        store2.add_sync_device("Store1", &vk).unwrap();

        let merged = store2.merge_from_sync(&export).unwrap();
        assert_eq!(merged, 1);
        assert!(store2.is_trusted("AA:BB:CC:DD:EE:FF:00:11"));
    }

    #[test]
    fn test_merge_rejects_unauthorized_device() {
        let (mut store, _tmp) = setup_unlocked_store();
        store.set_sync_enabled(true).unwrap();
        // Don't add any sync device — merge should fail

        let (mut other_store, _tmp2) = setup_unlocked_store();
        other_store.trust_peer("Injected", "FF:FF:FF:FF:FF:FF:FF:FF").unwrap();
        let export = other_store.export_for_sync().unwrap();

        let result = store.merge_from_sync(&export);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non autorisé"));
    }

    #[test]
    fn test_save_and_reload_persistence() {
        let tmp = TempDir::new().unwrap();
        let key = SecureKey::from_slice(&[0x44u8; 32]);

        // Create, unlock, add data, drop
        {
            let mut store = TrustStore::load(tmp.path()).unwrap();
            store.unlock(&key).unwrap();
            store.trust_peer("Persistent", "AA:BB:CC:DD:EE:FF:00:11").unwrap();
            store.set_sync_enabled(true).unwrap();
            store.add_sync_device("Device1", "a2V5").unwrap();
        }

        // Reload and verify
        {
            let mut store = TrustStore::load(tmp.path()).unwrap();
            store.unlock(&key).unwrap();
            assert!(store.is_trusted("AA:BB:CC:DD:EE:FF:00:11"));
            assert!(store.is_sync_enabled());
            assert_eq!(store.list_sync_devices().len(), 1);
            assert_eq!(store.list_trusted().len(), 1);
        }
    }

    #[test]
    fn test_merge_keeps_higher_transfer_count() {
        let (mut store, _tmp) = setup_unlocked_store();
        store.set_sync_enabled(true).unwrap();
        let vk = store.device_verifying_key_b64().unwrap();
        store.add_sync_device("Self", &vk).unwrap();

        // Local peer has 5 transfers
        store.trust_peer("Peer", "AA:BB:CC:DD:EE:FF:00:11").unwrap();
        for _ in 0..5 {
            store.record_transfer("AA:BB:CC:DD:EE:FF:00:11").unwrap();
        }
        assert_eq!(
            store.list_trusted().iter().find(|p| p.name == "Peer").unwrap().transfer_count,
            5
        );

        // Export from another store with only 2 transfers for same peer
        let tmp2 = TempDir::new().unwrap();
        let mut store2 = TrustStore::load(tmp2.path()).unwrap();
        let key2 = SecureKey::from_slice(&[0x55u8; 32]);
        store2.unlock(&key2).unwrap();
        store2.trust_peer("Peer", "AA:BB:CC:DD:EE:FF:00:11").unwrap();
        store2.record_transfer("AA:BB:CC:DD:EE:FF:00:11").unwrap();
        store2.record_transfer("AA:BB:CC:DD:EE:FF:00:11").unwrap();
        // Add store's VK as sync device in store2 so we can export
        // Actually we need store2 to produce the export. We do the reverse.
        let vk2 = store2.device_verifying_key_b64().unwrap();
        store.add_sync_device("Store2", &vk2).unwrap();
        let export2 = store2.export_for_sync().unwrap();

        // Merge — local has 5, remote has 2 → should keep local (no merge)
        let merged = store.merge_from_sync(&export2).unwrap();
        assert_eq!(merged, 0);
        assert_eq!(
            store.list_trusted().iter().find(|p| p.name == "Peer").unwrap().transfer_count,
            5
        );
    }
}

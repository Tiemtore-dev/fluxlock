//! # Synchronisation Continue Multi-Appareils P2P (HLC + CRDT Merkle-Delta signé ML-DSA-65)
//!
//! Implémente le moteur de réplication continue Zero-Trust de FluXlock :
//! - **Horloge Logique Hybride (HLC — Kulkarni et al., 2014)** : Ordre causal strict
//!   `(wall_ms, counter, device_id)` encodé au format canonique lexicographiquement triable
//!   `{:016x}:{:08x}:{device_id}`, avec garde-fou anti-dérive temporelle (`MAX_HLC_DRIFT_MS = 5 min`).
//! - **OpLog CRDT LWW-Element-Set signé ML-DSA-65 (FIPS 204)** : Chaque opération (`UPSERT` / `TOMBSTONE`)
//!   est identifiée par son empreinte `BLAKE3` et signée par la clé post-quantique `ML-DSA-65`
//!   du `TrustStore` de l'appareil émetteur.
//! - **Arbre de Merkle BLAKE3** : Calcul déterministe de la racine de Merkle du journal d'opérations
//!   pour détecter instantanément toute divergence d'état entre pairs.

use crate::database::SyncOpLogEntry;
use crate::transfer::trust_store::TrustStore;
use crate::AppState;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use tauri::State;

/// Dérive maximale tolérée sur l'horloge physique d'un pair distant (5 minutes).
/// Empêche un pair malveillant ou désynchronisé de figer l'état CRDT avec un timestamp dans le futur.
pub const MAX_HLC_DRIFT_MS: u64 = 5 * 60 * 1000;

/// Horloge Logique Hybride (HLC) garantissant un ordre total déterministe sans serveur central.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HlcTimestamp {
    pub wall_ms: u64,
    pub counter: u32,
    pub device_id: String,
}

impl Ord for HlcTimestamp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.wall_ms
            .cmp(&other.wall_ms)
            .then_with(|| self.counter.cmp(&other.counter))
            .then_with(|| self.device_id.cmp(&other.device_id))
    }
}

impl PartialOrd for HlcTimestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl HlcTimestamp {
    /// Encode le timestamp HLC sous forme canonique triable lexicographiquement dans SQLite :
    /// `<wall_ms_hex_16>:<counter_hex_8>:<device_id>`
    pub fn to_canonical_string(&self) -> String {
        format!("{:016x}:{:08x}:{}", self.wall_ms, self.counter, self.device_id)
    }

    /// Parse un timestamp HLC depuis sa représentation canonique.
    pub fn parse(encoded: &str) -> Result<Self, String> {
        let mut parts = encoded.splitn(3, ':');
        let wall_hex = parts.next().ok_or("HLC invalide: wall_ms manquant")?;
        let counter_hex = parts.next().ok_or("HLC invalide: counter manquant")?;
        let device_id = parts.next().ok_or("HLC invalide: device_id manquant")?;

        if wall_hex.len() != 16 || counter_hex.len() != 8 || device_id.is_empty() {
            return Err("Format HLC canonique invalide".into());
        }
        let wall_ms = u64::from_str_radix(wall_hex, 16)
            .map_err(|_| "HLC wall_ms hexadécimal invalide".to_string())?;
        let counter = u32::from_str_radix(counter_hex, 16)
            .map_err(|_| "HLC counter hexadécimal invalide".to_string())?;

        Ok(Self {
            wall_ms,
            counter,
            device_id: device_id.to_string(),
        })
    }

    /// Génère un nouveau timestamp HLC lors d'une mutation locale (`send` / `local_event`).
    pub fn next_local(last: Option<&HlcTimestamp>, physical_now_ms: u64, local_device_id: &str) -> Self {
        match last {
            Some(prev) if physical_now_ms <= prev.wall_ms => Self {
                wall_ms: prev.wall_ms,
                counter: prev.counter.saturating_add(1),
                device_id: local_device_id.to_string(),
            },
            _ => Self {
                wall_ms: physical_now_ms,
                counter: 0,
                device_id: local_device_id.to_string(),
            },
        }
    }

    /// Met à jour l'horloge HLC locale à la réception d'un événement distant, en rejetant
    /// tout timestamp dont l'avance dépasse `MAX_HLC_DRIFT_MS` (5 minutes).
    pub fn receive_remote(
        local: Option<&HlcTimestamp>,
        remote: &HlcTimestamp,
        physical_now_ms: u64,
        local_device_id: &str,
    ) -> Result<Self, String> {
        if remote.wall_ms > physical_now_ms.saturating_add(MAX_HLC_DRIFT_MS) {
            return Err(format!(
                "Dérive temporelle HLC excessive refusée ({} ms dans le futur > max {} ms)",
                remote.wall_ms.saturating_sub(physical_now_ms),
                MAX_HLC_DRIFT_MS
            ));
        }

        let local_wall = local.map_or(0, |l| l.wall_ms);
        let local_counter = local.map_or(0, |l| l.counter);
        let max_wall = physical_now_ms.max(local_wall).max(remote.wall_ms);

        let next_counter = if max_wall == local_wall && max_wall == remote.wall_ms {
            local_counter.max(remote.counter).saturating_add(1)
        } else if max_wall == local_wall {
            local_counter.saturating_add(1)
        } else if max_wall == remote.wall_ms {
            remote.counter.saturating_add(1)
        } else {
            0
        };

        Ok(Self {
            wall_ms: max_wall,
            counter: next_counter,
            device_id: local_device_id.to_string(),
        })
    }
}

/// Opération atomique du journal CRDT LWW-Element-Set, signée avec ML-DSA-65 (FIPS 204).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedVaultOp {
    pub op_id: String,
    pub entity_type: String,
    pub entity_uuid: String,
    pub op_kind: String, // "UPSERT" | "TOMBSTONE"
    pub hlc_timestamp: String,
    pub payload_json: String,
    pub signer_verifying_key: String,
    pub signature_mldsa65: String,
}

impl From<SyncOpLogEntry> for SignedVaultOp {
    fn from(row: SyncOpLogEntry) -> Self {
        Self {
            op_id: row.op_id,
            entity_type: row.entity_type,
            entity_uuid: row.entity_uuid,
            op_kind: row.op_kind,
            hlc_timestamp: row.hlc_timestamp,
            payload_json: row.payload_json,
            signer_verifying_key: row.signer_verifying_key,
            signature_mldsa65: row.signature_mldsa65,
        }
    }
}

fn canonical_op_bytes(
    entity_type: &str,
    entity_uuid: &str,
    op_kind: &str,
    hlc_timestamp: &str,
    payload_json: &str,
    signer_verifying_key: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(
        "fluxlock/vault-crdt-op/v1",
        entity_type,
        entity_uuid,
        op_kind,
        hlc_timestamp,
        payload_json,
        signer_verifying_key,
    ))
    .map_err(|e| format!("Sérialisation canonique CRDT: {}", e))
}

/// Construit et signe une opération CRDT avec la clé post-quantique ML-DSA-65 du `TrustStore`.
pub fn create_signed_op(
    store: &TrustStore,
    last_hlc: Option<&HlcTimestamp>,
    physical_now_ms: u64,
    entity_type: &str,
    entity_uuid: &str,
    op_kind: &str,
    payload_json: &str,
) -> Result<(SignedVaultOp, HlcTimestamp), String> {
    if !matches!(op_kind, "UPSERT" | "TOMBSTONE") {
        return Err(format!("Type d'opération CRDT invalide: {}", op_kind));
    }
    let device_id = store.local_sync_fingerprint()?;
    let signer_vk = store.device_verifying_key_b64()?;
    let hlc = HlcTimestamp::next_local(last_hlc, physical_now_ms, &device_id);
    let hlc_str = hlc.to_canonical_string();

    let canon = canonical_op_bytes(
        entity_type,
        entity_uuid,
        op_kind,
        &hlc_str,
        payload_json,
        &signer_vk,
    )?;
    let op_id = hex::encode(secure_vault_crypto::blake3_hash(&canon));
    let signature_mldsa65 = store.sign_registry_sync(&canon)?;

    Ok((
        SignedVaultOp {
            op_id,
            entity_type: entity_type.to_string(),
            entity_uuid: entity_uuid.to_string(),
            op_kind: op_kind.to_string(),
            hlc_timestamp: hlc_str,
            payload_json: payload_json.to_string(),
            signer_verifying_key: signer_vk,
            signature_mldsa65,
        },
        hlc,
    ))
}

/// Vérifie l'intégrité BLAKE3, la signature post-quantique ML-DSA-65 et la validité HLC d'une opération CRDT.
pub fn verify_signed_op(
    store: &TrustStore,
    op: &SignedVaultOp,
    physical_now_ms: u64,
) -> Result<HlcTimestamp, String> {
    if !matches!(op.op_kind.as_str(), "UPSERT" | "TOMBSTONE") {
        return Err("Type d'opération CRDT inconnu".into());
    }
    let parsed_hlc = HlcTimestamp::parse(&op.hlc_timestamp)?;
    if parsed_hlc.wall_ms > physical_now_ms.saturating_add(MAX_HLC_DRIFT_MS) {
        return Err("Opération CRDT rejetée : timestamp HLC hors fenêtre de dérive autorisée".into());
    }

    let canon = canonical_op_bytes(
        &op.entity_type,
        &op.entity_uuid,
        &op.op_kind,
        &op.hlc_timestamp,
        &op.payload_json,
        &op.signer_verifying_key,
    )?;
    let expected_id = hex::encode(secure_vault_crypto::blake3_hash(&canon));
    if op.op_id != expected_id {
        return Err("Empreinte BLAKE3 op_id falsifiée".into());
    }

    store.verify_registry_sync(&op.signer_verifying_key, &canon, &op.signature_mldsa65)?;
    Ok(parsed_hlc)
}

/// Réconcilie de manière déterministe (CRDT LWW-Element-Set) deux ensembles d'opérations
/// et retourne l'état gagnant pour chaque `(entity_type, entity_uuid)`.
pub fn reconcile_lww_state(ops: &[SignedVaultOp]) -> BTreeMap<(String, String), SignedVaultOp> {
    let mut winning: BTreeMap<(String, String), SignedVaultOp> = BTreeMap::new();
    for op in ops {
        let Ok(op_hlc) = HlcTimestamp::parse(&op.hlc_timestamp) else {
            continue;
        };
        let key = (op.entity_type.clone(), op.entity_uuid.clone());
        match winning.get(&key) {
            Some(current) => {
                if let Ok(curr_hlc) = HlcTimestamp::parse(&current.hlc_timestamp) {
                    if op_hlc > curr_hlc {
                        winning.insert(key, op.clone());
                    }
                }
            }
            None => {
                winning.insert(key, op.clone());
            }
        }
    }
    winning
}

/// Calcule la racine de Merkle BLAKE3 sur l'état CRDT convergent trié.
pub fn compute_oplog_merkle_root(ops: &[SignedVaultOp]) -> String {
    let winning = reconcile_lww_state(ops);
    if winning.is_empty() {
        return "0".repeat(64);
    }
    let mut leaves: Vec<Vec<u8>> = winning
        .values()
        .map(|op| {
            secure_vault_crypto::blake3_hash(
                format!("{}:{}:{}", op.entity_type, op.entity_uuid, op.op_id).as_bytes(),
            )
        })
        .collect();

    while leaves.len() > 1 {
        let mut next_level = Vec::with_capacity((leaves.len() + 1) / 2);
        for pair in leaves.chunks(2) {
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0][..32]);
            if pair.len() == 2 {
                combined[32..].copy_from_slice(&pair[1][..32]);
            } else {
                combined[32..].copy_from_slice(&pair[0][..32]);
            }
            next_level.push(secure_vault_crypto::blake3_hash(&combined));
        }
        leaves = next_level;
    }
    hex::encode(&leaves[0])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSyncStatus {
    pub sync_enabled: bool,
    pub paired_devices_count: usize,
    pub oplog_entries_count: usize,
    pub latest_hlc: Option<String>,
    pub merkle_root_blake3: String,
}

#[tauri::command]
pub async fn get_vault_sync_status(
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<VaultSyncStatus, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state.current_user_id.lock().await.ok_or("Non authentifié")?;

    let (sync_enabled, paired_devices_count) = {
        let tm_guard = state.transfer_manager.lock().await;
        if let Some(ref tm) = *tm_guard {
            let ts = tm.trust_store.lock().await;
            (ts.is_sync_enabled(), ts.list_sync_devices().len())
        } else {
            (false, 0)
        }
    };

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;
    let rows = db
        .get_sync_ops_since(user_id, None)
        .await
        .map_err(|e| format!("Erreur lecture OpLog CRDT: {}", e))?;
    let latest_hlc = db
        .get_latest_sync_hlc(user_id)
        .await
        .map_err(|e| format!("Erreur lecture curseur HLC: {}", e))?;

    let ops: Vec<SignedVaultOp> = rows.into_iter().map(SignedVaultOp::from).collect();
    let merkle_root_blake3 = compute_oplog_merkle_root(&ops);

    Ok(VaultSyncStatus {
        sync_enabled,
        paired_devices_count,
        oplog_entries_count: ops.len(),
        latest_hlc,
        merkle_root_blake3,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_key::SecureKey;

    fn make_paired_stores() -> (TrustStore, TrustStore, tempfile::TempDir, tempfile::TempDir) {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let mut s1 = TrustStore::load(d1.path()).unwrap();
        let mut s2 = TrustStore::load(d2.path()).unwrap();
        s1.unlock(&SecureKey::new(vec![1; 32])).unwrap();
        s2.unlock(&SecureKey::new(vec![2; 32])).unwrap();

        let vk1 = s1.device_verifying_key_b64().unwrap();
        let vk2 = s2.device_verifying_key_b64().unwrap();
        s1.pair_device("Device2", &vk2).unwrap();
        s2.pair_device("Device1", &vk1).unwrap();
        // Autoriser également la vérification locale de ses propres opérations
        s1.add_sync_device("Self1", &vk1).unwrap();
        s2.add_sync_device("Self2", &vk2).unwrap();
        (s1, s2, d1, d2)
    }

    #[test]
    fn test_hlc_monotonicity_and_drift_protection() {
        let t1 = HlcTimestamp::next_local(None, 1_700_000_000_000, "DEV-A");
        // Si l'horloge physique recule, HLC incrémente son compteur logique
        let t2 = HlcTimestamp::next_local(Some(&t1), 1_699_999_999_000, "DEV-A");
        assert!(t2 > t1);
        assert_eq!(t2.wall_ms, t1.wall_ms);
        assert_eq!(t2.counter, 1);

        // Lexicographical string order matches Ord
        assert!(t2.to_canonical_string() > t1.to_canonical_string());

        // Rejet d'un pair distant avec une horloge décalée de +10 minutes dans le futur
        let future_remote = HlcTimestamp {
            wall_ms: 1_700_000_000_000 + MAX_HLC_DRIFT_MS + 60_000,
            counter: 0,
            device_id: "DEV-B".into(),
        };
        assert!(HlcTimestamp::receive_remote(Some(&t2), &future_remote, 1_700_000_000_000, "DEV-A").is_err());
    }

    #[test]
    fn test_crdt_mldsa65_signed_oplog_convergence_and_merkle_root() {
        let (s1, s2, _d1, _d2) = make_paired_stores();
        let now = 1_700_000_000_000;

        // Device 1 crée une entrée
        let (op1, hlc1) = create_signed_op(
            &s1,
            None,
            now,
            "password",
            "uuid-github",
            "UPSERT",
            r#"{"title":"v2:aad:1"}"#,
        )
        .unwrap();

        // Device 2 vérifie la signature post-quantique ML-DSA-65 de op1
        let verified_hlc1 = verify_signed_op(&s2, &op1, now).unwrap();
        assert_eq!(verified_hlc1, hlc1);

        // Device 2 met à jour la même entrée plus tard
        let hlc_after_recv =
            HlcTimestamp::receive_remote(None, &verified_hlc1, now + 50, "DEV2").unwrap();
        let (op2, _) = create_signed_op(
            &s2,
            Some(&hlc_after_recv),
            now + 100,
            "password",
            "uuid-github",
            "UPSERT",
            r#"{"title":"v2:aad:2"}"#,
        )
        .unwrap();

        // Device 1 vérifie op2
        assert!(verify_signed_op(&s1, &op2, now + 100).is_ok());

        // Peu importe l'ordre d'arrivée des opérations ([op1, op2] vs [op2, op1]),
        // l'état CRDT LWW et la racine de Merkle BLAKE3 convergent à l'identique !
        let root_a = compute_oplog_merkle_root(&[op1.clone(), op2.clone()]);
        let root_b = compute_oplog_merkle_root(&[op2.clone(), op1.clone()]);
        assert_eq!(root_a, root_b);

        let state = reconcile_lww_state(&[op2.clone(), op1]);
        assert_eq!(
            state.get(&("password".into(), "uuid-github".into())).unwrap().op_id,
            op2.op_id
        );
    }
}

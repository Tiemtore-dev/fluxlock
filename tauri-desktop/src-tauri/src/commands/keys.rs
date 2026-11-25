use crate::{AppState, CreateKeyRequest, ImportKeyRequest};
use crate::generate_random_key_bytes;
use crate::crypto::{encrypt_field_secure, decrypt_field_secure};
use crate::security_monitor::get_security_monitor;
use crate::database::SecureKey;
use tauri::State;
use base64::{Engine as _, engine::general_purpose};
use zeroize::Zeroizing;

/// Formate des octets binaires en bloc PEM RFC 7468 (lignes de 64 caractères).
fn encode_pem_block(label: &str, der_or_raw: &[u8]) -> Zeroizing<String> {
    let b64 = Zeroizing::new(general_purpose::STANDARD.encode(der_or_raw));
    let mut out = String::with_capacity(b64.len() + label.len() * 2 + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----");
    Zeroizing::new(out)
}

/// Génère une paire de clés ou une clé symétrique authentique selon le type et l'algorithme demandés.
///
/// Normes implémentées :
/// - `ssh` / `ssh-ed25519` : paire Ed25519 RFC 8032 exportée au format OpenSSH `openssh-key-v1` + `ssh-ed25519` (RFC 8709)
/// - `ML-DSA-65` : paire de signature post-quantique NIST FIPS 204 (PKCS#8 DER PEM + SPKI DER PEM)
/// - `ML-KEM-768` : paire d'encapsulation post-quantique NIST FIPS 203 (Decapsulation Key PEM + Encapsulation Key PEM)
/// - `X25519` : paire Diffie-Hellman RFC 7748 §5 avec clamping scalaire
/// - `Ed25519` / `gpg` : paire de signature Ed25519 RFC 8032 (Private Seed PEM + Verifying Key PEM)
/// - `api` / `encryption` : clé symétrique CSPRNG de 256 bits (32 octets)
pub(crate) fn generate_key_material(
    key_name: &str,
    key_type: &str,
    algorithm: &str,
) -> Result<(Zeroizing<String>, String), String> {
    let kt = key_type.trim().to_lowercase();
    let algo = algorithm.trim();

    if kt == "ssh" || algo.eq_ignore_ascii_case("ssh-ed25519") {
        let kp = secure_vault_crypto::Ed25519KeyPair::generate();
        let (priv_openssh, pub_openssh) = kp
            .to_openssh_keypair(key_name)
            .map_err(|e| format!("Erreur génération clé OpenSSH Ed25519: {e}"))?;
        let combined = Zeroizing::new(format!("{}|||{}", &*priv_openssh, pub_openssh));
        return Ok((combined, "ssh-ed25519".to_string()));
    }

    if algo.eq_ignore_ascii_case("ML-DSA-65") || kt == "pqc-dsa" {
        let kp = secure_vault_crypto::MlDsaKeyPair::generate()
            .map_err(|e| format!("Erreur génération ML-DSA-65: {e}"))?;
        let sk_der = kp
            .to_pkcs8_der()
            .map_err(|e| format!("Erreur export PKCS#8 ML-DSA-65: {e}"))?;
        let vk_der = kp
            .verifying_key_bytes()
            .map_err(|e| format!("Erreur export SPKI ML-DSA-65: {e}"))?;
        let priv_pem = encode_pem_block("PRIVATE KEY", &sk_der);
        let pub_pem = encode_pem_block("PUBLIC KEY", &vk_der);
        let combined = Zeroizing::new(format!("{}|||{}", &*priv_pem, &*pub_pem));
        return Ok((combined, "ML-DSA-65".to_string()));
    }

    if algo.eq_ignore_ascii_case("ML-KEM-768") || kt == "pqc-kem" {
        let (pubkey, privkey) = secure_vault_crypto::generate_recipient_keypair()
            .map_err(|e| format!("Erreur génération ML-KEM-768: {e}"))?;
        let sk_bytes = privkey.to_bytes();
        let pk_bytes = pubkey.to_bytes();
        let priv_pem = encode_pem_block("ML-KEM-768 PRIVATE KEY", &sk_bytes);
        let pub_pem = encode_pem_block("ML-KEM-768 PUBLIC KEY", &pk_bytes);
        let combined = Zeroizing::new(format!("{}|||{}", &*priv_pem, &*pub_pem));
        return Ok((combined, "ML-KEM-768".to_string()));
    }

    if algo.eq_ignore_ascii_case("X25519") {
        let (secret, public) = secure_vault_crypto::generate_static_keypair_bytes()
            .map_err(|e| format!("Erreur génération X25519: {e}"))?;
        let priv_pem = encode_pem_block("X25519 PRIVATE KEY", &*secret);
        let pub_pem = encode_pem_block("X25519 PUBLIC KEY", &public);
        let combined = Zeroizing::new(format!("{}|||{}", &*priv_pem, &*pub_pem));
        return Ok((combined, "X25519".to_string()));
    }

    if kt == "gpg" || algo.eq_ignore_ascii_case("Ed25519") {
        let kp = secure_vault_crypto::Ed25519KeyPair::generate();
        let sk_seed = Zeroizing::new(kp.export_private_key());
        let pk_bytes = kp.export_public_key();
        let priv_pem = encode_pem_block("ED25519 PRIVATE KEY", &*sk_seed);
        let pub_pem = encode_pem_block("ED25519 PUBLIC KEY", &pk_bytes);
        let combined = Zeroizing::new(format!("{}|||{}", &*priv_pem, &*pub_pem));
        let normalized_algo = if algo.is_empty() || algo.starts_with("AES") || algo.starts_with("ChaCha") {
            "Ed25519".to_string()
        } else {
            algo.to_string()
        };
        return Ok((combined, normalized_algo));
    }

    // Clé symétrique 256 bits (API token ou clé de chiffrement AES-256-GCM / ChaCha20-Poly1305)
    let raw_key = Zeroizing::new(generate_random_key_bytes());
    let hex_key = Zeroizing::new(hex::encode(&*raw_key));
    let effective_algo = if algo.is_empty() {
        "ChaCha20-Poly1305".to_string()
    } else {
        algo.to_string()
    };
    Ok((hex_key, effective_algo))
}

#[tauri::command]
pub async fn create_secure_key(
    request: CreateKeyRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    if get_security_monitor().is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".to_string());
    }
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let key_name_trimmed = request.key_name.trim();
    if key_name_trimmed.is_empty() || key_name_trimmed.len() > 256 {
        return Err("Nom de clé invalide".into());
    }

    let (key_data, effective_algorithm) =
        generate_key_material(key_name_trimmed, &request.key_type, &request.algorithm)?;

    debug_log!("🔑 Clé {} générée (type: {}, algo: {})", key_name_trimmed, request.key_type, effective_algorithm);

    // Récupérer la clé maître via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    let encrypted_key = encrypt_field_secure(&key_data, &encryption_key, user_id, "secure_keys", "key_data")
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer le nom de la clé avec liaison AAD
    let encrypted_key_name = encrypt_field_secure(key_name_trimmed, &encryption_key, user_id, "secure_keys", "key_name")
        .map_err(|e| format!("Erreur chiffrement key_name: {}", e))?;

    let secure_key_id = db
        .create_secure_key(
            user_id,
            &encrypted_key_name,
            &request.key_type,
            &encrypted_key,
            &effective_algorithm,
        )
        .await
        .map_err(|e| format!("Erreur création clé: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "CREATE", "key", Some(secure_key_id)).await;

    Ok(secure_key_id)
}

#[tauri::command]
pub async fn import_secure_key(
    request: ImportKeyRequest,
    state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<i64, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    if get_security_monitor().is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".to_string());
    }
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let key_name_trimmed = request.key_name.trim();
    if key_name_trimmed.is_empty() || key_name_trimmed.len() > 256 {
        return Err("Nom de clé invalide".into());
    }
    if request.key_data.trim().is_empty() || request.key_data.len() > 65536 {
        return Err("Données de clé invalides ou trop volumineuses".into());
    }

    debug_log!("📥 Import de clé {} (type: {})", key_name_trimmed, request.key_type);

    // Récupérer la clé maître via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;
    
    // Chiffrer la clé importée avec liaison AAD
    let encrypted_key = encrypt_field_secure(&request.key_data, &encryption_key, user_id, "secure_keys", "key_data")
        .map_err(|e| format!("Erreur de chiffrement: {}", e))?;

    // Chiffrer le nom de la clé avec liaison AAD
    let encrypted_key_name = encrypt_field_secure(key_name_trimmed, &encryption_key, user_id, "secure_keys", "key_name")
        .map_err(|e| format!("Erreur chiffrement key_name: {}", e))?;

    let secure_key_id = db
        .create_secure_key(
            user_id,
            &encrypted_key_name,
            &request.key_type,
            &encrypted_key,
            &request.algorithm,
        )
        .await
        .map_err(|e| format!("Erreur import clé: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "IMPORT", "key", Some(secure_key_id)).await;

    Ok(secure_key_id)
}

#[tauri::command]
pub async fn get_secure_keys(state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<Vec<SecureKey>, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let keys = db
        .get_secure_keys(user_id)
        .await
        .map_err(|e| format!("Erreur récupération clés: {}", e))?;

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Déchiffrer uniquement les noms de clés ; ne jamais envoyer key_data déchiffré ni brut inutilement
    let mut decrypted_keys = Vec::new();
    for mut key in keys {
        if let Ok(decrypted_key_name) = decrypt_field_secure(&key.key_name, &encryption_key, user_id, "secure_keys", "key_name") {
            key.key_name = decrypted_key_name;
        } else {
            debug_log!("⚠️ Erreur déchiffrement key_name pour clé {}", key.id);
        }
        key.key_data = String::new();
        decrypted_keys.push(key);
    }

    Ok(decrypted_keys)
}

#[tauri::command]
pub async fn decrypt_key(id: i64, state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<String, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    // Récupérer la clé depuis la base
    let key = db
        .get_secure_key_by_id(id, user_id)
        .await
        .map_err(|e| format!("Erreur récupération clé: {}", e))?;

    // Récupérer la clé via le cache sécurisé (XOR-masked, TTL 3min, NIST SP 800-57)
    let encryption_key = crate::get_or_fetch_vault_key(&state, user_id).await?;

    // Déchiffrer les données de la clé avec vérification AAD
    let decrypted_key = decrypt_field_secure(&key.key_data, &encryption_key, user_id, "secure_keys", "key_data")
        .map_err(|e| format!("Erreur déchiffrement: {}", e))?;

    #[cfg(debug_assertions)]
    debug_log!("🔓 Clé {} déchiffrée pour utilisateur {}", id, user_id);

    Ok(decrypted_key)
}

#[tauri::command]
pub async fn delete_secure_key(id: i64, state: State<'_, AppState>,
    context: crate::vault::VaultContext,
) -> Result<bool, String> {
    let _lifecycle = crate::vault::access(&state, &context).await?;
    if get_security_monitor().is_readonly().await {
        return Err("🚨 Système en mode lecture seule (protection ransomware)".to_string());
    }
    let user_id = state
        .current_user_id
        .lock()
        .await
        .ok_or("Non authentifié")?;

    let db_guard = state.db.lock().await;
    let db = db_guard.as_ref().ok_or("Base de données non initialisée")?;

    let deleted = db
        .delete_secure_key(id, user_id)
        .await
        .map_err(|e| format!("Erreur suppression clé: {}", e))?;

    // Log l'action
    let _ = db.log_action(user_id, "DELETE", "key", Some(id)).await;

    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_authentic_openssh_ed25519_keypair() {
        let (material, algo) = generate_key_material("prod-deploy", "ssh", "ssh-ed25519").unwrap();
        assert_eq!(algo, "ssh-ed25519");
        let (priv_part, pub_part) = material.split_once("|||").expect("must contain private|||public");
        assert!(priv_part.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(priv_part.ends_with("\n-----END OPENSSH PRIVATE KEY-----"));
        assert!(pub_part.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA"));
        assert!(pub_part.ends_with(" prod-deploy"));
    }

    #[test]
    fn generates_authentic_post_quantum_ml_dsa_65_and_ml_kem_768_keys() {
        let (dsa_mat, dsa_algo) = generate_key_material("pq-sign", "gpg", "ML-DSA-65").unwrap();
        assert_eq!(dsa_algo, "ML-DSA-65");
        let (dsa_priv, dsa_pub) = dsa_mat.split_once("|||").unwrap();
        assert!(dsa_priv.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(dsa_pub.starts_with("-----BEGIN PUBLIC KEY-----\n"));

        let (kem_mat, kem_algo) = generate_key_material("pq-kem", "encryption", "ML-KEM-768").unwrap();
        assert_eq!(kem_algo, "ML-KEM-768");
        let (kem_priv, kem_pub) = kem_mat.split_once("|||").unwrap();
        assert!(kem_priv.starts_with("-----BEGIN ML-KEM-768 PRIVATE KEY-----\n"));
        assert!(kem_pub.starts_with("-----BEGIN ML-KEM-768 PUBLIC KEY-----\n"));
    }

    #[test]
    fn generates_authentic_x25519_and_ed25519_keypairs() {
        let (x_mat, x_algo) = generate_key_material("dh-peer", "encryption", "X25519").unwrap();
        assert_eq!(x_algo, "X25519");
        assert!(x_mat.contains("-----BEGIN X25519 PRIVATE KEY-----"));
        assert!(x_mat.contains("|||-----BEGIN X25519 PUBLIC KEY-----"));

        let (ed_mat, ed_algo) = generate_key_material("gpg-sign", "gpg", "Ed25519").unwrap();
        assert_eq!(ed_algo, "Ed25519");
        assert!(ed_mat.contains("-----BEGIN ED25519 PRIVATE KEY-----"));
        assert!(ed_mat.contains("|||-----BEGIN ED25519 PUBLIC KEY-----"));
    }
}

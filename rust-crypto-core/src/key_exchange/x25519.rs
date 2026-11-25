//! Échange de clés Diffie-Hellman avec X25519

use crate::errors::{CryptoError, Result};
use crate::secure_memory::SecretBytes;
use rand::{rngs::OsRng, RngCore};
use x25519_dalek::{x25519, EphemeralSecret, PublicKey, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;

/// Génère une paire de clés X25519 éphémère
///
/// # Returns
/// Tuple (clé privée, clé publique)
pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Génère une paire de clés X25519 statique exportable conforme à la RFC 7748 §5.
///
/// Applique le clamping standard RFC 7748 sur le scalaire secret de 32 octets
/// et dérive la clé publique correspondante par multiplication scalaire sur le point de base `u = 9`.
pub fn generate_static_keypair_bytes() -> Result<(Zeroizing<[u8; 32]>, [u8; 32])> {
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut *secret)
        .map_err(|e| CryptoError::RandomGenerationError(format!("X25519 CSPRNG failure: {e}")))?;
    // Clamping RFC 7748 §5
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    let public = x25519(*secret, X25519_BASEPOINT_BYTES);
    Ok((secret, public))
}

/// Calcule le secret partagé
///
/// # Arguments
/// * `private_key` - Clé privée locale (consommée)
/// * `peer_public_key` - Clé publique du pair
///
/// # Returns
/// Secret partagé de 32 bytes
///
/// # Note
/// Cette fonction consomme `private_key` car EphemeralSecret.diffie_hellman() prend ownership
pub fn compute_shared_secret(
    private_key: EphemeralSecret,
    peer_public_key: &PublicKey,
) -> Result<SecretBytes> {
    let shared = private_key.diffie_hellman(peer_public_key);
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidData(
            "Non-contributory X25519 public key".into(),
        ));
    }
    Ok(SecretBytes::from(shared.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_non_contributory_public_key() {
        let (private, _) = generate_keypair();
        assert!(compute_shared_secret(private, &PublicKey::from([0u8; 32])).is_err());
    }

    #[test]
    fn test_key_exchange() {
        let (alice_secret, alice_public) = generate_keypair();
        let (bob_secret, bob_public) = generate_keypair();

        let alice_shared = compute_shared_secret(alice_secret, &bob_public).unwrap();
        let bob_shared = compute_shared_secret(bob_secret, &alice_public).unwrap();

        assert_eq!(alice_shared.expose_secret(), bob_shared.expose_secret());
    }

    #[test]
    fn test_different_peers() {
        let (alice_secret1, _) = generate_keypair();
        let (alice_secret2, _) = generate_keypair();
        let (_, bob_public) = generate_keypair();
        let (_, charlie_public) = generate_keypair();

        let alice_bob_shared = compute_shared_secret(alice_secret1, &bob_public).unwrap();
        let alice_charlie_shared = compute_shared_secret(alice_secret2, &charlie_public).unwrap();

        assert_ne!(
            alice_bob_shared.expose_secret(),
            alice_charlie_shared.expose_secret()
        );
    }

    #[test]
    fn test_static_keypair_rfc7748_clamping_and_dh_agreement() {
        let (alice_sk, alice_pk) = generate_static_keypair_bytes().unwrap();
        let (bob_sk, bob_pk) = generate_static_keypair_bytes().unwrap();
        // Verify RFC 7748 §5 clamping bits
        assert_eq!(alice_sk[0] & 7, 0);
        assert_eq!(alice_sk[31] & 128, 0);
        assert_eq!(alice_sk[31] & 64, 64);

        let shared_a = x25519(*alice_sk, bob_pk);
        let shared_b = x25519(*bob_sk, alice_pk);
        assert_eq!(shared_a, shared_b);
        assert_ne!(shared_a, [0u8; 32]);
    }
}

//! Échange de clés Diffie-Hellman avec X25519

use crate::errors::{CryptoError, Result};
use crate::secure_memory::SecretBytes;
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Génère une paire de clés X25519
///
/// # Returns
/// Tuple (clé privée, clé publique)
pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
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
}

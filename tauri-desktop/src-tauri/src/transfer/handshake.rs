//! Handshake — SPAKE2 wormhole + ML-KEM-768 hybride.
//!
//! ## Flux :
//! 1. Les deux pairs échangent un code wormhole (court, humain-lisible).
//! 2. SPAKE2 dérive un secret commun à partir du code wormhole.
//! 3. Le pair A génère une paire ML-KEM-768 et envoie la clé publique.
//! 4. Le pair B encapsule un secret avec ML-KEM-768 et renvoie le ciphertext.
//! 5. Le secret final = HKDF(spake2_secret || kem_shared_secret).
//! 6. Le safety number = BLAKE3(k_session || id_A || id_B)[..6] affiché en hex.
//!
//! INVARIANT : Les clés éphémères sont zéroïsées IMMÉDIATEMENT après usage.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroize;
use rand::RngCore;
use secure_vault_crypto::crypto::kem;

/// Taille du code wormhole (en mots) — 4 mots × 256 mots ≈ 2³² combinaisons de mots
const WORMHOLE_CODE_WORDS: usize = 4;

/// Liste de 256 mots pour les codes wormhole (8 bits d'entropie par mot).
/// Total : 1000 canaux × 256⁴ mots ≈ 2⁴² combinaisons.
const WORD_LIST: &[&str] = &[
    // NATO alphabet (26)
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
    "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray",
    "yankee", "zulu",
    // Original extras (38)
    "anchor", "beacon", "cipher", "dagger", "falcon", "glacier", "harbor", "ivory",
    "jasper", "knight", "lunar", "marble", "nebula", "onyx", "prism", "quartz",
    "raven", "shadow", "titan", "ultra", "vortex", "zenith", "blaze", "coral",
    "drift", "ember", "frost", "grove", "haven", "iron", "jade", "karma",
    "lotus", "mist", "nova", "opal", "peak", "ridge",
    // Nature & geography (32)
    "amber", "arctic", "aurora", "bamboo", "basalt", "birch", "bloom", "brook",
    "canyon", "cedar", "cliff", "cloud", "cypress", "dawn", "desert", "dune",
    "earth", "fern", "fjord", "garden", "horizon", "island", "jungle", "lake",
    "marsh", "meadow", "moss", "ocean", "pine", "pond", "valley", "willow",
    // Minerals & materials (32)
    "agate", "anvil", "bronze", "carbon", "chalk", "chrome", "cobalt", "copper",
    "crystal", "diamond", "flint", "garnet", "gold", "granite", "nickel", "pearl",
    "ruby", "sand", "sapphire", "shield", "silk", "silver", "slate", "steel",
    "stone", "timber", "walnut", "wheat", "zinc", "linen", "oxide", "plume",
    // Animals (32)
    "crane", "dove", "eagle", "egret", "hawk", "heron", "lark", "lynx",
    "moose", "otter", "panther", "parrot", "phoenix", "puma", "robin", "salmon",
    "seal", "shark", "sparrow", "stork", "swan", "tiger", "viper", "whale",
    "wolf", "bison", "cobra", "condor", "drake", "finch", "gecko", "hound",
    // Tech & objects (32)
    "blade", "bolt", "bridge", "cargo", "castle", "chain", "compass", "crown",
    "dome", "engine", "forge", "gate", "helm", "lance", "lens", "lever",
    "magnet", "mirror", "pilot", "pixel", "portal", "rocket", "scroll", "spire",
    "sword", "temple", "torch", "tower", "tunnel", "vessel", "wagon", "widget",
    // Abstract & celestial (32)
    "eclipse", "flame", "flux", "glow", "orbit", "pulse", "solar", "spark",
    "storm", "summit", "surge", "swift", "thunder", "trail", "vapor", "vivid",
    "voyage", "wave", "wonder", "zephyr", "alder", "barrel", "basin", "berry",
    "cabin", "clover", "comet", "hollow", "latch", "manor", "meteor", "reef",
    // Additional (32)
    "badge", "bramble", "fig", "holly", "honey", "lemon", "maple", "nutmeg",
    "pebble", "plum", "poplar", "spruce", "thistle", "olive", "pepper", "sage",
    "cactus", "canvas", "elder", "field", "grain", "gust", "haze", "hunter",
    "lodge", "polar", "rapids", "river", "scout", "shell", "smoke", "star",
];

/// Génère un code wormhole aléatoire (ex: "42-alpha-beacon-drift")
pub fn generate_wormhole_code() -> String {
    let mut rng = rand::rngs::OsRng;
    let channel = rng.next_u32() % 1000;
    let words: Vec<&str> = (0..WORMHOLE_CODE_WORDS)
        .map(|_| {
            let idx = (rng.next_u32() as usize) % WORD_LIST.len();
            WORD_LIST[idx]
        })
        .collect();
    format!("{}-{}", channel, words.join("-"))
}

/// État du handshake côté initiateur (Alice)
pub struct HandshakeInitiator {
    spake_state: Option<Spake2<Ed25519Group>>,
    spake_msg: Vec<u8>,
    wormhole_code: String,
}

impl Drop for HandshakeInitiator {
    fn drop(&mut self) {
        self.spake_msg.zeroize();
        // Zéroïser le code wormhole (paraphrase secrète)
        // SAFETY: String est un Vec<u8> en interne — ok pour zeroize
        unsafe {
            self.wormhole_code.as_bytes_mut().zeroize();
        }
    }
}

impl HandshakeInitiator {
    /// Crée un initiateur avec un code wormhole
    pub fn new(code: &str) -> Result<Self, String> {
        let (state, msg) = Spake2::<Ed25519Group>::start_a(
            &Password::new(code.as_bytes()),
            &Identity::new(b"fluxlock-sender"),
            &Identity::new(b"fluxlock-receiver"),
        );

        Ok(Self {
            spake_state: Some(state),
            spake_msg: msg.to_vec(),
            wormhole_code: code.to_string(),
        })
    }

    /// Retourne le message SPAKE2 à envoyer au pair
    pub fn spake_message(&self) -> &[u8] {
        &self.spake_msg
    }

    /// Phase 1 : Finalise le SPAKE2, génère la paire ML-KEM-768.
    /// Retourne un résultat intermédiaire qui contient `ek_bytes` (à envoyer au pair)
    /// et conserve le secret SPAKE2 + la clé privée KEM pour la phase 2.
    pub fn complete_spake2(
        mut self,
        peer_spake_msg: &[u8],
    ) -> Result<InitiatorPhase1, String> {
        let state = self.spake_state.take()
            .ok_or_else(|| "SPAKE2 state already consumed".to_string())?;

        let spake_secret = state.finish(peer_spake_msg)
            .map_err(|e| format!("SPAKE2 finish failed: {:?}", e))?;

        // Générer paire ML-KEM-768
        let (keypair_ek, keypair_dk) = kem::generate_recipient_keypair()
            .map_err(|e| format!("ML-KEM keygen: {}", e))?;

        let ek_bytes = keypair_ek.to_bytes();
        let dk_bytes = keypair_dk.to_bytes();

        Ok(InitiatorPhase1 {
            spake_secret: spake_secret.to_vec(),
            ek_bytes,
            dk_bytes: dk_bytes.to_vec(),
        })
    }
}

/// Résultat intermédiaire de la phase 1 du handshake côté initiateur.
/// Contient la clé publique KEM (à envoyer) et les secrets nécessaires à la phase 2.
pub struct InitiatorPhase1 {
    spake_secret: Vec<u8>,
    /// Clé publique ML-KEM-768 à envoyer au pair
    pub ek_bytes: Vec<u8>,
    dk_bytes: Vec<u8>,
}

impl Drop for InitiatorPhase1 {
    fn drop(&mut self) {
        self.spake_secret.zeroize();
        self.dk_bytes.zeroize();
    }
}

impl InitiatorPhase1 {
    /// Phase 2 : Décapsule le ciphertext KEM reçu du pair et dérive la clé de session hybride.
    pub fn finalize_with_kem(mut self, kem_ciphertext: &[u8]) -> Result<HandshakeResult, String> {
        // Décapsuler avec la clé privée KEM
        let dk = kem::KemPrivateKey::from_bytes(&self.dk_bytes)
            .map_err(|e| format!("ML-KEM import dk: {}", e))?;
        let ct = kem::KemCiphertext::from_bytes(kem_ciphertext);
        let kem_shared = kem::decapsulate(&dk, &ct)
            .map_err(|e| format!("ML-KEM decapsulate: {}", e))?;

        // Dérivation hybride : HKDF(spake2_key || kem_shared_secret)
        let session_key = derive_hybrid_key(&self.spake_secret, kem_shared.as_bytes());

        // Zéroïser
        self.spake_secret.zeroize();
        self.dk_bytes.zeroize();

        let safety_number = compute_safety_number(&session_key, b"initiator", b"responder");

        Ok(HandshakeResult {
            session_key,
            safety_number,
            ek_bytes: Vec::new(),
        })
    }
}

/// État du handshake côté répondeur (Bob)
pub struct HandshakeResponder {
    spake_state: Option<Spake2<Ed25519Group>>,
    spake_msg: Vec<u8>,
}

impl Drop for HandshakeResponder {
    fn drop(&mut self) {
        self.spake_msg.zeroize();
    }
}

impl HandshakeResponder {
    /// Crée un répondeur avec le code wormhole partagé
    pub fn new(code: &str) -> Result<Self, String> {
        let (state, msg) = Spake2::<Ed25519Group>::start_b(
            &Password::new(code.as_bytes()),
            &Identity::new(b"fluxlock-sender"),
            &Identity::new(b"fluxlock-receiver"),
        );

        Ok(Self {
            spake_state: Some(state),
            spake_msg: msg.to_vec(),
        })
    }

    /// Retourne le message SPAKE2 à envoyer au pair
    pub fn spake_message(&self) -> &[u8] {
        &self.spake_msg
    }

    /// Finalise le SPAKE2 et encapsule avec ML-KEM
    pub fn complete_handshake(
        mut self,
        peer_spake_msg: &[u8],
        ek_bytes: &[u8],
    ) -> Result<(HandshakeResult, Vec<u8>), String> {
        let state = self.spake_state.take()
            .ok_or_else(|| "SPAKE2 state already consumed".to_string())?;

        let mut spake_secret = state.finish(peer_spake_msg)
            .map_err(|e| format!("SPAKE2 finish failed: {:?}", e))?;

        // Encapsuler avec ML-KEM-768 en utilisant la clé publique reçue
        let (kem_shared, ct_bytes) = {
            let ek = kem::KemPublicKey::from_bytes(ek_bytes)
                .map_err(|e| format!("ML-KEM import pubkey: {}", e))?;

            let (shared, ct) = kem::encapsulate(&ek)
                .map_err(|e| format!("ML-KEM encapsulate: {}", e))?;

            (shared, ct)
        };

        // Dérivation hybride
        let session_key = derive_hybrid_key(&spake_secret, kem_shared.as_bytes());

        // Zéroïser
        spake_secret.zeroize();

        let safety_number = compute_safety_number(&session_key, b"initiator", b"responder");

        let result = HandshakeResult {
            session_key,
            safety_number,
            ek_bytes: Vec::new(),
        };

        Ok((result, ct_bytes.as_bytes().to_vec()))
    }
}

/// Résultat du handshake
pub struct HandshakeResult {
    /// Clé de session 256 bits pour ChaCha20-Poly1305
    pub session_key: [u8; 32],
    /// Safety number à afficher et confirmer par les deux pairs
    pub safety_number: String,
    /// Clé publique ML-KEM exportée (pour l'initiateur uniquement)
    pub ek_bytes: Vec<u8>,
}

impl Drop for HandshakeResult {
    fn drop(&mut self) {
        self.session_key.zeroize();
        self.ek_bytes.zeroize();
    }
}

/// Dérive une clé hybride HKDF-SHA256(spake_key || kem_key) avec séparation de domaine.
///
/// Conforme à NIST SP 800-56C Rev 2 — Extract-then-Expand :
/// - **Extract** : HKDF-Extract(salt, spake_key || kem_key) → PRK
/// - **Expand**  : HKDF-Expand(PRK, info="fluxlock-transfer-v1 session-key") → OKM 32 bytes
fn derive_hybrid_key(spake_key: &[u8], kem_key: &[u8]) -> [u8; 32] {
    // Concaténer les IKM dans un buffer zéroïsé automatiquement
    let mut ikm = zeroize::Zeroizing::new(
        Vec::with_capacity(spake_key.len() + kem_key.len())
    );
    ikm.extend_from_slice(spake_key);
    ikm.extend_from_slice(kem_key);

    let salt = b"fluxlock-transfer-v1";
    let info = b"session-key";

    let derived = secure_vault_crypto::derive_key_hkdf(&ikm, Some(salt), info, 32)
        .expect("HKDF derivation should not fail with valid inputs");

    let mut okm = [0u8; 32];
    okm.copy_from_slice(derived.expose_secret());
    // ikm est automatiquement zéroïsé au drop de Zeroizing
    okm
}

/// Calcule le safety number à partir de la clé de session et des identifiants
fn compute_safety_number(session_key: &[u8; 32], id_a: &[u8], id_b: &[u8]) -> String {
    // Domain separation prefix pour éviter les collisions inter-protocoles
    let domain = b"fluxlock-safety-v1:";
    // Zeroizing pour protéger le buffer contenant la session_key concaténée
    let mut data = zeroize::Zeroizing::new(
        Vec::with_capacity(domain.len() + 32 + id_a.len() + id_b.len())
    );
    data.extend_from_slice(domain);
    data.extend_from_slice(session_key);
    data.extend_from_slice(id_a);
    data.extend_from_slice(id_b);
    let hash = secure_vault_crypto::blake3_hash(&data);

    // Les 8 premiers bytes en groupes de 2 hex (64 bits, probabilité de collision 1/2^64)
    if hash.len() >= 8 {
        format!(
            "{:02X}{:02X} {:02X}{:02X} {:02X}{:02X} {:02X}{:02X}",
            hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]
        )
    } else {
        hex::encode(&hash[..8.min(hash.len())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wormhole_code_generation() {
        let code = generate_wormhole_code();
        let parts: Vec<&str> = code.split('-').collect();
        assert_eq!(parts.len(), WORMHOLE_CODE_WORDS + 1); // channel + N words
        // Channel should be a number
        assert!(parts[0].parse::<u32>().is_ok());
    }

    #[test]
    fn test_safety_number_deterministic() {
        let key = [42u8; 32];
        let sn1 = compute_safety_number(&key, b"a", b"b");
        let sn2 = compute_safety_number(&key, b"a", b"b");
        assert_eq!(sn1, sn2);
        // Different inputs → different safety numbers
        let sn3 = compute_safety_number(&key, b"c", b"d");
        assert_ne!(sn1, sn3);
    }
}

//! Version 2 only: ML-KEM-768 contributes Noise XXpsk3's final secret; ML-DSA-65
//! signs the role-separated Noise transcripts. No application data before both
//! proofs and the hybrid key confirmation. Same implementation in native/WASM.
mod pq;
use pq::{SigningMaterial, KEM_CT, KEM_PK, SIGNATURE, VERIFY_KEY};
use sha2::{Digest, Sha256, Sha512};
pub use snow;
use snow::{
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};
use zeroize::Zeroizing;

pub const VERSION: u8 = 2;
pub const IDENTITY_SIZE: usize = 64;
pub const MAX_FRAME: usize = 64 * 1024;
pub const MAX_PLAINTEXT: usize = 32 * 1024;
pub const MAX_HANDSHAKE: usize = 16 * 1024;
const PROLOGUE: &[u8] = b"fluxlock-autofill-v2/ML-KEM-768/ML-DSA-65/Noise_XXpsk3_25519_ChaChaPoly_SHA512/browser-initiator/desktop-responder";
const HEADER: usize = 8;

struct Entropy;
impl Random for Entropy {
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), snow::Error> {
        random(bytes).map_err(|_| snow::Error::Rng)
    }
}
fn random(bytes: &mut [u8]) -> Result<(), String> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        getrandom::fill(bytes).map_err(|_| "Randomness unavailable".into())
    }
    #[cfg(target_arch = "wasm32")]
    {
        wasm::random(bytes).map_err(|_| "Randomness unavailable".into())
    }
}
struct Resolver;
impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(Entropy))
    }
    fn resolve_dh(&self, c: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(c)
    }
    fn resolve_hash(&self, c: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(c)
    }
    fn resolve_cipher(&self, c: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(c)
    }
}

/// Opaque identity fingerprint, not a Curve25519 public key. The full ML-DSA
/// verification key is proved during each handshake; only this pin is stored.
pub fn public_identity(private: &[u8; IDENTITY_SIZE]) -> [u8; 32] {
    identity_id(&SigningMaterial::new(&private[32..]).public())
}
fn identity_id(public: &[u8]) -> [u8; 32] {
    Sha256::digest(
        [
            b"fluxlock-autofill-v2/ML-DSA-65/identity".as_slice(),
            public,
        ]
        .concat(),
    )
    .into()
}

pub struct Handshake {
    inner: Option<snow::HandshakeState>,
    signing: Option<SigningMaterial>,
    kem_private: Option<ml_kem::DecapsulationKey<ml_kem::MlKem768>>,
    kem_public: Option<Vec<u8>>,
    server_signature: Vec<u8>,
    remote: Option<[u8; 32]>,
    final_hash: Option<[u8; 64]>,
    initiator: bool,
    stage: u8,
}
pub fn handshake(private: &[u8; IDENTITY_SIZE], initiator: bool) -> Result<Handshake, String> {
    let builder = snow::Builder::with_resolver(
        "Noise_XXpsk3_25519_ChaChaPoly_SHA512"
            .parse()
            .map_err(|_| "Noise parameters")?,
        Box::new(Resolver),
    )
    .prologue(PROLOGUE)
    .map_err(|_| "Noise prologue")?
    .local_private_key(&private[..32])
    .map_err(|_| "Noise identity")?;
    // Slot 3 is intentionally absent. Snow refuses message 3 until the genuine
    // per-handshake ML-KEM secret is installed; there is no placeholder PSK.
    let inner = if initiator {
        builder.build_initiator()
    } else {
        builder.build_responder()
    }
    .map_err(|_| "Noise initialization")?;
    Ok(Handshake {
        inner: Some(inner),
        signing: Some(SigningMaterial::new(&private[32..])),
        kem_private: None,
        kem_public: None,
        server_signature: Vec::new(),
        remote: None,
        final_hash: None,
        initiator,
        stage: 0,
    })
}
impl Handshake {
    fn fail(&mut self) {
        self.inner = None;
        self.signing = None;
        self.kem_private = None;
        self.kem_public = None;
        self.remote = None;
        self.final_hash = None;
        self.stage = 255;
    }
    pub fn write_message(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, String> {
        let result = self.write(payload, output);
        if result.is_err() {
            self.fail();
        }
        result
    }
    fn write(&mut self, payload: &[u8], output: &mut [u8]) -> Result<usize, String> {
        if !payload.is_empty() || output.len() < MAX_HANDSHAKE {
            return Err("Handshake buffer or payload refused".into());
        }
        let message = match (self.initiator, self.stage) {
            (true, 0) => 1,
            (false, 1) => 2,
            (true, 2) => 3,
            _ => return Err("Handshake order refused".into()),
        };
        let mut content = Vec::new();
        if message == 1 {
            let (private, public) = pq::kem_keypair()?;
            self.kem_private = Some(private);
            content = public;
        } else if message == 2 {
            let (ciphertext, secret) =
                pq::encapsulate(self.kem_public.take().as_deref().ok_or("KEM key absent")?)?;
            self.inner
                .as_mut()
                .ok_or("Handshake failed")?
                .set_psk(3, &*secret)
                .map_err(|_| "Hybrid secret refused")?;
            content.extend_from_slice(&ciphertext);
            content.extend_from_slice(&self.signing.as_ref().ok_or("Identity absent")?.public());
        } else {
            content.extend_from_slice(&self.signing.as_ref().ok_or("Identity absent")?.public());
        }
        let inner = self.inner.as_mut().ok_or("Handshake failed")?;
        let size = inner
            .write_message(&content, &mut output[HEADER..MAX_HANDSHAKE - SIGNATURE])
            .map_err(|_| "Handshake write refused")?;
        let signature = if message == 1 {
            Vec::new()
        } else {
            let transcript =
                signed_transcript(message, inner.get_handshake_hash(), &self.server_signature);
            self.signing
                .as_ref()
                .ok_or("Identity absent")?
                .sign(&transcript)?
        };
        output[..4].copy_from_slice(b"FLPQ");
        output[4] = VERSION;
        output[5] = message;
        output[6..8].copy_from_slice(&(size as u16).to_be_bytes());
        output[HEADER + size..HEADER + size + signature.len()].copy_from_slice(&signature);
        if message == 2 {
            self.server_signature = signature.clone();
        }
        if message == 3 {
            self.final_hash = Some(commitment(
                inner.get_handshake_hash(),
                &self.server_signature,
                &signature,
            ));
            self.signing = None;
        }
        self.stage = message;
        Ok(HEADER + size + if message == 1 { 0 } else { SIGNATURE })
    }
    pub fn read_message(&mut self, input: &[u8], _output: &mut [u8]) -> Result<usize, String> {
        let result = self.read(input);
        if result.is_err() {
            self.fail();
        }
        result.map(|()| 0)
    }
    fn read(&mut self, input: &[u8]) -> Result<(), String> {
        let expected = match (self.initiator, self.stage) {
            (false, 0) => 1,
            (true, 1) => 2,
            (false, 2) => 3,
            _ => return Err("Handshake order refused".into()),
        };
        let (packet, signature) = parse_frame(input, expected)?;
        let inner = self.inner.as_mut().ok_or("Handshake failed")?;
        let mut content = Zeroizing::new(vec![0; MAX_HANDSHAKE]);
        let n = inner
            .read_message(packet, &mut content)
            .map_err(|_| "Handshake read refused")?;
        content.truncate(n);
        if expected == 1 {
            if n != KEM_PK {
                return Err("ML-KEM key size refused".into());
            }
            self.kem_public = Some(content.to_vec());
        } else {
            let offset = if expected == 2 { KEM_CT } else { 0 };
            if n != offset + VERIFY_KEY {
                return Err("PQ identity size refused".into());
            }
            let public = &content[offset..];
            pq::verify(
                public,
                &signed_transcript(expected, inner.get_handshake_hash(), &self.server_signature),
                signature,
            )?;
            self.remote = Some(identity_id(public));
            if expected == 2 {
                let private = self.kem_private.take().ok_or("KEM key absent")?;
                let secret = pq::decapsulate(&private, &content[..KEM_CT])?;
                inner
                    .set_psk(3, &*secret)
                    .map_err(|_| "Hybrid secret refused")?;
                self.server_signature = signature.to_vec();
            } else {
                self.final_hash = Some(commitment(
                    inner.get_handshake_hash(),
                    &self.server_signature,
                    signature,
                ));
                self.signing = None;
            }
        }
        self.stage = expected;
        Ok(())
    }
    pub fn remote_identity(&self) -> Option<&[u8]> {
        self.remote.as_ref().map(|p| p.as_slice())
    }
    pub fn get_handshake_hash(&self) -> &[u8] {
        self.final_hash.as_ref().map_or(&[], |h| h.as_slice())
    }
    pub fn into_transport_mode(mut self) -> Result<snow::TransportState, String> {
        if self.stage != 3 || self.final_hash.is_none() || self.remote.is_none() {
            return Err("PQ authentication unfinished".into());
        }
        let mut inner = self.inner.take().ok_or("Handshake failed")?;
        // The hybrid PSK has already been mixed into the chaining key.
        inner
            .set_psk(3, &[0; 32])
            .map_err(|_| "Handshake cleanup")?;
        inner
            .into_transport_mode()
            .map_err(|_| "Hybrid transport refused".into())
    }
}
fn signed_transcript(message: u8, noise_hash: &[u8], server_signature: &[u8]) -> Vec<u8> {
    let mut out = b"fluxlock-autofill-v2/ML-DSA-65/transcript/".to_vec();
    out.push(message);
    out.extend_from_slice(noise_hash);
    if message == 3 {
        out.extend_from_slice(server_signature);
    }
    out
}
fn commitment(noise_hash: &[u8], server: &[u8], client: &[u8]) -> [u8; 64] {
    Sha512::digest(
        [
            b"fluxlock-autofill-v2/complete".as_slice(),
            noise_hash,
            server,
            client,
        ]
        .concat(),
    )
    .into()
}
fn parse_frame(bytes: &[u8], expected: u8) -> Result<(&[u8], &[u8]), String> {
    if bytes.len() < HEADER
        || bytes.len() > MAX_HANDSHAKE
        || &bytes[..4] != b"FLPQ"
        || bytes[4] != VERSION
        || bytes[5] != expected
    {
        return Err("PQ protocol version or role refused".into());
    }
    let size = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let sig = if expected == 1 { 0 } else { SIGNATURE };
    if size == 0 || bytes.len() != HEADER + size + sig {
        return Err("PQ frame size refused".into());
    }
    Ok((&bytes[HEADER..HEADER + size], &bytes[HEADER + size..]))
}
pub fn fingerprint(hash: &[u8]) -> String {
    let digest = Sha512::digest([b"fluxlock-autofill-pairing-v2".as_slice(), hash].concat());
    digest[..32]
        .chunks(4)
        .map(|p| p.iter().map(|b| format!("{b:02X}")).collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}
pub fn encrypt(channel: &mut snow::TransportState, bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.len() > MAX_PLAINTEXT {
        return Err("Message too large".into());
    }
    let mut out = vec![0; bytes.len() + 16];
    let n = channel
        .write_message(bytes, &mut out)
        .map_err(|_| "Channel encryption failed")?;
    out.truncate(n);
    Ok(out)
}
pub fn decrypt(
    channel: &mut snow::TransportState,
    bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    if bytes.len() > MAX_PLAINTEXT + 16 {
        return Err("Message too large".into());
    }
    let mut out = Zeroizing::new(vec![0; bytes.len()]);
    let n = channel
        .read_message(bytes, &mut out)
        .map_err(|_| "Invalid channel message")?;
    out.truncate(n);
    Ok(out)
}
#[cfg(test)]
mod tests;
#[cfg(target_arch = "wasm32")]
mod wasm;

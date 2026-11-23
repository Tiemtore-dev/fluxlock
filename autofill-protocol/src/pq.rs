//! FIPS primitives come from the exact RustCrypto versions already used by the
//! vault. Random inputs are supplied by our OS/Web Crypto bridge, never a PRNG
//! seeded from timestamps, and no platform-specific RNG enters the WASM build.
use ml_dsa::{ExpandedSigningKey, MlDsa65};
use ml_kem::{Decapsulate, KeyExport, TryKeyInit};
use std::mem::MaybeUninit;
use zeroize::Zeroizing;

pub(super) const KEM_PK: usize = 1184;
pub(super) const KEM_CT: usize = 1088;
pub(super) const VERIFY_KEY: usize = 1952;
pub(super) const SIGNATURE: usize = 3309;
type KemPrivate = ml_kem::DecapsulationKey<ml_kem::MlKem768>;
type DsaPrivate = ExpandedSigningKey<MlDsa65>;

// The pinned crate's Drop does not wipe every cached NTT representation. Run
// its destructor, then wipe the complete allocation, including cached values.
// MaybeUninit ensures the destroyed value is never dropped/observed again.
pub(super) struct SigningMaterial(Box<MaybeUninit<DsaPrivate>>);
impl SigningMaterial {
    pub(super) fn new(bytes: &[u8]) -> Self {
        let seed =
            Zeroizing::new(ml_dsa::Seed::try_from(bytes).expect("internal 32-byte ML-DSA seed"));
        Self(Box::new(MaybeUninit::new(DsaPrivate::from_seed(&seed))))
    }
    fn key(&self) -> &DsaPrivate {
        // SAFETY: new initializes the value, and Drop is the only destruction.
        unsafe { self.0.assume_init_ref() }
    }
    pub(super) fn public(&self) -> Vec<u8> {
        self.key().verifying_key().encode().to_vec()
    }
    pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.key()
            .sign_deterministic(message, b"FluXlock autofill v2")
            .map(|s| s.encode().to_vec())
            .map_err(|_| "ML-DSA signature failed".into())
    }
}
impl Drop for SigningMaterial {
    fn drop(&mut self) {
        // SAFETY: initialized owned value is dropped exactly once. Afterwards
        // only MaybeUninit storage remains; volatile byte writes do not read or
        // recreate a DsaPrivate value. The Box subsequently frees raw storage.
        unsafe {
            std::ptr::drop_in_place(self.0.as_mut_ptr());
            let ptr = self.0.as_mut_ptr().cast::<u8>();
            for i in 0..std::mem::size_of::<DsaPrivate>() {
                ptr.add(i).write_volatile(0);
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
}
pub(super) fn verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    let key =
        ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(public).map_err(|_| "ML-DSA key size")?;
    let key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&key);
    let sig = ml_dsa::Signature::<MlDsa65>::try_from(signature).map_err(|_| "ML-DSA encoding")?;
    if !key.verify_with_context(message, b"FluXlock autofill v2", &sig) {
        return Err("ML-DSA authentication failed".into());
    }
    Ok(())
}
pub(super) fn kem_keypair() -> Result<(KemPrivate, Vec<u8>), String> {
    let mut seed = Zeroizing::new(ml_kem::Seed::default());
    super::random(seed.as_mut_slice())?;
    let private = KemPrivate::from_seed(*seed);
    let public = private.encapsulation_key().to_bytes().to_vec();
    Ok((private, public))
}
pub(super) fn encapsulate(public: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>), String> {
    let key = ml_kem::EncapsulationKey::<ml_kem::MlKem768>::new_from_slice(public)
        .map_err(|_| "ML-KEM key refused")?;
    // FIPS Encaps_internal receives a full CSPRNG-generated 32-byte m.
    let mut random = Zeroizing::new(ml_kem::B32::default());
    super::random(random.as_mut_slice())?;
    let (ct, shared) = key.encapsulate_deterministic(&random);
    let shared = Zeroizing::new(shared);
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&shared);
    Ok((ct.to_vec(), secret))
}
pub(super) fn decapsulate(
    private: &KemPrivate,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let shared = Zeroizing::new(
        private
            .decapsulate_slice(ciphertext)
            .map_err(|_| "ML-KEM ciphertext refused")?,
    );
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(&shared);
    Ok(secret)
}

//! Single atomic OS credential: transport identity and public pairing registry.
//! It is intentionally independent of vault unlock keys and vault backups.
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub public: String,
    pub vault_id: String,
    pub name: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub version: u8,
    private: String,
    pub profiles: Vec<Profile>,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}
impl Identity {
    pub fn fresh() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new([0; fluxlock_autofill_protocol::IDENTITY_SIZE]);
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        Self {
            version: 2,
            private: hex::encode(&*seed),
            profiles: Vec::new(),
        }
    }
    pub fn key(
        &self,
    ) -> Result<Zeroizing<[u8; fluxlock_autofill_protocol::IDENTITY_SIZE]>, String> {
        let raw =
            Zeroizing::new(hex::decode(&self.private).map_err(|_| "Identité native invalide")?);
        Ok(Zeroizing::new(
            raw.as_slice()
                .try_into()
                .map_err(|_| "Identité native invalide")?,
        ))
    }
    pub fn validate(&self) -> Result<(), String> {
        self.key()?;
        if self.version != 2 || self.profiles.len() > 4 {
            return Err("Registre navigateur invalide".into());
        }
        let mut keys = std::collections::HashSet::new();
        for p in &self.profiles {
            if hex::decode(&p.public).map_or(true, |v| v.len() != 32)
                || !keys.insert(&p.public)
                || p.vault_id.len() > 64
                || p.name.chars().count() > 40
                || p.name.chars().any(char::is_control)
            {
                return Err("Profil navigateur invalide".into());
            }
        }
        Ok(())
    }
}
fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(
        if crate::hidden_storage::TEST_BUILD {
            "com.fluxlock.browser.test.v2"
        } else {
            "com.fluxlock.browser.v2"
        },
        "identity-and-registry",
    )
    .map_err(|e| e.to_string())
}
fn retire_legacy() -> Result<(), String> {
    let legacy = keyring::Entry::new(
        if crate::hidden_storage::TEST_BUILD {
            "com.fluxlock.browser.test.v1"
        } else {
            "com.fluxlock.browser.v1"
        },
        "identity-and-registry",
    )
    .map_err(|_| "Ancien registre inaccessible")?;
    match legacy.delete_password() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("Impossible de révoquer l’ancien appairage navigateur".into()),
    }
}
pub async fn load(create: bool) -> Result<Option<Identity>, String> {
    tokio::task::spawn_blocking(move || {
        let entry = entry()?;
        match entry.get_password() {
            Ok(value) => {
                let value = Zeroizing::new(value);
                let identity: Identity =
                    serde_json::from_str(&value).map_err(|_| "Registre navigateur illisible")?;
                identity.validate()?;
                retire_legacy()?;
                Ok(Some(identity))
            }
            Err(keyring::Error::NoEntry) if !create => Ok(None),
            Err(keyring::Error::NoEntry) => {
                let identity = Identity::fresh();
                let value =
                    Zeroizing::new(serde_json::to_string(&identity).map_err(|e| e.to_string())?);
                entry.set_password(&value).map_err(|e| e.to_string())?;
                retire_legacy()?;
                Ok(Some(identity))
            }
            Err(_) => {
                Err("Le trousseau système ne permet pas d’ouvrir la passerelle navigateur".into())
            }
        }
    })
    .await
    .map_err(|e| e.to_string())?
}
pub async fn save(identity: Identity) -> Result<(), String> {
    identity.validate()?;
    tokio::task::spawn_blocking(move || {
        let value = Zeroizing::new(serde_json::to_string(&identity).map_err(|e| e.to_string())?);
        if value.len() > 2400 {
            return Err("Registre navigateur trop volumineux".into());
        }
        entry()?
            .set_password(&value)
            .map_err(|_| "Enregistrement du profil impossible".into())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v2_identities_do_not_accept_legacy_key_material_or_registry_versions() {
        let first = Identity::fresh();
        let second = Identity::fresh();
        assert!(first.validate().is_ok());
        assert_eq!(first.key().unwrap().len(), 64);
        assert!(first.key().unwrap().as_slice() != second.key().unwrap().as_slice());
        let mut legacy = first.clone();
        legacy.version = 1;
        assert!(legacy.validate().is_err());
        legacy.version = 2;
        legacy.private = super::super::token();
        assert!(legacy.validate().is_err());
    }
    #[test]
    fn four_pq_profiles_fit_both_json_and_windows_utf16_credential_limits() {
        let mut identity = Identity::fresh();
        for i in 1..=4 {
            identity.profiles.push(Profile {
                public: hex::encode(fluxlock_autofill_protocol::public_identity(&[i; 64])),
                vault_id: "a".repeat(64),
                name: "🔐".repeat(40),
            });
        }
        identity.validate().unwrap();
        let encoded = Zeroizing::new(serde_json::to_string(&identity).unwrap());
        assert!(encoded.len() <= 2400);
        assert!(encoded.encode_utf16().count() * 2 <= 2560);
        let recovered: Identity = serde_json::from_str(&encoded).unwrap();
        assert_eq!(recovered.profiles.len(), 4);
        recovered.validate().unwrap();
    }
}

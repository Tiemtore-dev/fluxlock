//! Gestion avancée des clés cryptographiques

use crate::secure_memory::CryptoKey;
use std::collections::HashMap;

/// Gestionnaire de clés
#[derive(Debug)]
pub struct KeyManager {
    keys: HashMap<String, CryptoKey>,
}

impl KeyManager {
    pub fn new() -> Self {
        KeyManager {
            keys: HashMap::new(),
        }
    }

    pub fn add_key(&mut self, id: String, key: CryptoKey) {
        self.keys.insert(id, key);
    }

    pub fn get_key(&self, id: &str) -> Option<&CryptoKey> {
        self.keys.get(id)
    }

    pub fn remove_key(&mut self, id: &str) -> Option<CryptoKey> {
        self.keys.remove(id)
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

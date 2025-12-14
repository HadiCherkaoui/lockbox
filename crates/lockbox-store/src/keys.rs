use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
use std::collections::HashMap;

pub struct KeyStore {
    keys: HashMap<VerifyingKey, String>,
}

impl KeyStore {
    pub fn new() -> Self {
        KeyStore {
            keys: HashMap::new(),
        }
    }

    pub fn register_key(&mut self, public_key: VerifyingKey, label: &str) -> Result<(), String> {
        if self.keys.contains_key(&public_key) {
            return Err("Public key already exists".to_string());
        }
        self.keys.insert(public_key, label.to_string());
        Ok(())
    }

    pub fn key_allowed(&self, public_key: &VerifyingKey) -> bool {
        self.keys.contains_key(public_key)
    }

    pub fn save(&self, path: &str) -> Result<(), String> {
        let mut serializable_keys: Vec<(Vec<u8>, String)> = Vec::new();
        for (key, label) in &self.keys {
            serializable_keys.push((key.to_bytes().to_vec(), label.clone()));
        }
        let serialized = serde_json::to_string(&serializable_keys).map_err(|e| e.to_string())?;
        std::fs::write(path, serialized).map_err(|e| e.to_string())
    }

    pub fn load(&mut self, path: &str) -> Result<(), String> {
        let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let serializable_keys: Vec<([u8; PUBLIC_KEY_LENGTH], String)> =
            serde_json::from_str(&data).map_err(|e| e.to_string())?;
        for (key_bytes, label) in serializable_keys {
            if key_bytes.len() != PUBLIC_KEY_LENGTH {
                return Err("Invalid public key length".to_string());
            }
            let public_key = VerifyingKey::from_bytes(&key_bytes)
                .map_err(|_| "Invalid public key bytes".to_string())?;
            self.keys.insert(public_key, label);
        }
        Ok(())
    }
}

use std::sync::Arc;
use std::{collections::HashMap, fs::write};

use lockbox_crypto::cipher::{Ciphertext, SymmetricKey, decrypt, encrypt};

/// A secret containing multiple encrypted key-value pairs
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Secret {
    /// Map of key names to their encrypted values
    pub data: HashMap<String, Ciphertext>,
}

/// Store for managing encrypted secrets with key-value data
pub struct PasswordStore {
    secrets: HashMap<String, Secret>,
    symmetric_key: Arc<SymmetricKey>,
}

impl PasswordStore {
    /// Create a new password store with the given symmetric key
    pub fn new(symmetric_key: Arc<SymmetricKey>) -> Self {
        PasswordStore {
            secrets: HashMap::new(),
            symmetric_key,
        }
    }

    /// Set an entire secret with multiple key-value pairs
    /// All values are encrypted before storage
    pub fn set(&mut self, name: &str, data: HashMap<String, String>) -> Result<(), String> {
        let mut encrypted_data = HashMap::new();

        // Encrypt each value
        for (key, value) in data {
            let encrypted = encrypt(&self.symmetric_key, value.as_bytes())?;
            encrypted_data.insert(key, encrypted);
        }

        self.secrets.insert(
            name.to_string(),
            Secret {
                data: encrypted_data,
            },
        );
        Ok(())
    }

    /// Get all key-value pairs for a secret (decrypted)
    pub fn get(&self, name: &str) -> Result<HashMap<String, String>, String> {
        if let Some(secret) = self.secrets.get(name) {
            let mut decrypted_data = HashMap::new();

            // Decrypt each value
            for (key, ciphertext) in &secret.data {
                let decrypted = decrypt(&self.symmetric_key, ciphertext)?;
                let value = String::from_utf8(decrypted)
                    .map_err(|e| format!("Failed to decode value for key '{}': {}", key, e))?;
                decrypted_data.insert(key.clone(), value);
            }

            Ok(decrypted_data)
        } else {
            Err(format!("No secret found for name: {}", name))
        }
    }

    /// Get a single value from a secret by key
    pub fn get_value(&self, name: &str, key: &str) -> Result<String, String> {
        if let Some(secret) = self.secrets.get(name) {
            if let Some(ciphertext) = secret.data.get(key) {
                let decrypted = decrypt(&self.symmetric_key, ciphertext)?;
                let value = String::from_utf8(decrypted)
                    .map_err(|e| format!("Failed to decode value: {}", e))?;
                Ok(value)
            } else {
                Err(format!("No key '{}' found in secret '{}'", key, name))
            }
        } else {
            Err(format!("No secret found for name: {}", name))
        }
    }

    /// Check if a secret exists
    pub fn entry_exists(&self, name: &str) -> bool {
        self.secrets.contains_key(name)
    }

    /// Remove a secret entirely
    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        if self.secrets.remove(name).is_some() {
            Ok(())
        } else {
            Err(format!("No secret found for name: {}", name))
        }
    }

    /// Update specific keys in a secret (keeps other keys unchanged)
    /// Creates the secret if it doesn't exist
    pub fn update(&mut self, name: &str, data: HashMap<String, String>) -> Result<(), String> {
        // Get existing secret or create new one
        let secret = self.secrets.entry(name.to_string()).or_insert(Secret {
            data: HashMap::new(),
        });

        // Update or add each key-value pair
        for (key, value) in data {
            let encrypted = encrypt(&self.symmetric_key, value.as_bytes())?;
            secret.data.insert(key, encrypted);
        }

        Ok(())
    }

    /// List all secret names
    pub fn list(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    /// Save all secrets to a file
    pub fn save(&self, filepath: &str) -> Result<(), String> {
        let secrets_json = serde_json::to_string(&self.secrets)
            .map_err(|e| format!("Failed to serialize secrets: {}", e))?;
        write(filepath, secrets_json)
            .map_err(|e| format!("Failed to write secrets to file: {}", e))?;
        Ok(())
    }

    /// Load secrets from a file
    pub fn load(&mut self, filepath: &str) -> Result<(), String> {
        let data = std::fs::read_to_string(filepath)
            .map_err(|e| format!("Failed to read secrets from file: {}", e))?;
        self.secrets = serde_json::from_str(&data)
            .map_err(|e| format!("Failed to deserialize secrets: {}", e))?;
        Ok(())
    }
}

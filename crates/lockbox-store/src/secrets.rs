use lockbox_crypto::cipher::Ciphertext;
use std::{collections::HashMap, fs::write};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Secret {
    pub data: HashMap<String, Ciphertext>,
}

pub struct SecretStore {
    secrets: HashMap<String, Secret>,
}

impl SecretStore {
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    pub fn set(&mut self, name: &str, data: Secret) -> Result<(), String> {
        self.secrets.insert(name.to_string(), data);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<Secret, String> {
        if let Some(secret) = self.secrets.get(name) {
            let mut data = HashMap::new();

            for (key, ciphertext) in &secret.data {
                data.insert(key.clone(), ciphertext.clone());
            }
            Ok(Secret { data })
        } else {
            Err(format!("No secret found for name: {}", name))
        }
    }

    pub fn entry_exists(&self, name: &str) -> bool {
        self.secrets.contains_key(name)
    }

    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        if self.secrets.remove(name).is_some() {
            Ok(())
        } else {
            Err(format!("No secret found for name: {}", name))
        }
    }

    pub fn update(&mut self, name: &str, data: HashMap<String, Ciphertext>) -> Result<(), String> {
        let secret = self.secrets.entry(name.to_string()).or_insert(Secret {
            data: HashMap::new(),
        });

        for (key, value) in data {
            secret.data.insert(key, value);
        }

        Ok(())
    }

    pub fn list(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    pub fn save(&self, filepath: &str) -> Result<(), String> {
        let secrets_json = serde_json::to_string(&self.secrets)
            .map_err(|e| format!("Failed to serialize secrets: {}", e))?;
        write(filepath, secrets_json)
            .map_err(|e| format!("Failed to write secrets to file: {}", e))?;
        Ok(())
    }

    pub fn load(&mut self, filepath: &str) -> Result<(), String> {
        let data = std::fs::read_to_string(filepath)
            .map_err(|e| format!("Failed to read secrets from file: {}", e))?;
        self.secrets = serde_json::from_str(&data)
            .map_err(|e| format!("Failed to deserialize secrets: {}", e))?;
        Ok(())
    }
}

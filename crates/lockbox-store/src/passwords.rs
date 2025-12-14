use std::sync::Arc;
use std::{collections::HashMap, fs::write};

use lockbox_crypto::cipher::{Ciphertext, SymmetricKey, decrypt, encrypt};

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Password {
    pub username: String,
    pub encrypted_password: Ciphertext,
}

pub struct PasswordStore {
    passwords: HashMap<String, Password>,
    symmetric_key: Arc<SymmetricKey>,
}

impl PasswordStore {
    pub fn new(symmetric_key: Arc<SymmetricKey>) -> Self {
        PasswordStore {
            passwords: HashMap::new(),
            symmetric_key,
        }
    }

    pub fn add(&mut self, name: &str, username: &str, password: &str) -> Result<(), String> {
        let encrypted = encrypt(&self.symmetric_key, password.as_bytes())?;
        self.passwords.insert(
            name.to_string(),
            Password {
                username: username.to_string(),
                encrypted_password: encrypted,
            },
        );
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<(String, String), String> {
        if let Some(entry) = self.passwords.get(name) {
            let decrypted = decrypt(&self.symmetric_key, &entry.encrypted_password)?;
            let password = String::from_utf8(decrypted)
                .map_err(|e| format!("Failed to decode password: {}", e))?;
            Ok((entry.username.clone(), password))
        } else {
            Err(format!("No password found for name: {}", name))
        }
    }

    pub fn list(&self) -> Vec<String> {
        self.passwords.keys().cloned().collect()
    }

    pub fn save(&self, filepath: &str) -> Result<(), String> {
        let passwords_json = serde_json::to_string(&self.passwords)
            .map_err(|e| format!("Failed to serialize passwords: {}", e))?;
        write(filepath, passwords_json)
            .map_err(|e| format!("Failed to write passwords to file: {}", e))?;
        Ok(())
    }

    pub fn load(&mut self, filepath: &str) -> Result<(), String> {
        let data = std::fs::read_to_string(filepath)
            .map_err(|e| format!("Failed to read passwords from file: {}", e))?;
        self.passwords = serde_json::from_str(&data)
            .map_err(|e| format!("Failed to deserialize passwords: {}", e))?;
        Ok(())
    }

    pub fn entry_exists(&self, name: &str) -> bool {
        self.passwords.contains_key(name)
    }
}

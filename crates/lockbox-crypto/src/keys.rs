use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs::{read, write};

pub fn generate_keypair() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

pub fn save_signing_key(key: &SigningKey, filepath: &str) -> Result<(), String> {
    let key_bytes = key.to_bytes();
    write(filepath, key_bytes)
        .map_err(|e| format!("Failed to write signing key to file: {}", e))?;
    Ok(())
}

pub fn load_signing_key(filepath: &str) -> Result<SigningKey, String> {
    read(filepath)
        .map_err(|e| format!("Failed to read signing key from file: {}", e))
        .and_then(|data| {
            if data.len() != 32 {
                return Err("Invalid signing key length".to_string());
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&data);
            Ok(SigningKey::from_bytes(&key_bytes))
        })
}

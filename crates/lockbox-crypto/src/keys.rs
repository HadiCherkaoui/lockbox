use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::fs::{read, write};

/// Generate a new Ed25519 keypair
/// Returns the private key (SigningKey), which contains both private and public parts
pub fn generate_keypair() -> SigningKey {
    let mut csprng = OsRng;
    SigningKey::generate(&mut csprng)
}

/// Convert a SigningKey (private key) to bytes for storage
/// Returns 32 bytes that represent the private key
pub fn signing_key_to_bytes(key: &SigningKey) -> [u8; 32] {
    key.to_bytes()
}

/// Recreate a SigningKey from stored bytes
/// Takes the 32-byte private key and returns the SigningKey
pub fn signing_key_from_bytes(bytes: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(bytes)
}

/// Convert a VerifyingKey (public key) to bytes for storage/sharing
/// Returns 32 bytes that represent the public key
pub fn verifying_key_to_bytes(key: &VerifyingKey) -> [u8; 32] {
    key.to_bytes()
}

/// Recreate a VerifyingKey from bytes
/// Takes 32-byte public key and returns the VerifyingKey
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(bytes).map_err(|e| format!("Invalid public key: {}", e))
}

/// Sign a message with your private key
/// Returns a 64-byte signature that proves you signed this message
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> Signature {
    signing_key.sign(message)
}

/// Verify that a signature is valid for a message and public key
/// Returns true if the signature is valid, false otherwise
pub fn verify(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    verifying_key.verify(message, signature).is_ok()
}

pub fn save_signing_key(key: &SigningKey, filepath: &str) -> Result<(), String> {
    let key_bytes = signing_key_to_bytes(key);
    write(filepath, &key_bytes)
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
            Ok(signing_key_from_bytes(&key_bytes))
        })
}

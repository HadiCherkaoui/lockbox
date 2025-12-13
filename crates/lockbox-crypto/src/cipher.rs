use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use zeroize::Zeroizing;

/// A 256-bit symmetric key for AES-256-GCM encryption
/// The Zeroizing wrapper ensures the key is wiped from memory when dropped
pub struct SymmetricKey(Zeroizing<[u8; 32]>);

impl SymmetricKey {
    /// Generate a new random 256-bit key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        SymmetricKey(Zeroizing::new(key))
    }
}

/// Holds encrypted data: a 12-byte nonce + the ciphertext (which includes the GCM auth tag)
pub struct Ciphertext {
    pub nonce: [u8; 12],
    pub data: Vec<u8>,
}

/// Encrypt plaintext using AES-256-GCM
/// Returns the nonce + encrypted data, or an error if encryption fails
pub fn encrypt(key: &SymmetricKey, plaintext: &[u8]) -> Result<Ciphertext, String> {
    // Create the AES-256-GCM cipher from our key
    let cipher = Aes256Gcm::new(key.0.as_ref().into());

    // Generate a random 12-byte nonce (number used once)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the plaintext - this also adds an authentication tag
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(Ciphertext {
        nonce: nonce_bytes,
        data: ciphertext,
    })
}

/// Decrypt ciphertext using AES-256-GCM
/// Returns the original plaintext, or an error if decryption/authentication fails
pub fn decrypt(key: &SymmetricKey, ciphertext: &Ciphertext) -> Result<Vec<u8>, String> {
    // Create the same cipher
    let cipher = Aes256Gcm::new(key.0.as_ref().into());

    // Use the stored nonce
    let nonce = Nonce::from_slice(&ciphertext.nonce);

    // Decrypt and verify the authentication tag
    let plaintext = cipher
        .decrypt(nonce, ciphertext.data.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

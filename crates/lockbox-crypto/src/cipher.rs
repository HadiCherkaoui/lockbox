use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use zeroize::Zeroizing;

pub struct SymmetricKey(Zeroizing<[u8; 32]>);

impl SymmetricKey {
    pub fn from_ed25519(signing_key: &SigningKey) -> Self {
        let key_bytes = signing_key.to_bytes();
        SymmetricKey(Zeroizing::new(key_bytes))
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Ciphertext {
    pub nonce: [u8; 12],
    pub data: Vec<u8>,
}

pub fn encrypt(key: &SymmetricKey, plaintext: &[u8]) -> Result<Ciphertext, String> {
    let cipher = Aes256Gcm::new(key.0.as_ref().into());

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

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

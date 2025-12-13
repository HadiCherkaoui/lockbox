pub mod cipher;
pub mod keys;

#[cfg(test)]
mod tests {
    use crate::cipher::{SymmetricKey, decrypt, encrypt};
    use crate::keys::*;

    #[test]
    fn test_encrypt_decrypt() {
        // Generate a random key
        let key = SymmetricKey::generate();

        // Our secret password
        let password = b"my super secret password";

        // Encrypt it
        let encrypted = encrypt(&key, password).expect("encryption should work");

        // Decrypt it back
        let decrypted = decrypt(&key, &encrypted).expect("decryption should work");

        // Should match the original
        assert_eq!(password.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_keypair_roundtrip() {
        // Generate a keypair
        let signing_key = generate_keypair();
        let verifying_key = signing_key.verifying_key();

        // Convert to bytes (for saving to disk)
        let private_bytes = signing_key_to_bytes(&signing_key);
        let public_bytes = verifying_key_to_bytes(&verifying_key);

        // Convert back from bytes (like loading from disk)
        let _restored_signing = signing_key_from_bytes(&private_bytes);
        let restored_verifying = verifying_key_from_bytes(&public_bytes).unwrap();

        // Sign a message with original key
        let message = b"authenticate me";
        let signature = sign(&signing_key, message);

        // Verify with restored public key - should work!
        assert!(verify(&restored_verifying, message, &signature));

        // Try wrong message - should fail
        assert!(!verify(
            &restored_verifying,
            b"different message",
            &signature
        ));
    }
}

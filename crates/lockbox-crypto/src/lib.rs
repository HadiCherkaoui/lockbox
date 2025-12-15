pub mod cipher;
pub mod keys;

#[cfg(test)]
mod tests {
    use ed25519_dalek::ed25519::signature::SignerMut;

    use crate::cipher::{SymmetricKey, decrypt, encrypt};
    use crate::keys::*;

    #[test]
    fn test_encrypt_decrypt() {
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);

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
        let mut signing_key = generate_keypair();
        let _verifying_key = signing_key.verifying_key();

        // Convert to bytes (for saving to disk)
        save_signing_key(&signing_key, "./temp_signing_key.bin").expect("should save signing key");

        let restored_signing =
            load_signing_key("./temp_signing_key.bin").expect("should load signing key");
        let restored_verifying = restored_signing.verifying_key();

        // Sign a message with original key
        let message = b"authenticate me";
        let signature = signing_key.try_sign(message).expect("should sign message");
        let verify_result = restored_verifying.verify_strict(message, &signature);
        assert!(verify_result.is_ok());
        std::fs::remove_file("./temp_signing_key.bin").expect("should remove temp file");

        // Try wrong message - should fail
        let wrong_verify = restored_verifying.verify_strict(b"different message", &signature);
        assert!(wrong_verify.is_err());
    }

    #[test]
    fn test_signing_key_save_load() {
        let signing_key = generate_keypair();
        let filepath = "./test_signing_key.bin";

        save_signing_key(&signing_key, filepath).expect("should save signing key");

        let loaded_key = load_signing_key(filepath).expect("should load signing key");

        std::fs::remove_file(filepath).expect("should remove test file");
        assert_eq!(signing_key.to_bytes(), loaded_key.to_bytes());
    }
}

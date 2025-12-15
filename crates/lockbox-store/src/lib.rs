pub mod keys;
pub mod secrets;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::remove_file;

    use crate::keys::KeyStore;
    use crate::secrets::{Secret, SecretStore};
    use lockbox_crypto::cipher::{SymmetricKey, decrypt, encrypt};
    use lockbox_crypto::keys::generate_keypair;

    #[test]
    fn test_secret_store_basic() {
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);
        let mut store = SecretStore::new();

        // Encrypt data on "client side" (this would happen in CLI)
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            encrypt(&key, b"test@test.com").expect("should encrypt"),
        );
        data.insert(
            "password".to_string(),
            encrypt(&key, b"secretpasswd").expect("should encrypt"),
        );
        let secret = Secret { data };

        // Store encrypted secret (this is what server does)
        store.set("email", secret).expect("should set secret");

        // Retrieve encrypted secret (server returns this)
        let retrieved = store.get("email").expect("should get secret");

        // Decrypt on "client side" (this would happen in CLI)
        for (k, v) in &retrieved.data {
            let decrypted = String::from_utf8(decrypt(&key, v).expect("should decrypt"))
                .expect("should convert to string");
            if k == "username" {
                assert_eq!(decrypted, "test@test.com");
            } else if k == "password" {
                assert_eq!(decrypted, "secretpasswd");
            }
        }

        // List secrets (server operation)
        let list = store.list();
        assert_eq!(list, vec!["email".to_string()]);
    }

    #[test]
    fn test_secret_store_save_load() {
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);
        let mut store = SecretStore::new();

        // Encrypt data (client-side)
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            encrypt(&key, b"test@test.com").expect("should encrypt"),
        );
        data.insert(
            "password".to_string(),
            encrypt(&key, b"secretpasswd").expect("should encrypt"),
        );
        let secret = Secret { data };

        store.set("email", secret).expect("should set secret");
        store
            .save("./test_secretstore_save.json")
            .expect("should save secret store");

        // Load in same store
        store
            .load("./test_secretstore_save.json")
            .expect("should load secret store");

        // Load in new store (simulating server restart)
        let mut new_store = SecretStore::new();
        new_store
            .load("./test_secretstore_save.json")
            .expect("should load secret store");

        let retrieved = store.get("email").expect("should get secret");
        let retrieved_new = new_store.get("email").expect("should get secret");

        remove_file("./test_secretstore_save.json").expect("should remove test file");

        // Verify both stores have same encrypted data
        assert_eq!(retrieved_new.data.len(), retrieved.data.len());

        // Decrypt and verify (client-side)
        for (k, v) in &retrieved.data {
            let decrypted = String::from_utf8(decrypt(&key, v).expect("should decrypt"))
                .expect("should convert to string");
            if k == "username" {
                assert_eq!(decrypted, "test@test.com");
            } else if k == "password" {
                assert_eq!(decrypted, "secretpasswd");
            }
        }
    }

    #[test]
    fn test_multi_key_secret() {
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);
        let mut store = SecretStore::new();

        // Create a secret with multiple keys (like K8s env secret)
        // Encrypt on client-side
        let mut data = HashMap::new();
        data.insert(
            "API_KEY".to_string(),
            encrypt(&key, b"key123").expect("should encrypt"),
        );
        data.insert(
            "DB_HOST".to_string(),
            encrypt(&key, b"localhost").expect("should encrypt"),
        );
        data.insert(
            "DB_PORT".to_string(),
            encrypt(&key, b"5432").expect("should encrypt"),
        );
        data.insert(
            "DB_PASSWORD".to_string(),
            encrypt(&key, b"dbpass").expect("should encrypt"),
        );
        let secret = Secret { data };

        store
            .set("prod/database-config", secret)
            .expect("should set multi-key secret");

        // Retrieve encrypted secret (server operation)
        let retrieved = store
            .get("prod/database-config")
            .expect("should get secret");

        // Decrypt and verify (client-side)
        assert_eq!(
            String::from_utf8(decrypt(&key, &retrieved.data["API_KEY"]).unwrap()).unwrap(),
            "key123"
        );
        assert_eq!(
            String::from_utf8(decrypt(&key, &retrieved.data["DB_HOST"]).unwrap()).unwrap(),
            "localhost"
        );
        assert_eq!(
            String::from_utf8(decrypt(&key, &retrieved.data["DB_PORT"]).unwrap()).unwrap(),
            "5432"
        );
        assert_eq!(
            String::from_utf8(decrypt(&key, &retrieved.data["DB_PASSWORD"]).unwrap()).unwrap(),
            "dbpass"
        );
    }

    #[test]
    fn test_update_secret() {
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);
        let mut store = SecretStore::new();

        // Create initial secret (encrypt client-side)
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            encrypt(&key, b"user1").expect("should encrypt"),
        );
        data.insert(
            "password".to_string(),
            encrypt(&key, b"pass1").expect("should encrypt"),
        );
        let secret = Secret { data };
        store.set("test", secret).expect("should set secret");

        // Update only password, keep username (client encrypts new value)
        let mut update_data = HashMap::new();
        update_data.insert(
            "password".to_string(),
            encrypt(&key, b"newpass").expect("should encrypt"),
        );
        store
            .update("test", update_data)
            .expect("should update secret");

        // Retrieve and decrypt (client-side)
        let retrieved = store.get("test").expect("should get secret");
        let username =
            String::from_utf8(decrypt(&key, &retrieved.data["username"]).unwrap()).unwrap();
        let password =
            String::from_utf8(decrypt(&key, &retrieved.data["password"]).unwrap()).unwrap();

        assert_eq!(username, "user1"); // unchanged
        assert_eq!(password, "newpass"); // updated
    }

    #[test]
    fn test_remove_secret() {
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);
        let mut store = SecretStore::new();

        // Add a secret
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            encrypt(&key, b"test").expect("should encrypt"),
        );
        let secret = Secret { data };
        store.set("test", secret).expect("should set secret");

        assert!(store.entry_exists("test"));

        // Remove it
        store.remove("test").expect("should remove secret");

        assert!(!store.entry_exists("test"));
        assert!(store.get("test").is_err());
    }

    #[test]
    fn test_keystore() {
        let keypair = generate_keypair();
        let mut key_store = KeyStore::new();

        key_store
            .register_key(keypair.verifying_key(), "testkey")
            .expect("should register key");
        key_store
            .save("./test_keystore_save.json")
            .expect("should save key store");

        let mut new_key_store = KeyStore::new();
        new_key_store
            .load("./test_keystore_save.json")
            .expect("should load key store");

        remove_file("./test_keystore_save.json").expect("should remove test file");

        assert!(new_key_store.key_allowed(&keypair.verifying_key()));
    }
}

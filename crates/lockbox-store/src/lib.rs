pub mod passwords;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::remove_file;
    use std::sync::Arc;

    use crate::passwords::PasswordStore;
    use lockbox_crypto::cipher::SymmetricKey;
    use lockbox_crypto::keys::generate_keypair;

    #[test]
    fn test_password_store() {
        let keypair = generate_keypair();
        let key = Arc::new(SymmetricKey::from_ed25519(&keypair));
        let mut store = PasswordStore::new(key);

        // Create a secret with username and password
        let mut data = HashMap::new();
        data.insert("username".to_string(), "test@test.com".to_string());
        data.insert("password".to_string(), "secretpasswd".to_string());

        store.set("email", data).expect("should set secret");

        // Get entire secret
        let retrieved = store.get("email").expect("should get secret");
        assert_eq!(retrieved.get("username").unwrap(), "test@test.com");
        assert_eq!(retrieved.get("password").unwrap(), "secretpasswd");

        // Get single value
        let password = store
            .get_value("email", "password")
            .expect("should get value");
        assert_eq!(password, "secretpasswd");

        // List secrets
        let list = store.list();
        assert_eq!(list, vec!["email".to_string()]);
    }

    #[test]
    fn test_password_store_save_load() {
        let keypair = generate_keypair();
        let key = Arc::new(SymmetricKey::from_ed25519(&keypair));
        let mut store = PasswordStore::new(key.clone());

        // Create and save secret
        let mut data = HashMap::new();
        data.insert("username".to_string(), "test@test.com".to_string());
        data.insert("password".to_string(), "secretpasswd".to_string());

        store.set("email", data).expect("should set secret");
        store
            .save("./test_pwdstore_save.json")
            .expect("should save password store");

        // Load in same store
        store
            .load("./test_pwdstore_save.json")
            .expect("should load password store");

        // Load in new store
        let mut new_store = PasswordStore::new(key.clone());
        new_store
            .load("./test_pwdstore_save.json")
            .expect("should load password store");

        let retrieved = store.get("email").expect("should get secret");
        let retrieved_new = new_store.get("email").expect("should get secret");

        remove_file("./test_pwdstore_save.json").expect("should remove test file");

        assert_eq!(retrieved_new, retrieved);
        assert_eq!(retrieved.get("username").unwrap(), "test@test.com");
        assert_eq!(retrieved.get("password").unwrap(), "secretpasswd");
    }

    #[test]
    fn test_multi_key_secret() {
        let keypair = generate_keypair();
        let key = Arc::new(SymmetricKey::from_ed25519(&keypair));
        let mut store = PasswordStore::new(key);

        // Create a secret with multiple keys (like K8s env secret)
        let mut data = HashMap::new();
        data.insert("API_KEY".to_string(), "key123".to_string());
        data.insert("DB_HOST".to_string(), "localhost".to_string());
        data.insert("DB_PORT".to_string(), "5432".to_string());
        data.insert("DB_PASSWORD".to_string(), "dbpass".to_string());

        store
            .set("prod/database-config", data)
            .expect("should set multi-key secret");

        // Retrieve all values
        let retrieved = store
            .get("prod/database-config")
            .expect("should get secret");
        assert_eq!(retrieved.get("API_KEY").unwrap(), "key123");
        assert_eq!(retrieved.get("DB_HOST").unwrap(), "localhost");
        assert_eq!(retrieved.get("DB_PORT").unwrap(), "5432");
        assert_eq!(retrieved.get("DB_PASSWORD").unwrap(), "dbpass");

        // Retrieve single value
        let db_password = store
            .get_value("prod/database-config", "DB_PASSWORD")
            .expect("should get value");
        assert_eq!(db_password, "dbpass");
    }

    #[test]
    fn test_update_secret() {
        let keypair = generate_keypair();
        let key = Arc::new(SymmetricKey::from_ed25519(&keypair));
        let mut store = PasswordStore::new(key);

        // Create initial secret
        let mut data = HashMap::new();
        data.insert("username".to_string(), "user1".to_string());
        data.insert("password".to_string(), "pass1".to_string());
        store.set("test", data).expect("should set secret");

        // Update only password, keep username
        let mut update_data = HashMap::new();
        update_data.insert("password".to_string(), "newpass".to_string());
        store
            .update("test", update_data)
            .expect("should update secret");

        let retrieved = store.get("test").expect("should get secret");
        assert_eq!(retrieved.get("username").unwrap(), "user1"); // unchanged
        assert_eq!(retrieved.get("password").unwrap(), "newpass"); // updated
    }
}

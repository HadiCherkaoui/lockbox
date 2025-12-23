use lockbox_crypto::cipher::Ciphertext;
use std::collections::HashMap;

pub mod db;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Secret {
    pub data: HashMap<String, Ciphertext>,
}

#[cfg(test)]
mod tests {
    use crate::db::Database;
    use lockbox_crypto::cipher::{SymmetricKey, decrypt, encrypt};
    use lockbox_crypto::keys::generate_keypair;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_database_basic_operations() {
        let db = Database::new("sqlite::memory:").await.unwrap();
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);

        // Encrypt data on client-side
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            encrypt(&key, b"test@test.com").expect("should encrypt"),
        );
        data.insert(
            "password".to_string(),
            encrypt(&key, b"secretpasswd").expect("should encrypt"),
        );

        // Store encrypted secret (server operation)
        db.set_secret("email", &data)
            .await
            .expect("should set secret");

        // Retrieve encrypted secret (server returns this)
        let retrieved = db.get_secret("email").await.expect("should get secret");

        // Decrypt on client side
        for (k, v) in &retrieved {
            let decrypted = String::from_utf8(decrypt(&key, v).expect("should decrypt"))
                .expect("should convert to string");
            if k == "username" {
                assert_eq!(decrypted, "test@test.com");
            } else if k == "password" {
                assert_eq!(decrypted, "secretpasswd");
            }
        }

        // List secrets
        let list = db.list_secrets().await.expect("should list secrets");
        assert_eq!(list, vec!["email".to_string()]);

        db.close().await;
    }

    #[tokio::test]
    async fn test_database_multi_key_secret() {
        let db = Database::new("sqlite::memory:").await.unwrap();
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);

        // Create a secret with multiple keys (like K8s env secret)
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

        db.set_secret("prod/database-config", &data)
            .await
            .expect("should set multi-key secret");

        // Retrieve encrypted secret
        let retrieved = db
            .get_secret("prod/database-config")
            .await
            .expect("should get secret");

        // Decrypt and verify
        assert_eq!(
            String::from_utf8(decrypt(&key, &retrieved["API_KEY"]).unwrap()).unwrap(),
            "key123"
        );
        assert_eq!(
            String::from_utf8(decrypt(&key, &retrieved["DB_HOST"]).unwrap()).unwrap(),
            "localhost"
        );
        assert_eq!(
            String::from_utf8(decrypt(&key, &retrieved["DB_PORT"]).unwrap()).unwrap(),
            "5432"
        );
        assert_eq!(
            String::from_utf8(decrypt(&key, &retrieved["DB_PASSWORD"]).unwrap()).unwrap(),
            "dbpass"
        );

        db.close().await;
    }

    #[tokio::test]
    async fn test_database_update_secret() {
        let db = Database::new("sqlite::memory:").await.unwrap();
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);

        // Create initial secret
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            encrypt(&key, b"user1").expect("should encrypt"),
        );
        data.insert(
            "password".to_string(),
            encrypt(&key, b"pass1").expect("should encrypt"),
        );
        db.set_secret("test", &data)
            .await
            .expect("should set secret");

        // Update only password
        let mut update_data = HashMap::new();
        update_data.insert(
            "password".to_string(),
            encrypt(&key, b"newpass").expect("should encrypt"),
        );
        db.update_secret("test", update_data)
            .await
            .expect("should update secret");

        // Retrieve and decrypt
        let retrieved = db.get_secret("test").await.expect("should get secret");
        let username = String::from_utf8(decrypt(&key, &retrieved["username"]).unwrap()).unwrap();
        let password = String::from_utf8(decrypt(&key, &retrieved["password"]).unwrap()).unwrap();

        assert_eq!(username, "user1"); // unchanged
        assert_eq!(password, "newpass"); // updated

        db.close().await;
    }

    #[tokio::test]
    async fn test_database_remove_secret() {
        let db = Database::new("sqlite::memory:").await.unwrap();
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);

        // Add a secret
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            encrypt(&key, b"test").expect("should encrypt"),
        );
        db.set_secret("test", &data)
            .await
            .expect("should set secret");

        assert!(
            db.secret_exists("test")
                .await
                .expect("should check existence")
        );

        // Remove it
        db.remove_secret("test")
            .await
            .expect("should remove secret");

        assert!(
            !db.secret_exists("test")
                .await
                .expect("should check existence")
        );
        assert!(db.get_secret("test").await.is_err());

        db.close().await;
    }

    #[tokio::test]
    async fn test_database_keystore() {
        let db = Database::new("sqlite::memory:").await.unwrap();
        let keypair = generate_keypair();

        db.register_key(&keypair.verifying_key(), "testkey")
            .await
            .expect("should register key");

        assert!(
            db.key_allowed(&keypair.verifying_key())
                .await
                .expect("should check key")
        );

        // Try registering same key again (should fail)
        let result = db.register_key(&keypair.verifying_key(), "testkey").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));

        db.close().await;
    }
}

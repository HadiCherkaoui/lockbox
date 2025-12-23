use ed25519_dalek::VerifyingKey;
use lockbox_crypto::cipher::Ciphertext;
use serde_json;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = SqlitePool::connect(database_url).await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
    pub async fn register_key(&self, public_key: &VerifyingKey, label: &str) -> Result<(), String> {
        let key_bytes = public_key.to_bytes().to_vec();
        let now = current_timestamp();

        sqlx::query("INSERT INTO users (public_key, label, created_at) VALUES (?, ?, ?)")
            .bind(&key_bytes)
            .bind(label)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                if e.to_string().contains("UNIQUE constraint failed") {
                    "Public key already exists".to_string()
                } else {
                    format!("Failed to register key: {}", e)
                }
            })?;

        Ok(())
    }
    pub async fn key_allowed(&self, public_key: &VerifyingKey) -> Result<bool, String> {
        let key_bytes = public_key.to_bytes().to_vec();

        let result = sqlx::query("SELECT COUNT(*) as count FROM users WHERE public_key = ?")
            .bind(&key_bytes)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("Failed to check key: {}", e))?;

        let count: i64 = result.get("count");
        Ok(count > 0)
    }
    pub async fn set_secret(
        &self,
        name: &str,
        data: &HashMap<String, Ciphertext>,
    ) -> Result<(), String> {
        let data_json = serde_json::to_string(data)
            .map_err(|e| format!("Failed to serialize secret data: {}", e))?;

        let now = current_timestamp();
        sqlx::query(
            "INSERT INTO secrets (name, data, created_at, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(name) DO UPDATE SET
                data = excluded.data,
                updated_at = excluded.updated_at",
        )
        .bind(name)
        .bind(&data_json)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to set secret: {}", e))?;

        Ok(())
    }
    pub async fn get_secret(&self, name: &str) -> Result<HashMap<String, Ciphertext>, String> {
        let row = sqlx::query("SELECT data FROM secrets WHERE name = ?")
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| format!("Failed to fetch secret: {}", e))?;

        match row {
            Some(row) => {
                let data_json: String = row.get("data");
                let data: HashMap<String, Ciphertext> = serde_json::from_str(&data_json)
                    .map_err(|e| format!("Failed to deserialize secret data: {}", e))?;
                Ok(data)
            }
            None => Err(format!("No secret found for name: {}", name)),
        }
    }
    pub async fn secret_exists(&self, name: &str) -> Result<bool, String> {
        let result = sqlx::query("SELECT COUNT(*) as count FROM secrets WHERE name = ?")
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("Failed to check secret: {}", e))?;

        let count: i64 = result.get("count");
        Ok(count > 0)
    }
    pub async fn remove_secret(&self, name: &str) -> Result<(), String> {
        let result = sqlx::query("DELETE FROM secrets WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to remove secret: {}", e))?;

        if result.rows_affected() == 0 {
            Err(format!("No secret found for name: {}", name))
        } else {
            Ok(())
        }
    }
    pub async fn update_secret(
        &self,
        name: &str,
        updates: HashMap<String, Ciphertext>,
    ) -> Result<(), String> {
        let mut existing_data = self.get_secret(name).await?;
        for (key, value) in updates {
            existing_data.insert(key, value);
        }
        let data_json = serde_json::to_string(&existing_data)
            .map_err(|e| format!("Failed to serialize secret data: {}", e))?;

        let now = current_timestamp();

        sqlx::query("UPDATE secrets SET data = ?, updated_at = ? WHERE name = ?")
            .bind(&data_json)
            .bind(now)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to update secret: {}", e))?;

        Ok(())
    }
    pub async fn list_secrets(&self) -> Result<Vec<String>, String> {
        let rows = sqlx::query("SELECT name FROM secrets ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("Failed to list secrets: {}", e))?;

        let names = rows.iter().map(|row| row.get("name")).collect();
        Ok(names)
    }
    pub async fn store_challenge(
        &self,
        public_key_b64: &str,
        challenge: &str,
        expires_at: i64,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO challenges (public_key_b64, challenge, expires_at) VALUES (?, ?, ?)
             ON CONFLICT(public_key_b64) DO UPDATE SET
                challenge = excluded.challenge,
                expires_at = excluded.expires_at",
        )
        .bind(public_key_b64)
        .bind(challenge)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Failed to store challenge: {}", e))?;

        Ok(())
    }
    pub async fn consume_challenge(
        &self,
        public_key_b64: &str,
    ) -> Result<Option<(String, i64)>, String> {
        let row =
            sqlx::query("SELECT challenge, expires_at FROM challenges WHERE public_key_b64 = ?")
                .bind(public_key_b64)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| format!("Failed to fetch challenge: {}", e))?;

        if let Some(row) = row {
            let challenge: String = row.get("challenge");
            let expires_at: i64 = row.get("expires_at");
            sqlx::query("DELETE FROM challenges WHERE public_key_b64 = ?")
                .bind(public_key_b64)
                .execute(&self.pool)
                .await
                .map_err(|e| format!("Failed to delete challenge: {}", e))?;

            Ok(Some((challenge, expires_at)))
        } else {
            Ok(None)
        }
    }
    pub async fn cleanup_expired_challenges(&self, now: i64) -> Result<u64, String> {
        let result = sqlx::query("DELETE FROM challenges WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Failed to cleanup challenges: {}", e))?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockbox_crypto::cipher::{SymmetricKey, encrypt};
    use lockbox_crypto::keys::generate_keypair;

    #[tokio::test]
    async fn test_database_user_registration() {
        let db = Database::new("sqlite::memory:").await.unwrap();
        let keypair = generate_keypair();
        db.register_key(&keypair.verifying_key(), "test-key")
            .await
            .unwrap();
        assert!(db.key_allowed(&keypair.verifying_key()).await.unwrap());
        let result = db.register_key(&keypair.verifying_key(), "test-key").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_database_secret_operations() {
        let db = Database::new("sqlite::memory:").await.unwrap();
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);
        let mut data = HashMap::new();
        data.insert(
            "username".to_string(),
            encrypt(&key, b"test@test.com").unwrap(),
        );
        data.insert(
            "password".to_string(),
            encrypt(&key, b"secretpasswd").unwrap(),
        );
        db.set_secret("email", &data).await.unwrap();
        let retrieved = db.get_secret("email").await.unwrap();
        assert_eq!(retrieved.len(), 2);
        assert!(retrieved.contains_key("username"));
        assert!(retrieved.contains_key("password"));
        assert!(db.secret_exists("email").await.unwrap());
        assert!(!db.secret_exists("nonexistent").await.unwrap());
        let list = db.list_secrets().await.unwrap();
        assert_eq!(list, vec!["email"]);
        let mut updates = HashMap::new();
        updates.insert(
            "password".to_string(),
            encrypt(&key, b"newpassword").unwrap(),
        );
        db.update_secret("email", updates).await.unwrap();

        let updated = db.get_secret("email").await.unwrap();
        assert_eq!(updated.len(), 2);
        db.remove_secret("email").await.unwrap();
        assert!(!db.secret_exists("email").await.unwrap());

        db.close().await;
    }
}

pub mod passwords;

#[cfg(test)]
mod tests {
    use std::fs::remove_file;

    use crate::passwords::PasswordStore;
    use lockbox_crypto::cipher::SymmetricKey;
    use lockbox_crypto::keys::generate_keypair;
    #[test]
    fn test_password_store() {
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);
        let mut store = PasswordStore::new(&key);
        store
            .add("email", "test@test.com", "secretpasswd")
            .expect("should add password");
        let retrieved = store.get("email").expect("should get password");
        let list = store.list();
        assert_eq!(list, vec!["email".to_string()]);
        assert_eq!(retrieved, "secretpasswd");
    }

    #[test]
    fn test_password_store_save_load() {
        let keypair = generate_keypair();
        let key = SymmetricKey::from_ed25519(&keypair);
        let mut store = PasswordStore::new(&key);
        store
            .add("email", "test@test.com", "secretpasswd")
            .expect("should add password");
        store
            .save("./test_pwdstore_save.json")
            .expect("should save password store");
        store
            .load("./test_pwdstore_save.json")
            .expect("should load password store");
        let mut new_store = PasswordStore::new(&key);
        new_store
            .load("./test_pwdstore_save.json")
            .expect("should load password store");
        let retrieved = store.get("email").expect("should get password");
        let retrieved_new = new_store.get("email").expect("should get password");
        remove_file("./test_pwdstore_save.json").expect("should remove test file");
        assert_eq!(retrieved_new, retrieved);
        assert_eq!(retrieved, "secretpasswd");
    }
}

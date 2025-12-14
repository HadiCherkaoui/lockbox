use dirs::home_dir;
use lockbox_crypto::{
    cipher::SymmetricKey,
    keys::{generate_keypair, save_signing_key},
};
use lockbox_store::passwords::PasswordStore;
use rpassword::read_password;
use std::collections::HashMap;
use std::sync::Arc;
use std::{
    fs::create_dir_all,
    io::{Write, stdin, stdout},
    path::{Path, PathBuf},
};

struct Config {
    lockbox_path: PathBuf,
    keypair_path: PathBuf,
    password_store_path: PathBuf,
}

impl Config {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let home = home_dir().ok_or("home directory not found")?;
        let lockbox_path = home.join(".lockbox");
        let keypair_path = lockbox_path.join("id_ed25519");
        let password_store_path = lockbox_path.join("passwords.json");
        Ok(Config {
            lockbox_path,
            keypair_path,
            password_store_path,
        })
    }
}

fn load_lockbox() -> Result<PasswordStore, Box<dyn std::error::Error>> {
    let config = Config::new()?;
    if !config.lockbox_path.try_exists()? {
        return Err("Lockbox not initialized. Please run 'lockbox init' first.".into());
    }
    let keypair = lockbox_crypto::keys::load_signing_key(
        config
            .keypair_path
            .to_str()
            .ok_or("Path contains invalid UTF-8")?,
    )?;
    let symmetric_key = Arc::new(SymmetricKey::from_ed25519(&keypair));
    let mut password_store = PasswordStore::new(symmetric_key);
    password_store.load(
        &config
            .password_store_path
            .to_str()
            .ok_or("Path contains invalid UTF-8")?,
    )?;
    Ok(password_store)
}

pub fn handle_init() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing a new lockbox...");
    let config = Config::new()?;
    let dir = Path::new(config.lockbox_path.as_path());
    if dir.try_exists()? {
        return Err(format!(
            "Lockbox already exists at {}",
            config.lockbox_path.display()
        )
        .into());
    }
    create_dir_all(dir)?;
    println!("✓ Created: {}", config.lockbox_path.display());
    let keypair = generate_keypair();
    println!("✓ Generated Ed25519 keypair");
    save_signing_key(
        &keypair,
        config
            .keypair_path
            .to_str()
            .ok_or("Path contains invalid UTF-8")?,
    )?;
    println!("✓ Saved signing key to {}", config.keypair_path.display());
    let symmetric_key = Arc::new(SymmetricKey::from_ed25519(&keypair));
    let pwd_store = PasswordStore::new(symmetric_key);
    pwd_store.save(
        &config
            .password_store_path
            .to_str()
            .ok_or("Path contains invalid UTF-8")?,
    )?;
    println!(
        "✓ Created empty password store at {}",
        config.password_store_path.display()
    );
    println!("Lockbox initialization complete!");
    Ok(())
}

pub fn handle_set(name: &str, pairs: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new()?;
    let mut password_store = load_lockbox()?;

    if password_store.entry_exists(name) {
        return Err(format!("Secret '{}' already exists. Use 'update' to modify it.", name).into());
    }

    // Parse KEY=VALUE pairs
    let mut data = HashMap::new();
    for pair in pairs {
        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(format!("Invalid format '{}'. Use KEY=VALUE", pair).into());
        }
        let key = parts[0].trim();
        let value = parts[1].trim();

        if key.is_empty() || value.is_empty() {
            return Err(format!("Key or value cannot be empty in '{}'", pair).into());
        }

        data.insert(key.to_string(), value.to_string());
    }

    if data.is_empty() {
        return Err("No key-value pairs provided".into());
    }

    password_store.set(name, data)?;
    password_store.save(
        &config
            .password_store_path
            .to_str()
            .ok_or("Path contains invalid UTF-8")?,
    )?;
    println!("✓ Set secret '{}' with {} keys", name, password_store.get(name)?.len());
    Ok(())
}

pub fn handle_get(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let password_store = load_lockbox()?;
    let secret = password_store.get(name)?;

    println!("Entry: {}", name);

    // Display in order: username, password, then other keys
    if let Some(username) = secret.get("username") {
        println!("Username: {}", username);
    }
    if let Some(password) = secret.get("password") {
        println!("Password: {}", password);
    }

    // Display any other keys
    for (key, value) in &secret {
        if key != "username" && key != "password" {
            println!("{}: {}", key, value);
        }
    }

    Ok(())
}

pub fn handle_list() -> Result<(), Box<dyn std::error::Error>> {
    let password_store = load_lockbox()?;
    let entries = password_store.list();
    if entries.is_empty() {
        println!("No entries found in the password store.");
    } else {
        println!("Password Store Entries:");
        for entry in entries {
            println!("- {}", entry);
        }
    }
    Ok(())
}

pub fn handle_remove(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new()?;
    let mut password_store = load_lockbox()?;
    password_store.remove(name)?;
    password_store.save(
        &config
            .password_store_path
            .to_str()
            .ok_or("Path contains invalid UTF-8")?,
    )?;
    println!("✓ Removed entry '{}' from password store", name);
    Ok(())
}

pub fn handle_update(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new()?;
    let mut password_store = load_lockbox()?;
    if !password_store.entry_exists(name) {
        return Err(format!("Entry '{}' does not exist", name).into());
    }
    let mut stdout = stdout();
    print!("New Username (leave blank to keep unchanged): ");
    stdout.flush()?;
    let mut username_input = String::new();
    stdin().read_line(&mut username_input)?;
    let username = username_input.trim();

    print!("New Password (leave blank to keep unchanged): ");
    stdout.flush()?;
    let password = read_password()?;

    // Build update HashMap with only changed values
    let mut data = HashMap::new();
    if !username.is_empty() {
        data.insert("username".to_string(), username.to_string());
    }
    if !password.trim().is_empty() {
        data.insert("password".to_string(), password);
    }

    if data.is_empty() {
        return Err("No changes provided".into());
    }

    password_store.update(name, data)?;
    password_store.save(
        &config
            .password_store_path
            .to_str()
            .ok_or("Path contains invalid UTF-8")?,
    )?;
    println!("✓ Updated entry '{}' in password store", name);
    Ok(())
}

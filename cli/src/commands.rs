use dirs::home_dir;
use lockbox_crypto::{
    cipher::SymmetricKey,
    keys::{generate_keypair, save_signing_key},
};
use lockbox_store::passwords::PasswordStore;
use rpassword::read_password;
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

pub fn handle_add(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new()?;
    let mut password_store = load_lockbox()?;
    if password_store.entry_exists(name) {
        return Err(format!("Entry '{}' already exists", name).into());
    }
    let mut stdout = stdout();
    print!("Username: ");
    stdout.flush()?;
    let mut username = String::new();
    stdin().read_line(&mut username)?;
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err("Username cannot be empty".into());
    }
    print!("Password: ");
    stdout.flush()?;
    let password = read_password()?;
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }
    password_store.add(name, &username, &password)?;
    password_store.save(
        &config
            .password_store_path
            .to_str()
            .ok_or("Path contains invalid UTF-8")?,
    )?;
    println!("✓ Added entry '{}' to password store", name);
    Ok(())
}

pub fn handle_get(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let password_store = load_lockbox()?;
    if let Ok((username, password)) = password_store.get(name) {
        println!("Entry: {}", name);
        println!("Username: {}", username);
        println!("Password: {}", password);
    } else {
        return Err(format!("Entry '{}' not found", name).into());
    }
    Ok(())
}

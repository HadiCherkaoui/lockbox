use crate::helpers::{get, list, register_server, remove, set, update};
use dirs::home_dir;
use ed25519_dalek::SigningKey;
use lockbox_crypto::{
    cipher::{SymmetricKey, encrypt},
    keys::{generate_keypair, save_signing_key},
};
use lockbox_store::Secret;
use std::{
    collections::HashMap,
    fs::create_dir_all,
    io::{Write, stdin, stdout},
    path::{Path, PathBuf},
};

struct Config {
    lockbox_path: PathBuf,
    keypair_path: PathBuf,
    base_url_path: PathBuf,
}

impl Config {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let lockbox_path = home_dir()
            .ok_or("Could not find home directory")?
            .join(".lockbox");

        let keypair_path = lockbox_path.join("keypair.bin");
        let base_url_path = lockbox_path.join("serverbase.txt");

        Ok(Config {
            lockbox_path,
            keypair_path,
            base_url_path,
        })
    }
}

struct ClientConfig {
    base_url: String,
    keypair: SigningKey,
}

impl ClientConfig {
    fn load(config: &Config) -> Result<Self, Box<dyn std::error::Error>> {
        let base_url = std::fs::read_to_string(&config.base_url_path)?
            .trim()
            .to_string();
        let keypair = lockbox_crypto::keys::load_signing_key(
            config
                .keypair_path
                .to_str()
                .ok_or("Path contains invalid UTF-8")?,
        )?;
        Ok(ClientConfig { base_url, keypair })
    }
}

fn prompt(prompt_text: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt_text);
    stdout().flush()?;
    let mut input = String::new();
    stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn load_client_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let config = Config::new()?;
    ClientConfig::load(&config)
}

fn parse_key_value_pairs(
    pairs: Vec<String>,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
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

    Ok(data)
}

fn encrypt_data_to_secret(
    data: &HashMap<String, String>,
    keypair: &SigningKey,
) -> Result<Secret, Box<dyn std::error::Error>> {
    let symmetric_key = SymmetricKey::from_ed25519(keypair);
    let mut secret = Secret {
        data: HashMap::new(),
    };

    for (k, v) in data {
        secret
            .data
            .insert(k.clone(), encrypt(&symmetric_key, v.as_bytes())?);
    }

    Ok(secret)
}

pub async fn handle_init() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing a new lockbox...");
    let config = Config::new()?;
    let dir = Path::new(config.lockbox_path.as_path());
    if dir.try_exists()? {
        return Err(format!(
            "Lockbox already exists at {}. Remove it first if you want to reinitialize.",
            config.lockbox_path.display()
        )
        .into());
    }

    create_dir_all(&config.lockbox_path)?;
    println!(
        "✓ Created lockbox directory at {}",
        config.lockbox_path.display()
    );

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
    println!("Registering Server...");
    let base_url = prompt("Server Base URL: ")?;
    let api_key = prompt("API Key: ")?;
    let label = prompt("Label for this key (e.g., 'my-laptop'): ")?;
    write!(
        std::fs::File::create(&config.base_url_path)?,
        "{}",
        base_url.trim().trim_end_matches('/')
    )?;
    register_server(&keypair, &base_url, &api_key, &label).await?;
    Ok(())
}

pub async fn handle_set(
    namespace: String,
    name: String,
    pairs: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_config = load_client_config()?;

    let data = parse_key_value_pairs(pairs)?;

    // Encrypt the values client-side (E2EE!)
    let secret = encrypt_data_to_secret(&data, &client_config.keypair)?;

    set(
        namespace,
        name,
        secret,
        &client_config.base_url,
        &mut client_config.keypair,
    )
    .await?;
    Ok(())
}

pub async fn handle_get(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_config = load_client_config()?;
    let secret = get(name, &client_config.base_url, &mut client_config.keypair).await?;
    let symmetric_key = SymmetricKey::from_ed25519(&client_config.keypair);
    println!("Retrieved secret:");
    for (k, v) in &secret.data {
        let decrypted = String::from_utf8(lockbox_crypto::cipher::decrypt(&symmetric_key, v)?)?;
        println!("{}={}", k, decrypted);
    }
    Ok(())
}

pub async fn handle_list() -> Result<(), Box<dyn std::error::Error>> {
    let mut client_config = load_client_config()?;
    let secret_names = list(&client_config.base_url, &mut client_config.keypair).await?;
    println!("All Secrets:");
    for name in secret_names {
        println!("- {}", name);
    }
    Ok(())
}

pub async fn handle_remove(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_config = load_client_config()?;
    remove(name, &client_config.base_url, &mut client_config.keypair).await?;
    println!("✓ Secret '{}' removed successfully", name);
    Ok(())
}

pub async fn handle_update(
    name: &str,
    pairs: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client_config = load_client_config()?;

    let data = parse_key_value_pairs(pairs)?;

    // Encrypt the values client-side (E2EE!)
    let secret = encrypt_data_to_secret(&data, &client_config.keypair)?;

    update(
        name,
        secret,
        &client_config.base_url,
        &mut client_config.keypair,
    )
    .await?;
    println!("✓ Secret '{}' updated successfully", name);
    Ok(())
}

use clap::{Parser, Subcommand};
use dir::home_dir;
use lockbox_crypto::{
    cipher::SymmetricKey,
    keys::{generate_keypair, save_signing_key},
};
use lockbox_store::passwords::PasswordStore;
use std::{
    fs::create_dir_all,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize a new lockbox
    Init,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("Initializing a new lockbox...");
            let lockbox_path = lockbox_path()?;
            let dir = Path::new(lockbox_path.as_path());
            if dir.try_exists()? {
                return Err(format!("Lockbox already exists at {:?}", lockbox_path).into());
            }
            create_dir_all(dir)?;
            println!("✓ Created: {:?}", lockbox_path);
            let keypair = generate_keypair();
            println!("✓ Generated Ed25519 keypair");
            save_signing_key(
                &keypair,
                lockbox_path
                    .join("id_ed25519")
                    .to_str()
                    .ok_or("Path contains invalid UTF-8")?,
            )?;
            println!(
                "✓ Saved signing key to {:?}",
                lockbox_path.join("id_ed25519")
            );
            let symmetric_key = SymmetricKey::from_ed25519(&keypair);
            let pwd_store = PasswordStore::new(&symmetric_key);
            pwd_store.save(
                &lockbox_path
                    .join("passwords.json")
                    .to_str()
                    .ok_or("Path contains invalid UTF-8")?,
            )?;
            println!(
                "✓ Created empty password store at {:?}",
                lockbox_path.join("passwords.json")
            );
            println!("Lockbox initialization complete!");
        }
    }
    Ok(())
}

fn lockbox_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = home_dir().ok_or("home directory not found")?;
    let lockbox_path = home.join(".lockbox");
    Ok(lockbox_path)
}

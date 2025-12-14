use self::commands::*;
use clap::{Parser, Subcommand};
mod commands;

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
    /// Set a secret with multiple key-value pairs
    /// Example: lbx set prod/app-config API_KEY=xyz123 DB_HOST=localhost DB_PORT=5432
    Set {
        /// Secret name (e.g., "prod/database-config")
        name: String,
        /// Key-value pairs in format KEY=VALUE
        #[arg(required = true)]
        pairs: Vec<String>,
    },
    /// Get a secret entry
    Get { name: String },
    /// List all secret entries
    List,
    /// Remove a secret entry
    Remove { name: String },
    /// Update a secret entry
    Update { name: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            handle_init()?;
        }
        Commands::Set { name, pairs } => {
            handle_set(&name, pairs)?;
        }
        Commands::Get { name } => {
            handle_get(&name)?;
        }
        Commands::List => {
            handle_list()?;
        }
        Commands::Remove { name } => {
            handle_remove(&name)?;
        }
        Commands::Update { name } => {
            handle_update(&name)?;
        }
    }
    Ok(())
}

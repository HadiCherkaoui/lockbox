use self::commands::handle_init;
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
    /// Add a new password entry
    Add { name: String },
    /// Get a password entry
    Get { name: String },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            handle_init()?;
        }
        Commands::Add { name } => {
            commands::handle_add(&name)?;
        }
        Commands::Get { name } => {
            commands::handle_get(&name)?;
        }
    }
    Ok(())
}

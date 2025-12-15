use self::commands::*;
use clap::{Parser, Subcommand};
mod commands;
mod helpers;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init,
    Set {
        name: String,
        #[arg(required = true)]
        pairs: Vec<String>,
    },
    Get {
        name: String,
    },
    List,
    Remove {
        name: String,
    },
    Update {
        name: String,
        #[arg(required = true)]
        pairs: Vec<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            handle_init().await?;
        }
        Commands::Set { name, pairs } => {
            handle_set(name, pairs).await?;
        }
        Commands::Get { name } => {
            handle_get(&name).await?;
        }
        Commands::List => {
            handle_list().await?;
        }
        Commands::Remove { name } => {
            handle_remove(&name).await?;
        }
        Commands::Update { name, pairs } => {
            handle_update(&name, pairs).await?;
        }
    }
    Ok(())
}

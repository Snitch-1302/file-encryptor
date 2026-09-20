use clap::{Parser, Subcommand};
use std::path::PathBuf;
mod kdf;

#[derive(Parser)]
#[command(name = "file-encryptor")]
#[command(about = "A memory-safe file encryptor using Argon2id + AES-GCM-256")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Decrypt {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let salt = kdf::generate_salt();
let key1 = kdf::derive_key(b"test-password", &salt).unwrap();
let key2 = kdf::derive_key(b"test-password", &salt).unwrap();
let key3 = kdf::derive_key(b"different-password", &salt).unwrap();

println!("key1 == key2 (same password, same salt): {}", key1 == key2);
println!("key1 == key3 (diff password, same salt): {}", key1 == key3);
    match cli.command {
        Commands::Encrypt { input, output } => {
            println!("Encrypt mode: {:?} -> {:?}", input, output);
        }
        Commands::Decrypt { input, output } => {
            println!("Decrypt mode: {:?} -> {:?}", input, output);
        }
    }
}
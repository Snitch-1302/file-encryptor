use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::fs;
use std::fmt;

mod kdf;
mod cipher;
mod format;

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

/// Unified error type for the whole application. Every fallible operation
/// (file I/O, key derivation, encryption/decryption, file-format parsing)
/// converts into this one type so `main` can handle them uniformly with `?`.
#[derive(Debug)]
enum AppError {
    Io(std::io::Error),
    Kdf(argon2::Error),
    Cipher,       // deliberately no detail: wrong password vs. tampered file
                  // must look identical to the user (see Display impl below)
    Format(&'static str),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "file error: {e}"),
            AppError::Kdf(e) => write!(f, "key derivation error: {e}"),
            // Never distinguish "wrong password" from "corrupted/tampered file"
            // in the message shown to the user — that distinction is itself
            // information an attacker could use.
            AppError::Cipher => write!(f, "decryption failed: incorrect password or corrupted/tampered file"),
            AppError::Format(e) => write!(f, "invalid file format: {e}"),
        }
    }
}

impl std::error::Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<argon2::Error> for AppError {
    fn from(e: argon2::Error) -> Self {
        AppError::Kdf(e)
    }
}

impl From<aes_gcm::Error> for AppError {
    fn from(_e: aes_gcm::Error) -> Self {
        AppError::Cipher
    }
}

impl From<&'static str> for AppError {
    fn from(e: &'static str) -> Self {
        AppError::Format(e)
    }
}

fn encrypt_file(input: &PathBuf, output: &PathBuf) -> Result<(), AppError> {
    let password = rpassword::prompt_password("Enter password: ")?;
    let plaintext = fs::read(input)?;

    let salt = kdf::generate_salt();
    let key = kdf::derive_key(password.as_bytes(), &salt)?;

    let nonce = cipher::generate_nonce();
    let ciphertext = cipher::encrypt(&key, &nonce, &plaintext)?;

    let packed = format::pack(&salt, &nonce, &ciphertext);
    fs::write(output, packed)?;

    println!("Encrypted {:?} -> {:?}", input, output);
    Ok(())
}

fn decrypt_file(input: &PathBuf, output: &PathBuf) -> Result<(), AppError> {
    let password = rpassword::prompt_password("Enter password: ")?;
    let data = fs::read(input)?;

    let (salt, nonce, ciphertext) = format::unpack(&data)?;
    let key = kdf::derive_key(password.as_bytes(), &salt)?;

    let plaintext = cipher::decrypt(&key, &nonce, ciphertext)?;
    fs::write(output, plaintext)?;

    println!("Decrypted {:?} -> {:?}", input, output);
    Ok(())
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt { input, output } => encrypt_file(&input, &output),
        Commands::Decrypt { input, output } => decrypt_file(&input, &output),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
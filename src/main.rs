use clap::{Parser, Subcommand};
use std::path::PathBuf;
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

fn main() {
    let cli = Cli::parse();

    let salt = kdf::generate_salt();
    let key1 = kdf::derive_key(b"test-password", &salt).unwrap();
    let key2 = kdf::derive_key(b"test-password", &salt).unwrap();
    let key3 = kdf::derive_key(b"different-password", &salt).unwrap();

    println!("key1 == key2 (same password, same salt): {}", key1 == key2);
    println!("key1 == key3 (diff password, same salt): {}", key1 == key3);

    // --- Step 3: AES-GCM round-trip + tamper test ---
    let nonce = cipher::generate_nonce();
    let plaintext = b"attack at dawn";
    let ciphertext = cipher::encrypt(&key1, &nonce, plaintext).unwrap();
    println!("ciphertext len: {} (plaintext was {})", ciphertext.len(), plaintext.len());

    let decrypted = cipher::decrypt(&key1, &nonce, &ciphertext).unwrap();
    println!("round-trip matches: {}", decrypted == plaintext);

    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;
    match cipher::decrypt(&key1, &nonce, &tampered) {
        Ok(_) => println!("BUG: tampered ciphertext decrypted successfully!"),
        Err(_) => println!("correct: tampered ciphertext failed to decrypt"),
    }

    // --- Step 4: pack/unpack round-trip test ---
let packed = format::pack(&salt, &nonce, &ciphertext);
println!("packed file size: {} bytes", packed.len());

let (unpacked_salt, unpacked_nonce, unpacked_ciphertext) = format::unpack(&packed).unwrap();
println!("salt round-trips: {}", unpacked_salt == salt);
println!("nonce round-trips: {}", unpacked_nonce == nonce);
println!("ciphertext round-trips: {}", unpacked_ciphertext == ciphertext.as_slice());

    match cli.command {
        Commands::Encrypt { input, output } => {
            println!("Encrypt mode: {:?} -> {:?}", input, output);
        }
        Commands::Decrypt { input, output } => {
            println!("Decrypt mode: {:?} -> {:?}", input, output);
        }
    }
}
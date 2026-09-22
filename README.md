# file-encryptor

A memory-safe file encryptor written in Rust. Derives a 256-bit key from a
password using Argon2id, encrypts with AES-256-GCM, and stores everything
needed to decrypt (salt + nonce + ciphertext) in one self-contained file.

📝 This project has a two-part write-up:
1. [What Building a File Encryptor in Rust Taught Me About Authenticated Encryption](https://quietbytes.hashnode.dev/file-encryptor-rust-authenticated-encryption)
2. [Verifying Why `zeroize` Matters: Dead-Store Elimination and Memory Remanence in Rust](https://quietbytes.hashnode.dev/verifying-why-zeroize-matters-dead-store-elimination-and-memory-remanence-in-rust)

## Why this exists

Cryptographic code is exactly where memory bugs (buffer overflows,
use-after-free, leaked secrets from uninitialized memory) are most
dangerous. This project is a hands-on exploration of Rust's ownership
model applied to a real, working cryptographic tool — not a toy syntax
exercise.

## Tech stack

- **Rust** (2021 edition, requires 1.85+ toolchain — see below)
- [`argon2`](https://crates.io/crates/argon2) — Argon2id key derivation
- [`aes-gcm`](https://crates.io/crates/aes-gcm) — AES-256-GCM authenticated encryption
- [`rand`](https://crates.io/crates/rand) — CSPRNG for salt/nonce generation
- [`clap`](https://crates.io/crates/clap) — CLI argument parsing
- [`rpassword`](https://crates.io/crates/rpassword) — hidden password prompt (no shell-history/process-list leakage)
- [`zeroize`](https://crates.io/crates/zeroize) — guaranteed-not-optimized-away zeroing of passwords and keys in memory

## How it works

1. User provides a file path and a mode (encrypt/decrypt); the password is
   entered interactively and hidden — never passed as a CLI argument.
2. **Encrypt:** a random 16-byte salt and 12-byte nonce are generated.
   Argon2id derives a 256-bit key from the password + salt (memory=19 MiB,
   iterations=2, parallelism=1 — OWASP baseline). AES-256-GCM encrypts the
   file, producing ciphertext with a 16-byte authentication tag appended.
   `salt || nonce || ciphertext+tag` are concatenated into one output file.
3. **Decrypt:** the file is split back into salt, nonce, and ciphertext.
   The password (re-entered) plus the stored salt re-derive the same key.
   AES-256-GCM decrypts and verifies the auth tag. A wrong password or a
   tampered file fails cleanly with a readable error and a non-zero exit
   code — never a crash, and never silently corrupted output.
4. The password and derived key are wrapped in `Zeroizing<T>`, so their
   memory is explicitly overwritten with zeros the moment they go out of
   scope — rather than left intact in freed memory until reused.

## Development setup

Requires **Rust 1.85 or newer** (dependencies use edition 2024 manifests).
Check your version:

rustc --version


If you're below 1.85, update via `rustup`:

rustup update stable


Older toolchains fail with:

error: package requires the Cargo feature called edition2024,
but that feature is not stabilized in this version of Cargo


Updating rustup (not just re-running cargo) is the fix.

## Building

cargo build


## Testing

cargo test


11 unit tests cover key derivation determinism, encryption round-trips,
wrong-key rejection, tamper detection, and file-format parsing (including
truncated/malformed input).

## Usage

file-encryptor encrypt --input <path> --output <path>
file-encryptor decrypt --input <path> --output <path>


You'll be prompted for a password interactively (input is hidden).

**Example:**

$ file-encryptor encrypt --input secret.txt --output secret.enc
Enter password:
Encrypted "secret.txt" -> "secret.enc"

$ file-encryptor decrypt --input secret.enc --output secret_out.txt
Enter password:
Decrypted "secret.enc" -> "secret_out.txt"


A wrong password produces:

Error: decryption failed: incorrect password or corrupted/tampered file

with exit code 1 — no partial or corrupted output file is written.

## Output file format

[ salt (16 bytes) | nonce (12 bytes) | ciphertext + auth tag (rest) ]


Self-contained by design: the salt and nonce aren't secret (their value is
uniqueness, not secrecy), so storing them alongside the ciphertext costs
nothing in security while removing the risk of losing a separate
metadata file.

## Threat model & limitations

This is a learning project, not an audited production tool. It protects
file contents at rest against someone who obtains the `.enc` file without
the password. It does **not** protect against:
- A compromised machine (keyloggers, memory scrapers) while you type the password
- Weak/reused passwords — the tool cannot force good password hygiene
- Metadata leakage (filename, size, timestamps of the original file)

## Memory remanence verification study

The `memory-remanence-study/` folder contains a hands-on verification of
the `Zeroizing<T>` design choice above — compiling naive vs. volatile
zeroing loops in both C and Rust, inspecting the actual generated
assembly, and confirming which one survives compiler optimization.
Written up in Part 2 of the series:
[Verifying Why `zeroize` Matters: Dead-Store Elimination and Memory Remanence in Rust](https://quietbytes.hashnode.dev/verifying-why-zeroize-matters-dead-store-elimination-and-memory-remanence-in-rust).

## Project status

- [x] CLI argument parsing
- [x] Argon2id key derivation
- [x] AES-256-GCM encryption/decryption (round-trip + tamper tested)
- [x] Self-contained output file format (salt + nonce + ciphertext)
- [x] Secure interactive password prompt
- [x] Full file read/write wiring
- [x] Structured `Result`-based error handling — no panics on bad input
- [x] Unit test suite (11 tests across kdf, cipher, format modules)
- [x] Secrets (password, derived key) zeroized in memory on drop

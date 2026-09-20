# file-encryptor

A memory-safe file encryptor written in Rust. Derives a 256-bit key from a
password using Argon2id, encrypts with AES-256-GCM, and stores everything
needed to decrypt (salt + nonce + ciphertext) in one self-contained file.

🚧 Work in progress — core cryptography (key derivation, encryption,
file format) is implemented and tested; CLI wiring for full encrypt/decrypt
file I/O and error handling is in progress.

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

## How it works

1. User provides a password and a file path.
2. A random 16-byte salt is generated.
3. Argon2id derives a 256-bit key from the password + salt
   (memory=19 MiB, iterations=2, parallelism=1 — OWASP baseline).
4. A random 12-byte nonce is generated.
5. AES-256-GCM encrypts the file contents using the derived key and nonce,
   producing ciphertext with a 16-byte authentication tag appended.
6. `salt || nonce || ciphertext+tag` are concatenated into a single output
   file — no separate metadata file needed.

Decryption reverses this: read the file, split out salt/nonce/ciphertext,
re-derive the key from the (now-known) salt and the user's password, and
decrypt. AES-GCM's authentication tag ensures that a wrong password or a
tampered file fails decryption cleanly, rather than producing corrupted
plaintext silently.

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


## Usage

file-encryptor encrypt --input <path> --output <path>
file-encryptor decrypt --input <path> --output <path>


*(Full usage instructions will be finalized once file I/O and interactive
password prompting are complete.)*

## Project status

- [x] CLI argument parsing
- [x] Argon2id key derivation
- [x] AES-256-GCM encryption/decryption (round-trip + tamper tested)
- [x] Self-contained output file format (salt + nonce + ciphertext)
- [ ] Full file read/write wiring
- [ ] Proper `Result`-based error handling (no panics)
- [ ] Interactive password prompt (no password via CLI arg)

## License

*(add your chosen license here)*

# file-encryptor

A memory-safe file encryptor written in Rust. Derives a 256-bit key from a
password using Argon2id, encrypts with AES-256-GCM, and stores everything
needed to decrypt (salt + nonce + ciphertext) in one self-contained file.

🚧 Work in progress — building this step by step and writing up the design
decisions as I go.
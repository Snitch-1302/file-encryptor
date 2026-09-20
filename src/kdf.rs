use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use rand::rngs::OsRng;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Generates a fresh random salt using the OS CSPRNG.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives a 256-bit key from a password and salt using Argon2id.
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN], argon2::Error> {
    // memory_cost in KiB, time_cost (iterations), parallelism, output length
    let params = Params::new(19456, 2, 1, Some(KEY_LEN))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password, salt, &mut key)?;
    Ok(key)
}
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_password_and_salt_produce_same_key() {
        let salt = generate_salt();
        let key1 = derive_key(b"correct horse battery staple", &salt).expect("derivation should succeed");
        let key2 = derive_key(b"correct horse battery staple", &salt).expect("derivation should succeed");

        assert_eq!(key1, key2);
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let salt = generate_salt();
        let key1 = derive_key(b"password one", &salt).expect("derivation should succeed");
        let key2 = derive_key(b"password two", &salt).expect("derivation should succeed");

        assert_ne!(key1, key2);
    }

    #[test]
    fn same_password_different_salts_produce_different_keys() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        let key1 = derive_key(b"same password", &salt1).expect("derivation should succeed");
        let key2 = derive_key(b"same password", &salt2).expect("derivation should succeed");

        assert_ne!(key1, key2);
    }

    #[test]
    fn two_salts_are_different() {
        let s1 = generate_salt();
        let s2 = generate_salt();
        assert_ne!(s1, s2);
    }
}

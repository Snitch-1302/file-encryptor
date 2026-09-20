use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng as AeadOsRng};
use aes_gcm::aead::rand_core::RngCore;

pub const NONCE_LEN: usize = 12;

/// Generates a random 96-bit nonce.
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    AeadOsRng.fill_bytes(&mut nonce_bytes);
    nonce_bytes
}

/// Encrypts plaintext with AES-256-GCM. Returns ciphertext (with appended auth tag).
pub fn encrypt(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, plaintext)
}

/// Decrypts ciphertext with AES-256-GCM. Fails if tampered or wrong key.
pub fn decrypt(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_succeeds_with_correct_key_and_nonce() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"attack at dawn";

        let ciphertext = encrypt(&key, &nonce, plaintext).expect("encryption should succeed");
        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decryption_fails_with_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"attack at dawn";

        let ciphertext = encrypt(&key, &nonce, plaintext).expect("encryption should succeed");
        let result = decrypt(&wrong_key, &nonce, &ciphertext);

        assert!(result.is_err(), "decryption should fail with the wrong key");
    }

    #[test]
    fn decryption_fails_on_tampered_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = generate_nonce();
        let plaintext = b"attack at dawn";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).expect("encryption should succeed");
        ciphertext[0] ^= 0xFF; // flip one bit

        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err(), "tampered ciphertext should fail to decrypt");
    }

    #[test]
    fn two_nonces_are_different() {
        // Not a proof of randomness, but catches an obviously broken
        // (e.g. all-zero or hardcoded) nonce generator.
        let n1 = generate_nonce();
        let n2 = generate_nonce();
        assert_ne!(n1, n2);
    }
}
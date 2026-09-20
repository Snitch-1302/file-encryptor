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
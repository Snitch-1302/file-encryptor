use crate::kdf::SALT_LEN;
use crate::cipher::NONCE_LEN;

/// Combines salt, nonce, and ciphertext into one self-contained byte layout:
/// [ salt (16 bytes) | nonce (12 bytes) | ciphertext+tag (rest) ]
pub fn pack(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(ciphertext);
    out
}

/// Splits a packed file back into (salt, nonce, ciphertext).
/// Returns an error if the data is too short to even contain a valid header.
pub fn unpack(data: &[u8]) -> Result<([u8; SALT_LEN], [u8; NONCE_LEN], &[u8]), &'static str> {
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err("file too short to contain a valid header (truncated or not a file-encryptor output)");
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[0..SALT_LEN]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[SALT_LEN..SALT_LEN + NONCE_LEN]);

    let ciphertext = &data[SALT_LEN + NONCE_LEN..];

    Ok((salt, nonce, ciphertext))
}
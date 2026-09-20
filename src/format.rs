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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_then_unpack_round_trips_exactly() {
        let salt = [1u8; SALT_LEN];
        let nonce = [2u8; NONCE_LEN];
        let ciphertext = vec![3u8; 30]; // arbitrary sample ciphertext+tag

        let packed = pack(&salt, &nonce, &ciphertext);
        let (unpacked_salt, unpacked_nonce, unpacked_ciphertext) =
            unpack(&packed).expect("unpack should succeed on well-formed data");

        assert_eq!(unpacked_salt, salt);
        assert_eq!(unpacked_nonce, nonce);
        assert_eq!(unpacked_ciphertext, ciphertext.as_slice());
    }

    #[test]
    fn unpack_rejects_truncated_data() {
        let too_short = vec![0u8; SALT_LEN + NONCE_LEN - 1]; // one byte short of a valid header
        let result = unpack(&too_short);

        assert!(result.is_err(), "unpack should reject data shorter than salt+nonce");
    }

    #[test]
    fn unpack_accepts_minimal_valid_header_with_empty_ciphertext() {
        // Edge case: exactly salt+nonce length, zero-length ciphertext.
        // Not realistic (GCM always appends a 16-byte tag), but confirms
        // the boundary condition in unpack's length check is correct.
        let minimal = vec![0u8; SALT_LEN + NONCE_LEN];
        let result = unpack(&minimal);

        assert!(result.is_ok());
        let (_, _, ciphertext) = result.unwrap();
        assert_eq!(ciphertext.len(), 0);
    }
}

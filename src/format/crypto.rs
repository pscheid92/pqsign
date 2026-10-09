use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroizing;

use crate::errors::Error;

const ENCRYPTION_KEY_LEN: usize = 32;

pub(super) fn encrypt(plaintext: &[u8], password: &[u8], mem_limit: u64, ops_limit: u64, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
    let key = derive_key(mem_limit, ops_limit, password, salt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|e| Error::Crypto(format!("xchacha20: {e}")))?;

    cipher
        .encrypt(&parse_nonce(nonce)?, plaintext)
        .map_err(|e| Error::Crypto(format!("encrypt: {e}")))
}

pub(super) fn decrypt(ciphertext: &[u8], password: &[u8], mem_limit: u64, ops_limit: u64, salt: &[u8], nonce: &[u8]) -> Result<Vec<u8>, Error> {
    let key = derive_key(mem_limit, ops_limit, password, salt)?;

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|e| Error::Crypto(format!("xchacha20: {e}")))?;

    cipher.decrypt(&parse_nonce(nonce)?, ciphertext).map_err(|_| Error::WrongPassword)
}

fn parse_nonce(nonce: &[u8]) -> Result<XNonce, Error> {
    XNonce::try_from(nonce).map_err(|e| Error::Crypto(format!("nonce: {e}")))
}

fn derive_key(mem_limit: u64, ops_limit: u64, password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; ENCRYPTION_KEY_LEN]>, Error> {
    let m_cost = (mem_limit / 1024) as u32;
    let t_cost = ops_limit as u32;

    let params = Params::new(m_cost, t_cost, 1, Some(ENCRYPTION_KEY_LEN)).map_err(|e| Error::Crypto(format!("argon2 params: {e}")))?;
    let mut memory = argon2_memory(params.block_count())?;

    let mut key = Zeroizing::new([0u8; ENCRYPTION_KEY_LEN]);

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(password, salt, key.as_mut(), memory.as_mut_slice())
        .map_err(|e| Error::Crypto(format!("argon2 kdf: {e}")))?;

    Ok(key)
}

/// Argon2 frees the memory it allocates itself without wiping it. Supplying it here wipes the
/// password-derived blocks when the buffer drops, which costs about 2% of a key derivation.
fn argon2_memory(block_count: usize) -> Result<Zeroizing<Vec<Block>>, Error> {
    let mut memory = Vec::new();
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| Error::Crypto(format!("argon2 kdf: cannot allocate {block_count} KiB")))?;
    memory.resize(block_count, Block::default());
    Ok(Zeroizing::new(memory))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Existing key files must keep decrypting: supplying Argon2's memory ourselves must not change the derived key.
    #[test]
    fn test_derive_key_matches_argon2_allocating_its_own_memory() {
        let (mem_limit, ops_limit) = (64 * 1024, 2);
        let (password, salt) = (b"password".as_slice(), b"0123456789abcdef".as_slice());

        let params = Params::new((mem_limit / 1024) as u32, ops_limit as u32, 1, Some(ENCRYPTION_KEY_LEN)).unwrap();
        let mut expected = [0u8; ENCRYPTION_KEY_LEN];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password, salt, &mut expected)
            .unwrap();

        let key = derive_key(mem_limit, ops_limit, password, salt).unwrap();
        assert_eq!(*key, expected);
    }

    /// Fails to compile if the `zeroize` features of chacha20poly1305 or argon2 are switched off.
    #[test]
    fn test_kdf_and_cipher_state_is_wiped() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        fn wipeable<T: zeroize::Zeroize>() {}
        wiped_on_drop::<XChaCha20Poly1305>();
        wipeable::<Block>();
    }

    #[test]
    fn test_argon2_memory_has_exact_size() {
        let memory = argon2_memory(16).unwrap();
        assert_eq!(memory.len(), 16);
        assert_eq!(memory.capacity(), 16);
    }
}

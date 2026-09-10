use argon2::{Algorithm, Argon2, Params, Version};
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

    let mut key = Zeroizing::new([0u8; ENCRYPTION_KEY_LEN]);

    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|e| Error::Crypto(format!("argon2 kdf: {e}")))?;

    Ok(key)
}

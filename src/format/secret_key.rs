use std::fs;
use std::io::Cursor;
use std::path::Path;

use fips204::traits::SerDes;
use rand::Rng;
use zeroize::Zeroizing;

use super::{FileHeader, FileType, crypto, kdf};
use crate::domain::*;
use crate::errors::{Error, IoContext};
use crate::format::kdf::Kdf;

const ARGON2_SALT_LEN: usize = 16;
const XCHACHA20_NONCE_LEN: usize = 24;
const PAYLOAD_LEN: usize = Ed25519SecretKey::LEN + MlDsa65SecretKey::LEN + KeyId::LEN;

// -- Public API --

pub fn write(
    path: &Path,
    secret_key: &SecretKey,
    password: Zeroizing<String>,
) -> Result<(), Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).io_context(path)?;
    }

    let buf = encode(secret_key, &password)?;
    write_secret_file(path, &buf)
}

pub fn read(path: &Path, password: Zeroizing<String>) -> Result<SecretKey, Error> {
    read_with(path, |_| Ok(password))
}

pub fn read_with(
    path: &Path,
    password_fn: impl FnOnce(&Kdf) -> Result<Zeroizing<String>, Error>,
) -> Result<SecretKey, Error> {
    let data = fs::read(path).io_context(path)?;
    let mut r = Cursor::new(data.as_slice());
    let header = read_and_validate_header(&mut r)?;

    let kdf = kdf::read_from(&mut r)?;
    let password = password_fn(&kdf)?;

    let salt: [u8; ARGON2_SALT_LEN] = super::read_exact_array(&mut r)?;
    let nonce: [u8; XCHACHA20_NONCE_LEN] = super::read_exact_array(&mut r)?;
    let remaining = &data[r.position() as usize..];

    let plaintext = Zeroizing::new(crypto::decrypt(
        remaining,
        password.as_bytes(),
        kdf.mem_limit(),
        kdf.ops_limit(),
        &salt,
        &nonce,
    )?);
    let (ed25519, mldsa65, payload_key_id) = deserialize_payload(&plaintext)?;

    if payload_key_id != header.key_id {
        return Err(Error::Crypto(
            "decrypted key ID doesn't match header — file may be corrupt".into(),
        ));
    }

    SecretKey::from_parts(header.key_id, ed25519, mldsa65)
}

// -- Shared helpers --

fn read_and_validate_header(r: &mut impl std::io::Read) -> Result<FileHeader, Error> {
    let header = FileHeader::read(r)?;
    if header.file_type != FileType::SecretKey {
        return Err(Error::InvalidFormat("expected secret key file".into()));
    }
    Ok(header)
}

// -- Write helpers --

fn encode(secret_key: &SecretKey, password: &Zeroizing<String>) -> Result<Vec<u8>, Error> {
    let payload = serialize_payload(secret_key)?;
    let (kdf, salt, nonce, encrypted) = encrypt_payload(&payload, password)?;

    let mut buf = Vec::new();
    FileHeader::new(FileType::SecretKey, secret_key.key_id).write_to(&mut buf)?;
    kdf::write_to(&kdf, &mut buf)?;
    super::write_all(&mut buf, &salt)?;
    super::write_all(&mut buf, &nonce)?;
    super::write_all(&mut buf, &encrypted)?;

    Ok(buf)
}

fn serialize_payload(secret_key: &SecretKey) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut buf = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
    Ed25519SecretKey::from_bytes(secret_key.ed25519.to_bytes()).write_to(&mut *buf)?;
    MlDsa65SecretKey::from_bytes(secret_key.mldsa65.clone().into_bytes()).write_to(&mut *buf)?;
    secret_key.key_id.write_to(&mut *buf)?;
    Ok(buf)
}

type EncryptedPayload = (
    Kdf,
    [u8; ARGON2_SALT_LEN],
    [u8; XCHACHA20_NONCE_LEN],
    Vec<u8>,
);

fn encrypt_payload(
    payload: &[u8],
    password: &Zeroizing<String>,
) -> Result<EncryptedPayload, Error> {
    let mut rng = rand::rng();

    let mut salt = [0u8; ARGON2_SALT_LEN];
    rng.fill_bytes(&mut salt);

    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let k = Kdf::argon2id();
    let ct = crypto::encrypt(
        payload,
        password.as_bytes(),
        k.mem_limit(),
        k.ops_limit(),
        &salt,
        &nonce,
    )?;

    Ok((k, salt, nonce, ct))
}

fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), Error> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .io_context(path)?;
        file.write_all(data).io_context(path)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data).io_context(path)?;
    }
    Ok(())
}

// -- Read helpers --

fn deserialize_payload(data: &[u8]) -> Result<(Ed25519SecretKey, MlDsa65SecretKey, KeyId), Error> {
    let mut r = Cursor::new(data);
    let ed25519 = Ed25519SecretKey::read_from(&mut r)?;
    let mldsa65 = MlDsa65SecretKey::read_from(&mut r)?;
    let key_id = KeyId::read_from(&mut r)?;
    Ok((ed25519, mldsa65, key_id))
}

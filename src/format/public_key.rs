use std::io::Cursor;
use std::path::Path;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use fips204::traits::SerDes;

use super::file::{self, Access};
use super::{FileHeader, FileType};
use crate::domain::*;
use crate::errors::Error;

/// The text form names the public key format version, which must match the version byte in the binary header.
/// The header is authoritative; the prefix only lets a reader reject a newer format before decoding it.
const TEXT_VERSION: u8 = 1;
const TEXT_PREFIX: &str = "pqsign:v1:";

pub(super) fn encode(public_key: &PublicKey) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    FileHeader::new(FileType::PublicKey, public_key.key_id).write_to(&mut buf)?;
    Ed25519PublicKey::from_bytes(public_key.ed25519.to_bytes()).write_to(&mut buf)?;
    MlDsa65PublicKey::from_bytes(public_key.mldsa65.clone().into_bytes()).write_to(&mut buf)?;
    Ok(buf)
}

pub(super) fn decode(data: &[u8]) -> Result<PublicKey, Error> {
    let mut r = Cursor::new(data);

    let header = FileHeader::read(&mut r)?;
    if header.file_type != FileType::PublicKey {
        return Err(Error::InvalidFormat(format!("expected public key file, got: {:?}", header.file_type)));
    }

    let ed25519_pk = Ed25519PublicKey::read_from(&mut r)?;
    let mldsa65_pk = MlDsa65PublicKey::read_from(&mut r)?;

    PublicKey::from_parts(header.key_id, ed25519_pk, mldsa65_pk)
}

/// The single-line text form of a public key, as written to `.pub` files, including the trailing newline.
pub fn encode_text(public_key: &PublicKey) -> Result<String, Error> {
    let blob = encode(public_key)?;
    Ok(format!("{TEXT_PREFIX}{}\n", STANDARD.encode(&blob)))
}

/// Writes a public key atomically. An existing file is replaced.
pub fn write(path: &Path, public_key: &PublicKey) -> Result<(), Error> {
    let text = encode_text(public_key)?;
    file::write(path, text.as_bytes(), Access::Public)
}

pub fn read(path: &Path) -> Result<PublicKey, Error> {
    let data = file::read(path)?;
    let content = String::from_utf8(data).map_err(|_| Error::InvalidFormat("not a pqsign public key (not text)".into()))?;
    read_from_string(&content)
}

pub fn read_from_string(content: &str) -> Result<PublicKey, Error> {
    let line = content.trim_end();
    let encoded = strip_prefix(line)?;
    let blob = STANDARD.decode(encoded)?;
    check_text_version(&blob)?;
    decode(&blob)
}

fn check_text_version(blob: &[u8]) -> Result<(), Error> {
    let header = FileHeader::read(&mut Cursor::new(blob))?;
    if header.version != TEXT_VERSION {
        let msg = format!(
            "public key text says format v{TEXT_VERSION}, but its content is format v{}",
            header.version
        );
        let err = Error::InvalidFormat(msg);
        return Err(err);
    }
    Ok(())
}

fn strip_prefix(line: &str) -> Result<&str, Error> {
    if let Some(rest) = line.strip_prefix(TEXT_PREFIX) {
        return Ok(rest);
    }

    if line.starts_with("pqsign:v") {
        return Err(Error::InvalidFormat("public key requires a newer version of pqsign".into()));
    }

    Err(Error::InvalidFormat("not a pqsign public key (missing prefix)".into()))
}

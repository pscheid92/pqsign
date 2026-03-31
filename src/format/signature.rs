use std::fs;
use std::io::Cursor;
use std::path::Path;

use super::{FileHeader, FileType};
use crate::domain::*;
use crate::errors::{Error, IoContext};

const MAX_COMMENT_LEN: u32 = 1024;

// -- Public API --

pub fn write(path: &Path, sig: &Signature) -> Result<(), Error> {
    let buf = encode(sig)?;
    fs::write(path, &buf).io_context(path)
}

pub fn read(path: &Path) -> Result<Signature, Error> {
    let data = fs::read(path).io_context(path)?;
    decode(&data)
}

// -- Helpers --

fn encode(sig: &Signature) -> Result<Vec<u8>, Error> {
    let comment_bytes = sig.trusted_comment.as_bytes();
    validate_comment_len(comment_bytes.len())?;

    let mut buf = Vec::new();
    FileHeader::new(FileType::Signature, sig.key_id).write_to(&mut buf)?;
    sig.ed25519.write_to(&mut buf)?;
    sig.mldsa65.write_to(&mut buf)?;
    super::write_u32_le(&mut buf, comment_bytes.len() as u32)?;
    super::write_all(&mut buf, comment_bytes)?;

    Ok(buf)
}

fn decode(data: &[u8]) -> Result<Signature, Error> {
    let mut r = Cursor::new(data);

    let header = FileHeader::read(&mut r)?;
    if header.file_type != FileType::Signature {
        return Err(Error::InvalidFormat("expected signature file".into()));
    }

    let ed25519 = Ed25519Signature::read_from(&mut r)?;
    let mldsa65 = MlDsa65Signature::read_from(&mut r)?;

    let comment_len = super::read_u32_le(&mut r)?;
    validate_comment_len(comment_len as usize)?;

    let comment_bytes = super::read_vec(&mut r, comment_len as usize)?;
    let trusted_comment = String::from_utf8(comment_bytes).map_err(|_| Error::InvalidFormat("trusted comment is not valid UTF-8".into()))?;

    Ok(Signature {
        key_id: header.key_id,
        ed25519,
        mldsa65,
        trusted_comment,
    })
}

fn validate_comment_len(len: usize) -> Result<(), Error> {
    if len > MAX_COMMENT_LEN as usize {
        return Err(Error::InvalidFormat(format!(
            "trusted comment too long: {len} bytes (max {MAX_COMMENT_LEN})"
        )));
    }
    Ok(())
}

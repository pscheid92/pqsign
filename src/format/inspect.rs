use std::fmt;
use std::io::Cursor;
use std::path::Path;

use super::{FileHeader, FileType, file, kdf};
use crate::domain::{Fingerprint, KeyId, PublicKey};
use crate::errors::Error;
use crate::format::kdf::Kdf;

// -- Public API --

pub enum FileInfo {
    PublicKey { key_id: KeyId, fingerprint: Fingerprint },
    SecretKey { key_id: KeyId, kdf: Kdf },
    Signature { key_id: KeyId, trusted_comment: String },
}

/// Reads the file once, bounded to the size of a pqsign file, and decodes it from memory.
pub fn inspect_file(path: &Path) -> Result<FileInfo, Error> {
    let data = file::read(path)?;
    match std::str::from_utf8(&data) {
        Ok(text) if text.starts_with("pqsign:") => {
            let pk = super::public_key::read_from_string(text)?;
            Ok(public_key_info(&pk))
        }
        _ => inspect_binary(&data),
    }
}

// -- Display --

impl fmt::Display for FileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileInfo::PublicKey { key_id, fingerprint } => {
                writeln!(f, "Type:        Public key")?;
                writeln!(f, "Key ID:      {key_id}")?;
                writeln!(f, "Fingerprint: {fingerprint}")?;
                write!(f, "Algorithms:  Ed25519 + ML-DSA-65")
            }
            // The public key material is inside the encrypted payload, so the fingerprint needs the .pub file.
            FileInfo::SecretKey { key_id, kdf } => {
                writeln!(f, "Type:        Secret key (encrypted)")?;
                writeln!(f, "Key ID:      {key_id}")?;
                writeln!(f, "Fingerprint: not stored in plain text; inspect the .pub file")?;
                writeln!(f, "Algorithms:  Ed25519 + ML-DSA-65")?;
                match kdf {
                    Kdf::Argon2id { mem_limit, ops_limit } => {
                        writeln!(f, "KDF:         Argon2id")?;
                        writeln!(f, "Memory:      {} MiB", mem_limit / (1024 * 1024))?;
                        write!(f, "Ops:         {ops_limit}")
                    }
                }
            }
            // inspect never checks the signature, so the comment is shown as unverified.
            FileInfo::Signature { key_id, trusted_comment } => {
                writeln!(f, "Type:                 Signature")?;
                writeln!(f, "Key ID:               {key_id}")?;
                writeln!(f, "Algorithms:           Ed25519 + ML-DSA-65")?;
                write!(f, "Comment (unverified): {trusted_comment}")
            }
        }
    }
}

// -- Helpers --

fn public_key_info(pk: &PublicKey) -> FileInfo {
    FileInfo::PublicKey {
        key_id: pk.key_id(),
        fingerprint: pk.fingerprint(),
    }
}

fn inspect_binary(data: &[u8]) -> Result<FileInfo, Error> {
    let mut r = Cursor::new(data);
    let header = FileHeader::read(&mut r)?;

    let result = match header.file_type {
        FileType::PublicKey => public_key_info(&super::public_key::decode(data)?),
        FileType::SecretKey => {
            let kdf = kdf::read_from(&mut r)?;
            FileInfo::SecretKey { key_id: header.key_id, kdf }
        }
        FileType::Signature => {
            let sig = super::signature::decode(data)?;
            FileInfo::Signature {
                key_id: sig.key_id,
                trusted_comment: sig.trusted_comment,
            }
        }
    };

    Ok(result)
}

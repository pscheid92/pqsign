use std::fmt;
use std::fs;
use std::io::Cursor;
use std::path::Path;

use super::{FileHeader, FileType, kdf};
use crate::domain::KeyId;
use crate::errors::{Error, IoContext};
use crate::format::kdf::Kdf;

// -- Public API --

pub enum FileInfo {
    PublicKey { key_id: KeyId },
    SecretKey { key_id: KeyId, kdf: Kdf },
    Signature { key_id: KeyId, trusted_comment: String },
}

pub fn inspect_file(path: &Path) -> Result<FileInfo, Error> {
    if let Some(content) = read_text_if_public_key(path) {
        let pk = super::public_key::read_from_string(&content)?;
        return Ok(FileInfo::PublicKey { key_id: pk.key_id });
    }
    inspect_binary(path)
}

// -- Display --

impl fmt::Display for FileInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileInfo::PublicKey { key_id } => {
                writeln!(f, "Type:       Public key")?;
                writeln!(f, "Key ID:     {key_id}")?;
                write!(f, "Algorithms: Ed25519 + ML-DSA-65")
            }
            FileInfo::SecretKey { key_id, kdf } => {
                writeln!(f, "Type:       Secret key (encrypted)")?;
                writeln!(f, "Key ID:     {key_id}")?;
                writeln!(f, "Algorithms: Ed25519 + ML-DSA-65")?;
                match kdf {
                    Kdf::Argon2id { mem_limit, ops_limit } => {
                        writeln!(f, "KDF:        Argon2id")?;
                        writeln!(f, "Memory:     {} MiB", mem_limit / (1024 * 1024))?;
                        write!(f, "Ops:        {ops_limit}")
                    }
                }
            }
            FileInfo::Signature { key_id, trusted_comment } => {
                writeln!(f, "Type:            Signature")?;
                writeln!(f, "Key ID:          {key_id}")?;
                writeln!(f, "Algorithms:      Ed25519 + ML-DSA-65")?;
                write!(f, "Trusted comment: {trusted_comment}")
            }
        }
    }
}

// -- Helpers --

fn read_text_if_public_key(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().filter(|content| content.trim_end().starts_with("pqsign:"))
}

fn inspect_binary(path: &Path) -> Result<FileInfo, Error> {
    let data = fs::read(path).io_context(path)?;
    let mut r = Cursor::new(data.as_slice());
    let header = FileHeader::read(&mut r)?;

    let result = match header.file_type {
        FileType::PublicKey => FileInfo::PublicKey { key_id: header.key_id },
        FileType::SecretKey => {
            let kdf = kdf::read_from(&mut r)?;
            FileInfo::SecretKey { key_id: header.key_id, kdf }
        }
        FileType::Signature => {
            let sig = super::signature::read(path)?;
            FileInfo::Signature {
                key_id: sig.key_id,
                trusted_comment: sig.trusted_comment,
            }
        }
    };

    Ok(result)
}

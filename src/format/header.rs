use crate::domain::KeyId;
use crate::errors::Error;

const MAGIC: &[u8; 4] = b"PQSN";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    PublicKey,
    SecretKey,
    Signature,
}

impl FileType {
    /// The newest format version of each file type. Each type's version changes on its own, and only when that
    /// type's bytes change: public keys are still v1, signatures moved to v2 in pqsign 0.2, and secret keys moved
    /// to v2, which stores seeds, in pqsign 0.4.
    pub fn latest_version(self) -> u8 {
        match self {
            FileType::PublicKey => 1,
            FileType::SecretKey => 2,
            FileType::Signature => 2,
        }
    }

    fn name(self) -> &'static str {
        match self {
            FileType::PublicKey => "public key",
            FileType::SecretKey => "secret key",
            FileType::Signature => "signature",
        }
    }

    fn to_byte(self) -> u8 {
        match self {
            FileType::PublicKey => 0x01,
            FileType::SecretKey => 0x02,
            FileType::Signature => 0x03,
        }
    }

    fn from_byte(b: u8) -> Result<Self, Error> {
        match b {
            0x01 => Ok(FileType::PublicKey),
            0x02 => Ok(FileType::SecretKey),
            0x03 => Ok(FileType::Signature),
            _ => Err(Error::InvalidFormat(format!("unknown file type: 0x{b:02x}"))),
        }
    }
}

#[derive(Debug)]
pub struct FileHeader {
    pub version: u8,
    pub file_type: FileType,
    pub key_id: KeyId,
}

impl FileHeader {
    /// The serialized length: magic, version, file type and key ID.
    pub(crate) const LEN: usize = MAGIC.len() + 1 + 1 + KeyId::LEN;

    /// A header for the newest format version of `file_type`.
    pub fn new(file_type: FileType, key_id: KeyId) -> Self {
        FileHeader {
            version: file_type.latest_version(),
            file_type,
            key_id,
        }
    }

    /// Reads a header and requires it to be of `expected` type.
    pub(super) fn read_expecting(r: &mut impl std::io::Read, expected: FileType) -> Result<Self, Error> {
        let header = Self::read(r)?;
        if header.file_type != expected {
            let msg = format!("expected a {} file, got a {} file", expected.name(), header.file_type.name());
            let err = Error::InvalidFormat(msg);
            return Err(err);
        }
        Ok(header)
    }

    pub fn read(r: &mut impl std::io::Read) -> Result<Self, Error> {
        let magic: [u8; 4] = super::read_exact_array(r)?;
        if &magic != MAGIC {
            return Err(Error::InvalidFormat("not a pqsign file".to_string()));
        }

        let version = super::read_u8(r)?;
        let file_type = FileType::from_byte(super::read_u8(r)?)?;
        check_version(version, file_type)?;
        let key_id = KeyId::read_from(r)?;

        Ok(FileHeader { version, file_type, key_id })
    }

    pub fn write_to(&self, buf: &mut Vec<u8>) {
        super::write_all(buf, MAGIC);
        super::write_u8(buf, self.version);
        super::write_u8(buf, self.file_type.to_byte());
        self.key_id.write_to(buf);
    }
}

/// Versions start at 1. A newer version than this build knows gets a message that says so, rather than a parse error.
fn check_version(version: u8, file_type: FileType) -> Result<(), Error> {
    let latest = file_type.latest_version();
    if version == 0 {
        let err = Error::InvalidFormat("invalid format version 0".into());
        return Err(err);
    }
    if version > latest {
        let name = file_type.name();
        let msg = format!("this {name} file is format v{version}, which needs a newer pqsign (this build reads up to v{latest})");
        let err = Error::InvalidFormat(msg);
        return Err(err);
    }
    Ok(())
}

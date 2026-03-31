use crate::domain::KeyId;
use crate::errors::Error;

const MAGIC: &[u8; 4] = b"PQSN";
const FORMAT_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    PublicKey,
    SecretKey,
    Signature,
}

impl FileType {
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
            _ => Err(Error::InvalidFormat(format!(
                "unknown file type: 0x{b:02x}"
            ))),
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
    pub fn new(file_type: FileType, key_id: KeyId) -> Self {
        FileHeader {
            version: FORMAT_VERSION,
            file_type,
            key_id,
        }
    }

    pub fn read(r: &mut impl std::io::Read) -> Result<Self, Error> {
        let magic: [u8; 4] = super::read_exact_array(r)?;
        if &magic != MAGIC {
            return Err(Error::InvalidFormat("not a pqsign file".to_string()));
        }

        let version = super::read_u8(r)?;
        if version > FORMAT_VERSION {
            return Err(Error::InvalidFormat(format!(
                "file requires pqsign format v{version}, this build supports v{FORMAT_VERSION}"
            )));
        }

        let file_type = FileType::from_byte(super::read_u8(r)?)?;
        let key_id = KeyId::read_from(r)?;

        Ok(FileHeader {
            version,
            file_type,
            key_id,
        })
    }

    pub fn write_to(&self, w: &mut impl std::io::Write) -> Result<(), Error> {
        super::write_all(w, MAGIC)?;
        super::write_u8(w, self.version)?;
        super::write_u8(w, self.file_type.to_byte())?;
        self.key_id.write_to(w)?;
        Ok(())
    }
}

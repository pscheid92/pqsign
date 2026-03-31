use crate::errors::Error;

const KDF_ARGON2ID_BYTE: u8 = 0x02;
const DEFAULT_MEM_LIMIT: u64 = 256 * 1024 * 1024;
const DEFAULT_OPS_LIMIT: u64 = 3;

#[derive(Debug)]
pub enum Kdf {
    Argon2id { mem_limit: u64, ops_limit: u64 },
}

impl Kdf {
    pub fn argon2id() -> Self {
        Kdf::Argon2id {
            mem_limit: DEFAULT_MEM_LIMIT,
            ops_limit: DEFAULT_OPS_LIMIT,
        }
    }

    pub fn mem_limit(&self) -> u64 {
        match self {
            Kdf::Argon2id { mem_limit, .. } => *mem_limit,
        }
    }

    pub fn ops_limit(&self) -> u64 {
        match self {
            Kdf::Argon2id { ops_limit, .. } => *ops_limit,
        }
    }
}

pub(super) fn read_from(r: &mut impl std::io::Read) -> Result<Kdf, Error> {
    let kdf_byte = super::read_u8(r)?;
    let mem_limit = super::read_u64_le(r)?;
    let ops_limit = super::read_u64_le(r)?;

    match kdf_byte {
        KDF_ARGON2ID_BYTE => Ok(Kdf::Argon2id {
            mem_limit,
            ops_limit,
        }),
        other => Err(Error::InvalidFormat(format!(
            "unknown KDF algorithm: 0x{other:02x}"
        ))),
    }
}

pub(super) fn write_to(kdf: &Kdf, w: &mut impl std::io::Write) -> Result<(), Error> {
    let Kdf::Argon2id {
        mem_limit,
        ops_limit,
    } = kdf;

    super::write_u8(w, KDF_ARGON2ID_BYTE)?;
    super::write_u64_le(w, *mem_limit)?;
    super::write_u64_le(w, *ops_limit)?;

    Ok(())
}

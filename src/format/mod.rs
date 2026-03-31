mod crypto;
mod header;
mod inspect;
mod kdf;
mod public_key;
mod secret_key;
mod signature;

pub use header::{FileHeader, FileType};
pub use inspect::{FileInfo, inspect_file};
pub use kdf::Kdf;
pub use public_key::{
    read as read_public_key, read_from_string as read_public_key_string, write as write_public_key,
};
pub use secret_key::{
    read as read_secret_key, read_with as read_secret_key_with, write as write_secret_key,
};
pub use signature::{read as read_signature, write as write_signature};

pub const SIG_FILE_EXTENSION: &str = ".pqsig";

use std::io::{Read, Write};

use crate::errors::Error;

fn read_exact_array<const N: usize>(r: &mut impl Read) -> Result<[u8; N], Error> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf)
        .map_err(|_| Error::InvalidFormat("unexpected end of file".into()))?;
    Ok(buf)
}

fn read_u8(r: &mut impl Read) -> Result<u8, Error> {
    Ok(read_exact_array::<1>(r)?[0])
}

fn read_u32_le(r: &mut impl Read) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(read_exact_array(r)?))
}

fn read_u64_le(r: &mut impl Read) -> Result<u64, Error> {
    Ok(u64::from_le_bytes(read_exact_array(r)?))
}

fn read_vec(r: &mut impl Read, len: usize) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .map_err(|_| Error::InvalidFormat("unexpected end of file".into()))?;
    Ok(buf)
}

fn write_all(w: &mut impl Write, data: &[u8]) -> Result<(), Error> {
    Ok(w.write_all(data)?)
}

fn write_u8(w: &mut impl Write, val: u8) -> Result<(), Error> {
    write_all(w, &[val])
}

fn write_u32_le(w: &mut impl Write, val: u32) -> Result<(), Error> {
    write_all(w, &val.to_le_bytes())
}

fn write_u64_le(w: &mut impl Write, val: u64) -> Result<(), Error> {
    write_all(w, &val.to_le_bytes())
}

#[cfg(test)]
mod tests;

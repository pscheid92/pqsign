mod crypto;
mod file;
mod header;
mod inspect;
mod kdf;
mod key_pair;
mod public_key;
mod secret_key;
mod signature;

use header::{FileHeader, FileType};
pub use inspect::{FileInfo, inspect_file};
pub use kdf::Kdf;
pub use key_pair::write_key_pair;
pub use public_key::{
    encode_text as encode_public_key, read as read_public_key, read_from_string as read_public_key_string, write as write_public_key,
};
pub use secret_key::{
    PasswordChanged, change_password as change_secret_key_password, read as read_secret_key, read_with as read_secret_key_with,
    write as write_secret_key,
};
pub use signature::{check_trusted_comment, escape_file_name, read as read_signature, write as write_signature};

pub const SIG_FILE_EXTENSION: &str = ".pqsig";

use std::io::Read;

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

// Encoders append to a Vec, which can't fail, so they return nothing. Writing to a file is file.rs's job, and it
// adds the path to every I/O error.

fn write_all(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(data);
}

fn write_u8(buf: &mut Vec<u8>, val: u8) {
    write_all(buf, &[val]);
}

fn write_u32_le(buf: &mut Vec<u8>, val: u32) {
    write_all(buf, &val.to_le_bytes());
}

fn write_u64_le(buf: &mut Vec<u8>, val: u64) {
    write_all(buf, &val.to_le_bytes());
}

#[cfg(test)]
mod tests;

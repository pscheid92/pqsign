use std::fs;
use std::io::Cursor;
use std::path::Path;

use super::{FileHeader, FileType, file};
use crate::domain::*;
use crate::errors::{Error, IoContext};

const MAX_COMMENT_LEN: u32 = 1024;

// -- Public API --

/// Checks the rules every trusted comment must follow: at most 1024 bytes, no control characters other than
/// tab, and no Unicode bidirectional overrides. Signature files that break them are rejected when read, so a
/// comment can never rewrite terminal output or make text read differently than it is.
pub fn check_trusted_comment(comment: &str) -> Result<(), Error> {
    check_comment_len(comment.len())?;

    if let Some(c) = comment.chars().find(|&c| is_forbidden(c)) {
        let msg = format!("trusted comment contains a forbidden character ({})", c.escape_unicode());
        let err = Error::InvalidFormat(msg);
        return Err(err);
    }
    Ok(())
}

/// Makes text safe to embed as one field of a trusted comment: forbidden characters, the tab that separates
/// fields, and the backslash that starts an escape are written as Rust-style escapes such as `\t` or `\u{202e}`.
pub fn escape_comment_field(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\t' | '\\') || is_forbidden(c) {
            escaped.extend(c.escape_default());
        } else {
            escaped.push(c);
        }
    }
    escaped
}

pub fn write(path: &Path, sig: &Signature) -> Result<(), Error> {
    let buf = encode(sig)?;
    fs::write(path, &buf).io_context(path)
}

pub fn read(path: &Path) -> Result<Signature, Error> {
    let data = file::read(path)?;
    decode(&data)
}

// -- Helpers --

fn encode(sig: &Signature) -> Result<Vec<u8>, Error> {
    check_trusted_comment(&sig.trusted_comment)?;
    let comment_bytes = sig.trusted_comment.as_bytes();

    let mut buf = Vec::new();
    FileHeader::new(FileType::Signature, sig.key_id).write_to(&mut buf)?;
    sig.ed25519.write_to(&mut buf)?;
    sig.mldsa65.write_to(&mut buf)?;
    super::write_u32_le(&mut buf, comment_bytes.len() as u32)?;
    super::write_all(&mut buf, comment_bytes)?;

    Ok(buf)
}

pub(super) fn decode(data: &[u8]) -> Result<Signature, Error> {
    let mut r = Cursor::new(data);

    let header = FileHeader::read(&mut r)?;
    if header.file_type != FileType::Signature {
        return Err(Error::InvalidFormat("expected signature file".into()));
    }

    let ed25519 = Ed25519Signature::read_from(&mut r)?;
    let mldsa65 = MlDsa65Signature::read_from(&mut r)?;

    let comment_len = super::read_u32_le(&mut r)?;
    check_comment_len(comment_len as usize)?;

    let comment_bytes = super::read_vec(&mut r, comment_len as usize)?;
    let trusted_comment = String::from_utf8(comment_bytes).map_err(|_| Error::InvalidFormat("trusted comment is not valid UTF-8".into()))?;
    check_trusted_comment(&trusted_comment)?;

    Ok(Signature {
        key_id: header.key_id,
        ed25519,
        mldsa65,
        trusted_comment,
    })
}

fn check_comment_len(len: usize) -> Result<(), Error> {
    if len > MAX_COMMENT_LEN as usize {
        let msg = format!("trusted comment too long: {len} bytes (max {MAX_COMMENT_LEN})");
        let err = Error::InvalidFormat(msg);
        return Err(err);
    }
    Ok(())
}

/// Control characters other than tab can move the cursor, erase or recolor terminal output. Bidirectional
/// overrides and isolates reorder how text is displayed, so `invoice\u{202e}fdp.exe` reads as `invoiceexe.pdf`.
fn is_forbidden(c: char) -> bool {
    (c.is_control() && c != '\t') || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

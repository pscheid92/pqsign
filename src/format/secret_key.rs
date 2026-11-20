use std::io::Cursor;
use std::path::Path;

use rand::Rng;
use zeroize::Zeroizing;

use super::file::{self, Access};
use super::{FileHeader, FileType, crypto, kdf};
use crate::domain::*;
use crate::errors::Error;
use crate::format::kdf::Kdf;

/// Secret key format v1 (pqsign 0.1 to 0.3): the Ed25519 private key, the expanded ML-DSA-65 secret key and the
/// key ID.
const V1_PAYLOAD_LEN: usize = Ed25519SecretKey::LEN + MlDsa65SecretKey::LEN + KeyId::LEN;
/// Secret key format v2 (pqsign 0.4 on): the Ed25519 private key and the ML-DSA-65 seed ξ.
const V2_PAYLOAD_LEN: usize = Ed25519SecretKey::LEN + MlDsa65Seed::LEN;

// -- Public API --

/// Writes an encrypted secret key in format v2 atomically, readable by the owner only. An existing file is
/// replaced. `generate` uses [`Kdf::argon2id`]; tests pass small parameters so they do not spend their time in
/// Argon2id. Nothing encodes format v1 any more; [`change_password`] re-encrypts an existing format v1 payload
/// unchanged.
pub fn write(path: &Path, seeds: &SecretSeeds, password: Zeroizing<String>, kdf: &Kdf) -> Result<(), Error> {
    let data = encode_v2(seeds, &password, kdf)?;
    file::write(path, &data, Access::Private)
}

pub fn read(path: &Path, password: Zeroizing<String>) -> Result<SecretKey, Error> {
    read_with(path, |_| Ok(password))
}

/// Reads a secret key in format v1 or v2. Everything that can be checked without the password is checked before
/// `password_fn` is called: the header, the KDF parameters and the exact length of the encrypted payload, which
/// depends on the format version.
pub fn read_with(path: &Path, password_fn: impl FnOnce(&Kdf) -> Result<Zeroizing<String>, Error>) -> Result<SecretKey, Error> {
    let data = file::read(path)?;
    let parsed = parse(&data)?;
    let password = password_fn(&parsed.kdf)?;
    let plaintext = decrypt(&parsed, &password)?;
    decode(&plaintext, &parsed.header)
}

/// What [`change_password`] rewrote, for the caller's status line.
pub struct PasswordChanged {
    /// The secret key format version, from the header, which is kept.
    pub version: u8,
    pub key_id: KeyId,
    pub fingerprint: Fingerprint,
    /// The Argon2id parameters the file was written with.
    pub kdf: Kdf,
}

/// Re-encrypts a secret key file under a new password and `kdf`, keeping its header and payload bytes, so the
/// key, its format version, key ID and fingerprint stay the same. `current` is called after every check that
/// needs no password, and `new` only after the current password has opened the file. The new file is read back
/// with the new password before it atomically replaces the old one.
pub fn change_password(
    path: &Path,
    current: impl FnOnce(&Kdf) -> Result<Zeroizing<String>, Error>,
    new: impl FnOnce() -> Result<Zeroizing<String>, Error>,
    kdf: &Kdf,
) -> Result<PasswordChanged, Error> {
    kdf.check()?;
    let data = file::read(path)?;
    let parsed = parse(&data)?;
    let plaintext = decrypt(&parsed, &current(&parsed.kdf)?)?;
    // Decoding runs the key-ID check of the file's format version, so a file that would not load is never
    // rewritten. Only the key ID and fingerprint are kept; the key itself is dropped and wiped here.
    let (key_id, fingerprint) = {
        let secret_key = decode(&plaintext, &parsed.header)?;
        (secret_key.key_id(), secret_key.fingerprint())
    };

    let new_password = new()?;
    let rewritten = seal(&parsed.header, &plaintext, &new_password, kdf)?;
    check_rewritten(&rewritten, &data, &new_password, &plaintext, kdf)?;
    check_unchanged(path, &data)?;

    file::write(path, &rewritten, Access::Private)?;
    Ok(PasswordChanged {
        version: parsed.header.version,
        key_id,
        fingerprint,
        kdf: *kdf,
    })
}

// -- Shared helpers --

/// Everything in a secret key file that can be checked without the password.
struct Parsed<'a> {
    header: FileHeader,
    kdf: Kdf,
    salt: [u8; crypto::SALT_LEN],
    nonce: [u8; crypto::NONCE_LEN],
    ciphertext: &'a [u8],
}

/// Checks the header, the KDF parameters and the ciphertext length for the format version.
fn parse(data: &[u8]) -> Result<Parsed<'_>, Error> {
    let mut r = Cursor::new(data);
    let header = read_and_validate_header(&mut r)?;

    let kdf = kdf::read_from(&mut r)?;
    let salt: [u8; crypto::SALT_LEN] = super::read_exact_array(&mut r)?;
    let nonce: [u8; crypto::NONCE_LEN] = super::read_exact_array(&mut r)?;
    let ciphertext = &data[r.position() as usize..];
    check_ciphertext_len(header.version, ciphertext.len())?;

    Ok(Parsed {
        header,
        kdf,
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypts the payload of a parsed file, of either format version, into a buffer that is wiped on drop.
/// [`change_password`] encrypts the same bytes again without knowing the payload layout.
fn decrypt(parsed: &Parsed<'_>, password: &Zeroizing<String>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let plaintext = crypto::decrypt(parsed.ciphertext, password.as_bytes(), &parsed.kdf, &parsed.salt, &parsed.nonce)?;
    Ok(Zeroizing::new(plaintext))
}

/// Decodes a decrypted payload by format version, which runs that version's key-ID check.
///
/// It returns the `SecretKey` straight to its caller instead of inside a struct with the plaintext: the
/// ML-DSA-65 key is large, and every extra move of it costs stack in a debug build, where `sign` already comes
/// close to the 1 MiB main-thread stack of Windows.
fn decode(plaintext: &[u8], header: &FileHeader) -> Result<SecretKey, Error> {
    match header.version {
        1 => decode_v1(plaintext, header),
        2 => decode_v2(plaintext, header),
        other => Err(unsupported_version(other)),
    }
}

/// Reads the re-encrypted bytes back before they replace the file: the same length and header as the original,
/// the requested KDF parameters, and the same plaintext under the new password. The plaintext is not decoded
/// again; with the same header it would decode to the same key, and a format v1 decode leaves a copy of the key
/// inside fips204 that can't be wiped. Any failure is a bug in `seal` or below, never a user error, so every
/// failure becomes the same error, which says the file was left unchanged.
fn check_rewritten(rewritten: &[u8], original: &[u8], password: &Zeroizing<String>, plaintext: &[u8], kdf: &Kdf) -> Result<(), Error> {
    let reads_back = rewritten.len() == original.len()
        && rewritten[..FileHeader::LEN] == original[..FileHeader::LEN]
        && parse(rewritten).is_ok_and(|parsed| parsed.kdf == *kdf && decrypt(&parsed, password).is_ok_and(|read_back| *read_back == *plaintext));

    if !reads_back {
        let msg = "the re-encrypted secret key did not read back with the new password; the secret key file was left \
                   unchanged; please report this as a pqsign bug";
        return Err(Error::Crypto(msg.into()));
    }
    Ok(())
}

/// Stops the write when the file changed since it was read, for example by `generate --overwrite` while
/// `change-password` waited at a prompt. Writing the old key back would leave the `.key` and the `.pub` from
/// different keys. Not a lock: a change during the final write is still lost.
fn check_unchanged(path: &Path, original: &[u8]) -> Result<(), Error> {
    if file::read(path)? != original {
        return Err(Error::KeyFileChanged(path.to_path_buf()));
    }
    Ok(())
}

fn read_and_validate_header(r: &mut impl std::io::Read) -> Result<FileHeader, Error> {
    let header = FileHeader::read(r)?;
    if header.file_type != FileType::SecretKey {
        return Err(Error::InvalidFormat("expected secret key file".into()));
    }
    Ok(header)
}

/// Unreachable while [`FileHeader::read`] rejects secret key versions other than 1 and 2.
fn unsupported_version(version: u8) -> Error {
    Error::InvalidFormat(format!("unsupported secret key format v{version}"))
}

/// The length of the encrypted payload and its tag in each format version.
fn ciphertext_len(version: u8) -> Result<usize, Error> {
    match version {
        1 => Ok(V1_PAYLOAD_LEN + crypto::TAG_LEN),
        2 => Ok(V2_PAYLOAD_LEN + crypto::TAG_LEN),
        other => Err(unsupported_version(other)),
    }
}

/// The encrypted payload has a fixed size in each format version, so a truncated or padded file, or one relabelled
/// as the other version, is caught before asking for the password, instead of surfacing as a decryption failure
/// that looks like a wrong password.
fn check_ciphertext_len(version: u8, len: usize) -> Result<(), Error> {
    let expected = ciphertext_len(version)?;
    if len != expected {
        let msg = format!("secret key file is truncated or corrupt ({len} bytes of key data, expected {expected} for format v{version})");
        let err = Error::InvalidFormat(msg);
        return Err(err);
    }
    Ok(())
}

// -- Write helpers --

/// Format v2: the Ed25519 private key, then the ML-DSA-65 seed ξ, the order every other pqsign structure uses.
/// The header's key ID is derived from the seeds being encoded, never passed in, so a file can't carry a key ID
/// that doesn't match its keys. The KDF parameters are checked like those read from a key file, so pqsign never
/// writes a key it would refuse to read.
pub(super) fn encode_v2(seeds: &SecretSeeds, password: &Zeroizing<String>, kdf: &Kdf) -> Result<Vec<u8>, Error> {
    kdf.check()?;

    // Exact capacity: the buffer never reallocates, so no unwiped copy of the seeds is left on the heap.
    let mut payload = Zeroizing::new(Vec::with_capacity(V2_PAYLOAD_LEN));
    payload.extend_from_slice(seeds.ed25519().as_bytes());
    payload.extend_from_slice(seeds.mldsa65().as_bytes());

    let key_id = seeds.key_pair().public_key.key_id();
    seal(&FileHeader::new(FileType::SecretKey, key_id), &payload, password, kdf)
}

/// Writes `header`, then the sealed part of the file: the KDF block, a fresh salt and nonce, and `plaintext`
/// encrypted under `password`. The KDF parameters are checked first, so pqsign never writes a key it would refuse
/// to read; the public entry points check them before any other work as well.
fn seal(header: &FileHeader, plaintext: &[u8], password: &Zeroizing<String>, kdf: &Kdf) -> Result<Vec<u8>, Error> {
    kdf.check()?;

    let mut rng = rand::rng();
    let mut salt = [0u8; crypto::SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0u8; crypto::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let encrypted = crypto::encrypt(plaintext, password.as_bytes(), kdf, &salt, &nonce)?;

    let mut buf = Vec::new();
    header.write_to(&mut buf);
    kdf::write_to(kdf, &mut buf);
    super::write_all(&mut buf, &salt);
    super::write_all(&mut buf, &nonce);
    super::write_all(&mut buf, &encrypted);

    Ok(buf)
}

// -- Read helpers --

/// Frozen: decodes secret key format v1, which pqsign no longer encodes. Never change it; the fixtures in
/// tests/fixtures/secret-keys guard it.
fn decode_v1(plaintext: &[u8], header: &FileHeader) -> Result<SecretKey, Error> {
    let (ed25519, mldsa65, payload_key_id) = deserialize_payload(plaintext)?;

    if payload_key_id != header.key_id {
        return Err(Error::Crypto("decrypted key ID doesn't match header — file may be corrupt".into()));
    }

    SecretKey::from_parts(header.key_id, ed25519, mldsa65)
}

/// Frozen with [`decode_v1`]: the secret key format v1 payload, unchanged since pqsign 0.1.
fn deserialize_payload(data: &[u8]) -> Result<(Ed25519SecretKey, MlDsa65SecretKey, KeyId), Error> {
    let mut r = Cursor::new(data);
    let ed25519 = Ed25519SecretKey::read_from(&mut r)?;
    let mldsa65 = MlDsa65SecretKey::read_from(&mut r)?;
    let key_id = KeyId::read_from(&mut r)?;
    Ok((ed25519, mldsa65, key_id))
}

/// Format v2 stores no key ID in the payload. Keys made from the seeds must have the header's key ID, which for
/// format v2 is always the start of their fingerprint. That catches a changed header and also a build whose
/// dependencies turn the same seed into a different key. This is an [`Error::Crypto`], not the
/// [`Error::KeyIdMismatch`] of signature verification.
fn decode_v2(plaintext: &[u8], header: &FileHeader) -> Result<SecretKey, Error> {
    let mut r = Cursor::new(plaintext);
    let ed25519 = Ed25519SecretKey::read_from(&mut r)?;
    let mldsa65 = MlDsa65Seed::read_from(&mut r)?;
    let key_pair = SecretSeeds::from_parts(ed25519, mldsa65).key_pair();

    if key_pair.public_key.key_id() != header.key_id {
        let msg = "the key in this secret key file does not match its key ID; the file is corrupt, or this pqsign \
                   build derives keys differently from the one that wrote it; restore the file from a backup, and if \
                   the file is intact, report this as a pqsign bug";
        return Err(Error::Crypto(msg.into()));
    }

    let (secret_key, _) = key_pair.into_parts();
    Ok(secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KDF: Kdf = Kdf::Argon2id {
        mem_limit: 64 * 1024,
        ops_limit: 1,
    };
    const OTHER_KDF: Kdf = Kdf::Argon2id {
        mem_limit: 128 * 1024,
        ops_limit: 1,
    };

    fn pw(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.into())
    }

    /// The original file, what it opens to, and a correct rewrite of it under "new".
    fn rewrite() -> (Vec<u8>, Zeroizing<Vec<u8>>, Vec<u8>) {
        let original = encode_v2(&SecretSeeds::generate(), &pw("old"), &KDF).unwrap();
        let parsed = parse(&original).unwrap();
        let plaintext = decrypt(&parsed, &pw("old")).unwrap();
        let rewritten = seal(&parsed.header, &plaintext, &pw("new"), &KDF).unwrap();
        (original, plaintext, rewritten)
    }

    fn assert_bug_report(result: Result<(), Error>) {
        match result {
            Err(Error::Crypto(msg)) => assert_eq!(
                msg,
                "the re-encrypted secret key did not read back with the new password; the secret key file was left \
                 unchanged; please report this as a pqsign bug"
            ),
            Err(other) => panic!("expected the bug-report error, got: {other}"),
            Ok(()) => panic!("a broken rewrite passed the read-back"),
        }
    }

    #[test]
    fn test_check_rewritten_accepts_a_correct_rewrite() {
        let (original, plaintext, rewritten) = rewrite();
        check_rewritten(&rewritten, &original, &pw("new"), &plaintext, &KDF).unwrap();
    }

    /// Every way a rewrite can be wrong gives the one bug-report error, never `WrongPassword` or `InvalidFormat`.
    #[test]
    fn test_check_rewritten_reports_every_failure_as_a_bug() {
        let (original, plaintext, rewritten) = rewrite();

        let mut flipped = rewritten.clone();
        *flipped.last_mut().unwrap() ^= 0x01;
        assert_bug_report(check_rewritten(&flipped, &original, &pw("new"), &plaintext, &KDF));

        assert_bug_report(check_rewritten(&rewritten, &original, &pw("wrong"), &plaintext, &KDF));

        let mut header = rewritten.clone();
        header[6] ^= 0x01;
        assert_bug_report(check_rewritten(&header, &original, &pw("new"), &plaintext, &KDF));

        let longer = [rewritten.as_slice(), b"x"].concat();
        assert_bug_report(check_rewritten(&longer, &original, &pw("new"), &plaintext, &KDF));

        assert_bug_report(check_rewritten(&rewritten, &original, &pw("new"), &plaintext, &OTHER_KDF));

        let mut kdf_block = rewritten.clone();
        kdf_block[FileHeader::LEN + 9] ^= 0x01;
        assert_bug_report(check_rewritten(&kdf_block, &original, &pw("new"), &plaintext, &KDF));
    }
}

//! Password input for key generation and signing.
//!
//! A password comes from exactly one [`PasswordSource`]. Interactive prompting goes through
//! the controlling terminal, and the non-interactive sources read a single line. Nothing is
//! ever read from standard input unless explicitly asked for.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::errors::{Error, IoContext};

/// Maximum password length in bytes.
///
/// Applies to new passwords from every source and to passwords read non-interactively.
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Where the secret key password comes from.
pub enum PasswordSource {
    /// Prompt on the controlling terminal. Fails when no terminal is available.
    Prompt,
    /// The first line of standard input (`--password-stdin`). Meant for pipes: on a terminal the input is echoed.
    Stdin,
    /// The first line of a file (`--password-file`).
    File(PathBuf),
    /// A value supplied by the caller. Meant for library use, tests and benchmarks.
    Given(Zeroizing<String>),
}

impl PasswordSource {
    /// Obtains the password for an existing key. Nothing is confirmed.
    pub fn read_existing(self) -> Result<Zeroizing<String>, Error> {
        let password = match self {
            PasswordSource::Prompt => prompt_password("Password: ")?,
            PasswordSource::Stdin => read_first_line(raw_stdin()?)?,
            PasswordSource::File(path) => read_first_line_from_file(&path)?,
            PasswordSource::Given(password) => password,
        };
        require_non_empty(password)
    }

    /// Obtains the password for a new key. Interactive use asks twice; every other source reads once.
    pub fn read_new(self) -> Result<Zeroizing<String>, Error> {
        let password = match self {
            PasswordSource::Prompt => prompt_new_password()?,
            other => other.read_existing()?,
        };
        require_max_len(password.len())?;
        Ok(password)
    }
}

fn prompt_new_password() -> Result<Zeroizing<String>, Error> {
    let password = prompt_password("Password: ")?;
    let confirm = prompt_password("Confirm password: ")?;
    validate_new_password(&password, &confirm)?;
    Ok(password)
}

fn validate_new_password(password: &str, confirm: &str) -> Result<(), Error> {
    if password.is_empty() {
        return Err(Error::PasswordEmpty);
    }

    if password != confirm {
        return Err(Error::PasswordMismatch);
    }

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<Zeroizing<String>, Error> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|source| Error::PasswordPrompt { source })
}

fn require_non_empty(password: Zeroizing<String>) -> Result<Zeroizing<String>, Error> {
    if password.is_empty() {
        return Err(Error::PasswordEmpty);
    }
    Ok(password)
}

fn require_max_len(len: usize) -> Result<(), Error> {
    if len > MAX_PASSWORD_LEN {
        let err = Error::PasswordTooLong { max: MAX_PASSWORD_LEN };
        return Err(err);
    }
    Ok(())
}

/// Standard input as an unbuffered reader, so password bytes never linger in the shared buffer behind [`io::stdin`].
fn raw_stdin() -> Result<Box<dyn Read>, Error> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let fd = io::stdin().as_fd().try_clone_to_owned()?;
        Ok(Box::new(File::from(fd)))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        let handle = io::stdin().as_handle().try_clone_to_owned()?;
        Ok(Box::new(File::from(handle)))
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(Box::new(io::stdin()))
    }
}

fn read_first_line_from_file(path: &Path) -> Result<Zeroizing<String>, Error> {
    let file = File::open(path).io_context(path)?;
    read_first_line(file)
}

/// Reads one line without its line ending. Other whitespace is preserved.
///
/// Reads byte by byte so nothing past the line ending is consumed, and never grows the
/// buffer, so no un-wiped copy of the password is left behind on reallocation.
#[allow(
    clippy::unbuffered_bytes,
    reason = "bounded to MAX_PASSWORD_LEN + 1 reads; a BufReader would keep an un-zeroized copy of the password"
)]
fn read_first_line(reader: impl Read) -> Result<Zeroizing<String>, Error> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_LEN + 1));
    for byte in reader.bytes().take(MAX_PASSWORD_LEN + 1) {
        match byte? {
            b'\n' => break,
            byte => bytes.push(byte),
        }
    }
    bytes.pop_if(|byte| *byte == b'\r');
    require_max_len(bytes.len())?;

    let text = std::str::from_utf8(&bytes).map_err(|_| Error::PasswordNotUtf8)?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_line(input: &[u8]) -> Result<Zeroizing<String>, Error> {
        read_first_line(input)
    }

    fn given(password: &str) -> PasswordSource {
        PasswordSource::Given(Zeroizing::new(password.to_string()))
    }

    #[test]
    fn test_first_line_strips_one_line_ending() {
        assert_eq!(first_line(b"pw\n").unwrap().as_str(), "pw");
        assert_eq!(first_line(b"pw\r\n").unwrap().as_str(), "pw");
        assert_eq!(first_line(b"pw").unwrap().as_str(), "pw");
    }

    #[test]
    fn test_first_line_keeps_other_whitespace() {
        assert_eq!(first_line(b" pw \t\n").unwrap().as_str(), " pw \t");
    }

    #[test]
    fn test_first_line_ignores_following_lines() {
        assert_eq!(first_line(b"first\nsecond\n").unwrap().as_str(), "first");
    }

    #[test]
    fn test_first_line_may_be_empty() {
        assert_eq!(first_line(b"\n").unwrap().as_str(), "");
        assert_eq!(first_line(b"").unwrap().as_str(), "");
    }

    #[test]
    fn test_first_line_length_limit() {
        let max = "x".repeat(MAX_PASSWORD_LEN);
        assert_eq!(first_line(format!("{max}\n").as_bytes()).unwrap().as_str(), max);
        assert_eq!(first_line(format!("{max}\r\n").as_bytes()).unwrap().as_str(), max);

        let err = first_line(format!("{max}x\n").as_bytes()).unwrap_err();
        assert!(matches!(err, Error::PasswordTooLong { .. }));
    }

    #[test]
    fn test_first_line_rejects_invalid_utf8() {
        let err = first_line(b"\xff\xfe\n").unwrap_err();
        assert!(matches!(err, Error::PasswordNotUtf8));
    }

    #[test]
    fn test_given_password_is_used_as_is() {
        assert_eq!(given("pw ").read_existing().unwrap().as_str(), "pw ");
    }

    #[test]
    fn test_given_empty_password_is_rejected() {
        assert!(matches!(given("").read_existing().unwrap_err(), Error::PasswordEmpty));
        assert!(matches!(given("").read_new().unwrap_err(), Error::PasswordEmpty));
    }

    #[test]
    fn test_length_limit_applies_to_new_passwords_only() {
        let long = "x".repeat(MAX_PASSWORD_LEN + 1);
        assert!(matches!(given(&long).read_new().unwrap_err(), Error::PasswordTooLong { .. }));
        assert_eq!(given(&long).read_existing().unwrap().as_str(), long);
    }

    #[test]
    fn test_file_source_reads_first_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password");
        std::fs::write(&path, "file-pw\r\nignored\n").unwrap();

        assert_eq!(PasswordSource::File(path).read_existing().unwrap().as_str(), "file-pw");
    }

    #[test]
    fn test_file_source_missing_file() {
        let err = PasswordSource::File("/no/such/password".into()).read_existing().unwrap_err();
        assert!(matches!(err, Error::IoPath { .. }));
    }

    #[test]
    fn test_validate_matching_passwords() {
        validate_new_password("secret", "secret").unwrap();
    }

    #[test]
    fn test_validate_empty_password() {
        let err = validate_new_password("", "").unwrap_err();
        assert!(matches!(err, Error::PasswordEmpty));
    }

    #[test]
    fn test_validate_mismatched_passwords() {
        let err = validate_new_password("foo", "bar").unwrap_err();
        assert!(matches!(err, Error::PasswordMismatch));
    }

    #[test]
    fn test_validate_empty_confirm_mismatches() {
        let err = validate_new_password("secret", "").unwrap_err();
        assert!(matches!(err, Error::PasswordMismatch));
    }
}

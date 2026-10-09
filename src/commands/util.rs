use std::path::{Path, PathBuf};

use crate::errors::Error;
use crate::format::SIG_FILE_EXTENSION;

pub fn validate_file_path(path: &Path) -> Result<(), Error> {
    if path.file_name().is_none() {
        let msg = format!("not a valid file path: {}", path.display());
        let err = Error::InvalidFormat(msg);
        return Err(err);
    }

    Ok(())
}

pub fn default_key_dir() -> Result<PathBuf, Error> {
    let home = std::env::home_dir().ok_or(Error::HomeDirNotFound)?;
    Ok(home.join(".pqsign"))
}

pub fn resolve_key_path(path: Option<PathBuf>, default_filename: &str) -> Result<PathBuf, Error> {
    let path = match path {
        Some(p) => expand_tilde(p),
        None => default_key_dir()?.join(default_filename),
    };
    validate_file_path(&path)?;
    Ok(path)
}

pub fn resolve_signature_path(sig_file: Option<PathBuf>, file: &Path) -> Result<PathBuf, Error> {
    let path = sig_file.map(expand_tilde).unwrap_or_else(|| with_suffix(file, SIG_FILE_EXTENSION));
    validate_file_path(&path)?;
    Ok(path)
}

/// Appends `suffix` to the whole path. Works on the raw OS string, so a name that is not valid UTF-8 keeps its
/// exact bytes instead of having them replaced by U+FFFD, which could make two names collide.
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn expand_tilde(path: PathBuf) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("~")
        && let Some(home) = std::env::home_dir()
    {
        return home.join(rest);
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_file_path_valid() {
        validate_file_path(Path::new("my.key")).unwrap();
    }

    #[test]
    fn test_validate_file_path_nested() {
        validate_file_path(Path::new("keys/my.key")).unwrap();
    }

    #[test]
    fn test_validate_file_path_directory_only() {
        let err = validate_file_path(Path::new("/")).unwrap_err();
        assert!(matches!(err, Error::InvalidFormat(_)));
    }

    #[test]
    fn test_default_key_dir() {
        let dir = default_key_dir().unwrap();
        assert!(dir.ends_with(".pqsign"));
    }

    #[test]
    fn test_resolve_key_path_with_explicit_path() {
        let path = resolve_key_path(Some(PathBuf::from("custom.key")), "default.key").unwrap();
        assert_eq!(path, PathBuf::from("custom.key"));
    }

    #[test]
    fn test_resolve_key_path_default_uses_home_dir() {
        let path = resolve_key_path(None, "default.key").unwrap();
        let expected = std::env::home_dir().unwrap().join(".pqsign").join("default.key");
        assert_eq!(path, expected);
    }

    #[test]
    fn test_resolve_signature_path_with_some() {
        let path = resolve_signature_path(Some(PathBuf::from("custom.pqsig")), Path::new("data.txt")).unwrap();
        assert_eq!(path, PathBuf::from("custom.pqsig"));
    }

    #[test]
    fn test_resolve_signature_path_default_appends_extension() {
        let path = resolve_signature_path(None, Path::new("document.pdf")).unwrap();
        assert_eq!(path, PathBuf::from("document.pdf.pqsig"));
    }

    #[test]
    fn test_resolve_signature_path_preserves_directory() {
        let path = resolve_signature_path(None, Path::new("dir/file.txt")).unwrap();
        assert_eq!(path, PathBuf::from("dir/file.txt.pqsig"));
    }

    #[test]
    fn test_expand_tilde_in_key_path() {
        let path = resolve_key_path(Some(PathBuf::from("~/.pqsign/my.key")), "default.key").unwrap();
        let expected = std::env::home_dir().unwrap().join(".pqsign/my.key");
        assert_eq!(path, expected);
    }

    #[test]
    fn test_expand_tilde_in_signature_path() {
        let path = resolve_signature_path(Some(PathBuf::from("~/sigs/my.pqsig")), Path::new("data.txt")).unwrap();
        let expected = std::env::home_dir().unwrap().join("sigs/my.pqsig");
        assert_eq!(path, expected);
    }

    #[cfg(unix)]
    #[test]
    fn test_signature_path_keeps_non_utf8_bytes() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let first = resolve_signature_path(None, Path::new(OsStr::from_bytes(b"caf\xe9.txt"))).unwrap();
        let second = resolve_signature_path(None, Path::new(OsStr::from_bytes(b"caf\xe8.txt"))).unwrap();

        assert_eq!(first.as_os_str().as_bytes(), b"caf\xe9.txt.pqsig");
        assert_ne!(first, second, "different files must not share a signature file");
    }

    #[cfg(windows)]
    #[test]
    fn test_signature_path_keeps_unpaired_surrogates() {
        use std::ffi::OsString;
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        let name: Vec<u16> = "caf".encode_utf16().chain([0xD800]).chain(".txt".encode_utf16()).collect();
        let signature = resolve_signature_path(None, &PathBuf::from(OsString::from_wide(&name))).unwrap();

        let expected: Vec<u16> = name.iter().copied().chain(".pqsig".encode_utf16()).collect();
        assert_eq!(signature.as_os_str().encode_wide().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn test_no_expand_without_tilde() {
        let path = expand_tilde(PathBuf::from("/absolute/path.key"));
        assert_eq!(path, PathBuf::from("/absolute/path.key"));
    }
}

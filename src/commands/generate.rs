use std::path::{Path, PathBuf};

use super::util::{resolve_key_path, with_suffix};
use crate::domain::KeyPair;
use crate::errors::Error;
use crate::format;
use crate::password::PasswordSource;

pub struct Options {
    pub secret_key: Option<PathBuf>,
    pub password: PasswordSource,
    pub overwrite: bool,
}

pub fn run(opts: Options) -> Result<(), Error> {
    let Options {
        secret_key,
        password,
        overwrite,
    } = opts;
    let (secret_key_path, public_key_path) = resolve_paths(secret_key)?;

    if !overwrite {
        check_not_exists(&secret_key_path)?;
        check_not_exists(&public_key_path)?;
    }

    let password = password.read_new()?;

    eprintln!("Generating key pair...");
    let keypair = KeyPair::new();
    format::write_key_pair(&secret_key_path, &public_key_path, &keypair, password, overwrite)?;

    let pk_content = format::encode_public_key(&keypair.public_key)?;

    eprintln!("Secret key:  {}", secret_key_path.display());
    eprintln!("Public key:  {}", public_key_path.display());
    eprintln!("Key ID:      {}", keypair.public_key.key_id());
    eprintln!("Fingerprint: {}", keypair.public_key.fingerprint());
    eprintln!();
    eprint!("{pk_content}");

    Ok(())
}

fn resolve_paths(secret_key: Option<PathBuf>) -> Result<(PathBuf, PathBuf), Error> {
    let secret_key_path = resolve_key_path(secret_key, "default.key")?;
    let public_key_path = with_suffix(&secret_key_path, ".pub");
    Ok((secret_key_path, public_key_path))
}

fn check_not_exists(path: &Path) -> Result<(), Error> {
    if path.exists() {
        return Err(Error::FileExists(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    use super::*;

    #[test]
    fn test_public_key_path_keeps_non_utf8_bytes() {
        let (secret, public) = resolve_paths(Some(PathBuf::from(OsStr::from_bytes(b"k\xe9y.key")))).unwrap();
        assert_eq!(secret.as_os_str().as_bytes(), b"k\xe9y.key");
        assert_eq!(public.as_os_str().as_bytes(), b"k\xe9y.key.pub");
    }
}

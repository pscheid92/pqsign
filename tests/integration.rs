use std::fs;
use std::path::PathBuf;

use zeroize::Zeroizing;

use pqsign::commands::{generate, inspect, sign, verify};
use pqsign::domain::{KeyPair, SignatureFormat};
use pqsign::format::{self, Kdf};
use pqsign::password::PasswordSource;

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.into())
}

/// Small Argon2id parameters, so tests do not spend their time deriving keys. `generate` always uses the defaults.
const TEST_KDF: Kdf = Kdf::Argon2id {
    mem_limit: 64 * 1024,
    ops_limit: 1,
};

fn keygen(secret_key: PathBuf, password: &str, overwrite: bool) -> Result<(), pqsign::errors::Error> {
    generate::run(generate::Options {
        secret_key: Some(secret_key),
        password: PasswordSource::Given(pw(password)),
        overwrite,
        kdf: TEST_KDF,
    })
}

fn sig(file: PathBuf, secret_key: PathBuf, sig_file: Option<PathBuf>, trusted_comment: Option<String>) -> Result<(), pqsign::errors::Error> {
    sign::run(sign::Options {
        file,
        secret_key: Some(secret_key),
        sig_file,
        trusted_comment,
        password: PasswordSource::Given(pw("test-pw")),
        format: SignatureFormat::V2,
    })
}

fn ver(file: PathBuf, public_key: PathBuf, sig_file: PathBuf) -> Result<(), pqsign::errors::Error> {
    verify::run(verify::Options {
        file,
        public_key: Some(public_key),
        public_key_string: None,
        sig_file: Some(sig_file),
        quiet: false,
    })
}

// -- Full generate -> sign -> verify -> inspect flow --

#[test]
fn test_generate_sign_verify_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let pk_path = dir.path().join("test.key.pub");
    let file_path = dir.path().join("message.txt");
    let sig_path = dir.path().join("message.txt.pqsig");

    fs::write(&file_path, b"hello post-quantum world").unwrap();

    keygen(sk_path.clone(), "test-pw", false).unwrap();
    sig(file_path.clone(), sk_path.clone(), Some(sig_path.clone()), None).unwrap();
    ver(file_path.clone(), pk_path.clone(), sig_path.clone()).unwrap();

    inspect::run(pk_path).unwrap();
    inspect::run(sk_path).unwrap();
    inspect::run(sig_path).unwrap();
}

#[test]
fn test_generate_sign_verify_with_custom_comment() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let file_path = dir.path().join("data.bin");
    let sig_path = dir.path().join("data.bin.pqsig");

    fs::write(&file_path, b"binary data").unwrap();

    keygen(sk_path.clone(), "test-pw", false).unwrap();
    sig(file_path.clone(), sk_path, Some(sig_path.clone()), Some("release v1.0".into())).unwrap();

    let s = format::read_signature(&sig_path).unwrap();
    assert!(s.trusted_comment.contains("release v1.0"));
}

#[test]
fn test_verify_tampered_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let pk_path = dir.path().join("test.key.pub");
    let file_path = dir.path().join("message.txt");
    let sig_path = dir.path().join("message.txt.pqsig");

    fs::write(&file_path, b"original content").unwrap();
    keygen(sk_path.clone(), "test-pw", false).unwrap();
    sig(file_path.clone(), sk_path, Some(sig_path.clone()), None).unwrap();

    fs::write(&file_path, b"tampered content").unwrap();
    assert!(ver(file_path, pk_path, sig_path).is_err());
}

#[test]
fn test_verify_wrong_key_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk1_path = dir.path().join("key1.key");
    let sk2_path = dir.path().join("key2.key");
    let pk2_path = dir.path().join("key2.key.pub");
    let file_path = dir.path().join("message.txt");
    let sig_path = dir.path().join("message.txt.pqsig");

    fs::write(&file_path, b"content").unwrap();

    keygen(sk1_path.clone(), "test-pw", false).unwrap();
    keygen(sk2_path, "test-pw", false).unwrap();
    sig(file_path.clone(), sk1_path, Some(sig_path.clone()), None).unwrap();

    assert!(ver(file_path, pk2_path, sig_path).is_err());
}

// -- generate edge cases --

#[test]
fn test_generate_refuses_overwrite_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("existing.key");
    fs::write(&sk_path, b"").unwrap();

    let err = keygen(sk_path, "test-pw", false).unwrap_err();
    assert!(matches!(err, pqsign::errors::Error::FileExists(_)));
}

#[test]
fn test_generate_overwrite_flag_works() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("existing.key");
    let pk_path = dir.path().join("existing.key.pub");
    fs::write(&sk_path, b"old").unwrap();
    fs::write(&pk_path, b"old").unwrap();

    keygen(sk_path.clone(), "test-pw", true).unwrap();
    let data = fs::read(&sk_path).unwrap();
    assert_eq!(&data[0..4], b"PQSN");
}

#[test]
fn test_generate_default_path_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("pqsign.key");
    keygen(sk_path.clone(), "test-pw", false).unwrap();
    assert!(sk_path.exists());
    assert!(dir.path().join("pqsign.key.pub").exists());
}

// -- sign edge cases --

#[test]
fn test_sign_nonexistent_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    keygen(sk_path.clone(), "test-pw", false).unwrap();

    let err = sig(dir.path().join("does-not-exist.txt"), sk_path, None, None);
    assert!(err.is_err());
}

#[test]
fn test_sign_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let pk_path = dir.path().join("test.key.pub");
    let file_path = dir.path().join("empty.txt");
    let sig_path = dir.path().join("empty.txt.pqsig");

    fs::write(&file_path, b"").unwrap();
    keygen(sk_path.clone(), "test-pw", false).unwrap();
    sig(file_path.clone(), sk_path, Some(sig_path.clone()), None).unwrap();

    ver(file_path, pk_path, sig_path).unwrap();
}

// -- verify edge cases --

#[test]
fn test_verify_nonexistent_signature_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let pk_path = dir.path().join("test.key.pub");
    let file_path = dir.path().join("message.txt");

    fs::write(&file_path, b"content").unwrap();
    keygen(sk_path, "test-pw", false).unwrap();

    let err = ver(file_path, pk_path, dir.path().join("no-such.pqsig"));
    assert!(err.is_err());
}

#[test]
fn test_verify_nonexistent_pubkey_fails() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("message.txt");
    let sig_path = dir.path().join("message.txt.pqsig");
    fs::write(&file_path, b"content").unwrap();

    let (sk, _) = KeyPair::new().into_parts();
    let s = sk.sign(&file_path, "test").unwrap();
    format::write_signature(&sig_path, &s).unwrap();

    let err = ver(file_path, dir.path().join("no-such.key.pub"), sig_path);
    assert!(err.is_err());
}

// -- secret key file permissions --

#[cfg(unix)]
#[test]
fn test_secret_key_file_mode_is_600() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    keygen(sk_path.clone(), "test-pw", false).unwrap();

    let mode = fs::metadata(&sk_path).unwrap().mode();
    assert_eq!(mode & 0o777, 0o600, "secret key should be mode 0600");
}

// -- atomic key writes --

fn file_names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[cfg(unix)]
fn mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn test_generate_leaves_no_temp_files() {
    let dir = tempfile::tempdir().unwrap();
    keygen(dir.path().join("test.key"), "test-pw", false).unwrap();
    keygen(dir.path().join("test.key"), "test-pw", true).unwrap();

    assert_eq!(file_names(dir.path()), ["test.key", "test.key.pub"]);
}

#[test]
fn test_generate_overwrite_keeps_old_key_when_public_key_cannot_be_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let pk_path = dir.path().join("test.key.pub");
    keygen(sk_path.clone(), "old-pw", false).unwrap();
    let old_secret_key = fs::read(&sk_path).unwrap();

    // A non-empty directory in place of the public key makes its final rename fail.
    fs::remove_file(&pk_path).unwrap();
    fs::create_dir(&pk_path).unwrap();
    fs::write(pk_path.join("blocker"), b"").unwrap();

    assert!(keygen(sk_path.clone(), "new-pw", true).is_err());

    assert_eq!(fs::read(&sk_path).unwrap(), old_secret_key);
    format::read_secret_key(&sk_path, pw("old-pw")).unwrap();
    assert_eq!(file_names(dir.path()), ["test.key", "test.key.pub"]);
}

#[test]
fn test_write_key_pair_without_overwrite_never_replaces_files() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let pk_path = dir.path().join("test.key.pub");
    fs::write(&sk_path, b"existing").unwrap();

    // Skips the existence check in `generate`, as if the file appeared after it.
    let err = format::write_key_pair(&sk_path, &pk_path, &KeyPair::new(), pw("test-pw"), false, &TEST_KDF).unwrap_err();

    assert!(matches!(err, pqsign::errors::Error::FileExists(_)));
    assert_eq!(fs::read(&sk_path).unwrap(), b"existing");
    assert_eq!(
        file_names(dir.path()),
        ["test.key"],
        "the public key written by the failed call is removed"
    );
}

#[cfg(unix)]
#[test]
fn test_generate_overwrite_makes_existing_key_private() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    fs::write(&sk_path, b"old").unwrap();
    fs::set_permissions(&sk_path, fs::Permissions::from_mode(0o644)).unwrap();

    keygen(sk_path.clone(), "test-pw", true).unwrap();

    assert_eq!(mode(&sk_path), 0o600);
}

#[cfg(unix)]
#[test]
fn test_generate_creates_private_directories() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("keys").join("nested").join("test.key");

    keygen(sk_path.clone(), "test-pw", false).unwrap();

    assert_eq!(mode(&dir.path().join("keys")), 0o700);
    assert_eq!(mode(&dir.path().join("keys").join("nested")), 0o700);
    assert_eq!(mode(&sk_path), 0o600);
}

#[cfg(unix)]
#[test]
fn test_generate_overwrite_writes_through_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.key");
    let link = dir.path().join("link.key");
    keygen(target.clone(), "old-pw", false).unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();

    keygen(link.clone(), "new-pw", true).unwrap();

    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    format::read_secret_key(&target, pw("new-pw")).unwrap();
}

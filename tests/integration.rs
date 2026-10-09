use std::fs;
use std::path::PathBuf;

use zeroize::Zeroizing;

use pqsign::commands::{generate, inspect, sign, verify};
use pqsign::domain::KeyPair;
use pqsign::format;
use pqsign::password::PasswordSource;

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.into())
}

fn keygen(secret_key: PathBuf, password: &str, overwrite: bool) -> Result<(), pqsign::errors::Error> {
    generate::run(generate::Options {
        secret_key: Some(secret_key),
        password: PasswordSource::Given(pw(password)),
        overwrite,
    })
}

fn sig(file: PathBuf, secret_key: PathBuf, sig_file: Option<PathBuf>, trusted_comment: Option<String>) -> Result<(), pqsign::errors::Error> {
    sign::run(sign::Options {
        file,
        secret_key: Some(secret_key),
        sig_file,
        trusted_comment,
        password: PasswordSource::Given(pw("test-pw")),
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

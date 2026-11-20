use std::fs;

use zeroize::Zeroizing;

use pqsign::domain::{KeyPair, SecretSeeds};
use pqsign::format;
use pqsign::format::{FileInfo, Kdf};

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.into())
}

/// Small Argon2id parameters, so tests do not spend their time deriving keys. `generate` always uses the defaults.
const TEST_KDF: Kdf = Kdf::Argon2id {
    mem_limit: 64 * 1024,
    ops_limit: 1,
};

#[test]
fn test_inspect_text_public_key() {
    let dir = tempfile::tempdir().unwrap();
    let pk_path = dir.path().join("test.pub");
    let (_, pk) = KeyPair::new().into_parts();

    format::write_public_key(&pk_path, &pk).unwrap();
    let info = format::inspect_file(&pk_path).unwrap();

    match &info {
        FileInfo::PublicKey { key_id, fingerprint } => {
            assert_eq!(*key_id, pk.key_id());
            assert_eq!(*fingerprint, pk.fingerprint());
        }
        other => panic!("expected PublicKey, got: {other}"),
    }

    let output = format!("{info}");
    assert!(output.contains("Public key"));
    assert!(output.contains("Ed25519 + ML-DSA-65"));
    assert!(output.contains(&pk.key_id().to_string()));
    assert!(output.contains(&format!("Fingerprint: {}", pk.fingerprint())));
}

#[test]
fn test_inspect_encrypted_secret_key() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let seeds = SecretSeeds::generate();

    format::write_secret_key(&sk_path, &seeds, pw("pass"), &TEST_KDF).unwrap();
    let info = format::inspect_file(&sk_path).unwrap();

    match &info {
        FileInfo::SecretKey { key_id, .. } => {
            assert_eq!(*key_id, seeds.key_pair().public_key.key_id());
        }
        other => panic!("expected SecretKey, got: {other}"),
    }

    let output = format!("{info}");
    assert!(output.contains("encrypted"));
    assert!(output.contains("Secret key (format v2, encrypted)"), "got: {output}");
    assert!(output.contains("Argon2id"));
    assert!(output.contains("Memory:      64 KiB"), "got: {output}");
    assert!(output.contains("Ops:         1"), "got: {output}");
}

/// A secret key in format v1, written by pqsign 0.3.1, shows its format version.
#[test]
fn test_inspect_v1_secret_key_fixture() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/secret-keys/v1.key");
    let output = format!("{}", format::inspect_file(&path).unwrap());
    assert!(output.contains("Secret key (format v1, encrypted)"), "got: {output}");
}

#[test]
fn test_inspect_signature_file() {
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("data.txt");
    let sig_path = dir.path().join("data.txt.pqsig");
    fs::write(&file_path, b"some data").unwrap();

    let (sk, _) = KeyPair::new().into_parts();
    let sig = sk.sign(&file_path, "my comment").unwrap();
    format::write_signature(&sig_path, &sig).unwrap();

    let info = format::inspect_file(&sig_path).unwrap();
    match &info {
        FileInfo::Signature { key_id, trusted_comment, .. } => {
            assert_eq!(*key_id, sig.key_id());
            assert_eq!(trusted_comment, "my comment");
        }
        other => panic!("expected Signature, got: {other}"),
    }

    let output = format!("{info}");
    assert!(output.contains("Signature"));
    assert!(output.contains("my comment"));
    assert!(output.contains("Ed25519 + ML-DSA-65"));
}

#[test]
fn test_inspect_nonexistent_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let result = format::inspect_file(&dir.path().join("nope.key")).err();
    assert!(
        matches!(&result, Some(pqsign::errors::Error::IoPath { source, .. }) if source.kind() == std::io::ErrorKind::NotFound),
        "got: {result:?}"
    );
}

#[test]
fn test_inspect_corrupt_binary_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.key");
    fs::write(&path, b"not a pqsign file at all").unwrap();
    let result = format::inspect_file(&path).err();
    assert!(matches!(result, Some(pqsign::errors::Error::InvalidFormat(_))), "got: {result:?}");
}

/// A truncated or padded secret key is reported as corrupt, as `sign` reports it, rather than as a valid key.
#[test]
fn test_inspect_rejects_a_truncated_or_padded_secret_key() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    format::write_secret_key(&sk_path, &SecretSeeds::generate(), pw("test"), &TEST_KDF).unwrap();
    let data = fs::read(&sk_path).unwrap();

    let truncated = &data[..100];
    let padded = [data.as_slice(), data.as_slice()].concat();
    for corrupt in [truncated, padded.as_slice()] {
        let path = dir.path().join("corrupt.key");
        fs::write(&path, corrupt).unwrap();
        match format::inspect_file(&path).err() {
            Some(pqsign::errors::Error::InvalidFormat(msg)) => assert!(msg.contains("truncated or corrupt"), "got: {msg}"),
            Some(other) => panic!("expected InvalidFormat, got: {other}"),
            None => panic!("a corrupt secret key was inspected as valid"),
        }
    }
}

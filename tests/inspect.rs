use std::fs;

use zeroize::Zeroizing;

use pqsign::domain::KeyPair;
use pqsign::format;
use pqsign::format::FileInfo;

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.into())
}

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
    let (sk, _) = KeyPair::new().into_parts();

    format::write_secret_key(&sk_path, &sk, pw("pass")).unwrap();
    let info = format::inspect_file(&sk_path).unwrap();

    match &info {
        FileInfo::SecretKey { key_id, .. } => {
            assert_eq!(*key_id, sk.key_id());
        }
        other => panic!("expected SecretKey, got: {other}"),
    }

    let output = format!("{info}");
    assert!(output.contains("encrypted"));
    assert!(output.contains("Argon2id"));
    assert!(output.contains("MiB"));
    assert!(output.contains("Ops:"));
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
    assert!(format::inspect_file(&dir.path().join("nope.key")).is_err());
}

#[test]
fn test_inspect_corrupt_binary_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("corrupt.key");
    fs::write(&path, b"not a pqsign file at all").unwrap();
    assert!(format::inspect_file(&path).is_err());
}

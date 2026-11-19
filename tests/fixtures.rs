//! Committed files that must keep working across releases.

use std::fs;
use std::path::{Path, PathBuf};

use pqsign::domain::SignatureFormat;
use pqsign::errors::Error;
use pqsign::format;
use zeroize::Zeroizing;

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

/// A signature written by pqsign 0.1.1. Every later version must verify it.
#[test]
fn test_v1_signature_fixture_verifies() {
    let pk = format::read_public_key(&repo("tests/fixtures/v1/signer.pub")).unwrap();
    let sig = format::read_signature(&repo("tests/fixtures/v1/message.txt.pqsig")).unwrap();

    sig.verify(&pk, &repo("tests/fixtures/v1/message.txt")).unwrap();
    assert_eq!(sig.format(), SignatureFormat::V1);
    assert!(sig.trusted_comment.ends_with("\tfile:message.txt\tv1 fixture"));
}

/// A v2 signature written when the format was introduced. Every later version must verify it.
#[test]
fn test_v2_signature_fixture_verifies() {
    let pk = format::read_public_key(&repo("tests/fixtures/v2/signer.pub")).unwrap();
    let sig = format::read_signature(&repo("tests/fixtures/v2/message.txt.pqsig")).unwrap();

    sig.verify(&pk, &repo("tests/fixtures/v2/message.txt")).unwrap();
    assert_eq!(sig.format(), SignatureFormat::V2);
    assert_eq!(sig.signer(), Some(pk.fingerprint()));
    assert_eq!(pk.key_id(), pk.fingerprint().key_id());
    assert_eq!(pk.fingerprint().to_string(), "BLAKE2b-256:vaHlS1cT0OCY404qQT05a3qOUKN4SV0icxX4GbXfQHg");
    assert!(sig.trusted_comment.ends_with("\tfile:message.txt\tv2 fixture"));
}

/// Fingerprints are published and compared by people, so the algorithm must never change silently.
#[test]
fn test_fingerprint_is_stable() {
    let pk = format::read_public_key(&repo("tests/fixtures/v1/signer.pub")).unwrap();
    assert_eq!(pk.fingerprint().to_string(), "BLAKE2b-256:bfitHdkPM8gxN/zV3D9njrQLGI86fCgW8sDcVtoqjC8");
}

/// Users check the release key against the fingerprint in the docs, so the docs must match the key.
/// The published crate excludes the release key and `docs/`, so the test skips itself there.
#[test]
fn test_docs_publish_the_release_key_fingerprint() {
    let docs = ["README.md", "docs/install.md", "SECURITY.md"];
    if !repo("release.key.pub").exists() || docs.iter().any(|doc| !repo(doc).exists()) {
        eprintln!("skipped: the release key or the docs are not part of this checkout");
        return;
    }
    let fingerprint = format::read_public_key(&repo("release.key.pub")).unwrap().fingerprint().to_string();

    for doc in docs {
        let text = fs::read_to_string(repo(doc)).unwrap();
        assert!(
            text.contains(&fingerprint),
            "{doc} does not show the release key fingerprint {fingerprint}"
        );
    }
}

// -- Secret key fixtures --

const FIXTURE_PASSWORD: &str = "fixture-password";

fn fixture_password() -> Zeroizing<String> {
    Zeroizing::new(FIXTURE_PASSWORD.to_string())
}

/// Loads a secret key fixture, checks its pinned key ID and fingerprint, signs a file with it and verifies the
/// signature against the fixture's public key.
fn check_secret_key_fixture(name: &str, key_id: &str, fingerprint: &str) {
    let sk = format::read_secret_key(&repo(&format!("tests/fixtures/secret-keys/{name}")), fixture_password()).unwrap();
    let pk = format::read_public_key(&repo(&format!("tests/fixtures/secret-keys/{name}.pub"))).unwrap();

    assert_eq!(sk.key_id().to_string(), key_id);
    assert_eq!(pk.key_id().to_string(), key_id);
    assert_eq!(sk.fingerprint().to_string(), fingerprint);
    assert_eq!(pk.fingerprint().to_string(), fingerprint);

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("message.txt");
    fs::write(&file, b"signed with a fixture key").unwrap();
    let sig = sk.sign(&file, "fixture").unwrap();
    assert_eq!(sig.format(), SignatureFormat::V2);
    sig.verify(&pk, &file).unwrap();
}

/// A secret key in format v1 written by pqsign 0.3.1, the last release that writes that format.
#[test]
fn test_v1_secret_key_fixture_signs() {
    check_secret_key_fixture("v1.key", "EF0338D2AB2146C6", "BLAKE2b-256:7wM40qshRsa+M1qXLcRWaXc1mvYu6PDv6Kf6UhQDFYE");
}

/// A secret key in format v1 written by pqsign 0.1.1, which writes the same files as 0.1.0. Keys of that time
/// have a random key ID rather than the start of their fingerprint, and the default Argon2id parameters, so this
/// test takes about 0.4 s.
#[test]
fn test_v1_random_id_secret_key_fixture_signs() {
    let fingerprint = "BLAKE2b-256:bOzpMPaanVm/F1w77nNsBz8a/ZBdmt+p+AN3m4QbZrw";
    check_secret_key_fixture("v1-random-id.key", "0757CD16490BE8FF", fingerprint);

    let pk = format::read_public_key(&repo("tests/fixtures/secret-keys/v1-random-id.key.pub")).unwrap();
    assert_ne!(pk.key_id(), pk.fingerprint().key_id());
}

/// The header is not authenticated, so a changed header key ID still decrypts. The key ID stored inside the
/// format v1 payload must then catch it.
#[test]
fn test_v1_secret_key_header_key_id_mismatch_is_rejected() {
    let mut data = fs::read(repo("tests/fixtures/secret-keys/v1.key")).unwrap();
    for byte in &mut data[6..14] {
        *byte ^= 0x01;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tampered.key");
    fs::write(&path, &data).unwrap();

    match format::read_secret_key(&path, fixture_password()) {
        Err(Error::Crypto(msg)) => assert!(msg.contains("decrypted key ID doesn't match header"), "got: {msg}"),
        Err(other) => panic!("expected the key ID mismatch, got: {other}"),
        Ok(_) => panic!("a key with a changed header key ID was loaded"),
    }
}

/// A secret key in format v2, written once when the format was introduced. Every later version must load it to
/// the same key, so a change in how a seed becomes a key fails here.
#[test]
fn test_v2_secret_key_fixture_signs() {
    let path = repo("tests/fixtures/secret-keys/v2.key");
    assert_eq!(fs::metadata(&path).unwrap().len(), 151);
    check_secret_key_fixture("v2.key", "005D87F817789998", "BLAKE2b-256:AF2H+Bd4mZjatXH099oBMQFnU4+6QwLGi5XVul4ekm0");
}

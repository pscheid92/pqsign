//! Committed files that must keep working across releases.

use std::fs;
use std::path::{Path, PathBuf};

use pqsign::domain::SignatureFormat;
use pqsign::format;

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
    let docs = ["README.md", "docs/install.md"];
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

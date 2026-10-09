use std::io::Cursor;

use fips204::traits::SerDes;
use zeroize::Zeroizing;

use super::*;
use crate::domain::KeyPair;
use crate::errors::Error;

// -- Codec tests --

#[test]
fn test_codec_u8_roundtrip() {
    let mut buf = Vec::new();
    super::write_u8(&mut buf, 0xAB).unwrap();
    let mut r = Cursor::new(buf.as_slice());
    assert_eq!(super::read_u8(&mut r).unwrap(), 0xAB);
}

#[test]
fn test_codec_u32_le_roundtrip() {
    let mut buf = Vec::new();
    super::write_u32_le(&mut buf, 0xDEADBEEF).unwrap();
    let mut r = Cursor::new(buf.as_slice());
    assert_eq!(super::read_u32_le(&mut r).unwrap(), 0xDEADBEEF);
}

#[test]
fn test_codec_u64_le_roundtrip() {
    let mut buf = Vec::new();
    super::write_u64_le(&mut buf, 0x0102030405060708).unwrap();
    let mut r = Cursor::new(buf.as_slice());
    assert_eq!(super::read_u64_le(&mut r).unwrap(), 0x0102030405060708);
}

#[test]
fn test_codec_array_roundtrip() {
    let mut buf = Vec::new();
    super::write_all(&mut buf, &[1, 2, 3, 4]).unwrap();
    let mut r = Cursor::new(buf.as_slice());
    let arr: [u8; 4] = super::read_exact_array(&mut r).unwrap();
    assert_eq!(arr, [1, 2, 3, 4]);
}

#[test]
fn test_codec_vec_roundtrip() {
    let mut buf = Vec::new();
    super::write_all(&mut buf, &[10, 20, 30]).unwrap();
    let mut r = Cursor::new(buf.as_slice());
    let v = super::read_vec(&mut r, 3).unwrap();
    assert_eq!(v, vec![10, 20, 30]);
}

// -- Header tests --

#[test]
fn test_header_roundtrip() {
    use crate::domain::KeyId;
    let key_id = KeyId([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    let header = FileHeader::new(FileType::SecretKey, key_id);

    let mut buf = Vec::new();
    header.write_to(&mut buf).unwrap();

    let mut r = Cursor::new(buf.as_slice());
    let h2 = FileHeader::read(&mut r).unwrap();
    assert_eq!(h2.version, 1);
    assert_eq!(h2.file_type, FileType::SecretKey);
    assert_eq!(h2.key_id, key_id);
}

#[test]
fn test_header_wrong_magic() {
    let data = b"NOPE\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut r = Cursor::new(data.as_slice());
    let err = FileHeader::read(&mut r).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

#[test]
fn test_header_unsupported_version() {
    let data = b"PQSN\x99\x01\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut r = Cursor::new(data.as_slice());
    let err = FileHeader::read(&mut r).unwrap_err();
    match err {
        Error::InvalidFormat(msg) => assert!(msg.contains("format v"), "got: {msg}"),
        other => panic!("expected InvalidFormat, got: {other}"),
    }
}

#[test]
fn test_header_unknown_type() {
    let data = b"PQSN\x01\xFF\x00\x00\x00\x00\x00\x00\x00\x00";
    let mut r = Cursor::new(data.as_slice());
    let err = FileHeader::read(&mut r).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

// -- Public key tests --

#[test]
fn test_public_key_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pub");
    let (_, pk) = KeyPair::new().into_parts();

    write_public_key(&path, &pk).unwrap();
    let pk2 = read_public_key(&path).unwrap();

    assert_eq!(pk.key_id, pk2.key_id);
    assert_eq!(pk.ed25519.to_bytes(), pk2.ed25519.to_bytes());
    assert_eq!(pk.mldsa65.clone().into_bytes(), pk2.mldsa65.clone().into_bytes());
}

#[test]
fn test_public_key_is_single_text_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pub");
    let (_, pk) = KeyPair::new().into_parts();

    write_public_key(&path, &pk).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();

    assert!(content.starts_with("pqsign:v1:"));
    assert_eq!(content.lines().count(), 1);
}

#[test]
fn test_public_key_read_from_string() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.pub");
    let (_, pk) = KeyPair::new().into_parts();

    write_public_key(&path, &pk).unwrap();
    let content = std::fs::read_to_string(&path).unwrap();
    let pk2 = read_public_key_string(&content).unwrap();

    assert_eq!(pk.key_id, pk2.key_id);
}

#[test]
fn test_public_key_missing_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.pub");
    std::fs::write(&path, "not-a-pqsign-key\n").unwrap();

    assert!(matches!(read_public_key(&path), Err(Error::InvalidFormat(_))));
}

#[test]
fn test_public_key_wrong_version_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.pub");
    std::fs::write(&path, "pqsign:v2:AAAA\n").unwrap();

    match read_public_key(&path) {
        Err(Error::InvalidFormat(msg)) => assert!(msg.contains("newer version"), "got: {msg}"),
        Err(other) => panic!("expected InvalidFormat, got: {other}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

#[test]
fn test_public_key_invalid_base64() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.pub");
    std::fs::write(&path, "pqsign:v1:!!!not-base64!!!\n").unwrap();

    assert!(matches!(read_public_key(&path), Err(Error::Base64(_))));
}

// -- Secret key tests --

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.into())
}

#[test]
fn test_secret_key_roundtrip_with_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let (sk, _) = KeyPair::new().into_parts();

    write_secret_key(&path, &sk, pw("test-password")).unwrap();
    let sk2 = read_secret_key(&path, pw("test-password")).unwrap();

    assert_eq!(sk.key_id, sk2.key_id);
    assert_eq!(sk.ed25519.to_bytes(), sk2.ed25519.to_bytes());
    assert_eq!(sk.mldsa65.clone().into_bytes(), sk2.mldsa65.clone().into_bytes());
}

#[test]
fn test_secret_key_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let (sk, _) = KeyPair::new().into_parts();

    write_secret_key(&path, &sk, pw("correct")).unwrap();
    assert!(matches!(read_secret_key(&path, pw("wrong")), Err(Error::WrongPassword)));
}

#[test]
fn test_secret_key_is_raw_binary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let (sk, _) = KeyPair::new().into_parts();

    write_secret_key(&path, &sk, pw("test")).unwrap();
    let data = std::fs::read(&path).unwrap();

    assert_eq!(&data[0..4], b"PQSN");
}

// -- Signature tests --

#[test]
fn test_signature_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test data").unwrap();
    let sig_path = dir.path().join("test.txt.pqsig");

    let (sk, _) = KeyPair::new().into_parts();
    let sig = sk.sign(&file, "test comment").unwrap();

    write_signature(&sig_path, &sig).unwrap();
    let sig2 = read_signature(&sig_path).unwrap();

    assert_eq!(sig.key_id, sig2.key_id);
    assert_eq!(sig.ed25519, sig2.ed25519);
    assert_eq!(sig.trusted_comment, sig2.trusted_comment);
}

#[test]
fn test_signature_is_raw_binary() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test data").unwrap();
    let sig_path = dir.path().join("test.txt.pqsig");

    let (sk, _) = KeyPair::new().into_parts();
    let sig = sk.sign(&file, "test comment").unwrap();

    write_signature(&sig_path, &sig).unwrap();
    let data = std::fs::read(&sig_path).unwrap();

    assert_eq!(&data[0..4], b"PQSN");
}

#[test]
fn test_trusted_comment_too_long() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test data").unwrap();
    let sig_path = dir.path().join("test.txt.pqsig");

    let (sk, _) = KeyPair::new().into_parts();
    let long_comment = "x".repeat(1025);
    let sig = sk.sign(&file, &long_comment).unwrap();

    let err = write_signature(&sig_path, &sig).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

#[test]
fn test_trusted_comment_at_exact_max_length() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test data").unwrap();
    let sig_path = dir.path().join("test.txt.pqsig");

    let (sk, _) = KeyPair::new().into_parts();
    let comment = "x".repeat(1024);
    let sig = sk.sign(&file, &comment).unwrap();

    write_signature(&sig_path, &sig).unwrap();
    let sig2 = read_signature(&sig_path).unwrap();
    assert_eq!(sig2.trusted_comment, comment);
}

// -- Codec error paths --

#[test]
fn test_codec_read_u8_truncated() {
    let mut r = Cursor::new(&[] as &[u8]);
    let err = super::read_u8(&mut r).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

#[test]
fn test_codec_read_u32_truncated() {
    let mut r = Cursor::new(&[0x01u8, 0x02] as &[u8]);
    let err = super::read_u32_le(&mut r).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

#[test]
fn test_codec_read_u64_truncated() {
    let mut r = Cursor::new(&[0x01u8, 0x02, 0x03, 0x04] as &[u8]);
    let err = super::read_u64_le(&mut r).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

#[test]
fn test_codec_read_vec_truncated() {
    let mut r = Cursor::new(&[0x01u8] as &[u8]);
    let err = super::read_vec(&mut r, 10).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

#[test]
fn test_codec_read_exact_array_truncated() {
    let mut r = Cursor::new(&[0x01u8, 0x02] as &[u8]);
    let err: Result<[u8; 8], _> = super::read_exact_array(&mut r);
    assert!(matches!(err, Err(Error::InvalidFormat(_))));
}

// -- Header error paths --

#[test]
fn test_header_truncated_magic() {
    let mut r = Cursor::new(b"PQ" as &[u8]);
    let err = FileHeader::read(&mut r).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

#[test]
fn test_header_truncated_after_magic() {
    let mut r = Cursor::new(b"PQSN" as &[u8]);
    let err = FileHeader::read(&mut r).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

// -- KDF unknown algorithm --

#[test]
fn test_kdf_unknown_algorithm() {
    let mut data = vec![0xFF];
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    let mut r = Cursor::new(data.as_slice());

    let err = super::kdf::read_from(&mut r).unwrap_err();
    match err {
        Error::InvalidFormat(msg) => assert!(msg.contains("unknown KDF"), "got: {msg}"),
        other => panic!("expected InvalidFormat, got: {other}"),
    }
}

// -- Public key: decode truncated binary --

#[test]
fn test_public_key_truncated_base64() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.pub");
    std::fs::write(&path, "pqsign:v1:AQID\n").unwrap();

    assert!(matches!(read_public_key(&path), Err(Error::InvalidFormat(_))));
}

// -- Public key: wrong file type in binary decode --

#[test]
fn test_public_key_wrong_file_type_in_binary() {
    use crate::domain::KeyId;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.pub");

    let key_id = KeyId([1, 2, 3, 4, 5, 6, 7, 8]);
    let mut blob = Vec::new();
    FileHeader::new(FileType::SecretKey, key_id).write_to(&mut blob).unwrap();
    blob.extend_from_slice(&[0u8; 4096]);

    let line = format!("pqsign:v1:{}\n", STANDARD.encode(&blob));
    std::fs::write(&path, line).unwrap();

    match read_public_key(&path) {
        Err(Error::InvalidFormat(msg)) => {
            assert!(msg.contains("expected public key"), "got: {msg}")
        }
        Err(other) => panic!("expected InvalidFormat, got: {other}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

// -- Wrong file type errors --

#[test]
fn test_read_secret_key_on_signature_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test data").unwrap();
    let sig_path = dir.path().join("test.txt.pqsig");

    let (sk, _) = KeyPair::new().into_parts();
    let sig = sk.sign(&file, "test").unwrap();
    write_signature(&sig_path, &sig).unwrap();

    assert!(matches!(read_secret_key(&sig_path, pw("test")), Err(Error::InvalidFormat(_))));
}

#[test]
fn test_read_signature_on_secret_key_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let (sk, _) = KeyPair::new().into_parts();
    write_secret_key(&sk_path, &sk, pw("test")).unwrap();

    assert!(matches!(read_signature(&sk_path), Err(Error::InvalidFormat(_))));
}

#[test]
fn test_read_public_key_text_on_secret_key_binary_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let (sk, _) = KeyPair::new().into_parts();
    write_secret_key(&sk_path, &sk, pw("test")).unwrap();

    assert!(read_public_key(&sk_path).is_err());
}

// -- Inspect: binary public key path --

#[test]
fn test_inspect_binary_public_key_file() {
    use super::inspect::inspect_file;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary.pub");
    let (_, pk) = KeyPair::new().into_parts();
    std::fs::write(&path, super::public_key::encode(&pk).unwrap()).unwrap();

    match inspect_file(&path).unwrap() {
        super::inspect::FileInfo::PublicKey { key_id, fingerprint } => {
            assert_eq!(key_id, pk.key_id());
            assert_eq!(fingerprint, pk.fingerprint());
        }
        other => panic!("expected PublicKey, got: {other}"),
    }
}

#[test]
fn test_inspect_binary_public_key_header_only_fails() {
    use crate::domain::KeyId;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary.pub");
    let mut buf = Vec::new();
    FileHeader::new(FileType::PublicKey, KeyId([1, 2, 3, 4, 5, 6, 7, 8]))
        .write_to(&mut buf)
        .unwrap();
    buf.extend_from_slice(&[0u8; 64]);
    std::fs::write(&path, &buf).unwrap();

    assert!(matches!(inspect_file(&path), Err(Error::InvalidFormat(_))));
}

// -- Secret key: truncated or padded files --

#[test]
fn test_secret_key_wrong_length_detected_before_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let (sk, _) = KeyPair::new().into_parts();
    write_secret_key(&path, &sk, pw("test")).unwrap();
    let data = std::fs::read(&path).unwrap();

    let truncated = &data[..512];
    let padded = [data.as_slice(), b"extra"].concat();
    for corrupt in [truncated, padded.as_slice()] {
        std::fs::write(&path, corrupt).unwrap();
        let result = read_secret_key_with(&path, |_| panic!("password requested for a corrupt key file"));
        match result {
            Err(Error::InvalidFormat(msg)) => assert!(msg.contains("truncated or corrupt"), "got: {msg}"),
            Err(other) => panic!("expected InvalidFormat, got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}

// -- Bounded reads --

#[test]
fn test_readers_reject_large_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    std::fs::write(&path, vec![0u8; 1024 * 1024]).unwrap();

    assert!(matches!(read_signature(&path), Err(Error::InvalidFormat(_))));
    assert!(matches!(read_public_key(&path), Err(Error::InvalidFormat(_))));
    assert!(matches!(inspect_file(&path), Err(Error::InvalidFormat(_))));
    let secret_key = read_secret_key_with(&path, |_| panic!("password requested for a file that is not a key"));
    assert!(matches!(secret_key, Err(Error::InvalidFormat(_))));
}

// -- Trusted comment rules --

#[test]
fn test_trusted_comment_allowed_characters() {
    check_trusted_comment("timestamp:1791562322\tfile:app.tar.gz\trelease v1.0 für März 🚀").unwrap();
    check_trusted_comment("").unwrap();
}

#[test]
fn test_trusted_comment_forbidden_characters() {
    for bad in [
        "\x1b[2K",
        "a\rb",
        "a\nb",
        "\0",
        "\x7f",
        "\u{85}",
        "\u{9b}31m",
        "invoice\u{202e}fdp.exe",
        "\u{202a}",
        "\u{2066}x\u{2069}",
    ] {
        match check_trusted_comment(bad) {
            Err(Error::InvalidFormat(msg)) => assert!(msg.contains("forbidden character"), "got: {msg}"),
            other => panic!("expected InvalidFormat for {bad:?}, got: {:?}", other.err().map(|e| e.to_string())),
        }
    }
}

#[test]
fn test_escape_comment_field() {
    assert_eq!(escape_comment_field("app.tar.gz"), "app.tar.gz");
    assert_eq!(escape_comment_field("Bericht für März.pdf"), "Bericht für März.pdf");
    assert_eq!(escape_comment_field("a\tfile:b"), "a\\tfile:b");
    assert_eq!(escape_comment_field("line\nbreak"), "line\\nbreak");
    assert_eq!(escape_comment_field("invoice\u{202e}fdp.exe"), "invoice\\u{202e}fdp.exe");
    assert_eq!(escape_comment_field("back\\slash"), "back\\\\slash");
    assert_eq!(escape_comment_field("\x1b[2K"), "\\u{1b}[2K");

    for name in ["a\tb\nc\u{202e}d\x1b", "plain"] {
        check_trusted_comment(&escape_comment_field(name)).unwrap();
    }
}

#[test]
fn test_write_signature_rejects_forbidden_comment() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test data").unwrap();

    let (sk, _) = KeyPair::new().into_parts();
    let sig = sk.sign(&file, "bad\x1b[2K").unwrap();

    let err = write_signature(&dir.path().join("test.txt.pqsig"), &sig).unwrap_err();
    assert!(matches!(err, Error::InvalidFormat(_)));
}

#[test]
fn test_read_signature_rejects_forbidden_comment() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    let sig_path = dir.path().join("test.txt.pqsig");
    std::fs::write(&file, b"test data").unwrap();

    let (sk, _) = KeyPair::new().into_parts();
    write_signature(&sig_path, &sk.sign(&file, "abcd").unwrap()).unwrap();

    // The comment is the last field; replace it in place with one of the same length.
    let mut data = std::fs::read(&sig_path).unwrap();
    let len = data.len();
    data[len - 4..].copy_from_slice(b"a\x1b[K");
    std::fs::write(&sig_path, &data).unwrap();

    for result in [read_signature(&sig_path).map(|_| ()), inspect_file(&sig_path).map(|_| ())] {
        match result {
            Err(Error::InvalidFormat(msg)) => assert!(msg.contains("forbidden character"), "got: {msg}"),
            Err(other) => panic!("expected InvalidFormat, got: {other}"),
            Ok(()) => panic!("expected error, got Ok"),
        }
    }
}

// -- Signature format v2 --

fn signed_test_file() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test data").unwrap();
    let sig_path = dir.path().join("test.txt.pqsig");
    (dir, file, sig_path)
}

fn invalid_format_message<T>(result: Result<T, Error>) -> String {
    match result {
        Err(Error::InvalidFormat(msg)) => msg,
        Err(other) => panic!("expected InvalidFormat, got: {other}"),
        Ok(_) => panic!("expected an error, got Ok"),
    }
}

#[test]
fn test_signature_v2_roundtrip_and_layout() {
    use crate::domain::SignatureFormat;

    let (_dir, file, sig_path) = signed_test_file();
    let (sk, pk) = KeyPair::new().into_parts();
    write_signature(&sig_path, &sk.sign(&file, "comment").unwrap()).unwrap();

    let data = std::fs::read(&sig_path).unwrap();
    assert_eq!(data[4], 2, "header version");
    assert_eq!(data[14], crate::domain::signature::SUITE_ED25519_MLDSA65, "suite");
    assert_eq!(&data[15..47], pk.fingerprint().as_bytes(), "signer fingerprint");

    let sig = read_signature(&sig_path).unwrap();
    assert_eq!(sig.format(), SignatureFormat::V2);
    assert_eq!(sig.signer(), Some(pk.fingerprint()));
    assert_eq!(sig.trusted_comment, "comment");
    sig.verify(&pk, &file).unwrap();
}

#[test]
fn test_signature_v1_written_on_request() {
    use crate::domain::SignatureFormat;

    let (_dir, file, sig_path) = signed_test_file();
    let (sk, pk) = KeyPair::new().into_parts();
    write_signature(&sig_path, &sk.sign_as(&file, "comment", SignatureFormat::V1).unwrap()).unwrap();

    assert_eq!(std::fs::read(&sig_path).unwrap()[4], 1, "header version");
    let sig = read_signature(&sig_path).unwrap();
    assert_eq!(sig.format(), SignatureFormat::V1);
    assert_eq!(sig.signer(), None);
    sig.verify(&pk, &file).unwrap();
}

#[test]
fn test_signature_unknown_suite_is_rejected() {
    let (_dir, file, sig_path) = signed_test_file();
    let (sk, _) = KeyPair::new().into_parts();
    write_signature(&sig_path, &sk.sign(&file, "comment").unwrap()).unwrap();

    let mut data = std::fs::read(&sig_path).unwrap();
    data[14] = 0x7F;
    std::fs::write(&sig_path, &data).unwrap();

    let msg = invalid_format_message(read_signature(&sig_path));
    assert!(msg.contains("algorithm suite 0x7f"), "got: {msg}");
}

#[test]
fn test_signature_v2_rejects_trailing_data() {
    let (_dir, file, sig_path) = signed_test_file();
    let (sk, _) = KeyPair::new().into_parts();
    write_signature(&sig_path, &sk.sign(&file, "comment").unwrap()).unwrap();

    let mut data = std::fs::read(&sig_path).unwrap();
    data.extend_from_slice(b"extra");
    std::fs::write(&sig_path, &data).unwrap();

    let msg = invalid_format_message(read_signature(&sig_path));
    assert!(msg.contains("unexpected data"), "got: {msg}");
}

/// Changing the version byte must never turn a signature of one format into a valid one of the other.
#[test]
fn test_signature_relabelled_version_does_not_verify() {
    use crate::domain::SignatureFormat;

    let (_dir, file, sig_path) = signed_test_file();
    let (sk, pk) = KeyPair::new().into_parts();

    for (format, relabel) in [(SignatureFormat::V2, 1u8), (SignatureFormat::V1, 2u8)] {
        write_signature(&sig_path, &sk.sign_as(&file, "comment", format).unwrap()).unwrap();
        let mut data = std::fs::read(&sig_path).unwrap();
        data[4] = relabel;
        std::fs::write(&sig_path, &data).unwrap();

        let result = read_signature(&sig_path).and_then(|sig| sig.verify(&pk, &file));
        assert!(result.is_err(), "{format} signature relabelled as v{relabel} verified");
    }
}

#[test]
fn test_header_rejects_version_zero() {
    let data = b"PQSN\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00";
    let msg = invalid_format_message(FileHeader::read(&mut Cursor::new(data.as_slice())));
    assert!(msg.contains("version 0"), "got: {msg}");
}

/// Each file type has its own newest version: v2 is fine for signatures but too new for keys.
#[test]
fn test_header_versions_are_per_file_type() {
    let key_v2 = b"PQSN\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00";
    let msg = invalid_format_message(FileHeader::read(&mut Cursor::new(key_v2.as_slice())));
    assert!(msg.contains("requires pqsign format v2, this build supports v1"), "got: {msg}");

    let sig_v2 = b"PQSN\x02\x03\x00\x00\x00\x00\x00\x00\x00\x00";
    assert_eq!(FileHeader::read(&mut Cursor::new(sig_v2.as_slice())).unwrap().version, 2);

    let sig_v3 = b"PQSN\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00";
    let msg = invalid_format_message(FileHeader::read(&mut Cursor::new(sig_v3.as_slice())));
    assert!(msg.contains("requires pqsign format v3, this build supports v2"), "got: {msg}");
}

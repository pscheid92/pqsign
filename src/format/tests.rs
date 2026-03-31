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
    assert_eq!(
        pk.mldsa65.clone().into_bytes(),
        pk2.mldsa65.clone().into_bytes()
    );
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

    assert!(matches!(
        read_public_key(&path),
        Err(Error::InvalidFormat(_))
    ));
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
    assert_eq!(
        sk.mldsa65.clone().into_bytes(),
        sk2.mldsa65.clone().into_bytes()
    );
}

#[test]
fn test_secret_key_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let (sk, _) = KeyPair::new().into_parts();

    write_secret_key(&path, &sk, pw("correct")).unwrap();
    assert!(matches!(
        read_secret_key(&path, pw("wrong")),
        Err(Error::WrongPassword)
    ));
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

    assert!(matches!(
        read_public_key(&path),
        Err(Error::InvalidFormat(_))
    ));
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
    FileHeader::new(FileType::SecretKey, key_id)
        .write_to(&mut blob)
        .unwrap();
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

    assert!(matches!(
        read_secret_key(&sig_path, pw("test")),
        Err(Error::InvalidFormat(_))
    ));
}

#[test]
fn test_read_signature_on_secret_key_file_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    let (sk, _) = KeyPair::new().into_parts();
    write_secret_key(&sk_path, &sk, pw("test")).unwrap();

    assert!(matches!(
        read_signature(&sk_path),
        Err(Error::InvalidFormat(_))
    ));
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
    use crate::domain::KeyId;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary.pub");
    let key_id = KeyId([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);

    let mut buf = Vec::new();
    FileHeader::new(FileType::PublicKey, key_id)
        .write_to(&mut buf)
        .unwrap();
    buf.extend_from_slice(&[0u8; 64]);
    std::fs::write(&path, &buf).unwrap();

    let info = inspect_file(&path).unwrap();
    match info {
        super::inspect::FileInfo::PublicKey { key_id: id } => {
            assert_eq!(id, key_id);
        }
        other => panic!("expected PublicKey, got: {other}"),
    }
}

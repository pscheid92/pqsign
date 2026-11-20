use std::ffi::OsStr;
use std::io::Cursor;

use fips204::traits::SerDes;
use zeroize::Zeroizing;

use super::*;
use crate::domain::{KeyPair, SecretSeeds};
use crate::errors::Error;

// -- Codec tests --

#[test]
fn test_codec_u8_roundtrip() {
    let mut buf = Vec::new();
    super::write_u8(&mut buf, 0xAB);
    let mut r = Cursor::new(buf.as_slice());
    assert_eq!(super::read_u8(&mut r).unwrap(), 0xAB);
}

#[test]
fn test_codec_u32_le_roundtrip() {
    let mut buf = Vec::new();
    super::write_u32_le(&mut buf, 0xDEADBEEF);
    let mut r = Cursor::new(buf.as_slice());
    assert_eq!(super::read_u32_le(&mut r).unwrap(), 0xDEADBEEF);
}

#[test]
fn test_codec_u64_le_roundtrip() {
    let mut buf = Vec::new();
    super::write_u64_le(&mut buf, 0x0102030405060708);
    let mut r = Cursor::new(buf.as_slice());
    assert_eq!(super::read_u64_le(&mut r).unwrap(), 0x0102030405060708);
}

#[test]
fn test_codec_array_roundtrip() {
    let mut buf = Vec::new();
    super::write_all(&mut buf, &[1, 2, 3, 4]);
    let mut r = Cursor::new(buf.as_slice());
    let arr: [u8; 4] = super::read_exact_array(&mut r).unwrap();
    assert_eq!(arr, [1, 2, 3, 4]);
}

#[test]
fn test_codec_vec_roundtrip() {
    let mut buf = Vec::new();
    super::write_all(&mut buf, &[10, 20, 30]);
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
    header.write_to(&mut buf);

    let mut r = Cursor::new(buf.as_slice());
    let h2 = FileHeader::read(&mut r).unwrap();
    assert_eq!(h2.version, 2);
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

    assert_eq!(pk.to_parts(), pk2.to_parts());
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

    assert_eq!(pk.key_id(), pk2.key_id());
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

/// Small Argon2id parameters, so tests do not spend their time deriving keys. `generate` always uses the defaults.
const TEST_KDF: Kdf = Kdf::Argon2id {
    mem_limit: 64 * 1024,
    ops_limit: 1,
};

#[test]
fn test_secret_key_roundtrip_with_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let seeds = SecretSeeds::generate();
    let (sk, _) = seeds.key_pair().into_parts();

    write_secret_key(&path, &seeds, pw("test-password"), &TEST_KDF).unwrap();
    let sk2 = read_secret_key(&path, pw("test-password")).unwrap();

    assert_eq!(sk.key_id, sk2.key_id);
    assert_eq!(sk.fingerprint(), sk2.fingerprint());
    assert_eq!(sk.ed25519.to_bytes(), sk2.ed25519.to_bytes());
    assert_eq!(sk.mldsa65.clone().into_bytes(), sk2.mldsa65.clone().into_bytes());
}

#[test]
fn test_secret_key_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let seeds = SecretSeeds::generate();

    write_secret_key(&path, &seeds, pw("correct"), &TEST_KDF).unwrap();
    assert!(matches!(read_secret_key(&path, pw("wrong")), Err(Error::WrongPassword)));
}

#[test]
fn test_secret_key_records_its_kdf_parameters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let seeds = SecretSeeds::generate();

    let kdf = Kdf::Argon2id {
        mem_limit: 128 * 1024,
        ops_limit: 2,
    };
    write_secret_key(&path, &seeds, pw("test"), &kdf).unwrap();

    let mut recorded = None;
    read_secret_key_with(&path, |kdf| {
        recorded = Some(*kdf);
        Ok(pw("test"))
    })
    .unwrap();
    assert_eq!(recorded, Some(kdf));
}

/// pqsign never writes a key it would refuse to read.
#[test]
fn test_secret_key_write_rejects_invalid_kdf_parameters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let seeds = SecretSeeds::generate();

    let cases = [
        (2048 * 1024 * 1024, 3, "asks for 2048 MiB of Argon2id memory"),
        (64 * 1024, 17, "asks for 17 Argon2id iterations"),
        (64 * 1024, 0, "invalid Argon2id parameters"),
    ];
    for (mem_limit, ops_limit, expected) in cases {
        let kdf = Kdf::Argon2id { mem_limit, ops_limit };
        match write_secret_key(&path, &seeds, pw("test"), &kdf) {
            Err(Error::InvalidFormat(msg)) => assert!(msg.contains(expected), "got: {msg}"),
            Err(other) => panic!("expected InvalidFormat, got: {other}"),
            Ok(()) => panic!("expected an error for {kdf:?}"),
        }
        assert!(!path.exists());
    }
}

#[test]
fn test_secret_key_is_raw_binary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let seeds = SecretSeeds::generate();

    write_secret_key(&path, &seeds, pw("test"), &TEST_KDF).unwrap();
    let data = std::fs::read(&path).unwrap();

    assert_eq!(&data[0..4], b"PQSN");
    assert!(std::str::from_utf8(&data).is_err(), "a secret key file is binary, not text");
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

/// Only 0x02, Argon2id, is defined. 0x01 is Argon2i in libsodium's numbering and stays unused.
#[test]
fn test_kdf_unknown_algorithm() {
    for byte in [0x00, 0x01, 0xFF] {
        let mut data = vec![byte];
        data.extend_from_slice(&(256u64 * 1024 * 1024).to_le_bytes());
        data.extend_from_slice(&3u64.to_le_bytes());
        let mut r = Cursor::new(data.as_slice());

        let err = super::kdf::read_from(&mut r).unwrap_err();
        match err {
            Error::InvalidFormat(msg) => assert!(msg.contains(&format!("unknown KDF algorithm: 0x{byte:02x}")), "got: {msg}"),
            other => panic!("expected InvalidFormat, got: {other}"),
        }
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
    // Version 1, so the text form's version check passes and the file type check is what fails.
    let header = FileHeader {
        version: 1,
        file_type: FileType::SecretKey,
        key_id,
    };
    header.write_to(&mut blob);
    blob.extend_from_slice(&[0u8; 4096]);

    let line = format!("pqsign:v1:{}\n", STANDARD.encode(&blob));
    std::fs::write(&path, line).unwrap();

    match read_public_key(&path) {
        Err(Error::InvalidFormat(msg)) => {
            assert!(msg.contains("expected a public key file, got a secret key file"), "got: {msg}")
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
    write_secret_key(&sk_path, &SecretSeeds::generate(), pw("test"), &TEST_KDF).unwrap();

    assert!(matches!(read_signature(&sk_path), Err(Error::InvalidFormat(_))));
}

#[test]
fn test_read_public_key_text_on_secret_key_binary_fails() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    write_secret_key(&sk_path, &SecretSeeds::generate(), pw("test"), &TEST_KDF).unwrap();

    let result = read_public_key(&sk_path);
    assert!(matches!(result, Err(Error::InvalidFormat(_))), "got: {:?}", result.err());
}

// -- Inspect: binary public key path --

#[test]
fn test_inspect_binary_public_key_file() {
    use super::inspect::inspect_file;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary.pub");
    let (_, pk) = KeyPair::new().into_parts();
    std::fs::write(&path, super::public_key::encode(&pk)).unwrap();

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
    FileHeader::new(FileType::PublicKey, KeyId([1, 2, 3, 4, 5, 6, 7, 8])).write_to(&mut buf);
    buf.extend_from_slice(&[0u8; 64]);
    std::fs::write(&path, &buf).unwrap();

    assert!(matches!(inspect_file(&path), Err(Error::InvalidFormat(_))));
}

// -- Secret key format v2 --

/// The format v1 fixture written by pqsign 0.3.1, password `fixture-password`.
fn v1_fixture() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/secret-keys/v1.key");
    std::fs::read(path).unwrap()
}

#[test]
fn test_secret_key_v2_file_layout() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let seeds = SecretSeeds::generate();
    write_secret_key(&path, &seeds, pw("test"), &TEST_KDF).unwrap();
    let data = std::fs::read(&path).unwrap();

    assert_eq!(data.len(), 151);
    let header = FileHeader::read(&mut Cursor::new(data.as_slice())).unwrap();
    assert_eq!(header.version, 2);
    assert_eq!(header.file_type, FileType::SecretKey);
    assert_eq!(header.key_id, seeds.key_pair().public_key.fingerprint().key_id());
}

#[test]
fn test_secret_key_v2_signs_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    let file = dir.path().join("test.txt");
    std::fs::write(&file, b"test data").unwrap();
    let seeds = SecretSeeds::generate();
    write_secret_key(&path, &seeds, pw("test"), &TEST_KDF).unwrap();

    let sk = read_secret_key(&path, pw("test")).unwrap();
    let (_, pk) = seeds.key_pair().into_parts();
    sk.sign(&file, "v2").unwrap().verify(&pk, &file).unwrap();
}

/// The payload length depends on the version, so relabelling a file as the other version fails before the
/// password prompt, although the header is not authenticated.
#[test]
fn test_secret_key_relabelled_version_detected_before_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    write_secret_key(&path, &SecretSeeds::generate(), pw("test"), &TEST_KDF).unwrap();
    let mut v2_as_v1 = std::fs::read(&path).unwrap();
    v2_as_v1[4] = 1;
    let mut v1_as_v2 = v1_fixture();
    v1_as_v2[4] = 2;

    for (claimed, data) in [(1, v2_as_v1), (2, v1_as_v2)] {
        std::fs::write(&path, &data).unwrap();
        let result = read_secret_key_with(&path, |_| panic!("password requested for a relabelled key file"));
        match result {
            Err(Error::InvalidFormat(msg)) => assert!(msg.contains(&format!("for format v{claimed}")), "got: {msg}"),
            Err(other) => panic!("expected InvalidFormat, got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}

/// Format v2 stores no key ID in the payload: the keys made from the seeds must match the header's key ID.
#[test]
fn test_secret_key_v2_header_key_id_mismatch_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    write_secret_key(&path, &SecretSeeds::generate(), pw("test"), &TEST_KDF).unwrap();
    let mut data = std::fs::read(&path).unwrap();
    data[6] ^= 0x01;
    std::fs::write(&path, &data).unwrap();

    match read_secret_key(&path, pw("test")) {
        Err(Error::Crypto(msg)) => {
            assert!(msg.contains("does not match its key ID"), "got: {msg}");
            assert!(msg.contains("restore the file from a backup"), "got: {msg}");
        }
        Err(other) => panic!("expected the key-ID mismatch error, got: {other}"),
        Ok(_) => panic!("a key with a changed header key ID was loaded"),
    }
}

// -- Secret key: truncated or padded files --

#[test]
fn test_secret_key_wrong_length_detected_before_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.key");
    write_secret_key(&path, &SecretSeeds::generate(), pw("test"), &TEST_KDF).unwrap();
    let v2 = std::fs::read(&path).unwrap();

    for (version, data) in [(1, v1_fixture()), (2, v2)] {
        let truncated = &data[..data.len() - 1];
        let padded = [data.as_slice(), b"extra"].concat();
        for corrupt in [truncated, padded.as_slice()] {
            std::fs::write(&path, corrupt).unwrap();
            let result = read_secret_key_with(&path, |_| panic!("password requested for a corrupt key file"));
            match result {
                Err(Error::InvalidFormat(msg)) => {
                    assert!(msg.contains("truncated or corrupt"), "got: {msg}");
                    assert!(msg.contains(&format!("for format v{version}")), "got: {msg}");
                }
                Err(other) => panic!("expected InvalidFormat, got: {other}"),
                Ok(_) => panic!("expected error, got Ok"),
            }
        }
    }
}

// -- Secret key: change password --

const NEW_KDF: Kdf = Kdf::Argon2id {
    mem_limit: 128 * 1024,
    ops_limit: 2,
};

fn kdf_block(kdf: &Kdf) -> Vec<u8> {
    let mut buf = Vec::new();
    kdf::write_to(kdf, &mut buf);
    buf
}

fn v2_key_file(dir: &std::path::Path, password: &str) -> std::path::PathBuf {
    let path = dir.join("test.key");
    write_secret_key(&path, &SecretSeeds::generate(), pw(password), &TEST_KDF).unwrap();
    path
}

#[test]
fn test_change_password_keeps_the_key_and_header() {
    let dir = tempfile::tempdir().unwrap();
    let path = v2_key_file(dir.path(), "old");
    let before = std::fs::read(&path).unwrap();
    let key = read_secret_key(&path, pw("old")).unwrap();

    let changed = change_secret_key_password(&path, |_| Ok(pw("old")), || Ok(pw("new")), &NEW_KDF).unwrap();

    let after = std::fs::read(&path).unwrap();
    assert_eq!(after.len(), 151);
    assert_eq!(after[..FileHeader::LEN], before[..FileHeader::LEN]);
    assert_eq!(after[14..31], kdf_block(&NEW_KDF));
    assert_ne!(after[31..47], before[31..47], "salt");
    assert_ne!(after[47..71], before[47..71], "nonce");

    let reloaded = read_secret_key(&path, pw("new")).unwrap();
    assert_eq!(reloaded.key_id(), key.key_id());
    assert_eq!(reloaded.fingerprint(), key.fingerprint());

    assert_eq!(changed.version, 2);
    assert_eq!(changed.key_id, key.key_id());
    assert_eq!(changed.fingerprint, key.fingerprint());
    assert_eq!(changed.kdf, NEW_KDF);
}

#[test]
fn test_change_password_old_password_fails_afterwards() {
    let dir = tempfile::tempdir().unwrap();
    let path = v2_key_file(dir.path(), "old");

    change_secret_key_password(&path, |_| Ok(pw("old")), || Ok(pw("new")), &TEST_KDF).unwrap();

    assert!(matches!(read_secret_key(&path, pw("old")), Err(Error::WrongPassword)));
}

/// A fresh salt and nonce, also when the password stays the same.
#[test]
fn test_change_password_uses_a_fresh_salt_and_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let path = v2_key_file(dir.path(), "same");
    let before = std::fs::read(&path).unwrap();

    change_secret_key_password(&path, |_| Ok(pw("same")), || Ok(pw("same")), &TEST_KDF).unwrap();

    let after = std::fs::read(&path).unwrap();
    assert_ne!(after[31..47], before[31..47], "salt");
    assert_ne!(after[47..71], before[47..71], "nonce");
    read_secret_key(&path, pw("same")).unwrap();
}

/// A file that fails the checks needing no password gets the same error as from `read_with`, and no password is
/// asked for.
#[test]
fn test_change_password_checks_the_file_before_any_password() {
    let dir = tempfile::tempdir().unwrap();
    let path = v2_key_file(dir.path(), "test");
    let v2 = std::fs::read(&path).unwrap();
    let mut relabelled = v2.clone();
    relabelled[4] = 1;
    let (_, pk) = KeyPair::new().into_parts();
    let pk_path = dir.path().join("test.pub");
    write_public_key(&pk_path, &pk).unwrap();
    let pk_bytes = std::fs::read(&pk_path).unwrap();

    let corrupt = [relabelled, v2[..v2.len() - 1].to_vec(), [v2.as_slice(), b"extra"].concat(), pk_bytes];
    for data in corrupt {
        std::fs::write(&path, &data).unwrap();
        let expected = read_secret_key_with(&path, |_| panic!("password requested")).err().unwrap().to_string();

        let result = change_secret_key_password(
            &path,
            |_| panic!("current password requested"),
            || panic!("new password requested"),
            &TEST_KDF,
        );

        assert_eq!(result.err().unwrap().to_string(), expected);
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }
}

#[test]
fn test_change_password_wrong_current_password_asks_for_no_new_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = v2_key_file(dir.path(), "old");
    let before = std::fs::read(&path).unwrap();

    let result = change_secret_key_password(&path, |_| Ok(pw("wrong")), || panic!("new password requested"), &TEST_KDF);
    assert!(matches!(result, Err(Error::WrongPassword)));

    let result = change_secret_key_password(&path, |_| Err(Error::PasswordEmpty), || panic!("new password requested"), &TEST_KDF);
    assert!(matches!(result, Err(Error::PasswordEmpty)));

    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn test_change_password_failed_new_password_leaves_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = v2_key_file(dir.path(), "old");
    let before = std::fs::read(&path).unwrap();

    let result = change_secret_key_password(&path, |_| Ok(pw("old")), || Err(Error::PasswordMismatch), &TEST_KDF);

    assert!(matches!(result, Err(Error::PasswordMismatch)));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn test_change_password_rejects_invalid_parameters_first() {
    let dir = tempfile::tempdir().unwrap();
    let path = v2_key_file(dir.path(), "old");
    let before = std::fs::read(&path).unwrap();
    let invalid = Kdf::Argon2id {
        mem_limit: 64 * 1024,
        ops_limit: 17,
    };

    let result = change_secret_key_password(
        &path,
        |_| panic!("current password requested"),
        || panic!("new password requested"),
        &invalid,
    );

    match result {
        Err(Error::InvalidFormat(msg)) => assert!(msg.contains("17 Argon2id iterations"), "got: {msg}"),
        Err(other) => panic!("expected InvalidFormat, got: {other}"),
        Ok(_) => panic!("invalid parameters were accepted"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

/// Stands in for `generate --overwrite` running while `change-password` waits at the new-password prompt: the
/// other file must stay, rather than the old key being written back over it.
#[test]
fn test_change_password_stops_when_the_file_changed_meanwhile() {
    let dir = tempfile::tempdir().unwrap();
    let path = v2_key_file(dir.path(), "old");
    let other = dir.path().join("other.key");
    write_secret_key(&other, &SecretSeeds::generate(), pw("other"), &TEST_KDF).unwrap();
    let other_bytes = std::fs::read(&other).unwrap();

    let result = change_secret_key_password(
        &path,
        |_| Ok(pw("old")),
        || {
            std::fs::write(&path, &other_bytes).unwrap();
            Ok(pw("new"))
        },
        &TEST_KDF,
    );

    match result {
        Err(err @ Error::KeyFileChanged(_)) => assert!(err.to_string().contains("nothing was written"), "got: {err}"),
        Err(other) => panic!("expected KeyFileChanged, got: {other}"),
        Ok(_) => panic!("the old key was written over a changed file"),
    }
    assert_eq!(std::fs::read(&path).unwrap(), other_bytes);
}

#[test]
fn test_kdf_display() {
    assert_eq!(Kdf::argon2id().to_string(), "Argon2id, 256 MiB, 3 passes");
    assert_eq!(TEST_KDF.to_string(), "Argon2id, 64 KiB, 1 pass");
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
fn test_escape_file_name_escapes_comment_field_characters() {
    assert_eq!(escape_file_name(OsStr::new("app.tar.gz")), "app.tar.gz");
    assert_eq!(escape_file_name(OsStr::new("Bericht für März.pdf")), "Bericht für März.pdf");
    assert_eq!(escape_file_name(OsStr::new("a\tfile:b")), "a\\tfile:b");
    assert_eq!(escape_file_name(OsStr::new("line\nbreak")), "line\\nbreak");
    assert_eq!(escape_file_name(OsStr::new("invoice\u{202e}fdp.exe")), "invoice\\u{202e}fdp.exe");
    assert_eq!(escape_file_name(OsStr::new("back\\slash")), "back\\\\slash");
    assert_eq!(escape_file_name(OsStr::new("\x1b[2K")), "\\u{1b}[2K");

    for name in ["a\tb\nc\u{202e}d\x1b", "plain"] {
        check_trusted_comment(&escape_file_name(OsStr::new(name))).unwrap();
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
    assert_eq!(data[14], crate::domain::SUITE_ED25519_MLDSA65, "suite");
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

/// Every reader names both file types when it gets the wrong one.
#[test]
fn test_readers_name_the_file_type_they_expected_and_got() {
    let dir = tempfile::tempdir().unwrap();
    let sk_path = dir.path().join("test.key");
    write_secret_key(&sk_path, &SecretSeeds::generate(), pw("test"), &TEST_KDF).unwrap();
    let blob = std::fs::read(&sk_path).unwrap();

    let msg = invalid_format_message(super::public_key::decode(&blob));
    assert_eq!(msg, "expected a public key file, got a secret key file");
    let msg = invalid_format_message(read_signature(&sk_path));
    assert_eq!(msg, "expected a signature file, got a secret key file");
}

/// Signature format v1 files are read as leniently as pqsign 0.1 read them: bytes after the comment are ignored, so
/// signatures pqsign 0.1 accepted keep verifying. ARCHITECTURE.md states this exception.
#[test]
fn test_signature_v1_ignores_trailing_data() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v1");
    let pk = read_public_key(&fixture.join("signer.pub")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let sig_path = dir.path().join("message.txt.pqsig");
    let mut data = std::fs::read(fixture.join("message.txt.pqsig")).unwrap();
    data.extend_from_slice(b"extra");
    std::fs::write(&sig_path, &data).unwrap();

    let sig = read_signature(&sig_path).unwrap();

    sig.verify(&pk, &fixture.join("message.txt")).unwrap();
}

/// The binary data of a public key may continue after the ML-DSA-65 key; the key read is the same.
#[test]
fn test_public_key_binary_ignores_trailing_data() {
    let (_, pk) = KeyPair::new().into_parts();
    let mut blob = super::public_key::encode(&pk);
    blob.extend_from_slice(b"extra");

    let decoded = super::public_key::decode(&blob).unwrap();

    assert_eq!(decoded.key_id(), pk.key_id());
    assert_eq!(decoded.fingerprint(), pk.fingerprint());
}

/// The text form of a public key is one line. A second line is rejected, from a file and inline, although trailing
/// whitespace, such as the line ending `encode_text` writes, is allowed.
#[test]
fn test_public_key_text_must_be_one_line() {
    let (_, pk) = KeyPair::new().into_parts();
    let text = encode_public_key(&pk);
    assert_eq!(read_public_key_string(&format!("{text}  \n\n")).unwrap().fingerprint(), pk.fingerprint());

    let two_lines = format!("{text}second line\n");
    assert!(read_public_key_string(&two_lines).is_err(), "a second line was accepted inline");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two-lines.pub");
    std::fs::write(&path, &two_lines).unwrap();
    assert!(read_public_key(&path).is_err(), "a second line was accepted from a file");
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
    let public_key_v2 = b"PQSN\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00";
    let msg = invalid_format_message(FileHeader::read(&mut Cursor::new(public_key_v2.as_slice())));
    assert!(
        msg.contains("this public key file is format v2, which needs a newer pqsign (this build reads up to v1)"),
        "got: {msg}"
    );

    let secret_key_v2 = b"PQSN\x02\x02\x00\x00\x00\x00\x00\x00\x00\x00";
    assert_eq!(FileHeader::read(&mut Cursor::new(secret_key_v2.as_slice())).unwrap().version, 2);

    let secret_key_v3 = b"PQSN\x03\x02\x00\x00\x00\x00\x00\x00\x00\x00";
    let msg = invalid_format_message(FileHeader::read(&mut Cursor::new(secret_key_v3.as_slice())));
    assert!(
        msg.contains("this secret key file is format v3, which needs a newer pqsign (this build reads up to v2)"),
        "got: {msg}"
    );

    let sig_v2 = b"PQSN\x02\x03\x00\x00\x00\x00\x00\x00\x00\x00";
    assert_eq!(FileHeader::read(&mut Cursor::new(sig_v2.as_slice())).unwrap().version, 2);

    let sig_v3 = b"PQSN\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00";
    let msg = invalid_format_message(FileHeader::read(&mut Cursor::new(sig_v3.as_slice())));
    assert!(
        msg.contains("this signature file is format v3, which needs a newer pqsign (this build reads up to v2)"),
        "got: {msg}"
    );
}

// -- File names in trusted comments --

#[test]
fn test_escape_file_name_keeps_valid_names() {
    assert_eq!(escape_file_name(OsStr::new("Bericht für März.pdf")), "Bericht für März.pdf");
    assert_eq!(escape_file_name(OsStr::new("a\tb\\c")), "a\\tb\\\\c");
}

#[cfg(unix)]
#[test]
fn test_escape_file_name_keeps_invalid_bytes_distinct() {
    use std::os::unix::ffi::OsStrExt;

    let name = |bytes: &[u8]| escape_file_name(OsStr::from_bytes(bytes));
    assert_eq!(name(b"caf\xe9.txt"), "caf\\xe9.txt");
    assert_ne!(name(b"caf\xe9.txt"), name(b"caf\xe8.txt"));
    // A literal backslash is doubled, so it can never look like an escaped byte.
    assert_eq!(name(b"caf\\xe9.txt"), "caf\\\\xe9.txt");
    check_trusted_comment(&name(b"caf\xe9\t\x1b.txt")).unwrap();
}

// -- Public key text prefix and header version --

/// The prefix and the header must agree. Secret keys moved to format v2 while public keys stay at v1, so a v2
/// header inside `pqsign:v1:` text is rejected by this check.
#[test]
fn test_public_key_text_and_header_versions_must_match() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let (_, pk) = KeyPair::new().into_parts();
    let mut blob = super::public_key::encode(&pk);
    read_public_key_string(&format!("pqsign:v1:{}", STANDARD.encode(&blob))).unwrap();

    blob[4] = 2;
    let result = read_public_key_string(&format!("pqsign:v1:{}", STANDARD.encode(&blob)));
    assert!(matches!(result, Err(Error::InvalidFormat(_))));
}

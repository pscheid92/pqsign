mod keys;
pub mod signature;
mod types;

pub use keys::{KeyPair, PublicKey, SecretKey};
pub use signature::Signature;
pub use types::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, KeyId, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature};

use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

use blake2::{Blake2b512, Digest};

use crate::errors::{Error, IoContext};

const ED25519_CONTEXT: &[u8] = b"pqsign-ed25519";
const MLDSA65_CONTEXT: &[u8] = b"pqsign-mldsa65";

fn prehash_file(path: &Path) -> Result<[u8; 64], Error> {
    let file = File::open(path).io_context(path)?;
    let mut hasher = Blake2b512::new();
    io::copy(&mut BufReader::new(file), &mut hasher).io_context(path)?;
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use fips204::traits::SerDes;

    use super::*;

    #[test]
    fn test_generate_produces_valid_keypair() {
        let kp = KeyPair::new();
        assert_eq!(kp.secret_key.key_id, kp.public_key.key_id);
    }

    #[test]
    fn test_from_parts_roundtrip() {
        let (sk, _) = KeyPair::new().into_parts();
        let ed25519 = Ed25519SecretKey::from_bytes(sk.ed25519.to_bytes());
        let mldsa65 = MlDsa65SecretKey::from_bytes(sk.mldsa65.clone().into_bytes());
        let sk2 = SecretKey::from_parts(sk.key_id, ed25519, mldsa65).unwrap();
        assert_eq!(sk.key_id, sk2.key_id);
        assert_eq!(sk.ed25519.to_bytes(), sk2.ed25519.to_bytes());
    }

    fn setup() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, b"test content for hybrid verification").unwrap();
        (dir, file)
    }

    #[test]
    fn test_sign_and_verify() {
        let (_dir, file) = setup();
        let (sk, pk) = KeyPair::new().into_parts();
        let sig = sk.sign(&file, "test").unwrap();
        sig.verify(&pk, &file).unwrap();
    }

    #[test]
    fn test_tampered_file_fails() {
        let (_dir, file) = setup();
        let (sk, pk) = KeyPair::new().into_parts();
        let sig = sk.sign(&file, "test").unwrap();
        std::fs::write(&file, b"tampered!").unwrap();
        assert!(matches!(sig.verify(&pk, &file), Err(Error::SignatureVerificationFailed)));
    }

    #[test]
    fn test_wrong_key_fails() {
        let (_dir, file) = setup();
        let (sk1, _) = KeyPair::new().into_parts();
        let (_, pk2) = KeyPair::new().into_parts();
        let sig = sk1.sign(&file, "test").unwrap();
        assert!(sig.verify(&pk2, &file).is_err());
    }

    #[test]
    fn test_key_id_mismatch() {
        let (_dir, file) = setup();
        let (sk, mut pk) = KeyPair::new().into_parts();
        let sig = sk.sign(&file, "test").unwrap();
        pk.key_id = KeyId([0xFF; KeyId::LEN]);
        assert!(matches!(sig.verify(&pk, &file), Err(Error::KeyIdMismatch { .. })));
    }

    #[test]
    fn test_tampered_comment_fails() {
        let (_dir, file) = setup();
        let (sk, pk) = KeyPair::new().into_parts();
        let mut sig = sk.sign(&file, "original").unwrap();
        sig.trusted_comment = "tampered".to_string();
        assert!(matches!(sig.verify(&pk, &file), Err(Error::SignatureVerificationFailed)));
    }

    #[test]
    fn test_tampered_ed25519_sig_fails() {
        let (_dir, file) = setup();
        let (sk, pk) = KeyPair::new().into_parts();
        let mut sig = sk.sign(&file, "test").unwrap();
        sig.ed25519.0[0] ^= 0x01;
        assert!(matches!(sig.verify(&pk, &file), Err(Error::SignatureVerificationFailed)));
    }

    #[test]
    fn test_tampered_mldsa65_sig_fails() {
        let (_dir, file) = setup();
        let (sk, pk) = KeyPair::new().into_parts();
        let mut sig = sk.sign(&file, "test").unwrap();
        sig.mldsa65.0[0] ^= 0x01;
        assert!(matches!(sig.verify(&pk, &file), Err(Error::SignatureVerificationFailed)));
    }

    #[test]
    fn test_sign_and_verify_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("empty.txt");
        std::fs::write(&file, b"").unwrap();
        let (sk, pk) = KeyPair::new().into_parts();
        let sig = sk.sign(&file, "empty").unwrap();
        sig.verify(&pk, &file).unwrap();
    }

    #[test]
    fn test_key_id_display_hex() {
        let id = KeyId([0xAB, 0xCD, 0x01, 0x23, 0x45, 0x67, 0x89, 0xEF]);
        assert_eq!(id.to_string(), "ABCD0123456789EF");
    }

    #[test]
    fn test_key_id_as_bytes() {
        let id = KeyId([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(id.as_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}

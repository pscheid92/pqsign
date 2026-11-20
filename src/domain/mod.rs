mod fingerprint;
mod keys;
mod signature;
mod types;

pub use fingerprint::Fingerprint;
pub use keys::{KeyPair, PublicKey, SecretKey, SecretSeeds};
pub(crate) use signature::Version;
pub use signature::{SUITE_ED25519_MLDSA65, Signature, SignatureFormat};
pub use types::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, KeyId, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Seed, MlDsa65Signature};

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use blake2::{Blake2b512, Digest};

use crate::errors::{Error, IoContext};

fn prehash_file(path: &Path) -> Result<[u8; 64], Error> {
    let file = File::open(path).io_context(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Blake2b512::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).io_context(path)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
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
    fn test_secret_key_types_are_wiped_on_drop() {
        fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wiped_on_drop::<SecretKey>();
        wiped_on_drop::<Ed25519SecretKey>();
        wiped_on_drop::<MlDsa65SecretKey>();
        wiped_on_drop::<MlDsa65Seed>();
        wiped_on_drop::<SecretSeeds>();
        wiped_on_drop::<ed25519_dalek::SigningKey>();
        wiped_on_drop::<fips204::ml_dsa_65::PrivateKey>();
    }

    #[test]
    fn test_secret_key_bytes_are_never_printed() {
        let ed25519 = Ed25519SecretKey::from_bytes([0x41; Ed25519SecretKey::LEN]);
        let mldsa65 = MlDsa65SecretKey::from_bytes([0x41; MlDsa65SecretKey::LEN]);

        assert_eq!(format!("{ed25519:?}"), "Ed25519SecretKey([REDACTED])");
        assert_eq!(format!("{mldsa65:?}"), "MlDsa65SecretKey([REDACTED])");
        assert_eq!(format!("{ed25519:#?}"), "Ed25519SecretKey([REDACTED])");

        let seed = MlDsa65Seed::from_bytes([0x41; MlDsa65Seed::LEN]);
        assert_eq!(format!("{seed:?}"), "MlDsa65Seed([REDACTED])");
        let seeds = SecretSeeds::from_parts(ed25519, seed);
        assert_eq!(format!("{seeds:?}"), "SecretSeeds([REDACTED])");
        assert_eq!(format!("{seeds:#?}"), "SecretSeeds([REDACTED])");
    }

    #[test]
    fn test_secret_key_read_from() {
        let mut r = std::io::Cursor::new([7u8; Ed25519SecretKey::LEN + 1]);
        let key = Ed25519SecretKey::read_from(&mut r).unwrap();
        assert_eq!(key.as_bytes(), &[7u8; Ed25519SecretKey::LEN]);

        let mut short = std::io::Cursor::new([7u8; Ed25519SecretKey::LEN - 1]);
        assert!(matches!(Ed25519SecretKey::read_from(&mut short), Err(Error::InvalidFormat(_))));
    }

    #[test]
    fn test_fingerprint_ignores_key_id() {
        let (_, mut pk) = KeyPair::new().into_parts();
        let fingerprint = pk.fingerprint();
        pk.key_id = KeyId([0xFF; KeyId::LEN]);
        assert_eq!(pk.fingerprint(), fingerprint);
    }

    #[test]
    fn test_fingerprints_differ_between_keys() {
        let (_, pk1) = KeyPair::new().into_parts();
        let (_, pk2) = KeyPair::new().into_parts();
        assert_ne!(pk1.fingerprint(), pk2.fingerprint());
    }

    #[test]
    fn test_new_key_id_is_fingerprint_prefix() {
        let (sk, pk) = KeyPair::new().into_parts();
        assert_eq!(pk.key_id(), pk.fingerprint().key_id());
        assert_eq!(pk.key_id().as_bytes(), &pk.fingerprint().as_bytes()[..KeyId::LEN]);
        assert_eq!(sk.key_id(), pk.key_id());
    }

    fn seeds(ed25519: [u8; 32], mldsa65: [u8; 32]) -> SecretSeeds {
        SecretSeeds::from_parts(Ed25519SecretKey::from_bytes(ed25519), MlDsa65Seed::from_bytes(mldsa65))
    }

    fn hex32(text: &str) -> [u8; 32] {
        std::array::from_fn(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
    }

    /// Secret key format v2 stores only the seeds, so the same seeds must always give the same keys.
    #[test]
    fn test_same_seeds_give_the_same_key_pair() {
        let a = seeds([1; 32], [2; 32]).key_pair();
        let b = seeds([1; 32], [2; 32]).key_pair();
        assert_eq!(a.public_key.fingerprint(), b.public_key.fingerprint());
        assert_eq!(a.public_key.ed25519.to_bytes(), b.public_key.ed25519.to_bytes());
        assert_eq!(a.public_key.mldsa65.clone().into_bytes(), b.public_key.mldsa65.clone().into_bytes());
        assert_eq!(
            crate::format::encode_public_key(&a.public_key),
            crate::format::encode_public_key(&b.public_key)
        );

        let other = seeds([1; 32], [3; 32]).key_pair();
        assert_ne!(other.public_key.fingerprint(), a.public_key.fingerprint());
    }

    #[test]
    fn test_seed_key_pair_key_id_is_fingerprint_prefix() {
        let (sk, pk) = seeds([5; 32], [6; 32]).key_pair().into_parts();
        assert_eq!(pk.key_id(), pk.fingerprint().key_id());
        assert_eq!(sk.key_id(), pk.key_id());
        assert_eq!(sk.fingerprint(), pk.fingerprint());
    }

    #[test]
    fn test_seed_key_pair_signs_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, b"signed with keys from seeds").unwrap();
        let (sk, pk) = SecretSeeds::generate().key_pair().into_parts();
        sk.sign(&file, "seeds").unwrap().verify(&pk, &file).unwrap();
    }

    #[test]
    fn test_generated_seeds_differ() {
        let a = SecretSeeds::generate().key_pair().public_key.fingerprint();
        let b = SecretSeeds::generate().key_pair().public_key.fingerprint();
        assert_ne!(a, b);
    }

    /// Pins the Ed25519 half of the seed derivation to the private-to-public examples of RFC 8032 Section 7.1,
    /// TEST 1 to 3. The ML-DSA-65 half is pinned by Wycheproof's seed vectors in tests/mldsa_vectors.rs.
    #[test]
    fn test_ed25519_seed_derivation_matches_rfc_8032() {
        let vectors = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            ),
        ];
        for (secret_key, public_key) in vectors {
            let pair = seeds(hex32(secret_key), [0; 32]).key_pair();
            assert_eq!(pair.public_key.ed25519.to_bytes(), hex32(public_key), "RFC 8032 secret key {secret_key}");
        }
    }

    #[test]
    fn test_fingerprint_display() {
        let (_, pk) = KeyPair::new().into_parts();
        let shown = pk.fingerprint().to_string();
        assert!(shown.starts_with("BLAKE2b-256:"), "got: {shown}");
        assert_eq!(shown.len(), "BLAKE2b-256:".len() + 43, "got: {shown}");
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

use std::fmt;
use std::path::Path;

use ed25519_dalek as ed25519;
use ed25519_dalek::Verifier;
use fips204::traits::Verifier as MlDsaVerifier;

use super::fingerprint::Fingerprint;
use super::keys::PublicKey;
use super::prehash_file;
use super::types::*;
use crate::errors::Error;

/// The algorithm suite of v2 signatures: Ed25519 and ML-DSA-65 over a BLAKE2b-512 hash of the file.
pub const SUITE_ED25519_MLDSA65: u8 = 0x01;

/// The signature formats pqsign reads and writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureFormat {
    /// pqsign 0.1. Neither algorithm signs the key ID, and ML-DSA-65 covers the comment only through the
    /// Ed25519 signature. Still verified; written only on request, for verifiers older than pqsign 0.2.
    V1,
    /// Since pqsign 0.2. Both algorithms sign one record with the key ID, the signer's fingerprint, the file
    /// hash and the comment.
    V2,
}

impl fmt::Display for SignatureFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureFormat::V1 => f.write_str("v1"),
            SignatureFormat::V2 => f.write_str("v2"),
        }
    }
}

/// A signature's format, with the data only v2 carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Version {
    V1,
    V2 { signer: Fingerprint },
}

/// A hybrid signature over a file and trusted comment.
pub struct Signature {
    pub(crate) version: Version,
    pub(crate) key_id: KeyId,
    pub(crate) ed25519: Ed25519Signature,
    pub(crate) mldsa65: MlDsa65Signature,
    pub trusted_comment: String,
}

impl Signature {
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn format(&self) -> SignatureFormat {
        match self.version {
            Version::V1 => SignatureFormat::V1,
            Version::V2 { .. } => SignatureFormat::V2,
        }
    }

    /// The fingerprint of the key that made a v2 signature. Only a claim of the file until `verify` succeeds.
    pub fn signer(&self) -> Option<Fingerprint> {
        match self.version {
            Version::V1 => None,
            Version::V2 { signer } => Some(signer),
        }
    }

    pub fn verify(&self, pk: &PublicKey, path: &Path) -> Result<(), Error> {
        self.check_signer(pk)?;
        self.check_key_id(pk)?;

        let file_hash = prehash_file(path)?;
        let message = SignedMessage::new(self.version, self.key_id, &file_hash, &self.trusted_comment);
        self.verify_ed25519(pk, &message)?;
        self.verify_mldsa65(pk, &message)?;

        Ok(())
    }

    /// Names both keys when a v2 signature was made by a different key than the one given.
    fn check_signer(&self, pk: &PublicKey) -> Result<(), Error> {
        let Some(signer) = self.signer() else {
            return Ok(());
        };

        let public_key = pk.fingerprint();
        if signer != public_key {
            let err = Error::SignerMismatch { signer, public_key };
            return Err(err);
        }
        Ok(())
    }

    fn check_key_id(&self, pk: &PublicKey) -> Result<(), Error> {
        if self.key_id != pk.key_id {
            let err = Error::KeyIdMismatch {
                sig_id: self.key_id,
                pk_id: pk.key_id,
            };
            return Err(err);
        }

        Ok(())
    }

    fn verify_ed25519(&self, pk: &PublicKey, message: &SignedMessage) -> Result<(), Error> {
        let signature = ed25519::Signature::from_bytes(self.ed25519.as_bytes());
        pk.ed25519
            .verify(&message.ed25519(), &signature)
            .map_err(|_| Error::SignatureVerificationFailed)
    }

    fn verify_mldsa65(&self, pk: &PublicKey, message: &SignedMessage) -> Result<(), Error> {
        pk.mldsa65
            .verify(&message.mldsa65(&self.ed25519), &self.mldsa65.0, message.mldsa65_context())
            .then_some(())
            .ok_or(Error::SignatureVerificationFailed)
    }
}

/// What the two algorithms sign. In both formats ML-DSA-65 signs over the Ed25519 signature, so neither
/// signature can be replaced on its own. v2 adds one record with everything a signature asserts, which each
/// algorithm signs by itself, and new context strings, so no message of one format is valid in the other.
pub(super) struct SignedMessage<'a> {
    version: Version,
    key_id: KeyId,
    file_hash: &'a [u8; 64],
    comment: &'a str,
}

impl<'a> SignedMessage<'a> {
    const V1_ED25519_CONTEXT: &'static [u8] = b"pqsign-ed25519";
    const V1_MLDSA65_CONTEXT: &'static [u8] = b"pqsign-mldsa65";
    const V2_ED25519_CONTEXT: &'static [u8] = b"pqsign-v2-ed25519";
    const V2_MLDSA65_CONTEXT: &'static [u8] = b"pqsign-v2-mldsa65";
    const V2_RECORD_VERSION: u8 = 2;

    pub(super) fn new(version: Version, key_id: KeyId, file_hash: &'a [u8; 64], comment: &'a str) -> Self {
        SignedMessage {
            version,
            key_id,
            file_hash,
            comment,
        }
    }

    /// v1: `context || file hash || comment`. v2: `context || record`.
    pub(super) fn ed25519(&self) -> Vec<u8> {
        match self.version {
            Version::V1 => [Self::V1_ED25519_CONTEXT, self.file_hash, self.comment.as_bytes()].concat(),
            Version::V2 { signer } => [Self::V2_ED25519_CONTEXT, &self.record(signer)].concat(),
        }
    }

    /// v1: `file hash || Ed25519 signature`. v2: `record || Ed25519 signature`.
    pub(super) fn mldsa65(&self, ed25519: &Ed25519Signature) -> Vec<u8> {
        match self.version {
            Version::V1 => [self.file_hash.as_slice(), ed25519.as_ref()].concat(),
            Version::V2 { signer } => [self.record(signer).as_slice(), ed25519.as_ref()].concat(),
        }
    }

    /// The FIPS 204 context string.
    pub(super) fn mldsa65_context(&self) -> &'static [u8] {
        match self.version {
            Version::V1 => Self::V1_MLDSA65_CONTEXT,
            Version::V2 { .. } => Self::V2_MLDSA65_CONTEXT,
        }
    }

    /// `version || suite || key ID || signer fingerprint || file hash || comment length (u64 LE) || comment`.
    /// Every field has a fixed length except the comment, which is length-prefixed, so the record is unambiguous.
    fn record(&self, signer: Fingerprint) -> Vec<u8> {
        let comment = self.comment.as_bytes();
        let comment_len = (comment.len() as u64).to_le_bytes();
        [
            &[Self::V2_RECORD_VERSION, SUITE_ED25519_MLDSA65][..],
            self.key_id.as_bytes(),
            signer.as_bytes(),
            self.file_hash,
            &comment_len,
            comment,
        ]
        .concat()
    }
}

#[cfg(test)]
mod tests {
    use super::super::KeyPair;
    use super::*;

    fn signed_file() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, b"test content").unwrap();
        (dir, file)
    }

    /// The point of v2: ML-DSA-65 alone protects the comment, without relying on the Ed25519 check.
    #[test]
    fn test_v2_mldsa65_alone_rejects_a_swapped_comment() {
        let (_dir, file) = signed_file();
        let (sk, pk) = KeyPair::new().into_parts();
        let sig = sk.sign(&file, "original").unwrap();
        let file_hash = prehash_file(&file).unwrap();

        let original = SignedMessage::new(sig.version, sig.key_id, &file_hash, "original");
        let swapped = SignedMessage::new(sig.version, sig.key_id, &file_hash, "swapped");
        sig.verify_mldsa65(&pk, &original).unwrap();
        assert!(matches!(sig.verify_mldsa65(&pk, &swapped), Err(Error::SignatureVerificationFailed)));
    }

    #[test]
    fn test_v2_mldsa65_alone_rejects_a_changed_key_id() {
        let (_dir, file) = signed_file();
        let (sk, pk) = KeyPair::new().into_parts();
        let sig = sk.sign(&file, "comment").unwrap();
        let file_hash = prehash_file(&file).unwrap();

        let changed = SignedMessage::new(sig.version, KeyId([0xFF; KeyId::LEN]), &file_hash, "comment");
        assert!(matches!(sig.verify_mldsa65(&pk, &changed), Err(Error::SignatureVerificationFailed)));
    }

    /// An attacker who copies another key's ID into both their key and their signature no longer gets a valid signature.
    #[test]
    fn test_v2_key_id_is_signed() {
        let (_dir, file) = signed_file();
        let (sk, mut pk) = KeyPair::new().into_parts();
        let mut sig = sk.sign(&file, "comment").unwrap();

        let other_id = KeyId([0xAB; KeyId::LEN]);
        sig.key_id = other_id;
        pk.key_id = other_id;
        assert!(matches!(sig.verify(&pk, &file), Err(Error::SignatureVerificationFailed)));
    }

    #[test]
    fn test_v2_names_both_keys_on_signer_mismatch() {
        let (_dir, file) = signed_file();
        let (sk, signer_pk) = KeyPair::new().into_parts();
        let (_, other_pk) = KeyPair::new().into_parts();
        let sig = sk.sign(&file, "comment").unwrap();

        match sig.verify(&other_pk, &file) {
            Err(Error::SignerMismatch { signer, public_key }) => {
                assert_eq!(signer, signer_pk.fingerprint());
                assert_eq!(public_key, other_pk.fingerprint());
            }
            other => panic!("expected SignerMismatch, got: {:?}", other.err().map(|e| e.to_string())),
        }
    }

    #[test]
    fn test_sign_defaults_to_v2_with_signer_fingerprint() {
        let (_dir, file) = signed_file();
        let (sk, pk) = KeyPair::new().into_parts();
        let sig = sk.sign(&file, "comment").unwrap();

        assert_eq!(sig.format(), SignatureFormat::V2);
        assert_eq!(sig.signer(), Some(pk.fingerprint()));
        assert_eq!(sk.fingerprint(), pk.fingerprint());
        sig.verify(&pk, &file).unwrap();
    }

    #[test]
    fn test_v1_signatures_still_sign_and_verify() {
        let (_dir, file) = signed_file();
        let (sk, pk) = KeyPair::new().into_parts();
        let sig = sk.sign_as(&file, "comment", SignatureFormat::V1).unwrap();

        assert_eq!(sig.format(), SignatureFormat::V1);
        assert_eq!(sig.signer(), None);
        sig.verify(&pk, &file).unwrap();
    }

    /// The same signature bytes must never verify under the other format.
    #[test]
    fn test_formats_do_not_verify_as_each_other() {
        let (_dir, file) = signed_file();
        let (sk, pk) = KeyPair::new().into_parts();

        let mut v2_as_v1 = sk.sign(&file, "comment").unwrap();
        v2_as_v1.version = Version::V1;
        assert!(v2_as_v1.verify(&pk, &file).is_err());

        let mut v1_as_v2 = sk.sign_as(&file, "comment", SignatureFormat::V1).unwrap();
        v1_as_v2.version = Version::V2 { signer: pk.fingerprint() };
        assert!(v1_as_v2.verify(&pk, &file).is_err());
    }
}

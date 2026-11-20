use std::path::Path;

use ed25519_dalek as ed25519;
use ed25519_dalek::Signer;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as MlDsaSigner};
use rand::Rng;
use zeroize::ZeroizeOnDrop;

use super::fingerprint::Fingerprint;
use super::prehash_file;
use super::signature::{Signature, SignatureFormat, SignedMessage, Version};
use super::types::*;
use crate::errors::Error;

pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPair {
    /// Generates a key pair from fresh seeds. Its key ID is the start of its fingerprint, so a key with a chosen
    /// ID cannot be made without about 2^64 attempts. Keys from pqsign 0.1 have random key IDs and keep working.
    pub fn new() -> Self {
        SecretSeeds::generate().key_pair()
    }

    pub fn into_parts(self) -> (SecretKey, PublicKey) {
        (self.secret_key, self.public_key)
    }
}

/// The two 32-byte values a key pair is generated from: the RFC 8032 Ed25519 private key, which is itself a seed,
/// and FIPS 204's ML-DSA-65 seed ξ. Each is as sensitive as the key it makes: the whole key pair is rebuilt from
/// them. Wiped on drop, never printed, and neither cloned nor compared.
#[derive(ZeroizeOnDrop)]
pub struct SecretSeeds {
    ed25519: Ed25519SecretKey,
    mldsa65: MlDsa65Seed,
}

impl SecretSeeds {
    /// Fresh seeds from `rand::rng()`, a cryptographically secure generator seeded from the operating system, read
    /// straight into the wiped byte types.
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let mut ed25519 = Ed25519SecretKey([0u8; Ed25519SecretKey::LEN]);
        rng.fill_bytes(&mut ed25519.0);
        let mut mldsa65 = MlDsa65Seed([0u8; MlDsa65Seed::LEN]);
        rng.fill_bytes(&mut mldsa65.0);
        SecretSeeds { ed25519, mldsa65 }
    }

    /// Every 32-byte value is a valid seed, so this cannot fail.
    pub fn from_parts(ed25519: Ed25519SecretKey, mldsa65: MlDsa65Seed) -> Self {
        SecretSeeds { ed25519, mldsa65 }
    }

    pub fn ed25519(&self) -> &Ed25519SecretKey {
        &self.ed25519
    }

    pub fn mldsa65(&self) -> &MlDsa65Seed {
        &self.mldsa65
    }

    /// Runs the standard key generation of each algorithm: RFC 8032's for Ed25519 and FIPS 204's
    /// ML-DSA.KeyGen_internal for ML-DSA-65. Both keys get the start of their fingerprint as key ID.
    ///
    /// This derivation is part of secret key format v2, which stores only the seeds: changing it would turn every
    /// such key file into a different key. A different derivation needs a new secret key format version.
    pub fn key_pair(&self) -> KeyPair {
        let ed25519_secret_key = ed25519::SigningKey::from_bytes(self.ed25519.as_bytes());
        let ed25519_public_key = ed25519_secret_key.verifying_key();
        let (mldsa65_public_key, mldsa65_secret_key) = ml_dsa_65::KG::keygen_from_seed(self.mldsa65.as_bytes());
        let key_id = Fingerprint::of(&ed25519_public_key, &mldsa65_public_key).key_id();

        let secret_key = SecretKey {
            key_id,
            ed25519: ed25519_secret_key,
            mldsa65: mldsa65_secret_key,
        };
        let public_key = PublicKey {
            key_id,
            ed25519: ed25519_public_key,
            mldsa65: mldsa65_public_key,
        };
        KeyPair { secret_key, public_key }
    }
}

impl std::fmt::Debug for SecretSeeds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretSeeds([REDACTED])")
    }
}

/// A secret key capable of signing files.
#[derive(ZeroizeOnDrop)]
pub struct SecretKey {
    pub(crate) key_id: KeyId,
    pub(crate) ed25519: ed25519::SigningKey,
    pub(crate) mldsa65: ml_dsa_65::PrivateKey,
}

impl SecretKey {
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn from_parts(key_id: KeyId, ed25519: Ed25519SecretKey, mldsa65: MlDsa65SecretKey) -> Result<Self, Error> {
        let ed25519_key = ed25519::SigningKey::from_bytes(ed25519.as_bytes());
        // fips204 takes the array by value; that copy is beyond our reach to wipe.
        let mldsa65_key = ml_dsa_65::PrivateKey::try_from_bytes(*mldsa65.as_bytes()).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(SecretKey {
            key_id,
            ed25519: ed25519_key,
            mldsa65: mldsa65_key,
        })
    }

    /// The fingerprint of the matching public key, which the secret key can derive itself.
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.ed25519.verifying_key(), &self.mldsa65.get_public_key())
    }

    /// Signs a file in the current format, v2.
    pub fn sign(&self, path: &Path, trusted_comment: &str) -> Result<Signature, Error> {
        self.sign_as(path, trusted_comment, SignatureFormat::V2)
    }

    /// Signs a file in the given format. Use v1 only for verifiers older than pqsign 0.2.
    pub fn sign_as(&self, path: &Path, trusted_comment: &str, format: SignatureFormat) -> Result<Signature, Error> {
        let file_hash = prehash_file(path)?;
        let version = match format {
            SignatureFormat::V1 => Version::V1,
            SignatureFormat::V2 => Version::V2 { signer: self.fingerprint() },
        };
        let message = SignedMessage::new(version, self.key_id, &file_hash, trusted_comment);

        let ed25519 = Ed25519Signature::from_bytes(self.ed25519.sign(&message.ed25519()).to_bytes());
        let mldsa65 = MlDsa65Signature::from_bytes(
            self.mldsa65
                .try_sign(&message.mldsa65(&ed25519), message.mldsa65_context())
                .map_err(|e| Error::Crypto(e.to_string()))?,
        );

        Ok(Signature {
            version,
            key_id: self.key_id,
            ed25519,
            mldsa65,
            trusted_comment: trusted_comment.to_string(),
        })
    }
}

/// A public key for verifying signatures.
pub struct PublicKey {
    pub(super) key_id: KeyId,
    pub(super) ed25519: ed25519::VerifyingKey,
    pub(super) mldsa65: ml_dsa_65::PublicKey,
}

impl PublicKey {
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.ed25519, &self.mldsa65)
    }

    /// The key ID and both public keys as bytes, the inverse of [`PublicKey::from_parts`]. The file format uses
    /// this instead of the `ed25519-dalek` and `fips204` types, so only `domain` depends on them.
    pub fn to_parts(&self) -> (KeyId, Ed25519PublicKey, MlDsa65PublicKey) {
        let ed25519 = Ed25519PublicKey::from_bytes(self.ed25519.to_bytes());
        let mldsa65 = MlDsa65PublicKey::from_bytes(self.mldsa65.clone().into_bytes());
        (self.key_id, ed25519, mldsa65)
    }

    pub fn from_parts(key_id: KeyId, ed25519: Ed25519PublicKey, mldsa65: MlDsa65PublicKey) -> Result<Self, Error> {
        let ed25519 =
            ed25519::VerifyingKey::from_bytes(ed25519.as_bytes()).map_err(|e| Error::InvalidFormat(format!("invalid Ed25519 public key: {e}")))?;
        let mldsa65 = ml_dsa_65::PublicKey::try_from_bytes(mldsa65.into_bytes())
            .map_err(|e| Error::InvalidFormat(format!("invalid ML-DSA-65 public key: {e}")))?;
        Ok(PublicKey { key_id, ed25519, mldsa65 })
    }
}

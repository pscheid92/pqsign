use std::path::Path;

use ed25519_dalek as ed25519;
use ed25519_dalek::Signer;
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, SerDes, Signer as MlDsaSigner};
use rand::Rng;
use zeroize::ZeroizeOnDrop;

use super::signature::Signature;
use super::types::*;
use super::{ED25519_CONTEXT, MLDSA65_CONTEXT, prehash_file};
use crate::errors::Error;

pub struct KeyPair {
    pub secret_key: SecretKey,
    pub public_key: PublicKey,
}

#[allow(clippy::new_without_default)]
impl KeyPair {
    const ED25519_SEED_LEN: usize = 32;
    const MLDSA65_SEED_LEN: usize = 32;

    pub fn new() -> Self {
        let mut rng = rand::rng();
        let key_id = KeyId::random(&mut rng);

        let (ed25519_secret_key, ed25519_public_key) = Self::gen_ed25519_keys(&mut rng);
        let (mldsa65_secret_key, mldsa65_public_key) = Self::gen_mldsa65_keys(&mut rng);

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

    pub fn into_parts(self) -> (SecretKey, PublicKey) {
        (self.secret_key, self.public_key)
    }

    fn gen_ed25519_keys(rng: &mut impl Rng) -> (ed25519::SigningKey, ed25519::VerifyingKey) {
        let mut seed = [0u8; Self::ED25519_SEED_LEN];
        rng.fill_bytes(&mut seed);

        let secret_key = ed25519::SigningKey::from_bytes(&seed);
        let public_key = secret_key.verifying_key();
        (secret_key, public_key)
    }

    fn gen_mldsa65_keys(rng: &mut impl Rng) -> (ml_dsa_65::PrivateKey, ml_dsa_65::PublicKey) {
        let mut seed = [0u8; Self::MLDSA65_SEED_LEN];
        rng.fill_bytes(&mut seed);

        let (public_key, secret_key) = ml_dsa_65::KG::keygen_from_seed(&seed);
        (secret_key, public_key)
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
        let mldsa65_key = ml_dsa_65::PrivateKey::try_from_bytes(mldsa65.into_bytes()).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(SecretKey {
            key_id,
            ed25519: ed25519_key,
            mldsa65: mldsa65_key,
        })
    }

    pub fn sign(&self, path: &Path, trusted_comment: &str) -> Result<Signature, Error> {
        let file_hash = prehash_file(path)?;

        // Ed25519 signs (domain prefix || file hash || trusted comment)
        let ed25519_msg = [ED25519_CONTEXT, file_hash.as_ref(), trusted_comment.as_bytes()].concat();
        let ed25519 = Ed25519Signature::from_bytes(self.ed25519.sign(&ed25519_msg).to_bytes());

        // ML-DSA-65 nests over (file hash || ed25519 sig) with domain context
        let mldsa65_msg = [file_hash.as_ref(), ed25519.as_ref()].concat();
        let mldsa65 = MlDsa65Signature::from_bytes(
            self.mldsa65
                .try_sign(&mldsa65_msg, MLDSA65_CONTEXT)
                .map_err(|e| Error::Crypto(e.to_string()))?,
        );

        Ok(Signature {
            key_id: self.key_id,
            ed25519,
            mldsa65,
            trusted_comment: trusted_comment.to_string(),
        })
    }
}

/// A public key for verifying signatures.
pub struct PublicKey {
    pub(crate) key_id: KeyId,
    pub(crate) ed25519: ed25519::VerifyingKey,
    pub(crate) mldsa65: ml_dsa_65::PublicKey,
}

impl PublicKey {
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn from_parts(key_id: KeyId, ed25519: Ed25519PublicKey, mldsa65: MlDsa65PublicKey) -> Result<Self, Error> {
        let ed25519 = ed25519::VerifyingKey::from_bytes(ed25519.as_bytes()).map_err(|e| Error::Crypto(format!("invalid ed25519 public key: {e}")))?;
        let mldsa65 =
            ml_dsa_65::PublicKey::try_from_bytes(mldsa65.into_bytes()).map_err(|e| Error::Crypto(format!("invalid mldsa65 public key: {e}")))?;
        Ok(PublicKey { key_id, ed25519, mldsa65 })
    }
}

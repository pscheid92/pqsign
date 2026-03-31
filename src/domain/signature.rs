use std::path::Path;

use ed25519_dalek as ed25519;
use ed25519_dalek::Verifier;
use fips204::traits::Verifier as MlDsaVerifier;

use super::keys::PublicKey;
use super::types::*;
use super::{ED25519_CONTEXT, MLDSA65_CONTEXT, prehash_file};
use crate::errors::Error;

/// A hybrid signature over a file and trusted comment.
pub struct Signature {
    pub(crate) key_id: KeyId,
    pub(crate) ed25519: Ed25519Signature,
    pub(crate) mldsa65: MlDsa65Signature,
    pub trusted_comment: String,
}

impl Signature {
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn verify(&self, pk: &PublicKey, path: &Path) -> Result<(), Error> {
        self.check_key_id(pk)?;

        let file_hash = prehash_file(path)?;
        self.verify_ed25519(pk, &file_hash)?;
        self.verify_mldsa65(pk, &file_hash)?;

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

    fn verify_ed25519(&self, pk: &PublicKey, prehash: &[u8]) -> Result<(), Error> {
        let signature = ed25519::Signature::from_bytes(self.ed25519.as_bytes());
        let msg = [ED25519_CONTEXT, prehash, self.trusted_comment.as_bytes()].concat();
        pk.ed25519.verify(&msg, &signature).map_err(|_| Error::SignatureVerificationFailed)
    }

    fn verify_mldsa65(&self, pk: &PublicKey, prehash: &[u8]) -> Result<(), Error> {
        let msg = [prehash, self.ed25519.as_ref()].concat();
        pk.mldsa65
            .verify(&msg, &self.mldsa65.0, MLDSA65_CONTEXT)
            .then_some(())
            .ok_or(Error::SignatureVerificationFailed)
    }
}

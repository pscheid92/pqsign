use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use blake2::{Blake2b256, Digest};
use ed25519_dalek as ed25519;
use fips204::ml_dsa_65;
use fips204::traits::SerDes;

use super::types::KeyId;

/// Identifies a key pair by its public key material, for comparing keys out of band.
///
/// It is a BLAKE2b-256 hash over a domain tag and both public keys. Unlike the 8-byte key ID, which only
/// locates a key and can be set to anything, a fingerprint cannot be matched by a different key. It does not
/// depend on the key ID, so changing a file's key ID never changes its fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fingerprint(pub(crate) [u8; Fingerprint::LEN]);

impl Fingerprint {
    pub const LEN: usize = 32;

    /// Both public keys have a fixed length, so their concatenation after the tag is unambiguous.
    const DOMAIN: &[u8] = b"pqsign fingerprint: Ed25519 + ML-DSA-65";

    pub(crate) fn of(ed25519: &ed25519::VerifyingKey, mldsa65: &ml_dsa_65::PublicKey) -> Self {
        let digest = Blake2b256::new()
            .chain_update(Self::DOMAIN)
            .chain_update(ed25519.as_bytes())
            .chain_update(mldsa65.clone().into_bytes())
            .finalize();
        Fingerprint(digest.into())
    }

    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// The first eight bytes, which become the key ID of keys generated since pqsign 0.2.
    pub fn key_id(&self) -> KeyId {
        KeyId(std::array::from_fn(|i| self.0[i]))
    }
}

/// `BLAKE2b-256:` followed by the hash in unpadded base64, in the style of ssh's `SHA256:` fingerprints.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BLAKE2b-256:{}", STANDARD_NO_PAD.encode(self.0))
    }
}

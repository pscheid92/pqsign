use std::fmt;

use ed25519_dalek as ed25519;
use fips204::ml_dsa_65;
use rand::Rng;

use crate::errors::Error;

macro_rules! byte_io {
    ($name:ident, $len:expr) => {
        impl $name {
            pub const LEN: usize = $len;

            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            pub fn read_from(r: &mut impl std::io::Read) -> Result<Self, Error> {
                let mut buf = [0u8; $len];
                r.read_exact(&mut buf)
                    .map_err(|_| Error::InvalidFormat("unexpected end of file".into()))?;
                Ok(Self(buf))
            }

            pub fn write_to(&self, w: &mut impl std::io::Write) -> Result<(), Error> {
                Ok(w.write_all(&self.0)?)
            }
        }
    };
}

macro_rules! byte_type {
    ($name:ident, $len:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name(pub(crate) [u8; $len]);

        byte_io!($name, $len);

        impl $name {
            pub fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }
            pub fn into_bytes(self) -> [u8; $len] {
                self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }
    };
}

byte_type!(Ed25519PublicKey, ed25519::PUBLIC_KEY_LENGTH);
byte_type!(Ed25519SecretKey, ed25519::SECRET_KEY_LENGTH);
byte_type!(Ed25519Signature, ed25519::SIGNATURE_LENGTH);
byte_type!(MlDsa65PublicKey, ml_dsa_65::PK_LEN);
byte_type!(MlDsa65SecretKey, ml_dsa_65::SK_LEN);
byte_type!(MlDsa65Signature, ml_dsa_65::SIG_LEN);

#[derive(Clone, Copy, Debug, PartialEq, Eq, zeroize::Zeroize)]
pub struct KeyId(pub(crate) [u8; 8]);

byte_io!(KeyId, 8);

impl KeyId {
    pub fn random(rng: &mut impl Rng) -> KeyId {
        let mut buf = [0u8; Self::LEN];
        rng.fill_bytes(&mut buf);
        KeyId(buf)
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02X}"))
    }
}

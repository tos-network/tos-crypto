use super::{CompressedPublicKey, PublicKey};
use crate::proofs::H;
use curve25519_dalek::{RistrettoPoint, Scalar};
use serde::{de::Error, Serialize};
use sha3::{Digest, Sha3_512};

// SCALAR_SIZE moved to parent module
const SCALAR_SIZE: usize = 32;

pub const SIGNATURE_SIZE: usize = SCALAR_SIZE * 2;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Signature {
    s: Scalar,
    e: Scalar,
}

impl Signature {
    pub fn new(s: Scalar, e: Scalar) -> Self {
        Self { s, e }
    }

    // Verify the signature using the Public Key and the hash of the message
    pub fn verify(&self, message: &[u8], key: &PublicKey) -> bool {
        let r = (*H) * self.s + key.as_point() * -self.e;
        let calculated = hash_and_point_to_scalar(&key.compress(), message, &r);
        self.e == calculated
    }
}

// Create a Scalar from Public Key, Hash of the message, and selected point
pub fn hash_and_point_to_scalar(
    key: &CompressedPublicKey,
    message: &[u8],
    point: &RistrettoPoint,
) -> Scalar {
    let mut hasher = Sha3_512::new();
    hasher.update(key.as_bytes());
    hasher.update(message);
    hasher.update(point.compress().as_bytes());

    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.to_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(D::Error::custom)
    }
}

impl Signature {
    pub fn to_bytes(&self) -> [u8; SIGNATURE_SIZE] {
        let mut bytes = [0u8; SIGNATURE_SIZE];
        bytes[0..32].copy_from_slice(self.s.as_bytes());
        bytes[32..64].copy_from_slice(self.e.as_bytes());
        bytes
    }

    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: &[u8; SIGNATURE_SIZE]) -> Result<Self, ()> {
        let s = Scalar::from_canonical_bytes(bytes[0..32].try_into().unwrap())
            .into_option()
            .ok_or(())?;
        let e = Scalar::from_canonical_bytes(bytes[32..64].try_into().unwrap())
            .into_option()
            .ok_or(())?;
        Ok(Self { s, e })
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, hex::FromHexError> {
        let bytes: [u8; SIGNATURE_SIZE] = hex::decode(hex_str)?
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Self::from_bytes(&bytes).map_err(|_| hex::FromHexError::InvalidStringLength)
    }
}

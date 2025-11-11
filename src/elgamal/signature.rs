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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyPair, PrivateKey};

    /// Test that signature verification works correctly
    /// This ensures that the sign/verify logic is consistent
    #[test]
    fn signature_sign_and_verify() {
        // Create a keypair
        let keypair = KeyPair::new();
        let message = b"test message for TOS signature";

        // Sign the message
        let signature = keypair.sign(message);

        // Verify the signature
        assert!(
            signature.verify(message, keypair.get_public_key()),
            "Signature verification should pass for valid signature"
        );

        // Verify fails with wrong message
        let wrong_message = b"wrong message";
        assert!(
            !signature.verify(wrong_message, keypair.get_public_key()),
            "Signature verification should fail for wrong message"
        );

        // Verify fails with wrong public key
        let wrong_keypair = KeyPair::new();
        assert!(
            !signature.verify(message, wrong_keypair.get_public_key()),
            "Signature verification should fail for wrong public key"
        );
    }

    /// Test that signatures can be serialized and deserialized
    #[test]
    fn signature_serialization() {
        let keypair = KeyPair::new();
        let message = b"test serialization";
        let signature = keypair.sign(message);

        // Serialize to bytes
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), SIGNATURE_SIZE);

        // Deserialize from bytes
        let deserialized = Signature::from_bytes(&bytes).expect("Should deserialize");
        assert_eq!(signature, deserialized);

        // Verify deserialized signature
        assert!(
            deserialized.verify(message, keypair.get_public_key()),
            "Deserialized signature should verify"
        );
    }

    /// Test hex encoding/decoding
    #[test]
    fn signature_hex_encoding() {
        let keypair = KeyPair::new();
        let message = b"test hex encoding";
        let signature = keypair.sign(message);

        // Encode to hex
        let hex_str = signature.to_hex();
        assert_eq!(hex_str.len(), SIGNATURE_SIZE * 2); // 2 hex chars per byte

        // Decode from hex
        let decoded = Signature::from_hex(&hex_str).expect("Should decode from hex");
        assert_eq!(signature, decoded);

        // Verify decoded signature
        assert!(
            decoded.verify(message, keypair.get_public_key()),
            "Decoded signature should verify"
        );
    }

    /// Test that signature verification uses the correct H generator
    #[test]
    fn signature_uses_correct_h_generator() {
        use crate::proofs::H;

        // Create a known private key (for testing purposes)
        let private_key = PrivateKey::from_scalar(Scalar::from(42u64));

        // Compute public key manually: P = H * private_key
        let public_key_point = (*H) * private_key.as_scalar();

        // Create keypair from this private key
        let keypair = KeyPair::from_private_key(private_key).expect("Should create keypair");

        // Verify that the keypair's public key matches our manual calculation
        assert_eq!(
            keypair.get_public_key().as_point(),
            &public_key_point,
            "KeyPair should use H generator for public key derivation"
        );

        // Sign and verify to ensure H is used consistently
        let message = b"test H generator usage";
        let signature = keypair.sign(message);
        assert!(
            signature.verify(message, keypair.get_public_key()),
            "Signature should verify using same H generator"
        );
    }
}
